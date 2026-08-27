package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/emailidentity"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/passwordhash"
	"github.com/go-chi/chi/v5"
)

// UserHandler handles admin user CRUD and invitation endpoints.
type UserHandler struct {
	queries                  *db.Queries
	cfg                      *config.Config
	inviteRandom             io.Reader
	invitationPasswordHasher func(string) (string, error)
	// vault is optional and used only to detach a disabled user's rotation
	// delivery targets. Wired by SetVault after construction because the vault
	// handler is built later in main; nil simply skips the purge, and the
	// authoritative refusal still happens at delivery time.
	vault *VaultHandler
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(queries *db.Queries, cfg *config.Config) *UserHandler {
	return &UserHandler{
		queries:                  queries,
		cfg:                      cfg,
		inviteRandom:             rand.Reader,
		invitationPasswordHasher: passwordhash.Hash,
	}
}

// SetVault wires the vault handler used to purge rotation targets when an
// account is disabled.
func (h *UserHandler) SetVault(v *VaultHandler) { h.vault = v }

var validRoles = map[string]bool{"admin": true, "user": true, "vault_only": true}

type adminUserResponse struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Disabled    bool   `json:"disabled"`
	TOTPEnabled bool   `json:"totp_enabled"`
	EntryCount  int    `json:"entry_count"`
	CreatedAt   string `json:"created_at"`
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

type updateUserRequest struct {
	Name     *string `json:"name"`
	Role     *string `json:"role"`
	Disabled *bool   `json:"disabled"`
}

// List handles GET /api/admin/users - returns all users with their vault
// entry counts.
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.queries.ListUsersWithEntryCount(r.Context(), privateIngressSQLFlag(r.Context()))
	if err != nil {
		logError(r, "users.list: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	users := make([]adminUserResponse, 0, len(rows))
	for _, row := range rows {
		users = append(users, adminUserResponse{
			ID:          row.ID,
			Email:       row.Email,
			Name:        nullStringToString(row.Name),
			Role:        row.Role,
			Disabled:    row.Disabled != 0,
			TOTPEnabled: nullInt64Is1(row.TotpEnabled),
			EntryCount:  int(row.EntryCount),
			CreatedAt:   nullTimeStr(row.CreatedAt),
		})
	}

	writeJSON(w, http.StatusOK, users)
}

// Create handles POST /api/admin/users - creates a user with an explicit role.
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}
	req.Email = emailidentity.Canonical(req.Email)

	if err := ValidateRequired("email", req.Email); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if err := ValidateEmail(req.Email); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if err := validatePasswordWithPolicy(r.Context(), h.queries, req.Password); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if req.Role == "" {
		req.Role = "user"
	}
	if !validRoles[req.Role] {
		writeValidationError(w, r, "role must be one of: admin, user, vault_only")
		return
	}
	// An instance admin is automatically a manager of every collection and has
	// full use/manage rights over every vault entry. Once the optional private
	// listener exists, minting that global authority is therefore part of the
	// private control plane. Gate from the requested role before any account
	// lookup/insert so the public response cannot reveal whether the address is
	// already registered. Ordinary user/client creation remains public.
	if req.Role == middleware.RoleAdmin && !requireConfiguredPrivateControlPlaneIngress(w, r) {
		return
	}
	if req.Name != "" {
		if err := ValidateStringLength("name", req.Name, 1, 255); err != nil {
			writeValidationError(w, r, err.Error())
			return
		}
	}

	hash, err := passwordhash.Hash(req.Password)
	if err != nil {
		logError(r, "users.create: failed to hash password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	row, err := h.queries.CreateUser(r.Context(), db.CreateUserParams{
		Email:        req.Email,
		PasswordHash: hash,
		Name:         toNullString(req.Name),
		Role:         req.Role,
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeConflict(w, r, "a user with this email already exists")
			return
		}
		logError(r, "users.create: insert failed", "error", err)
		writeInternalError(w, r, "failed to create user")
		return
	}

	// A seat may already be waiting for this address (invited before it had an
	// account). See claimCollectionInvitations.
	claimCollectionInvitationsBestEffort(r.Context(), h.queries, row.ID, row.Email)

	LogActivityFromRequest(h.queries, r, "admin.user_created",
		fmt.Sprintf("User %s created with role %s", req.Email, req.Role))

	writeJSON(w, http.StatusCreated, adminUserResponse{
		ID:        row.ID,
		Email:     row.Email,
		Name:      nullStringToString(row.Name),
		Role:      row.Role,
		CreatedAt: nullTimeStr(row.CreatedAt),
	})
}

// Update handles PATCH /api/admin/users/{id} - updates name, role, or
// disabled state. Guards against removing the last active admin and against
// an admin disabling or demoting themselves.
func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	callerID := middleware.GetUserID(r.Context())

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	// Gate access-expanding request SHAPES before resolving the target. A public
	// caller receives the same refusal for a missing, disabled, already-enabled,
	// admin, or non-admin id. Disabling and demotion remain public emergency
	// reductions; promoting to global admin or re-enabling an account does not.
	expandsAccess := (req.Role != nil && *req.Role == middleware.RoleAdmin) ||
		(req.Disabled != nil && !*req.Disabled)
	if expandsAccess && !requireConfiguredPrivateControlPlaneIngress(w, r) {
		return
	}

	target, err := h.queries.GetUserByID(r.Context(), targetID)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "user not found")
		return
	}
	if err != nil {
		logError(r, "users.update: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	if req.Role != nil {
		if !validRoles[*req.Role] {
			writeValidationError(w, r, "role must be one of: admin, user, vault_only")
			return
		}
		if targetID == callerID && *req.Role != "admin" {
			writeBadRequest(w, r, "you cannot demote your own account")
			return
		}
		// The last-admin guard travels WITH the write.
		//
		// It used to be a COUNT in one statement and the UPDATE in another, with
		// no transaction between them: two admins demoting each other at the same
		// time both saw count = 2, both proceeded, and the instance was left with
		// ZERO admins. Nothing in the product recovers from that (CreateFirstAdmin
		// needs an empty users table, every admin route needs an admin), so the
		// fix has to be atomic rather than merely re-checked.
		res, err := h.queries.UpdateUserRoleIfNotLastAdmin(r.Context(), db.UpdateUserRoleIfNotLastAdminParams{
			Role: *req.Role, ID: targetID, Column3: *req.Role,
		})
		if err != nil {
			logError(r, "users.update: role update failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeBadRequest(w, r, "cannot remove the last active admin")
			return
		}
		LogActivityFromRequest(h.queries, r, "admin.user_role_changed",
			fmt.Sprintf("User %s role changed to %s", target.Email, *req.Role))
	}

	if req.Disabled != nil {
		if targetID == callerID && *req.Disabled {
			writeBadRequest(w, r, "you cannot disable your own account")
			return
		}
		disabled := int64(0)
		if *req.Disabled {
			disabled = 1
		}
		// Atomic last-admin guard, same reasoning as the role change above.
		dres, err := h.queries.SetUserDisabledIfNotLastAdmin(r.Context(), db.SetUserDisabledIfNotLastAdminParams{
			Disabled: disabled, ID: targetID, Column3: disabled,
		})
		if err != nil {
			logError(r, "users.update: disabled update failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		if n, _ := dres.RowsAffected(); n == 0 {
			writeBadRequest(w, r, "cannot remove the last active admin")
			return
		}
		action := "admin.user_enabled"
		if *req.Disabled {
			action = "admin.user_disabled"
		}
		LogActivityFromRequest(h.queries, r, action, fmt.Sprintf("User %s", target.Email))

		// Disabling is an offboarding control, so it has to invalidate standing
		// credentials and detach delivery endpoints the same way removing
		// someone from a collection does. Cutting only HTTP access left their
		// rotation webhook receiving fresh plaintext on the next sweep, which
		// meant the rotation an admin runs BECAUSE of an incident was what
		// delivered the new key to them.
		if *req.Disabled {
			invalidateCredentials(r, h.queries, h.vault, targetID, target.Email, "Disabling")
		}
	}

	if req.Name != nil {
		if err := h.queries.UpdateUserName(r.Context(), db.UpdateUserNameParams{
			Name: sql.NullString{String: *req.Name, Valid: true},
			ID:   targetID,
		}); err != nil {
			logError(r, "users.update: name update failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}

	updated, err := h.queries.GetUserByID(r.Context(), targetID)
	if err != nil {
		logError(r, "users.update: reload failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, adminUserResponse{
		ID:          updated.ID,
		Email:       updated.Email,
		Name:        nullStringToString(updated.Name),
		Role:        updated.Role,
		Disabled:    updated.Disabled != 0,
		TOTPEnabled: nullInt64Is1(updated.TotpEnabled),
		CreatedAt:   nullTimeStr(updated.CreatedAt),
	})
}

// Delete handles DELETE /api/admin/users/{id}. Refuses self-deletion and
// deleting the last active admin. API keys cascade via FK; vault entries are
// the vault feature's concern (its FK/cleanup is defined in its own
// migrations).
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	// With the optional connector configured, hard offboarding is uniformly a
	// private control-plane operation. Gate before reading the target or even
	// comparing it with the caller so public responses cannot reveal state.
	if !requireConfiguredPrivateControlPlaneIngress(w, r) {
		return
	}
	targetID := chi.URLParam(r, "id")
	callerID := middleware.GetUserID(r.Context())

	if targetID == callerID {
		writeBadRequest(w, r, "you cannot delete your own account")
		return
	}

	// Hard deletion is one offboarding mutation, not a DELETE followed by a
	// best-effort repair. Start the write transaction before reading the target,
	// collection policy or admin count so a concurrent policy promotion or role
	// change is observed before any credential, target or vault row is touched.
	tx, qtx, err := beginQueriesTx(r.Context(), h.queries, nil)
	if err != nil {
		logError(r, "users.delete: begin failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	defer func() { _ = tx.Rollback() }()
	txh := *h
	txh.queries = qtx
	if h.vault != nil {
		txVault := *h.vault
		txVault.queries = qtx
		txh.vault = &txVault
	}

	target, err := qtx.GetUserByID(r.Context(), targetID)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "user not found")
		return
	}
	if err != nil {
		logError(r, "users.delete: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// This friendly pre-check now shares the DELETE's write transaction. The
	// conditional DELETE remains the final invariant, so the last-admin rule is
	// still carried by the write even if this handler is changed later.
	if target.Role == "admin" && target.Disabled == 0 {
		count, countErr := qtx.CountAdmins(r.Context())
		if countErr != nil {
			logError(r, "users.delete: admin count failed", "error", countErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if count <= 1 {
			writeBadRequest(w, r, "cannot remove the last active admin")
			return
		}
	}
	// Hard delete re-owns shared entries and removes collection memberships. It
	// is not merely incident-response revocation, so only a target whose removal
	// actually touches a protected collection needs private ingress. Disable and
	// demotion remain public emergency reductions. Password replacement is gated
	// separately because an attacker chooses a new login credential, so it is not
	// a pure reduction. DeleteUserIfNotLastAdmin repeats this predicate on the
	// write itself to close a concurrent policy-promotion window.
	if !middleware.IsPrivateIngress(r.Context()) {
		protected, impactErr := qtx.UserHasProtectedCollectionImpact(r.Context(), targetID)
		if impactErr != nil {
			logError(r, "users.delete: protected-impact lookup failed", "error", impactErr)
			writeInternalError(w, r, "private access policy could not be verified")
			return
		}
		if protected {
			writePrivateIngressRequired(w, r)
			return
		}
	}

	// Revocations BEFORE the row goes away: the cleanup resolves the user by id,
	// and once the users row is deleted there is nothing left to look up. Hard
	// delete previously did none of this, so it was strictly weaker than the
	// Disable toggle next to it.
	//
	// Every half runs inside this transaction. The strict cleanup revokes
	// credentials, purges targets, transfers the shared vault and deletes the
	// personal one. If any step, verification or the authoritative DELETE
	// refuses, all of those writes roll back together. Operator-facing audit is
	// emitted only after commit, so sealing names never reaches out to the pool
	// while this transaction owns SQLite's write connection.
	cleanupSummary, cleanupErr := txh.hardDeleteCleanup(r.Context(), targetID, target.Email, callerID)
	if cleanupErr != nil {
		logError(r, "users.delete: offboarding cleanup failed", "user", targetID, "error", cleanupErr)
		writeInternalError(w, r, "user was not deleted because offboarding could not be completed safely")
		return
	}
	if verifyErr := txh.verifyHardDeleteCleanup(r.Context(), targetID); verifyErr != nil {
		logError(r, "users.delete: offboarding cleanup failed", "user", targetID, "error", verifyErr)
		writeInternalError(w, r, "user was not deleted because offboarding could not be completed safely")
		return
	}

	// The guard is ON the delete, so a concurrent second delete cannot slip
	// between a count and a write and take the last admin with it. The
	// pre-check above still runs first, because it rejects the ordinary case
	// BEFORE offboarding side effects; this is the authoritative refusal for
	// the racing case.
	result, err := qtx.DeleteUserIfNotLastAdmin(r.Context(), db.DeleteUserIfNotLastAdminParams{
		ID:             targetID,
		PrivateIngress: privateIngressSQLFlag(r.Context()),
	})
	if err != nil {
		logError(r, "users.delete: delete failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		// Target existence, policy and the admin count were all read after this
		// transaction acquired the write lock. A zero-row result can therefore
		// only be the statement's last-admin guard refusing the mutation.
		writeBadRequest(w, r, "cannot remove the last active admin")
		return
	}

	if err := tx.Commit(); err != nil {
		logError(r, "users.delete: commit failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	h.logHardDeleteSummary(r, target.Email, cleanupSummary)
	LogActivityFromRequest(h.queries, r, "admin.user_deleted",
		fmt.Sprintf("User %s deleted", target.Email))

	w.WriteHeader(http.StatusNoContent)
}

// ResetPassword handles POST /api/admin/users/{id}/reset-password. Sets a new
// password for the target user and invalidates their standing credentials
// (sessions, API keys, service identities). Refuses to target the caller's
// own account: an admin resetting their own password this way would need no
// current password, unlike ChangePassword, which is exactly the shape a
// stolen admin API key uses to escalate to a login it controls. Admins change
// their own password through ChangePassword instead.
func (h *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	// Choosing a replacement credential is an access-establishing control-plane
	// action, even though it also revokes the target's old credentials. A stolen
	// public admin session could otherwise reset a different administrator and
	// persist as that account. Gate before resolving either id so public ingress
	// cannot use response differences as an account or role oracle.
	if !requireConfiguredPrivateControlPlaneIngress(w, r) {
		return
	}
	targetID := chi.URLParam(r, "id")
	callerID := middleware.GetUserID(r.Context())

	if targetID == callerID {
		writeBadRequest(w, r, "you cannot reset your own password here; use change password instead")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}
	if err := validatePasswordWithPolicy(r.Context(), h.queries, req.Password); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}

	target, err := h.queries.GetUserByID(r.Context(), targetID)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "user not found")
		return
	}
	if err != nil {
		logError(r, "users.reset_password: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	hash, err := passwordhash.Hash(req.Password)
	if err != nil {
		logError(r, "users.reset_password: failed to hash password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// SetPasswordHash, not UpdatePasswordHash: an admin choosing this password
	// on the target's behalf is exactly the kind of human-set password that
	// TOTPVerify should later accept as proof of identity, including for a
	// legacy password_set=0 account created by an older release.
	if err := h.queries.SetPasswordHash(r.Context(), db.SetPasswordHashParams{
		PasswordHash: hash,
		ID:           targetID,
	}); err != nil {
		logError(r, "users.reset_password: update failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// An admin resetting a compromised account's password has to be able to
	// cut off the attacker completely: sessions, API keys, and any service
	// identity the account owns, which used to survive a password reset
	// untouched despite the offboarding docstring claiming otherwise.
	invalidateCredentials(r, h.queries, h.vault, targetID, target.Email, "Resetting password for")

	LogActivityFromRequest(h.queries, r, "admin.user_password_reset",
		fmt.Sprintf("Password reset for %s; sessions and API keys revoked", target.Email))

	w.WriteHeader(http.StatusNoContent)
}

// ensureNotLastAdmin returns an error when only one active admin remains.
func (h *UserHandler) ensureNotLastAdmin(ctx context.Context) error {
	count, err := h.queries.CountAdmins(ctx)
	if err != nil {
		slog.Error("users: failed to count admins", "error", err)
		return fmt.Errorf("internal server error")
	}
	if count <= 1 {
		return fmt.Errorf("cannot remove the last active admin")
	}
	return nil
}

// --- Invitations ------------------------------------------------------------

type invitationResponse struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// Serialized as "role" to match the frontend Invitation type; the column
	// stays target_role in the database.
	TargetRole string `json:"role"`
	ExpiresAt  string `json:"expires_at"`
	CreatedAt  string `json:"created_at"`
}

type createInvitationRequest struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	SendEmail bool   `json:"send_email"`
}

type redeemInvitationRequest struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

type redeemInvitationResponse struct {
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	} `json:"user"`
}

// inviteCharset excludes 0/O/1/I to avoid confusion.
const inviteCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generateInviteCode(random io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", fmt.Errorf("read invitation entropy: %w", err)
	}
	code := make([]byte, 16)
	for i := range code {
		code[i] = inviteCharset[int(b[i])%len(inviteCharset)]
	}
	return "INV-" + string(code), nil
}

// ListInvitations handles GET /api/admin/invitations - returns all invitations.
func (h *UserHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Expire stale invitations first
	h.queries.ExpireStaleInvitations(ctx)

	rows, err := h.queries.ListInvitations(ctx)
	if err != nil {
		logError(r, "invitations.list: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	invitations := make([]invitationResponse, 0, len(rows))
	for _, row := range rows {
		invitations = append(invitations, invitationResponse{
			ID:         row.ID,
			Code:       h.openInviteCode(row.Code),
			Email:      row.Email,
			Name:       row.Name,
			Status:     row.Status,
			TargetRole: row.TargetRole,
			ExpiresAt:  row.ExpiresAt.Format(time.RFC3339),
			CreatedAt:  nullTimeRFC3339(row.CreatedAt),
		})
	}

	writeJSON(w, http.StatusOK, invitations)
}

// CreateInvitation handles POST /api/admin/invitations - creates a new
// invitation. Role defaults to vault_only (browser extension onboarding).
func (h *UserHandler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	req.Email = emailidentity.Canonical(req.Email)
	req.Name = strings.TrimSpace(req.Name)
	if req.Email == "" {
		writeBadRequest(w, r, "email is required")
		return
	}
	if err := ValidateEmail(req.Email); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if req.Role == "" {
		req.Role = "vault_only"
	}
	if !validRoles[req.Role] {
		writeValidationError(w, r, "role must be one of: admin, user, vault_only")
		return
	}
	// Admin invitations delegate the same instance-wide authority as direct
	// admin creation. Keep ordinary user/vault_only client onboarding public,
	// but require the configured private control plane to mint an admin bearer
	// invitation.
	if req.Role == middleware.RoleAdmin && !requireConfiguredPrivateControlPlaneIngress(w, r) {
		return
	}

	adminID := middleware.GetUserID(ctx)
	code, codeErr := generateInviteCode(h.inviteRandom)
	if codeErr != nil {
		logError(r, "invitations.create: secure random source failed", "error", codeErr)
		writeInternalError(w, r, "failed to create invitation")
		return
	}
	expiresAt := time.Now().UTC().Add(48 * time.Hour)

	// Refuse rather than storing an unrecoverable code: see sealInviteCode.
	sealed, sealErr := h.sealInviteCode(code)
	if sealErr != nil {
		logError(r, "invitations.create: could not seal the invite code", "error", sealErr)
		writeInternalError(w, r, "failed to create invitation")
		return
	}

	row, err := h.queries.CreateInvitation(ctx, db.CreateInvitationParams{
		// Ciphertext at rest, hash for lookup. See invitation_code.go.
		Code:       sealed,
		CodeHash:   hashInviteCode(code),
		Email:      req.Email,
		Name:       req.Name,
		TargetRole: req.Role,
		CreatedBy:  toNullString(adminID),
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		logError(r, "invitations.create: insert failed", "error", err)
		writeInternalError(w, r, "failed to create invitation")
		return
	}

	inv := invitationResponse{
		ID: row.ID,
		// The plaintext, shown to the admin once here and never readable from
		// the stored row without the vault key.
		Code:       code,
		Email:      row.Email,
		Name:       row.Name,
		Status:     row.Status,
		TargetRole: row.TargetRole,
		ExpiresAt:  row.ExpiresAt.Format(time.RFC3339),
		CreatedAt:  nullTimeRFC3339(row.CreatedAt),
	}

	// Send email if requested and SMTP is configured
	if req.SendEmail {
		go h.trySendInvitationEmail(req.Email, req.Name, code)
	}

	LogActivityFromRequest(h.queries, r, "admin.invitation_created",
		fmt.Sprintf("Invitation created for %s (role %s)", req.Email, req.Role))

	writeJSON(w, http.StatusCreated, inv)
}

// DeleteInvitation handles DELETE /api/admin/invitations/{id} - deletes a
// pending invitation.
func (h *UserHandler) DeleteInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	result, err := h.queries.DeletePendingInvitation(ctx, id)
	if err != nil {
		logError(r, "invitations.delete: delete failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeNotFound(w, r, "invitation not found or already redeemed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResendInvitation handles POST /api/admin/invitations/{id}/resend - resends
// the invitation email.
func (h *UserHandler) ResendInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	row, err := h.queries.GetInvitationForResend(ctx, id)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "invitation not found")
		return
	}
	if err != nil {
		logError(r, "invitations.resend: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	if row.Status != "pending" {
		writeBadRequest(w, r, "can only resend pending invitations")
		return
	}

	// openInviteCode returns "" when the stored code will not decrypt, and its own
	// doc says the caller must render that as such rather than as a blank code. This
	// call site did not: it mailed the invitee a branded email containing an EMPTY
	// setup code, told the admin 200 "invitation email queued", and left nothing in
	// the activity trail. The only evidence was one slog line.
	//
	// The invitation is unrecoverable through the product from there: redemption keys
	// off code_hash and the plaintext was shown once at creation, so nobody can
	// supply the code again. Sending the mail is the harm, because it burns the
	// invitee's trust in a link that cannot work.
	//
	// Refuse instead, and say what to do. Revoking and re-inviting mints a fresh code.
	code := h.openInviteCode(row.Code)
	if code == "" {
		logError(r, "invitations.resend: stored code did not decrypt, refusing to mail a blank code",
			"invitation", row.ID, "email", row.Email)
		LogActivityFromRequest(h.queries, r, "invitation.resend_failed",
			fmt.Sprintf("Could not resend the invitation for %s: the stored code is unreadable", row.Email))
		writeError(w, r, http.StatusConflict, "code_unreadable",
			"this invitation's code could not be read, so no email was sent. Revoke it and invite "+
				"the person again to mint a fresh code.")
		return
	}

	go h.trySendInvitationEmail(row.Email, row.Name, code)
	writeJSON(w, http.StatusOK, map[string]string{"message": "invitation email queued"})
}

// RedeemInvitation handles POST /api/invitations/redeem - redeems an
// invitation code. This endpoint is public (no auth required) but
// rate-limited. Every invitee chooses a password here, then signs in through
// the ordinary interactive web flow. API keys can only be minted later from
// that authenticated interactive session.
func (h *UserHandler) RedeemInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req redeemInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	req.Code = strings.TrimSpace(strings.ToUpper(req.Code))
	if req.Code == "" {
		writeBadRequest(w, r, "code is required")
		return
	}

	codeHash := hashInviteCode(req.Code)

	// This first lookup is only a preflight. Password hashing is intentionally
	// kept outside the write transaction, but NONE of the
	// authority established here is trusted for a write. The invitation is read
	// again after BEGIN IMMEDIATE below, and the conditional consume travels in
	// the same transaction as the user and pending-seat writes.
	if err := h.queries.ExpireStaleInvitations(ctx); err != nil {
		logError(r, "invitations.redeem: expire stale invitations failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	inv, err := h.queries.GetPendingInvitationByCode(ctx, codeHash)
	if err == sql.ErrNoRows {
		writeBadRequest(w, r, "invalid or expired invitation code")
		return
	}
	if err != nil {
		logError(r, "invitations.redeem: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	// The code is itself the high-entropy bearer credential for this invitation,
	// so its holder may learn that admin onboarding needs the private origin. Gate
	// before password hashing or any account/key/membership write. Ordinary and
	// vault_only invitation redemption stays available on public ingress.
	if inv.TargetRole == middleware.RoleAdmin && !requireConfiguredPrivateControlPlaneIngress(w, r) {
		return
	}

	// Invitations create human accounts, including vault_only client accounts.
	// Requiring a password for every role makes the web login the sole bootstrap
	// authority; the public bearer invitation never mints a reusable API key.
	password := req.Password
	if password == "" {
		writeBadRequest(w, r, "password is required for this invitation")
		return
	}
	if err := validatePasswordWithPolicy(ctx, h.queries, password); err != nil {
		writeBadRequest(w, r, "password "+err.(*ValidationError).Message)
		return
	}

	passwordHash, err := h.invitationPasswordHasher(password)
	if err != nil {
		logError(r, "invitations.redeem: failed to hash password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Production opens SQLite with _txlock=immediate. The transaction therefore
	// takes the writer lock before this authoritative re-read: deletion,
	// expiration, another redemption, user creation, and collection-seat claims
	// cannot interleave between the check and the final conditional consume.
	tx, qtx, err := beginQueriesTx(ctx, h.queries, nil)
	if err != nil {
		logError(r, "invitations.redeem: begin transaction failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	defer tx.Rollback() // no-op after Commit

	if err := qtx.ExpireStaleInvitations(ctx); err != nil {
		logError(r, "invitations.redeem: expire stale invitations in transaction failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	txInv, err := qtx.GetPendingInvitationByCode(ctx, codeHash)
	if err == sql.ErrNoRows {
		writeBadRequest(w, r, "invalid or expired invitation code")
		return
	}
	if err != nil {
		logError(r, "invitations.redeem: transactional invitation query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// No product route mutates these fields, but bind the expensive preflight to
	// the exact row shape that is now authoritative. This also prevents a direct
	// database edit from switching the bearer to a stronger role between reads.
	if txInv.ID != inv.ID || txInv.Email != inv.Email || txInv.Name != inv.Name ||
		txInv.TargetRole != inv.TargetRole {
		writeBadRequest(w, r, "invalid or expired invitation code")
		return
	}
	if txInv.TargetRole == middleware.RoleAdmin && !requireConfiguredPrivateControlPlaneIngress(w, r) {
		return
	}
	// The preflight password check keeps expensive hashing outside the
	// transaction, but the policy can change before the writer lock is acquired.
	// Re-check the current policy while holding that lock.
	if password == "" {
		writeBadRequest(w, r, "password is required for this invitation")
		return
	}
	if err := validatePasswordWithPolicy(ctx, qtx, password); err != nil {
		writeBadRequest(w, r, "password "+err.(*ValidationError).Message)
		return
	}
	identityEmail := emailidentity.Canonical(txInv.Email)

	if _, lookupErr := qtx.GetUserIDByEmailForInvite(ctx, identityEmail); lookupErr == nil {
		writeConflict(w, r, "a user with this email already exists")
		return
	} else if lookupErr != sql.ErrNoRows {
		logError(r, "invitations.redeem: user lookup failed", "error", lookupErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	userID, err := qtx.CreateInvitedUser(ctx, db.CreateInvitedUserParams{
		Email:        identityEmail,
		PasswordHash: passwordHash,
		Name:         toNullString(txInv.Name),
		Role:         txInv.TargetRole,
		PasswordSet:  1,
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeConflict(w, r, "a user with this email already exists")
			return
		}
		logError(r, "invitations.redeem: create user failed", "error", err)
		writeInternalError(w, r, "failed to create user")
		return
	}

	// A seat claim is part of onboarding, not best-effort cleanup. If any claim
	// fails, rolling back the new account leaves the invitation redeemable after
	// the underlying problem is repaired instead of stranding a client account.
	if _, err := claimCollectionInvitations(ctx, qtx, userID, identityEmail); err != nil {
		logError(r, "invitations.redeem: claim collection invitations failed", "error", err)
		writeInternalError(w, r, "failed to create user")
		return
	}

	resp := redeemInvitationResponse{}
	resp.User.ID = userID
	resp.User.Email = txInv.Email
	resp.User.Name = txInv.Name
	resp.User.Role = txInv.TargetRole

	consume, err := qtx.MarkInvitationRedeemedIfPending(ctx, db.MarkInvitationRedeemedIfPendingParams{
		RedeemedBy: toNullString(userID),
		ID:         txInv.ID,
		CodeHash:   codeHash,
	})
	if err != nil {
		logError(r, "invitations.redeem: consume invitation failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	consumedRows, rowsErr := consume.RowsAffected()
	if rowsErr != nil || consumedRows != 1 {
		logError(r, "invitations.redeem: invitation was not consumed",
			"rows", consumedRows, "error", rowsErr)
		writeBadRequest(w, r, "invalid or expired invitation code")
		return
	}

	if err := tx.Commit(); err != nil {
		logError(r, "invitations.redeem: commit failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	LogActivityFromRequest(h.queries, r, "invitation.redeemed",
		fmt.Sprintf("Invitation redeemed by %s (role %s)", txInv.Email, txInv.TargetRole))

	writeJSON(w, http.StatusOK, resp)
}

// trySendInvitationEmail attempts to send an invitation email via SMTP.
// It reads SMTP settings from the database; if SMTP is not configured it
// silently returns.
func (h *UserHandler) trySendInvitationEmail(toEmail, name, code string) {
	// Never mail a blank setup code.
	//
	// The resend path is fixed at its own call site with a 409 the admin can act on,
	// and this is the belt: every current and future caller passes a code through
	// here, and a branded email containing an empty code is worse than no email at
	// all. It burns the invitee's trust in a link that cannot work, and the
	// invitation is unrecoverable through the product because redemption keys off
	// code_hash and the plaintext was only ever shown once.
	//
	// One property, several doors, which is the shape that keeps recurring in this
	// codebase: two call sites today and nothing stopping a third.
	if strings.TrimSpace(code) == "" {
		slog.Error("invitations: refusing to send an invitation email with an empty setup code",
			"to", toEmail)
		return
	}

	ctx := context.Background()

	scanSetting := func(key string) string {
		v, _ := h.queries.GetSetting(ctx, key)
		return v
	}

	host := scanSetting("smtp_host")
	port := scanSetting("smtp_port")
	from := scanSetting("smtp_from")
	username := scanSetting("smtp_username")
	// Stored encrypted at rest. Shared with the "send test email" path so both
	// resolve the credential identically; they used to disagree.
	password, pwErr := resolveSMTPPassword(scanSetting("smtp_password"), h.cfg.VaultKey, h.cfg.VaultKeyPrevious)
	if pwErr != nil {
		slog.Error("invitations: smtp password decrypt failed", "error", pwErr)
		return
	}
	useTLS := scanSetting("smtp_use_tls")

	if host == "" || from == "" {
		slog.Debug("invitations: SMTP not configured, skipping email")
		return
	}

	err := sendInvitationEmail(host, port, from, username, password, useTLS == "true", toEmail, name, code, h.cfg.BaseURL)
	if err != nil {
		slog.Error("invitations: failed to send email", "error", err, "to", toEmail)
	}
}

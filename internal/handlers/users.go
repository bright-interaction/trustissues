package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/passwordhash"
	"github.com/go-chi/chi/v5"
)

// UserHandler handles admin user CRUD and invitation endpoints.
type UserHandler struct {
	queries *db.Queries
	cfg     *config.Config
	// vault is optional and used only to detach a disabled user's rotation
	// delivery targets. Wired by SetVault after construction because the vault
	// handler is built later in main; nil simply skips the purge, and the
	// authoritative refusal still happens at delivery time.
	vault *VaultHandler
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(queries *db.Queries, cfg *config.Config) *UserHandler {
	return &UserHandler{queries: queries, cfg: cfg}
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
	rows, err := h.queries.ListUsersWithEntryCount(r.Context())
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

		// Disabling is an offboarding control, so it has to detach delivery
		// endpoints the same way removing someone from a collection does.
		// Cutting only HTTP access left their rotation webhook receiving fresh
		// plaintext on the next sweep, which meant the rotation an admin runs
		// BECAUSE of an incident was what delivered the new key to them.
		if *req.Disabled {
			h.offboardUser(r, targetID, target.Email)
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
	targetID := chi.URLParam(r, "id")
	callerID := middleware.GetUserID(r.Context())

	if targetID == callerID {
		writeBadRequest(w, r, "you cannot delete your own account")
		return
	}

	target, err := h.queries.GetUserByID(r.Context(), targetID)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "user not found")
		return
	}
	if err != nil {
		logError(r, "users.delete: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// The DELETE below carries its own last-admin guard (see
	// DeleteUserIfNotLastAdmin), so this pre-check is only a fast, friendly
	// rejection. The authoritative refusal is the RowsAffected == 0 branch at
	// the write itself, because a count taken here and a delete run afterwards
	// are two separate statements and two concurrent deletes both pass a
	// pre-check.
	if target.Role == "admin" && target.Disabled == 0 {
		if err := h.ensureNotLastAdmin(r.Context()); err != nil {
			writeBadRequest(w, r, err.Error())
			return
		}
	}

	// Revocations BEFORE the row goes away: the cleanup resolves the user by id,
	// and once the users row is deleted there is nothing left to look up. Hard
	// delete previously did none of this, so it was strictly weaker than the
	// Disable toggle next to it.
	//
	// Only the REVERSIBLE half runs here. offboardUser revokes service
	// identities and purges rotation targets, which is the right outcome for a
	// user being removed and is recoverable (re-mint, re-add) if the delete is
	// then refused. The IRREVERSIBLE half, deleting the personal vault, is
	// deliberately deferred until after the authoritative guard has run.
	h.offboardUser(r, targetID, target.Email)

	// The guard is ON the delete, so a concurrent second delete cannot slip
	// between a count and a write and take the last admin with it. The
	// pre-check above still runs first, because it rejects the ordinary case
	// BEFORE offboarding side effects; this is the authoritative refusal for
	// the racing case.
	result, err := h.queries.DeleteUserIfNotLastAdmin(r.Context(), targetID)
	if err != nil {
		logError(r, "users.delete: delete failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		// Zero rows now means EITHER no such user OR the guard refused, and
		// answering "user not found" for a refusal would be a lie that reads as
		// "already gone". Ask which one it was.
		if _, lookupErr := h.queries.GetUserByID(r.Context(), targetID); lookupErr == nil {
			writeBadRequest(w, r, "cannot remove the last active admin")
			return
		}
		writeNotFound(w, r, "user not found")
		return
	}

	// The vault goes ONLY after the delete is authorized and committed.
	//
	// This used to run three statements earlier, before DeleteUserIfNotLastAdmin,
	// with no transaction spanning the two. So a delete the guard then REFUSED
	// (the racing last-admin case) or that errored had already hard-deleted every
	// personal entry the user owned and re-owned their shared entries, and the
	// API returned failure over a vault that was already gone. There is no undo
	// for that inside the product: the rows are DELETEd, not soft-deleted, and
	// the only copy is whatever backup.sh last wrote.
	h.disposeVaultEntriesOnDelete(r, targetID, target.Email, middleware.GetUserID(r.Context()))

	LogActivityFromRequest(h.queries, r, "admin.user_deleted",
		fmt.Sprintf("User %s deleted", target.Email))

	w.WriteHeader(http.StatusNoContent)
}

// ResetPassword handles POST /api/admin/users/{id}/reset-password. Sets a
// new password for the target user and revokes their outstanding sessions.
func (h *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")

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

	if err := h.queries.UpdatePasswordHash(r.Context(), db.UpdatePasswordHashParams{
		PasswordHash: hash,
		ID:           targetID,
	}); err != nil {
		logError(r, "users.reset_password: update failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Revoke every outstanding session for the target so tokens minted under
	// the old password die with it.
	if err := h.queries.InvalidateUserSessions(r.Context(), db.InvalidateUserSessionsParams{
		SessionsValidAfter: time.Now().Unix(),
		ID:                 targetID,
	}); err != nil {
		logError(r, "users.reset_password: failed to invalidate sessions", "error", err)
	}
	// Also drop the server-side session rows, matching ChangePassword. The
	// iat cutoff above only catches tokens that carry an iat claim, so this is
	// what makes the reset unconditional.
	if err := h.queries.RevokeUserSessions(r.Context(), targetID); err != nil {
		logError(r, "users.reset_password: failed to revoke sessions", "error", err, "user_id", targetID)
	}
	// An admin resetting a compromised account's password has to be able to
	// cut off the attacker completely, and API keys are a second credential
	// that would otherwise survive the reset.
	if err := h.queries.RevokeAPIKeysByUser(r.Context(), targetID); err != nil {
		logError(r, "users.reset_password: failed to revoke api keys", "error", err, "user_id", targetID)
	}

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

// invitationAPIKeyTTL time-boxes the extension key minted by the PUBLIC redeem
// endpoint. That key is bootstrapped from an invitation code rather than from a
// session, so it is never permanent: it ages out on its own, it shows up in the
// owner's GET /api/api-keys list like any other key, and an admin can revoke it
// from the admin API-key routes at any time.
const invitationAPIKeyTTL = 90 * 24 * time.Hour

type redeemInvitationResponse struct {
	APIKey string `json:"api_key,omitempty"`
	// When the bootstrapped key expires, so the extension can warn before it
	// stops working and the user can mint a replacement.
	APIKeyExpiresAt string `json:"api_key_expires_at,omitempty"`
	ServerURL       string `json:"server_url"`
	User            struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	} `json:"user"`
}

// inviteCharset excludes 0/O/1/I to avoid confusion.
const inviteCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generateInviteCode() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: should never happen
		return "INV-FALLBK"
	}
	code := make([]byte, 16)
	for i := range code {
		code[i] = inviteCharset[int(b[i])%len(inviteCharset)]
	}
	return "INV-" + string(code)
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

	req.Email = strings.TrimSpace(req.Email)
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

	adminID := middleware.GetUserID(ctx)
	code := generateInviteCode()
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
// rate-limited. vault_only redemptions get an API key for the browser
// extension; other roles log in with their password afterwards.
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

	// Expire stale invitations
	h.queries.ExpireStaleInvitations(ctx)

	inv, err := h.queries.GetPendingInvitationByCode(ctx, hashInviteCode(req.Code))
	if err == sql.ErrNoRows {
		writeBadRequest(w, r, "invalid or expired invitation code")
		return
	}
	if err != nil {
		logError(r, "invitations.redeem: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Use the provided password or generate a random one (vault_only
	// extension users authenticate with the API key, not the password).
	password := req.Password
	if password == "" {
		pwBytes := make([]byte, 32)
		if _, err := rand.Read(pwBytes); err != nil {
			// Never fall through with a zeroed buffer: that would be a known
			// password on a real account.
			logError(r, "invitations.redeem: failed to generate password", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		password = hex.EncodeToString(pwBytes)
	} else if err := validatePasswordWithPolicy(ctx, h.queries, password); err != nil {
		writeBadRequest(w, r, "password "+err.(*ValidationError).Message)
		return
	}

	passwordHash, err := passwordhash.Hash(password)
	if err != nil {
		logError(r, "invitations.redeem: failed to hash password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Check if a user with this email already exists
	if _, err = h.queries.GetUserIDByEmailForInvite(ctx, inv.Email); err == nil {
		writeConflict(w, r, "a user with this email already exists")
		return
	}

	userID, err := h.queries.CreateInvitedUser(ctx, db.CreateInvitedUserParams{
		Email:        inv.Email,
		PasswordHash: passwordHash,
		Name:         toNullString(inv.Name),
		Role:         inv.TargetRole,
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

	resp := redeemInvitationResponse{
		ServerURL: h.cfg.BaseURL,
	}
	resp.User.ID = userID
	resp.User.Email = inv.Email
	resp.User.Name = inv.Name
	resp.User.Role = inv.TargetRole

	// vault_only users get an API key for the browser extension. This is the
	// one credential this server hands out over an unauthenticated endpoint,
	// so it is deliberately time-boxed (invitationAPIKeyTTL) rather than
	// permanent, and it is an ordinary api_keys row: it appears in the owner's
	// key list, the owner can delete it, and an admin can revoke it.
	if inv.TargetRole == "vault_only" {
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			logError(r, "invitations.redeem: failed to generate key", "error", err)
			writeInternalError(w, r, "failed to create API key")
			return
		}
		rawKey := hex.EncodeToString(keyBytes)
		fullKey := "ti_" + rawKey

		hash := sha256.Sum256([]byte(fullKey))
		keyHash := hex.EncodeToString(hash[:])

		now := time.Now().UTC()
		expiresAt := now.Add(invitationAPIKeyTTL)
		err = h.queries.CreateAPIKeyForUser(ctx, db.CreateAPIKeyForUserParams{
			ID:        generateID(),
			UserID:    userID,
			Name:      "Vault Extension",
			KeyHash:   keyHash,
			KeyPrefix: rawKey[:8],
			ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
			CreatedAt: sql.NullTime{Time: now, Valid: true},
		})
		if err != nil {
			logError(r, "invitations.redeem: create API key failed", "error", err)
			writeInternalError(w, r, "failed to create API key")
			return
		}
		resp.APIKey = fullKey
		resp.APIKeyExpiresAt = expiresAt.Format(time.RFC3339)
	}

	// Mark invitation as redeemed
	if err := h.queries.MarkInvitationRedeemed(ctx, db.MarkInvitationRedeemedParams{
		RedeemedBy: toNullString(userID),
		ID:         inv.ID,
	}); err != nil {
		logError(r, "invitations.redeem: update invitation failed", "error", err)
	}

	LogActivityFromRequest(h.queries, r, "invitation.redeemed",
		fmt.Sprintf("Invitation redeemed by %s (role %s)", inv.Email, inv.TargetRole))

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

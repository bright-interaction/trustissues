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

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
	"github.com/brightinteraction/trustissues/internal/passwordhash"
	"github.com/go-chi/chi/v5"
)

// UserHandler handles admin user CRUD and invitation endpoints.
type UserHandler struct {
	queries *db.Queries
	cfg     *config.Config
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(queries *db.Queries, cfg *config.Config) *UserHandler {
	return &UserHandler{queries: queries, cfg: cfg}
}

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
		if target.Role == "admin" && *req.Role != "admin" {
			if err := h.ensureNotLastAdmin(r.Context()); err != nil {
				writeBadRequest(w, r, err.Error())
				return
			}
		}
		if _, err := h.queries.UpdateUserRole(r.Context(), db.UpdateUserRoleParams{
			Role: *req.Role, ID: targetID,
		}); err != nil {
			logError(r, "users.update: role update failed", "error", err)
			writeInternalError(w, r, "internal server error")
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
		if target.Role == "admin" && *req.Disabled {
			if err := h.ensureNotLastAdmin(r.Context()); err != nil {
				writeBadRequest(w, r, err.Error())
				return
			}
		}
		disabled := int64(0)
		if *req.Disabled {
			disabled = 1
		}
		if _, err := h.queries.SetUserDisabled(r.Context(), db.SetUserDisabledParams{
			Disabled: disabled, ID: targetID,
		}); err != nil {
			logError(r, "users.update: disabled update failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		action := "admin.user_enabled"
		if *req.Disabled {
			action = "admin.user_disabled"
		}
		LogActivityFromRequest(h.queries, r, action, fmt.Sprintf("User %s", target.Email))
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

	if target.Role == "admin" && target.Disabled == 0 {
		if err := h.ensureNotLastAdmin(r.Context()); err != nil {
			writeBadRequest(w, r, err.Error())
			return
		}
	}

	result, err := h.queries.DeleteUser(r.Context(), targetID)
	if err != nil {
		logError(r, "users.delete: delete failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		writeNotFound(w, r, "user not found")
		return
	}

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
			Code:       row.Code,
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

	row, err := h.queries.CreateInvitation(ctx, db.CreateInvitationParams{
		Code:       code,
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
		ID:         row.ID,
		Code:       row.Code,
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

	go h.trySendInvitationEmail(row.Email, row.Name, row.Code)
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

	inv, err := h.queries.GetPendingInvitationByCode(ctx, req.Code)
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
	password, pwErr := resolveSMTPPassword(scanSetting("smtp_password"), h.cfg.VaultKey)
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

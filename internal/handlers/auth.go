package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/brightinteraction/trustissues/internal/columncrypto"
	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
	"github.com/brightinteraction/trustissues/internal/passwordhash"
	"github.com/brightinteraction/trustissues/internal/totp"
	"github.com/golang-jwt/jwt/v5"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	queries *db.Queries
	cfg     *config.Config
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(queries *db.Queries, cfg *config.Config) *AuthHandler {
	return &AuthHandler{queries: queries, cfg: cfg}
}

// dummyPasswordHash is verified against on the no-account login path so
// response latency does not reveal whether an email has an account. Computed
// once at startup at the same cost as real hashes.
var dummyPasswordHash, _ = passwordhash.Hash("dummy-password-for-timing-equalization")

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type authResponse struct {
	Token        string   `json:"token,omitempty"`
	User         userInfo `json:"user,omitempty"`
	TOTPRequired bool     `json:"totp_required,omitempty"`
}

type userInfo struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	TOTPEnabled bool   `json:"totp_enabled"`
	CreatedAt   string `json:"created_at,omitempty"`
	// TOTPEnrollmentRequired is true when the vault policy requires 2FA and
	// this user has not set it up. Refusing the login instead would lock out
	// everyone the moment an admin ticks the policy, so the account stays
	// usable and the UI nags until they enrol.
	TOTPEnrollmentRequired bool `json:"totp_enrollment_required,omitempty"`
}

// decryptTOTPSecret returns the usable TOTP seed from the stored column,
// transparently handling both the encrypted form (current) and legacy
// plaintext rows. A decrypt failure means the value was never ciphertext, so
// it is returned as-is.
func decryptTOTPSecret(stored, key string) string {
	if stored == "" {
		return ""
	}
	if dec, err := columncrypto.DecryptString(stored, key); err == nil {
		return dec
	}
	return stored
}

// MigrateTOTPSecrets encrypts any plaintext totp_secret rows at boot so all
// 2FA enrollments get at-rest protection. Rows that already decrypt are left
// untouched, so it is idempotent. Call once at startup.
func (h *AuthHandler) MigrateTOTPSecrets() error {
	ctx := context.Background()
	rows, err := h.queries.ListUsersWithTOTPSecret(ctx)
	if err != nil {
		return err
	}
	migrated := 0
	for _, row := range rows {
		stored := nullStringToString(row.TotpSecret)
		if stored == "" {
			continue
		}
		// Already at-rest encrypted (marked): NEVER re-encrypt. A decrypt failure
		// here is a key mismatch or corruption, not plaintext; re-encrypting would
		// make a recoverable mismatch permanent. Log and leave untouched.
		if columncrypto.IsEncrypted(stored) {
			if _, derr := columncrypto.DecryptString(stored, h.cfg.VaultKey); derr != nil {
				slog.Error("totp.migrate: marked secret failed to decrypt under current key, leaving untouched", "user_id", row.ID, "error", derr)
			}
			continue
		}
		// Unmarked. Legacy binaries wrote bare-base64 ciphertext without a marker;
		// if it still decrypts under the current key it is already encrypted (just
		// missing the marker) and we recover the seed, otherwise it is genuine
		// plaintext to be encrypted now.
		seed := stored
		if dec, derr := columncrypto.DecryptString(stored, h.cfg.VaultKey); derr == nil {
			seed = dec
		}
		enc, eerr := columncrypto.EncryptString(seed, h.cfg.VaultKey)
		if eerr != nil {
			slog.Error("totp.migrate: encrypt failed", "user_id", row.ID, "error", eerr)
			continue
		}
		if serr := h.queries.StoreTOTPSecret(ctx, db.StoreTOTPSecretParams{
			TotpSecret: sql.NullString{String: enc, Valid: true},
			ID:         row.ID,
		}); serr != nil {
			slog.Error("totp.migrate: store failed", "user_id", row.ID, "error", serr)
			continue
		}
		migrated++
	}
	if migrated > 0 {
		slog.Info("totp.migrate: encrypted TOTP secrets at rest", "count", migrated)
	}
	return nil
}

// Status handles GET /api/auth/status - returns whether first-run setup is
// required. This endpoint does not require authentication.
func (h *AuthHandler) Status(w http.ResponseWriter, r *http.Request) {
	count, err := h.queries.CountUsers(r.Context())
	if err != nil {
		logError(r, "status: failed to count users", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"setup_required": count == 0})
}

// Register handles POST /api/auth/register - first-run admin creation. It
// only works while the users table is empty; once the first (admin) account
// exists the endpoint is permanently disabled and all further accounts come
// from admin-created users or invitations.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	count, err := h.queries.CountUsers(r.Context())
	if err != nil {
		logError(r, "register: failed to count users", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if count > 0 {
		writeConflict(w, r, "setup already completed")
		return
	}

	var req registerRequest
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
	if req.Name != "" {
		if err := ValidateStringLength("name", req.Name, 1, 255); err != nil {
			writeValidationError(w, r, err.Error())
			return
		}
	}

	hash, err := passwordhash.Hash(req.Password)
	if err != nil {
		logError(r, "register: failed to hash password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Atomic: the "is this the first run" test happens INSIDE the insert.
	//
	// The CountUsers check above still runs, because it gives an honest 409 for the
	// ordinary case, but it is no longer what enforces the rule. The gap between that
	// check and this write contains the body decode, and the server's ReadTimeout is
	// 30s, so a client that trickles its body holds the window open for as long as it
	// likes. Proven with a test: a request that passed the count==0 gate and then
	// stalled mid-body still created an account after a legitimate operator completed
	// setup, giving 2 users and 2 ADMINS. Register is unauthenticated, so that is a
	// full takeover of a fresh instance by anyone who can reach it during setup.
	//
	// sql.ErrNoRows here means the WHERE NOT EXISTS matched nothing, i.e. somebody
	// else completed setup while this request was still arriving. That is the same
	// answer as the pre-check: setup is done.
	row, err := h.queries.CreateFirstAdmin(r.Context(), db.CreateFirstAdminParams{
		Email:        req.Email,
		PasswordHash: hash,
		Name:         toNullString(req.Name),
	})
	if errors.Is(err, sql.ErrNoRows) {
		logError(r, "register: setup completed while this registration was in flight, refusing",
			"email", req.Email)
		writeConflict(w, r, "setup already completed")
		return
	}
	if err != nil {
		logError(r, "register: failed to create user", "error", err)
		writeInternalError(w, r, "failed to create user")
		return
	}

	user := userInfo{
		ID:        row.ID,
		Email:     row.Email,
		Name:      nullStringToString(row.Name),
		Role:      row.Role,
		CreatedAt: nullTimeStr(row.CreatedAt),
	}

	token, err := h.generateToken(user.ID)
	if err != nil {
		logError(r, "register: failed to generate token", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	logAuthEvent(h.queries, r, &row.ID, "auth.setup_completed", "First-run admin account created")

	h.setSessionCookie(w, token)
	writeJSON(w, http.StatusCreated, authResponse{Token: token, User: user})
}

// Login handles POST /api/auth/login - user authentication with lockout
// (5 failed attempts per email / 15 min, 20 per IP) and optional TOTP 2FA.

// capacityExhausted answers 503 and reports true when a passwordhash.Verify
// failure was SERVER CAPACITY rather than a wrong password.
//
// Every site that checks a password must call this before treating the failure as
// a credential error, and the reason is not cosmetic. Where failed attempts are
// counted (login, TOTP disable) conflating the two is an account-lockout vector:
// saturate the hash semaphore, spray requests at an address, and the account locks
// out on capacity errors with nothing guessed. Where they are not counted (change
// password, the vault reauth gates) it still tells a user their password is wrong
// when the server is merely busy, which sends them to reset a credential that was
// always correct.
//
// It exists as ONE function because the property was fixed on the login path and
// missed on the five siblings, which is the shape that keeps recurring in this
// codebase: one security property, several doors. TestCapacityErrorIsNeverAFailed\
// LoginAttempt enforces that every Verify site routes through here.
func capacityExhausted(w http.ResponseWriter, r *http.Request, verifyErr error, logPrefix string) bool {
	if !errors.Is(verifyErr, passwordhash.ErrBusy) {
		return false
	}
	logError(r, logPrefix+": hash capacity exhausted", "error", verifyErr)
	w.Header().Set("Retry-After", "2")
	writeError(w, r, http.StatusServiceUnavailable, "server_busy",
		"the server is at capacity verifying passwords; retry shortly")
	return true
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	if err := ValidateRequired("email", req.Email); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if err := ValidateRequired("password", req.Password); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if err := ValidateEmail(req.Email); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}

	ip := middleware.ClientIP(r)

	// Per-IP rate limit: block credential stuffing across many emails from one IP
	ipFailCount, err := h.queries.CountRecentFailedLoginAttemptsByIP(r.Context(), ip)
	if err != nil {
		logError(r, "login: failed to query IP login attempts", "error", err)
	}
	if ipFailCount >= 20 {
		writeRateLimited(w, r, "too many failed attempts from this address, try again later")
		return
	}

	// Per-email lockout: 5 failures in 15 minutes
	failCount, err := h.queries.CountRecentFailedLoginAttemptsByEmail(r.Context(), req.Email)
	if err != nil {
		logError(r, "login: failed to query login attempts", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if failCount >= 5 {
		writeRateLimited(w, r, "too many failed attempts, try again in 15 minutes")
		return
	}
	if failCount >= 3 {
		delay := time.Duration(failCount-2) * 2 * time.Second
		if delay > 10*time.Second {
			delay = 10 * time.Second
		}
		time.Sleep(delay)
	}

	row, err := h.queries.GetUserByEmail(r.Context(), req.Email)
	if err == sql.ErrNoRows {
		// Equalize timing with the real path (which runs a hash verify) so a
		// missing account cannot be distinguished by response latency.
		_, _ = passwordhash.Verify(req.Password, dummyPasswordHash)
		writeUnauthorized(w, r, "invalid credentials")
		return
	}
	if err != nil {
		logError(r, "login: failed to query user", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	recordFailure := func() {
		if dbErr := h.queries.CreateLoginAttempt(r.Context(), db.CreateLoginAttemptParams{
			Email: req.Email, IpAddress: ip, Success: 0,
		}); dbErr != nil {
			logError(r, "login: failed to record failed attempt", "error", dbErr)
		}
		// Surface failures in the audit trail alongside successful logins.
		// Attributed to the resolved account with the attempted email + source
		// IP in the detail so admins can spot targeted or brute-force attempts.
		logAuthEvent(h.queries, r, &row.ID, "auth.login_failed",
			fmt.Sprintf("Failed login for %s from %s", req.Email, ip))
	}

	ok, verifyErr := passwordhash.Verify(req.Password, row.PasswordHash)
	// Server capacity is not a wrong password, and counting it as a failed attempt
	// would be an account-lockout vector. See capacityExhausted.
	if capacityExhausted(w, r, verifyErr, "auth.login") {
		return
	}
	if verifyErr != nil || !ok {
		recordFailure()
		writeUnauthorized(w, r, "invalid credentials")
		return
	}

	if row.Disabled != 0 {
		recordFailure()
		writeForbidden(w, r, "account is disabled")
		return
	}

	// Transparently upgrade legacy bcrypt hashes to argon2id on successful
	// login. Failure to rehash is non-fatal: the login still succeeds and
	// we'll retry on the next login.
	if passwordhash.NeedsRehash(row.PasswordHash) {
		if upgraded, hashErr := passwordhash.Hash(req.Password); hashErr == nil {
			if dbErr := h.queries.UpdatePasswordHash(r.Context(), db.UpdatePasswordHashParams{
				ID:           row.ID,
				PasswordHash: upgraded,
			}); dbErr != nil {
				logError(r, "login: argon2id rehash failed", "error", dbErr, "user_id", row.ID)
			}
		}
	}

	// Check 2FA. A DB error MUST block login to prevent 2FA bypass.
	totpState, err := h.queries.GetUserTOTPState(r.Context(), row.ID)
	if err != nil {
		logError(r, "login: failed to query 2FA state", "error", err, "user_id", row.ID)
		writeInternalError(w, r, "internal server error")
		return
	}

	totpEnabled := nullInt64Is1(totpState.TotpEnabled)
	if totpEnabled {
		if req.TOTPCode == "" {
			// Password correct but 2FA required: signal the client.
			writeJSON(w, http.StatusOK, authResponse{TOTPRequired: true})
			return
		}

		secret := decryptTOTPSecret(nullStringToString(totpState.TotpSecret), h.cfg.VaultKey)
		// spendTOTPStep, not ValidateCode: the code is accepted only if its time step
		// can also be CONSUMED, which makes a captured code unusable twice inside its
		// own 60-second window.
		if !spendTOTPStep(r.Context(), h.queries, row.ID, secret, req.TOTPCode) {
			// A recovery code is accepted ONLY if it is also durably spent.
			//
			// This was a read-modify-write with a plain UPDATE, and the login
			// continued even when the write failed. Each code is a standalone 64-bit
			// 2FA bypass, so a code already redeemed and crossed off a printed list
			// stayed a working second factor. See consumeRecoveryCode.
			if !consumeRecoveryCode(r.Context(), h.queries, row.ID, req.TOTPCode) {
				recordFailure()
				writeUnauthorized(w, r, "invalid 2FA code")
				return
			}
		}
	}

	// Record successful login
	if dbErr := h.queries.CreateLoginAttempt(r.Context(), db.CreateLoginAttemptParams{
		Email: req.Email, IpAddress: ip, Success: 1,
	}); dbErr != nil {
		logError(r, "login: failed to record successful login", "error", dbErr)
	}

	token, err := h.generateToken(row.ID)
	if err != nil {
		logError(r, "login: failed to generate token", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	logAuthEvent(h.queries, r, &row.ID, "auth.login", fmt.Sprintf("Login from %s", ip))

	user := userInfo{
		ID:          row.ID,
		Email:       row.Email,
		Name:        nullStringToString(row.Name),
		Role:        row.Role,
		TOTPEnabled: totpEnabled,
		CreatedAt:   nullTimeStr(row.CreatedAt),
	}

	h.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, authResponse{Token: token, User: user})
}

// Logout handles POST /api/auth/logout - revokes the current session
// server-side and clears the session cookie. Revocation marks the session row
// so the JWT (bearer token or cookie) stops authenticating immediately on the
// next request, even if it was captured; it does not merely rely on the client
// discarding the token.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if sessionID := middleware.GetSessionID(r.Context()); sessionID != "" {
		if err := h.queries.RevokeSession(r.Context(), sessionID); err != nil {
			logError(r, "logout: failed to revoke session", "error", err)
		}
	}
	if userID := middleware.GetUserID(r.Context()); userID != "" {
		logAuthEvent(h.queries, r, &userID, "auth.logout", "")
	}
	h.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// setNoStore marks a response as non-cacheable. Applied to every
// credential-bearing auth response (login, register, change-password, me) so a
// token or profile never lands in a shared or on-disk HTTP cache.
func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// Me handles GET /api/auth/me - returns the current authenticated user as
// {id, email, name, role} plus 2FA state.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	row, err := h.queries.GetUserByID(r.Context(), userID)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "user not found")
		return
	}
	if err != nil {
		logError(r, "me: failed to query user", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	enabled := nullInt64Is1(row.TotpEnabled)
	writeJSON(w, http.StatusOK, userInfo{
		ID:                     row.ID,
		Email:                  row.Email,
		Name:                   nullStringToString(row.Name),
		Role:                   row.Role,
		TOTPEnabled:            enabled,
		CreatedAt:              nullTimeStr(row.CreatedAt),
		TOTPEnrollmentRequired: !enabled && settingBool(r.Context(), h.queries, "require_totp", false),
	})
}

// UpdateMe handles PATCH /api/auth/me - lets the current user update their
// own profile (name only).
func (h *AuthHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	var req struct {
		Name *string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	if req.Name != nil {
		if err := ValidateStringLength("name", *req.Name, 1, 255); err != nil {
			writeValidationError(w, r, err.Error())
			return
		}
		if err := h.queries.UpdateUserName(r.Context(), db.UpdateUserNameParams{
			Name: sql.NullString{String: *req.Name, Valid: true},
			ID:   userID,
		}); err != nil {
			logError(r, "me.update: name update failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}

	row, err := h.queries.GetUserByID(r.Context(), userID)
	if err != nil {
		logError(r, "me.update: reload failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, userInfo{
		ID:          row.ID,
		Email:       row.Email,
		Name:        nullStringToString(row.Name),
		Role:        row.Role,
		TOTPEnabled: nullInt64Is1(row.TotpEnabled),
		CreatedAt:   nullTimeStr(row.CreatedAt),
	})
}

// ChangePassword handles POST /api/auth/change-password.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeBadRequest(w, r, "current_password and new_password are required")
		return
	}
	if err := validatePasswordWithPolicy(r.Context(), h.queries, req.NewPassword); err != nil {
		writeBadRequest(w, r, "new password "+err.(*ValidationError).Message)
		return
	}

	passwordHash, err := h.queries.GetPasswordHashByUserID(r.Context(), userID)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "user not found")
		return
	}
	if err != nil {
		logError(r, "change-password: failed to query user", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	ok, verifyErr := passwordhash.Verify(req.CurrentPassword, passwordHash)
	if capacityExhausted(w, r, verifyErr, "auth.change_password") {
		return
	}
	if verifyErr != nil || !ok {
		writeUnauthorized(w, r, "current password is incorrect")
		return
	}

	newHash, err := passwordhash.Hash(req.NewPassword)
	if err != nil {
		logError(r, "change-password: failed to hash password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	if err := h.queries.UpdatePasswordHash(r.Context(), db.UpdatePasswordHashParams{
		PasswordHash: newHash,
		ID:           userID,
	}); err != nil {
		logError(r, "change-password: failed to update password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Revoke every outstanding token for this account so one stolen under the
	// old password cannot outlive the change. We then mint a fresh token
	// (issued now, so it survives the revocation cutoff) and return it,
	// letting a cooperating client keep the current session alive while all
	// older tokens die.
	if err := h.queries.InvalidateUserSessions(r.Context(), db.InvalidateUserSessionsParams{
		SessionsValidAfter: time.Now().Unix(),
		ID:                 userID,
	}); err != nil {
		logError(r, "change-password: failed to invalidate sessions", "error", err, "user_id", userID)
	}
	// Also revoke the server-side session rows so tokens minted before the
	// change die immediately, independent of the iat-based cutoff above. The
	// fresh token minted below gets a new, non-revoked session row.
	if err := h.queries.RevokeUserSessions(r.Context(), userID); err != nil {
		logError(r, "change-password: failed to revoke sessions", "error", err, "user_id", userID)
	}
	// API keys are a separate credential and outlive sessions unless we cut
	// them too. Changing the password is the incident-response action a user
	// takes after a compromise, so a stolen extension key must not survive it.
	// The owner mints a replacement from POST /api/api-keys afterwards.
	if err := h.queries.RevokeAPIKeysByUser(r.Context(), userID); err != nil {
		logError(r, "change-password: failed to revoke api keys", "error", err, "user_id", userID)
	}

	LogActivityFromRequest(h.queries, r, "auth.password_changed",
		"Password changed; sessions and API keys revoked")

	resp := map[string]string{"message": "password changed successfully"}
	if token, terr := h.generateToken(userID); terr == nil {
		resp["token"] = token
		h.setSessionCookie(w, token)
	}
	writeJSON(w, http.StatusOK, resp)
}

// TOTPSetup handles POST /api/auth/totp/setup - initiates 2FA setup.
func (h *AuthHandler) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	row, err := h.queries.GetUserByID(r.Context(), userID)
	if err != nil {
		logError(r, "totp.setup: failed to query user", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if nullInt64Is1(row.TotpEnabled) {
		writeConflict(w, r, "2FA is already enabled")
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		logError(r, "totp.setup: failed to generate secret", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Encrypt the seed at rest, like every other secret column.
	encSecret, encErr := columncrypto.EncryptString(secret, h.cfg.VaultKey)
	if encErr != nil {
		logError(r, "totp.setup: failed to encrypt secret", "error", encErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Store secret but don't enable yet (wait for verification)
	if err := h.queries.StoreTOTPSecret(r.Context(), db.StoreTOTPSecretParams{
		TotpSecret: sql.NullString{String: encSecret, Valid: true},
		ID:         userID,
	}); err != nil {
		logError(r, "totp.setup: failed to store secret", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	uri := totp.GenerateOTPAuthURI(row.Email, "Trustissues", secret)

	LogActivityFromRequest(h.queries, r, "totp.setup_started", "2FA setup initiated")

	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret,
		"qr_uri": uri,
	})
}

// TOTPVerify handles POST /api/auth/totp/verify - confirms 2FA setup with a
// valid code and returns single-use recovery codes.
func (h *AuthHandler) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	var req struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeBadRequest(w, r, "code is required")
		return
	}

	userEmail, err := h.queries.GetUserEmailByID(r.Context(), userID)
	if err != nil {
		logError(r, "totp.verify: failed to query user email", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// ENABLING 2FA requires the password, not just a session.
	//
	// Enrolment used to need only a live session or API key. Turning 2FA ON is an
	// irreversible-by-the-owner act: after it, login demands a code the owner does not
	// have, TOTPDisable demands a live code they cannot produce, the recovery codes
	// were returned to whoever enrolled, and no admin route exists to reset another
	// user's 2FA. So anyone holding a stolen session, or the vault_only extension API
	// key handed out by the PUBLIC invite-redemption endpoint, could permanently lock
	// the owner out of their own vault without ever knowing the password.
	//
	// Requiring the password here is what makes that impossible: the one credential a
	// session thief does not have is the one that gates the irreversible action.
	// Disabling already required it; enabling did not, which was the asymmetry.
	passwordHash, phErr := h.queries.GetPasswordHashByUserID(r.Context(), userID)
	if phErr != nil {
		logError(r, "totp.verify: failed to query password hash", "error", phErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	pwOK, pwErr := passwordhash.Verify(req.Password, passwordHash)
	if capacityExhausted(w, r, pwErr, "totp.verify") {
		return
	}
	if pwErr != nil || !pwOK {
		if dbErr := h.queries.CreateLoginAttempt(r.Context(), db.CreateLoginAttemptParams{
			Email: userEmail, IpAddress: middleware.ClientIP(r), Success: 0,
		}); dbErr != nil {
			logError(r, "totp.verify: failed to record attempt", "error", dbErr)
		}
		writeUnauthorized(w, r, "your password is required to enable two-factor authentication")
		return
	}

	// Rate limit TOTP verify attempts per user to prevent brute force
	ip := middleware.ClientIP(r)
	failCount, err := h.queries.CountRecentFailedLoginAttemptsByEmail(r.Context(), userEmail)
	if err != nil {
		logError(r, "totp.verify: failed to query attempts", "error", err)
	}
	if failCount >= 5 {
		writeRateLimited(w, r, "too many attempts, try again in 15 minutes")
		return
	}

	secretRow, err := h.queries.GetTOTPSecret(r.Context(), userID)
	if err != nil {
		logError(r, "totp.verify: failed to query secret", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	secret := decryptTOTPSecret(nullStringToString(secretRow), h.cfg.VaultKey)
	if secret == "" {
		writeBadRequest(w, r, "run setup first")
		return
	}

	if !totp.ValidateCode(secret, req.Code) {
		if dbErr := h.queries.CreateLoginAttempt(r.Context(), db.CreateLoginAttemptParams{
			Email: userEmail, IpAddress: ip, Success: 0,
		}); dbErr != nil {
			logError(r, "totp.verify: failed to record attempt", "error", dbErr)
		}
		writeUnauthorized(w, r, "invalid code")
		return
	}

	plaintext, hashed, err := totp.GenerateRecoveryCodes()
	if err != nil {
		logError(r, "totp.verify: failed to generate recovery codes", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	hashedJSON := mustMarshalJSON(hashed)
	if err := h.queries.EnableTOTP(r.Context(), db.EnableTOTPParams{
		TotpRecoveryCodes: sql.NullString{String: string(hashedJSON), Valid: true},
		ID:                userID,
	}); err != nil {
		logError(r, "totp.verify: failed to enable 2FA", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	LogActivityFromRequest(h.queries, r, "totp.enabled", "2FA enabled")

	writeJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": plaintext,
	})
}

// TOTPDisable handles POST /api/auth/totp/disable - disables 2FA after
// verifying password and a current code.
func (h *AuthHandler) TOTPDisable(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}
	if req.Password == "" || req.Code == "" {
		writeBadRequest(w, r, "password and code are required")
		return
	}

	userEmail, err := h.queries.GetUserEmailByID(r.Context(), userID)
	if err != nil {
		logError(r, "totp.disable: failed to query user", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	failCount, err := h.queries.CountRecentFailedLoginAttemptsByEmail(r.Context(), userEmail)
	if err != nil {
		logError(r, "totp.disable: failed to query attempts", "error", err)
	}
	if failCount >= 5 {
		writeRateLimited(w, r, "too many failed attempts, try again in 15 minutes")
		return
	}

	ip := middleware.ClientIP(r)
	recordFailure := func() {
		if dbErr := h.queries.CreateLoginAttempt(r.Context(), db.CreateLoginAttemptParams{
			Email: userEmail, IpAddress: ip, Success: 0,
		}); dbErr != nil {
			logError(r, "totp.disable: failed to record failed attempt", "error", dbErr)
		}
	}

	passwordHash, err := h.queries.GetPasswordHashByUserID(r.Context(), userID)
	if err != nil {
		logError(r, "totp.disable: failed to query password hash", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	ok, verifyErr := passwordhash.Verify(req.Password, passwordHash)
	// Same contract as login, and it was missing here.
	//
	// This path counts failed attempts against the same 5-attempt lockout above, so
	// reporting hash-capacity exhaustion as a bad password is the same
	// account-lockout vector: saturate the semaphore, spray requests, and the
	// account locks out on server-capacity errors with nothing guessed.
	//
	// The login path was fixed and this sibling was not, which is the shape that
	// keeps recurring here: one security property, several doors. Found by a
	// positional guard, not by reading.
	if capacityExhausted(w, r, verifyErr, "totp.disable") {
		return
	}
	if verifyErr != nil || !ok {
		recordFailure()
		writeUnauthorized(w, r, "invalid password")
		return
	}

	totpState, err := h.queries.GetUserTOTPState(r.Context(), userID)
	if err != nil {
		logError(r, "totp.disable: failed to query 2FA state", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	// A RECOVERY CODE is accepted here, not only a live authenticator code.
	//
	// It used to demand a live code, which made the advertised recovery mechanism a
	// dead end: a user who loses their authenticator can log in with recovery codes
	// (8 of them) but could never turn 2FA off, so after the eighth the account was
	// permanently unauthenticatable, with no admin route to reset it. Recovery codes
	// bought 8 more logins and nothing else.
	//
	// The password has already been verified above, so accepting a recovery code here
	// requires BOTH factors: something known and something issued at enrolment. That
	// is the same bar as a normal disable.
	secret := decryptTOTPSecret(nullStringToString(totpState.TotpSecret), h.cfg.VaultKey)
	if !spendTOTPStep(r.Context(), h.queries, userID, secret, req.Code) {
		if !consumeRecoveryCode(r.Context(), h.queries, userID, req.Code) {
			recordFailure()
			writeUnauthorized(w, r, "invalid 2FA or recovery code")
			return
		}
		logError(r, "totp.disable: 2FA removed with a recovery code", "user_id", userID)
	}

	// Honour the vault policy. "Require two-factor authentication for all users"
	// was written to the settings table, read back to render the checkbox, and
	// enforced nowhere: any user could switch 2FA straight off with the policy
	// on, so an admin who ticked it got a compliance indicator rather than a
	// control. Refusing here is the enforcement point that cannot lock anyone
	// out, since the user demonstrably has a working code to reach this line.
	if settingBool(r.Context(), h.queries, "require_totp", false) {
		writeError(w, r, http.StatusConflict, "totp_required",
			"two-factor authentication is required by the vault policy and cannot be disabled; ask an administrator to change the policy first")
		return
	}

	if err := h.queries.DisableTOTP(r.Context(), userID); err != nil {
		logError(r, "totp.disable: failed to disable 2FA", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	LogActivityFromRequest(h.queries, r, "totp.disabled", "2FA disabled")

	writeJSON(w, http.StatusOK, map[string]string{"message": "2FA disabled"})
}

// generateToken creates a signed JWT for the given user ID and a matching
// server-side session record. Expiry is configurable via the
// session_duration_hours setting (default 7 days). The JWT carries the session
// id as its jti claim; the auth middleware rejects any token whose session row
// is missing, revoked (logout), or idle past the window, so a leaked token
// stops working the moment the user logs out.
func (h *AuthHandler) generateToken(userID string) (string, error) {
	sessionDuration := 7 * 24 * time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	durationStr, err := h.queries.GetSessionDurationSetting(ctx)
	if err == nil && durationStr != "" {
		var hours int
		if _, err := fmt.Sscanf(durationStr, "%d", &hours); err == nil && hours > 0 {
			sessionDuration = time.Duration(hours) * time.Hour
		}
	}

	now := time.Now()
	expiresAt := now.Add(sessionDuration)

	jti := generateID()
	if err := h.queries.CreateSession(ctx, db.CreateSessionParams{
		ID:        jti,
		UserID:    userID,
		ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
	}); err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}

	claims := jwt.MapClaims{
		"sub": userID,
		"jti": jti,
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.cfg.JWTSecret))
}

// setSessionCookie writes the session JWT as an HttpOnly cookie for browser
// clients. Secure + SameSite=Strict always: on a plain-HTTP localhost dev
// setup browsers still accept Secure cookies from 127.0.0.1/localhost.
func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie expires the session cookie.
func (h *AuthHandler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

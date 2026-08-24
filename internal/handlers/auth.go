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

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/passwordhash"
	"github.com/bright-interaction/trustissues/internal/totp"
	"github.com/golang-jwt/jwt/v5"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	queries *db.Queries
	cfg     *config.Config
	// vault is optional and used only by ChangePassword to purge a caller's
	// own rotation delivery targets as part of full credential invalidation.
	// Wired by SetVault after construction, matching UserHandler; nil simply
	// skips that step.
	vault *VaultHandler
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(queries *db.Queries, cfg *config.Config) *AuthHandler {
	return &AuthHandler{queries: queries, cfg: cfg}
}

// SetVault wires the vault handler used by ChangePassword to purge the
// caller's own rotation delivery targets during credential invalidation.
func (h *AuthHandler) SetVault(v *VaultHandler) { h.vault = v }

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

type setInitialPasswordRequest struct {
	Password string `json:"password"`
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
//
// keys is variadic so callers pass the CURRENT master key followed by
// TRUSTISSUES_VAULT_KEY_PREVIOUS. Without the fallback, the first login after a
// master-key change would fail 2FA for every enrolled user: the seed is still
// sealed under the old key until the re-encrypt sweep runs, the decrypt fails,
// and the ciphertext gets fed to the TOTP validator as if it were the seed.
func decryptTOTPSecret(stored string, keys ...string) string {
	if stored == "" {
		return ""
	}
	if dec, err := columncrypto.DecryptStringAny(stored, vaultFieldTOTPSecret, keys...); err == nil {
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
		//
		// A seed that opens under the PREVIOUS key is not a mismatch, it is a
		// rotation that has not been swept yet, so it is not an error. Converting
		// it is the rekey sweep's job (RekeyVault), not this migration's: this one
		// runs on every boot and its contract is "encrypt plaintext", and giving it
		// a second job that rewrites ciphertext is how the double-encryption bug
		// happened in the first place.
		if columncrypto.IsEncrypted(stored) {
			if _, derr := columncrypto.DecryptString(stored, h.cfg.VaultKey, vaultFieldTOTPSecret); derr != nil {
				if _, prevErr := columncrypto.DecryptStringAny(stored, vaultFieldTOTPSecret, h.cfg.VaultKeyPrevious); prevErr == nil {
					slog.Info("totp.migrate: secret is sealed under the previous vault key; run the re-encrypt sweep to convert it", "user_id", row.ID)
				} else {
					slog.Error("totp.migrate: marked secret failed to decrypt under current key, leaving untouched", "user_id", row.ID, "error", derr)
				}
			}
			continue
		}
		// Unmarked. Legacy binaries wrote bare-base64 ciphertext without a marker;
		// if it still decrypts under EITHER configured key it is already encrypted
		// (just missing the marker) and we recover the seed, otherwise it is
		// genuine plaintext to be encrypted now.
		//
		// The previous key has to be in this test. Without it, an unmarked legacy
		// ciphertext sealed under the OLD key fails the decrypt, gets classified as
		// plaintext, and is re-encrypted as Enc_new(Enc_old(seed)). That is the
		// irreversible corruption the marker was introduced to prevent, reachable
		// again through the one row shape the marker does not cover.
		seed := stored
		if dec, derr := columncrypto.DecryptStringAny(stored, vaultFieldTOTPSecret,
			h.cfg.VaultKey, h.cfg.VaultKeyPrevious); derr == nil {
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

	// Same claim every account-creation path runs. Nothing can have invited the
	// FIRST admin (there are no other accounts and no collections yet), but the
	// rule is "every path that creates an account claims its seats", and a rule
	// with an exception is the shape that lets the next path forget. Costs one
	// indexed read on a once-per-instance route.
	claimCollectionInvitationsBestEffort(r.Context(), h.queries, row.ID, row.Email)

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

	// Per-email lockout: 5 failures in 15 minutes, counting ONLY failures made at
	// this endpoint.
	//
	// The scope filter is the fix for a denial of service, not a tidy-up. This
	// counter is attacker-writable by design -- anyone who knows an address can
	// POST wrong passwords here -- so it must gate this endpoint and nothing
	// else. While it was unscoped, those same five requests also refused the
	// owner's authenticated TOTP enrolment, which require_totp had just made the
	// only exit from a 403 on every other route. See migration 00042.
	failCount, err := h.queries.CountRecentFailedLoginAttemptsByEmailAndScope(r.Context(),
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: req.Email, Scope: db.LoginAttemptScopePasswordLogin,
		})
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
		// The unknown-account path has to look EXACTLY like the known one, and
		// the dummy hash verify is only half of that.
		//
		// It equalizes latency, which is what it was added for. But the lockout
		// above reads a counter that this branch never fed: an address with no
		// account returned here before recording anything, so its failure count
		// stayed at zero forever. Five wrong passwords at a real address then
		// answered 429 (plus the graduated two- and four-second delays); the
		// same five at an unknown address answered a fast 401 every time. The
		// status code alone gave a certain answer to "does this person have a
		// vault account", which is the exact question the dummy hash exists to
		// refuse, only louder and without needing to measure anything.
		//
		// Recording the attempt for an unknown address costs one insert bounded
		// by the login limiter (30 per 15 min per IP) and makes both paths
		// accrue, delay and lock out identically. There is no activity_log event
		// because there is no account to attribute one to.
		if dbErr := h.queries.CreateLoginAttempt(r.Context(), db.CreateLoginAttemptParams{
			Email: req.Email, IpAddress: ip, Success: 0,
			Scope: db.LoginAttemptScopePasswordLogin,
		}); dbErr != nil {
			logError(r, "login: failed to record failed attempt for an unknown address", "error", dbErr)
		}
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
			Scope: db.LoginAttemptScopePasswordLogin,
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

		secret := decryptTOTPSecret(nullStringToString(totpState.TotpSecret), h.cfg.VaultKey, h.cfg.VaultKeyPrevious)
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
		Scope: db.LoginAttemptScopePasswordLogin,
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
		// Same expression as Me() below. It has to be here as well as there,
		// because login is the ONE path every gated user takes and the SPA does
		// not call /auth/me after it: useAuth.login does setUser(res.user) and
		// navigates. Omitting it here left the enrolment banner rendering only
		// after a manual reload, so a user the gate had just locked out of every
		// route landed on /vault, watched every query 403, and was shown nothing
		// telling them to enrol. That silently defeated the escape hatch the
		// whole gate depends on.
		TOTPEnrollmentRequired: !totpEnabled && settingBool(r.Context(), h.queries, "require_totp", false),
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

	// SetPasswordHash, not UpdatePasswordHash: the owner is choosing this
	// password themselves, which is exactly what password_set records. See
	// migration 00043 and TOTPVerify.
	if err := h.queries.SetPasswordHash(r.Context(), db.SetPasswordHashParams{
		PasswordHash: newHash,
		ID:           userID,
	}); err != nil {
		logError(r, "change-password: failed to update password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Revoke every outstanding credential for this account so one stolen under
	// the old password cannot outlive the change: sessions, API keys, and any
	// service identity the account owns (see invalidateCredentials; this used
	// to stop at sessions and API keys, which left a stolen service key
	// reading the account's vault straight through the incident-response
	// change meant to cut it off). We then mint a fresh token (issued now, so
	// it survives the revocation cutoff) and return it, letting a cooperating
	// client keep the current session alive while all older tokens die.
	email, emailErr := h.queries.GetUserEmailByID(r.Context(), userID)
	if emailErr != nil {
		logError(r, "change-password: failed to look up email for activity log", "error", emailErr, "user_id", userID)
		email = userID
	}
	invalidateCredentials(r, h.queries, h.vault, userID, email, "Changing password for")

	LogActivityFromRequest(h.queries, r, "auth.password_changed",
		"Password changed; sessions and API keys revoked")

	resp := map[string]string{"message": "password changed successfully"}
	if token, terr := h.generateToken(userID); terr == nil {
		resp["token"] = token
		h.setSessionCookie(w, token)
	}
	writeJSON(w, http.StatusOK, resp)
}

// SetInitialPassword handles POST /api/auth/set-initial-password.
//
// This is the other half of P0-2. RedeemInvitation's password-less branch
// (vault_only extension activation) mints hex(rand 32), hashes it, and
// discards it: nobody, including the account's own owner, has ever known
// that password. migration 00043's TOTPVerify fix let those accounts past
// the enrolment gate without one, but every OTHER password-gated door --
// vault Unlock/Rotate/ValidateKey (reauthOrRefuse) and TOTPDisable -- still
// unconditionally demands a password this account cannot supply. This
// endpoint is the only way such an account ever acquires a real, known
// password, which is what those doors already assume every caller has.
//
// It is deliberately registered inside the /api/auth route group, which
// sits OUTSIDE RequireTOTPEnrollment (see main.go): a vault_only user who
// has enrolled TOTP but not yet set a password must still be able to reach
// this endpoint, or the enrolment gate just relocates the deadlock one step
// later instead of closing it.
//
// SECURITY CRUX: this must never be usable to overwrite a password a human
// already chose. That is what turns "self-service bootstrap" into "session
// or API-key theft equals password reset". The refusal below on
// password_set != 0 is that boundary, and it is unconditional: there is no
// branch of this function that writes a password hash without having first
// confirmed the account has none.
//
// Credential survival: unlike ChangePassword and the admin reset-password
// path, this handler does NOT call invalidateCredentials. Those two exist to
// cut off a credential (a password) that might have been stolen; a
// password_set=0 account has no such credential to protect against, and the
// API key that authenticated THIS request is, for these accounts, the extension's
// only means of ever reaching this endpoint again. Revoking it here would
// disconnect the extension in the same request meant to finish connecting
// it -- exactly the trap that makes the admin reset-password remedy so
// painful for this account shape (see user_offboard.go). So existing
// sessions and API keys deliberately survive a call to this endpoint.
func (h *AuthHandler) SetInitialPassword(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	var req setInitialPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}
	if req.Password == "" {
		writeBadRequest(w, r, "password is required")
		return
	}
	if err := validatePasswordWithPolicy(r.Context(), h.queries, req.Password); err != nil {
		writeBadRequest(w, r, "password "+err.(*ValidationError).Message)
		return
	}

	// The refusal: this endpoint is a bootstrap for accounts that have never
	// had a password, not a password-reset bypass for one that has. A caller
	// with a valid session or API key for an account whose owner already
	// chose a password gets refused here every time, unconditionally, no
	// matter how the caller came to hold that credential.
	passwordSet, psErr := h.queries.GetUserPasswordSet(r.Context(), userID)
	if psErr != nil {
		logError(r, "set-initial-password: failed to query password-set marker", "error", psErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	if passwordSet != 0 {
		writeError(w, r, http.StatusConflict, "password_already_set",
			"this account already has a password; use change-password instead")
		return
	}

	newHash, err := passwordhash.Hash(req.Password)
	if err != nil {
		logError(r, "set-initial-password: failed to hash password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// SetPasswordHash sets password_hash and password_set=1 in the same UPDATE
	// statement, so there is no partial-failure window where the row claims a
	// password it does not have (or vice versa). See migration 00043.
	if err := h.queries.SetPasswordHash(r.Context(), db.SetPasswordHashParams{
		PasswordHash: newHash,
		ID:           userID,
	}); err != nil {
		logError(r, "set-initial-password: failed to set password", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	email, emailErr := h.queries.GetUserEmailByID(r.Context(), userID)
	if emailErr != nil {
		logError(r, "set-initial-password: failed to look up email for activity log", "error", emailErr, "user_id", userID)
		email = userID
	}
	LogActivityFromRequest(h.queries, r, "auth.initial_password_set",
		fmt.Sprintf("Initial password set for %s", email))

	writeJSON(w, http.StatusOK, map[string]string{"message": "password set successfully"})
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

	// The lockout is checked BEFORE the password, which is the whole point of it.
	//
	// This block used to sit after the verify's early return below, so it was only
	// ever evaluated once the password was already correct: against a guesser it
	// was unreachable code carrying a comment claiming it prevented brute force.
	// The endpoint is mounted under the ordinary /api limiter (500 req/min per IP),
	// not the login limiter (30 per 15 min), so a stolen session had a password
	// oracle two orders of magnitude faster than /api/auth/login with the account
	// lockout switched off, and every wrong guess still wrote a login_attempts row
	// that locked the real owner out of the login page.
	//
	// TOTPDisable checks the same counter in the right order. One property, two
	// doors, fixed at one of them, which is the shape that keeps recurring here.
	//
	// The "locked the real owner out of the login page" half above is closed too,
	// from the other side: these rows carry scope=session_reauth and login counts
	// only scope=password_login, so the two doors no longer hold each other shut
	// in either direction.
	//
	// Scoped to session_reauth: only a caller already authenticated AS this user
	// can write a row this counter sees. An outsider spraying the public login
	// endpoint no longer refuses the owner's own enrolment, which is what made
	// this endpoint -- the gate's sole exit -- remotely closable by a stranger.
	ip := middleware.ClientIP(r)
	failCount, err := h.queries.CountRecentFailedLoginAttemptsByEmailAndScope(r.Context(),
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: userEmail, Scope: db.LoginAttemptScopeSessionReauth,
		})
	if err != nil {
		logError(r, "totp.verify: failed to query attempts", "error", err)
	}
	if failCount >= 5 {
		writeRateLimited(w, r, "too many attempts, try again in 15 minutes")
		return
	}

	// ENABLING 2FA requires the password -- but only from an account a human
	// actually set one on.
	//
	// Enrolment used to need only a live session or API key. Turning 2FA ON is an
	// irreversible-by-the-owner act: after it, login demands a code the owner does not
	// have, TOTPDisable demands a live code they cannot produce, the recovery codes
	// were returned to whoever enrolled, and no admin route exists to reset another
	// user's 2FA. So anyone holding a stolen session, or an API key stolen from
	// someone else's account, could permanently lock the owner out of their own
	// vault without ever knowing the password.
	//
	// Requiring the password here is what makes that impossible: the one credential a
	// session thief does not have is the one that gates the irreversible action.
	// Disabling already required it; enabling did not, which was the asymmetry.
	//
	// THAT REASONING BREAKS for the vault_only extension's password-less
	// redemption (RedeemInvitation in users.go): the "password" on that account
	// is hex(rand 32), hashed and immediately discarded, so nobody -- including
	// the account's own owner -- has ever known it. Requiring it here does not
	// stop a thief, because a thief cannot produce it either; it just makes
	// enrolment permanently impossible for the legitimate owner too, which is
	// exactly what turned into P0-2: an admin enables require_totp, the
	// vault_only user is 403 everywhere, and the ONLY exit from that 403 demands
	// a credential that provably does not exist. For that account the API key
	// (or session) that already got this request past authentication and past
	// the session_reauth lockout above IS the whole credential; there is no
	// second factor a thief could be missing that the password would have
	// tested for. See migration 00043 and its comment for the full argument.
	passwordSet, psErr := h.queries.GetUserPasswordSet(r.Context(), userID)
	if psErr != nil {
		logError(r, "totp.verify: failed to query password-set marker", "error", psErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	if passwordSet != 0 {
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
				Email: userEmail, IpAddress: ip, Success: 0,
				Scope: db.LoginAttemptScopeSessionReauth,
			}); dbErr != nil {
				logError(r, "totp.verify: failed to record attempt", "error", dbErr)
			}
			writeUnauthorized(w, r, "your password is required to enable two-factor authentication")
			return
		}
	}

	secretRow, err := h.queries.GetTOTPSecret(r.Context(), userID)
	if err != nil {
		logError(r, "totp.verify: failed to query secret", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	secret := decryptTOTPSecret(nullStringToString(secretRow), h.cfg.VaultKey, h.cfg.VaultKeyPrevious)
	if secret == "" {
		writeBadRequest(w, r, "run setup first")
		return
	}

	if !totp.ValidateCode(secret, req.Code) {
		if dbErr := h.queries.CreateLoginAttempt(r.Context(), db.CreateLoginAttemptParams{
			Email: userEmail, IpAddress: ip, Success: 0,
			Scope: db.LoginAttemptScopeSessionReauth,
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

	// Same scope as TOTPVerify, for the same reason: an already-authenticated
	// door must not be closable by rows the public login endpoint writes.
	failCount, err := h.queries.CountRecentFailedLoginAttemptsByEmailAndScope(r.Context(),
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: userEmail, Scope: db.LoginAttemptScopeSessionReauth,
		})
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
			Scope: db.LoginAttemptScopeSessionReauth,
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

	// Honour the vault policy, and do it BEFORE spending the second factor.
	//
	// "Require two-factor authentication for all users" was written to the settings
	// table, read back to render the checkbox, and enforced nowhere: any user could
	// switch 2FA straight off with the policy on, so an admin who ticked it got a
	// compliance indicator rather than a control.
	//
	// The refusal originally sat below the code check, which made a refused attempt
	// destructive: the TOTP step was claimed, or worse a recovery code was consumed,
	// and then the request was refused anyway. Recovery codes are the case that
	// bites. There are eight, they are single-use, and no route exists to reissue
	// them, so eight refused attempts under this policy left an account with no
	// recovery path at all, having never once succeeded at anything. Refusing on the
	// password alone costs the user nothing and locks nobody out: a refused disable
	// is a no-op either way, and the policy state is already readable by every
	// authenticated role through the vault-policy settings read.
	if settingBool(r.Context(), h.queries, "require_totp", false) {
		writeError(w, r, http.StatusConflict, "totp_required",
			"two-factor authentication is required by the vault policy and cannot be disabled; ask an administrator to change the policy first")
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
	secret := decryptTOTPSecret(nullStringToString(totpState.TotpSecret), h.cfg.VaultKey, h.cfg.VaultKeyPrevious)
	if !spendTOTPStep(r.Context(), h.queries, userID, secret, req.Code) {
		if !consumeRecoveryCode(r.Context(), h.queries, userID, req.Code) {
			recordFailure()
			writeUnauthorized(w, r, "invalid 2FA or recovery code")
			return
		}
		logError(r, "totp.disable: 2FA removed with a recovery code", "user_id", userID)
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

package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// SettingsHandler handles global settings endpoints.
type SettingsHandler struct {
	queries *db.Queries
	cfg     *config.Config
}

// NewSettingsHandler creates a new SettingsHandler.
func NewSettingsHandler(queries *db.Queries, cfg *config.Config) *SettingsHandler {
	return &SettingsHandler{queries: queries, cfg: cfg}
}

// Defaults when the setting rows are missing.
const (
	defaultAutoLockMaxMinutes   = 15
	defaultMinPasswordLength    = 12
	defaultRotationReminderDays = 14
	defaultSessionDurationHours = 168
	minPasswordLengthFloor      = 12
	maxPasswordLengthPolicy     = 64
)

// vaultPolicy is the team-wide vault policy, editable by admins in Settings.
// The auto-lock field is serialized as auto_lock_max_minutes to match the
// shipping browser-extension client (bright-vault-extension src/lib/api.ts
// settings.vaultPolicy) and the CONTRACT.md vault-policy endpoint; the stored
// setting key is vault_auto_lock_max_minutes.
type vaultPolicy struct {
	MinPasswordLength    int  `json:"min_password_length"`
	RequireTOTP          bool `json:"require_totp"`
	AutoLockMinutes      int  `json:"auto_lock_max_minutes"`
	RotationReminderDays int  `json:"rotation_reminder_days"`
}

// settingInt reads an integer setting with a default for missing/invalid rows.
func settingInt(ctx context.Context, q *db.Queries, key string, def int) int {
	v, err := q.GetSetting(ctx, key)
	if err != nil || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// settingBool reads a boolean setting ("true"/"false") with a default.
func settingBool(ctx context.Context, q *db.Queries, key string, def bool) bool {
	v, err := q.GetSetting(ctx, key)
	if err != nil || v == "" {
		return def
	}
	return v == "true"
}

func readVaultPolicy(ctx context.Context, q *db.Queries) vaultPolicy {
	return vaultPolicy{
		MinPasswordLength:    settingInt(ctx, q, "min_password_length", defaultMinPasswordLength),
		RequireTOTP:          settingBool(ctx, q, "require_totp", false),
		AutoLockMinutes:      settingInt(ctx, q, "vault_auto_lock_max_minutes", defaultAutoLockMaxMinutes),
		RotationReminderDays: settingInt(ctx, q, "rotation_reminder_days", defaultRotationReminderDays),
	}
}

// GetVaultPolicy handles GET /api/settings/vault-policy. Readable by every
// authenticated user (the vault UI needs the auto-lock deadline), writable by
// admins only.
func (h *SettingsHandler) GetVaultPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, readVaultPolicy(r.Context(), h.queries))
}

// UpdateVaultPolicy handles PUT /api/settings/vault-policy (admin only).
func (h *SettingsHandler) UpdateVaultPolicy(w http.ResponseWriter, r *http.Request) {
	var req vaultPolicy
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	if req.AutoLockMinutes < 1 || req.AutoLockMinutes > 1440 {
		writeValidationError(w, r, "auto_lock_max_minutes must be between 1 and 1440")
		return
	}
	if req.MinPasswordLength < minPasswordLengthFloor || req.MinPasswordLength > maxPasswordLengthPolicy {
		writeValidationError(w, r, fmt.Sprintf("min_password_length must be between %d and %d",
			minPasswordLengthFloor, maxPasswordLengthPolicy))
		return
	}
	if req.RotationReminderDays < 0 || req.RotationReminderDays > 365 {
		writeValidationError(w, r, "rotation_reminder_days must be between 0 and 365")
		return
	}

	requireTOTP := "false"
	if req.RequireTOTP {
		requireTOTP = "true"
		// Do not let an admin switch on a policy they would immediately fail.
		// Enforcement lives on the TOTP-disable path and (for the operator) in
		// the enrolment nudge, but an admin with no 2FA who enables this is
		// asking every user including themselves to comply with something they
		// have not set up, which reads as a working control while nobody is
		// actually covered.
		state, err := h.queries.GetUserTOTPState(r.Context(), middleware.GetUserID(r.Context()))
		if err != nil {
			logError(r, "settings.policy: could not read the acting admin's 2FA state", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		if !nullInt64Is1(state.TotpEnabled) {
			writeValidationError(w, r,
				"set up two-factor authentication on your own account before requiring it for everyone, otherwise you would be enforcing a policy you do not meet")
			return
		}
	}
	updates := map[string]string{
		"min_password_length":         strconv.Itoa(req.MinPasswordLength),
		"require_totp":                requireTOTP,
		"vault_auto_lock_max_minutes": strconv.Itoa(req.AutoLockMinutes),
		"rotation_reminder_days":      strconv.Itoa(req.RotationReminderDays),
	}
	for key, value := range updates {
		if err := h.queries.UpsertSetting(r.Context(), db.UpsertSettingParams{
			Key: key, Value: value,
		}); err != nil {
			logError(r, "settings.vault_policy: update failed", "key", key, "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}

	LogActivityFromRequest(h.queries, r, "settings.vault_policy_updated",
		fmt.Sprintf("Vault policy updated (auto-lock %d min, min password %d)",
			req.AutoLockMinutes, req.MinPasswordLength))

	writeJSON(w, http.StatusOK, req)
}

// validatePasswordWithPolicy enforces the shared password rules plus the
// admin-configurable min_password_length policy. The server floor stays at
// minPasswordLengthFloor regardless of the stored setting so a corrupted row
// can never weaken the baseline.
func validatePasswordWithPolicy(ctx context.Context, q *db.Queries, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	minLen := settingInt(ctx, q, "min_password_length", defaultMinPasswordLength)
	if minLen < minPasswordLengthFloor {
		minLen = minPasswordLengthFloor
	}
	if len(password) < minLen {
		return &ValidationError{Field: "password", Message: fmt.Sprintf("must be at least %d characters", minLen)}
	}
	return nil
}

// --- Session duration --------------------------------------------------------

type sessionDurationResponse struct {
	// IdleMinutes is how long a session survives WITHOUT USE, as opposed to
	// DurationHours which is its absolute lifetime. It lives in the same
	// payload so the Session settings card shows both, because they used to be
	// governed by one control and an operator could not see the second.
	IdleMinutes   int `json:"idle_minutes"`
	DurationHours int `json:"duration_hours"`
}

// GetSessionDuration handles GET /api/settings/session-duration (admin only).
func (h *SettingsHandler) GetSessionDuration(w http.ResponseWriter, r *http.Request) {
	hours := defaultSessionDurationHours
	if v, err := h.queries.GetSessionDurationSetting(r.Context()); err == nil && v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			hours = n
		}
	} else if err != nil && err != sql.ErrNoRows {
		logError(r, "settings.session_duration: read failed", "error", err)
	}
	idle := middleware.DefaultSessionIdleMinutes
	if v, err := h.queries.GetSessionIdleSetting(r.Context()); err == nil && v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			idle = n
		}
	} else if err != nil && err != sql.ErrNoRows {
		logError(r, "settings.session_idle: read failed", "error", err)
	}
	writeJSON(w, http.StatusOK, sessionDurationResponse{DurationHours: hours, IdleMinutes: idle})
}

// UpdateSessionDuration handles PUT /api/settings/session-duration (admin
// only). New JWTs pick the value up on the next login.
func (h *SettingsHandler) UpdateSessionDuration(w http.ResponseWriter, r *http.Request) {
	var req sessionDurationResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}
	if req.DurationHours < 1 || req.DurationHours > 720 {
		writeValidationError(w, r, "duration_hours must be between 1 and 720")
		return
	}
	// 0 means "not supplied": keep whatever is stored rather than silently
	// resetting the idle window to a default an older client never sent.
	if req.IdleMinutes != 0 && (req.IdleMinutes < 1 || req.IdleMinutes > 1440) {
		writeValidationError(w, r, "idle_minutes must be between 1 and 1440")
		return
	}

	if err := h.queries.UpsertSetting(r.Context(), db.UpsertSettingParams{
		Key:   "session_duration_hours",
		Value: strconv.Itoa(req.DurationHours),
	}); err != nil {
		logError(r, "settings.session_duration: update failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	if req.IdleMinutes != 0 {
		if err := h.queries.UpsertSetting(r.Context(), db.UpsertSettingParams{
			Key:   "session_idle_minutes",
			Value: strconv.Itoa(req.IdleMinutes),
		}); err != nil {
			logError(r, "settings.session_idle: update failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}

	LogActivityFromRequest(h.queries, r, "settings.session_duration_updated",
		fmt.Sprintf("Session duration set to %d hours, idle window %d minutes",
			req.DurationHours, req.IdleMinutes))

	writeJSON(w, http.StatusOK, req)
}

// --- SMTP --------------------------------------------------------------------

// smtpConfigResponse matches the frontend SMTPConfig type. The password is
// never returned; password_set reports whether one is stored.
type smtpConfigResponse struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	From        string `json:"from"`
	Username    string `json:"username"`
	PasswordSet bool   `json:"password_set"`
	UseTLS      bool   `json:"use_tls"`
}

type smtpUpdateRequest struct {
	Host     *string `json:"host"`
	Port     *string `json:"port"`
	From     *string `json:"from"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	UseTLS   *bool   `json:"use_tls"`
}

func (h *SettingsHandler) readSMTPConfig(ctx context.Context) smtpConfigResponse {
	get := func(key string) string {
		v, _ := h.queries.GetSetting(ctx, key)
		return v
	}
	return smtpConfigResponse{
		Host:        get("smtp_host"),
		Port:        get("smtp_port"),
		From:        get("smtp_from"),
		Username:    get("smtp_username"),
		PasswordSet: get("smtp_password") != "",
		UseTLS:      get("smtp_use_tls") == "true",
	}
}

// GetSMTP handles GET /api/settings/smtp (admin only).
func (h *SettingsHandler) GetSMTP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.readSMTPConfig(r.Context()))
}

// UpdateSMTP handles PUT /api/settings/smtp (admin only). The password is
// only updated when a non-empty value is provided; sending the other fields
// without a password keeps the stored one.
func (h *SettingsHandler) UpdateSMTP(w http.ResponseWriter, r *http.Request) {
	var req smtpUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	updates := map[string]*string{
		"smtp_host":     req.Host,
		"smtp_port":     req.Port,
		"smtp_from":     req.From,
		"smtp_username": req.Username,
	}
	if req.From != nil && *req.From != "" {
		if err := ValidateEmail(*req.From); err != nil {
			writeValidationError(w, r, "from: invalid email address format")
			return
		}
	}
	if req.UseTLS != nil {
		useTLS := "false"
		if *req.UseTLS {
			useTLS = "true"
		}
		updates["smtp_use_tls"] = &useTLS
	}
	if req.Password != nil && *req.Password != "" {
		// Encrypt at rest. This is a live relay credential and was the lone
		// setting stored in cleartext, so it survived into every DB backup while
		// every other secret in the product was ciphertext.
		enc, encErr := columncrypto.EncryptString(*req.Password, h.cfg.VaultKey)
		if encErr != nil {
			logError(r, "settings.smtp: password encrypt failed", "error", encErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		updates["smtp_password"] = &enc
	}

	for key, value := range updates {
		if value == nil {
			continue
		}
		if err := h.queries.UpsertSetting(r.Context(), db.UpsertSettingParams{
			Key: key, Value: *value,
		}); err != nil {
			logError(r, "settings.smtp: update failed", "key", key, "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}

	LogActivityFromRequest(h.queries, r, "settings.smtp_updated", "SMTP settings updated")

	writeJSON(w, http.StatusOK, h.readSMTPConfig(r.Context()))
}

// TestSMTP handles POST /api/settings/smtp/test (admin only). Sends a test
// email to the calling admin's own address using the stored settings.
func (h *SettingsHandler) TestSMTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.GetUserID(ctx)

	userEmail, err := h.queries.GetUserEmailByID(ctx, userID)
	if err != nil {
		logError(r, "settings.smtp_test: failed to get user email", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	get := func(key string) string {
		v, _ := h.queries.GetSetting(ctx, key)
		return v
	}
	host := get("smtp_host")
	from := get("smtp_from")
	if host == "" || from == "" {
		writeBadRequest(w, r, "SMTP is not configured; set host and from address first")
		return
	}

	// smtp_password is ciphertext at rest, so it has to be decrypted before it
	// can be used as a credential. Passing the stored value straight through
	// authenticated with "tienc:v1:..." and failed against every real relay.
	password, err := resolveSMTPPassword(get("smtp_password"), h.cfg.VaultKey)
	if err != nil {
		logError(r, "settings.smtp_test: password decrypt failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	err = sendTestEmail(host, get("smtp_port"), from, get("smtp_username"),
		password, get("smtp_use_tls") == "true", userEmail)
	if err != nil {
		logError(r, "settings.smtp_test: send failed", "error", err)
		writeBadRequest(w, r, "SMTP test failed; check the server logs for detail")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Test email sent to " + userEmail})
}

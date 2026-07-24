package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SessionCookieName is the HttpOnly cookie carrying the session JWT for
// browser clients. The auth handler sets it on login with
// HttpOnly + Secure + SameSite=Strict; this middleware accepts it as a
// fallback when no Authorization header is present.
const SessionCookieName = "trustissues_session"

// contextKey is an unexported type for context keys defined in this package,
// preventing collisions with keys defined in other packages.
type contextKey string

const (
	// UserIDKey is the context key for the authenticated user's ID.
	UserIDKey contextKey = "user_id"
	// UserRoleKey is the context key for the authenticated user's role
	// (admin/user/vault_only).
	UserRoleKey contextKey = "user_role"
	// SessionIDKey is the context key for the validated server-side session id
	// (the JWT jti). Empty on the API-key path, which has no session.
	SessionIDKey contextKey = "session_id"
)

// GetUserID extracts the authenticated user ID from the request context.
// Returns an empty string if no user ID is present.
func GetUserID(ctx context.Context) string {
	if v, ok := ctx.Value(UserIDKey).(string); ok {
		return v
	}
	return ""
}

// GetUserRole extracts the authenticated user's role from the request context.
func GetUserRole(ctx context.Context) string {
	if v, ok := ctx.Value(UserRoleKey).(string); ok {
		return v
	}
	return ""
}

// GetSessionID extracts the validated server-side session id (JWT jti) from the
// request context. Returns an empty string on the API-key path or when no
// session is present.
func GetSessionID(ctx context.Context) string {
	if v, ok := ctx.Value(SessionIDKey).(string); ok {
		return v
	}
	return ""
}

// IsAdmin returns true if the authenticated user has the admin role.
func IsAdmin(ctx context.Context) bool {
	return GetUserRole(ctx) == "admin"
}

// IsVaultOnly returns true if the authenticated user has the vault_only role.
func IsVaultOnly(ctx context.Context) bool {
	return GetUserRole(ctx) == "vault_only"
}

// VaultOnlyBlock returns middleware that rejects requests from vault_only
// users with 403. Mount it on every route group that is not part of the
// vault surface so vault_only users stay locked to the vault UI.
func VaultOnlyBlock() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsVaultOnly(r.Context()) {
				http.Error(w, `{"error":"access denied for vault-only users"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AdminOnly returns middleware that rejects requests from non-admin users with 403.
func AdminOnly() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsAdmin(r.Context()) {
				http.Error(w, `{"error":"admin access required"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// enrichUserContext looks up the user's role and disabled status, rejects
// disabled users, and adds the role to the request context.
// Returns (enriched ctx, sessionsValidAfter, rejectReason). sessionsValidAfter
// is the unix time before which JWTs for this user are revoked (set on
// password change); callers on a JWT path compare it to the token's iat,
// non-JWT callers ignore it.
func enrichUserContext(ctx context.Context, db *sql.DB, userID string) (context.Context, int64, string) {
	var role string
	var disabled int
	var sessionsValidAfter int64
	err := db.QueryRowContext(ctx, "SELECT role, disabled, sessions_valid_after FROM users WHERE id = ?", userID).
		Scan(&role, &disabled, &sessionsValidAfter)
	if err != nil {
		if err == sql.ErrNoRows {
			return ctx, 0, "user not found"
		}
		slog.Error("auth: failed to lookup user role", "error", err)
		return ctx, 0, "internal error"
	}
	if disabled != 0 {
		return ctx, 0, "account is disabled"
	}
	return context.WithValue(ctx, UserRoleKey, role), sessionsValidAfter, ""
}

// sessionRevoked reports whether a JWT with the given issued-at is older than
// the user's revocation point (set on password change). Tokens with no iat
// (iat==0) and users with no revocation point (sva==0) are never revoked here.
func sessionRevoked(iat, sessionsValidAfter int64) bool {
	return sessionsValidAfter > 0 && iat > 0 && iat < sessionsValidAfter
}

// JWTOrAPIKeyAuth returns middleware that accepts a JWT (Authorization Bearer
// header or the session cookie) or an X-API-Key header. API keys let the
// browser extension and external integrations authenticate while the web UI
// uses JWTs. On success it sets the user ID and role in the request context.
func JWTOrAPIKeyAuth(jwtSecret string, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for API key first
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != "" {
				hash := sha256.Sum256([]byte(apiKey))
				keyHash := hex.EncodeToString(hash[:])

				var userID string
				var expiresAt sql.NullString
				err := db.QueryRowContext(
					r.Context(),
					"SELECT user_id, expires_at FROM api_keys WHERE key_hash = ?",
					keyHash,
				).Scan(&userID, &expiresAt)

				if err != nil {
					if err == sql.ErrNoRows {
						slog.Debug("api key auth: unknown key")
					} else {
						slog.Error("api key auth: database error", "error", err)
					}
					http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
					return
				}

				// Check expiry
				if expiresAt.Valid && expiresAt.String != "" {
					exp, err := time.Parse(time.RFC3339, expiresAt.String)
					if err == nil && time.Now().After(exp) {
						http.Error(w, `{"error":"API key has expired"}`, http.StatusUnauthorized)
						return
					}
				}

				// Update last_used_at (best effort)
				db.ExecContext(r.Context(), "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?",
					time.Now().UTC().Format(time.RFC3339), keyHash)

				ctx := context.WithValue(r.Context(), UserIDKey, userID)
				// API-key auth: no JWT session, so session revocation does not apply.
				ctx, _, reject := enrichUserContext(ctx, db, userID)
				if reject != "" {
					writeAuthReject(w, http.StatusForbidden, reject)
					return
				}
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Fall back to JWT auth (Authorization header, then session cookie)
			tokenString := extractSessionToken(r)
			if tokenString == "" {
				http.Error(w, `{"error":"authorization header or X-API-Key required"}`, http.StatusUnauthorized)
				return
			}

			userID, iat, jti, err := ParseJWTWithIssuedAt(tokenString, jwtSecret)
			if err != nil {
				slog.Debug("jwt auth: invalid token", "error", err)
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			ctx, sva, reject := enrichUserContext(ctx, db, userID)
			if reject != "" {
				writeAuthReject(w, http.StatusForbidden, reject)
				return
			}
			if sessionRevoked(iat, sva) {
				writeAuthReject(w, http.StatusUnauthorized, "session expired, please log in again")
				return
			}
			// Server-side session check: a JWT is only valid while its session
			// row is live (not revoked by logout, not idle past the window).
			if status, msg := validateSession(ctx, db, userID, jti); msg != "" {
				writeAuthReject(w, status, msg)
				return
			}
			ctx = context.WithValue(ctx, SessionIDKey, jti)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ParseJWT parses a JWT token string and returns the user ID from the "sub"
// claim.
func ParseJWT(tokenString, secret string) (string, error) {
	sub, _, _, err := ParseJWTWithIssuedAt(tokenString, secret)
	return sub, err
}

// ParseJWTWithIssuedAt validates the token and additionally returns the iat
// (issued-at) unix seconds and the jti (session id) claim. iat is 0 if the
// token carries no iat claim; jti is empty if it carries no jti claim.
func ParseJWTWithIssuedAt(tokenString, secret string) (string, int64, string, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return "", 0, "", err
	}
	if !token.Valid {
		return "", 0, "", jwt.ErrSignatureInvalid
	}
	sub, err := token.Claims.GetSubject()
	if err != nil {
		return "", 0, "", err
	}
	if sub == "" {
		return "", 0, "", jwt.ErrTokenRequiredClaimMissing
	}
	var iat int64
	if issued, ierr := token.Claims.GetIssuedAt(); ierr == nil && issued != nil {
		iat = issued.Unix()
	}
	var jti string
	if mc, ok := token.Claims.(jwt.MapClaims); ok {
		if v, ok := mc["jti"].(string); ok {
			jti = v
		}
	}
	return sub, iat, jti, nil
}

// validateSession enforces the server-side session record backing a JWT. It
// returns ("", "") when the session is valid, or an (HTTP status, message)
// pair to reject with. A token whose session row is missing (logged out /
// unknown), revoked, bound to a different user, or idle past the configured
// window is rejected with 401. On success it bumps last_used_at so the idle
// clock tracks real activity.
func validateSession(ctx context.Context, db *sql.DB, userID, jti string) (int, string) {
	if jti == "" {
		// Every token this server mints carries a jti; a missing one means a
		// pre-revocation or forged token. Fail closed.
		return http.StatusUnauthorized, "session expired, please log in again"
	}

	var sessUserID string
	var revokedAt sql.NullString
	var idle int
	err := db.QueryRowContext(ctx,
		"SELECT user_id, revoked_at, (last_used_at <= datetime('now', ?)) FROM sessions WHERE id = ?",
		sessionIdleModifier(ctx, db), jti,
	).Scan(&sessUserID, &revokedAt, &idle)
	if err == sql.ErrNoRows {
		return http.StatusUnauthorized, "session expired, please log in again"
	}
	if err != nil {
		slog.Error("auth: session lookup failed", "error", err)
		return http.StatusInternalServerError, "internal error"
	}
	if revokedAt.Valid || sessUserID != userID {
		return http.StatusUnauthorized, "session expired, please log in again"
	}
	if idle == 1 {
		return http.StatusUnauthorized, "session expired due to inactivity, please log in again"
	}

	// Best effort: record activity so the idle timeout measures inactivity.
	if _, uerr := db.ExecContext(ctx,
		"UPDATE sessions SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", jti); uerr != nil {
		slog.Error("auth: failed to update session activity", "error", uerr)
	}
	return 0, ""
}

// sessionIdleModifier returns a SQLite datetime modifier ("-N minutes") for the
// idle-timeout window, reusing the vault auto-lock setting. Defaults to 15
// minutes when the setting is missing or invalid so a corrupt row cannot
// disable the timeout.
func sessionIdleModifier(ctx context.Context, db *sql.DB) string {
	mins := 15
	var v string
	if err := db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE key = ?", "vault_auto_lock_max_minutes").Scan(&v); err == nil {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			mins = n
		}
	}
	return fmt.Sprintf("-%d minutes", mins)
}

// extractSessionToken pulls the JWT from the Authorization header
// ("Bearer <token>") or, failing that, from the session cookie.
func extractSessionToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
		return ""
	}
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// writeAuthReject writes a JSON error body with the given status.
func writeAuthReject(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
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

			userID, iat, err := ParseJWTWithIssuedAt(tokenString, jwtSecret)
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
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ParseJWT parses a JWT token string and returns the user ID from the "sub"
// claim.
func ParseJWT(tokenString, secret string) (string, error) {
	sub, _, err := ParseJWTWithIssuedAt(tokenString, secret)
	return sub, err
}

// ParseJWTWithIssuedAt validates the token and additionally returns the iat
// (issued-at) unix seconds, used by the session-revocation check. iat is 0 if
// the token carries no iat claim.
func ParseJWTWithIssuedAt(tokenString, secret string) (string, int64, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return "", 0, err
	}
	if !token.Valid {
		return "", 0, jwt.ErrSignatureInvalid
	}
	sub, err := token.Claims.GetSubject()
	if err != nil {
		return "", 0, err
	}
	if sub == "" {
		return "", 0, jwt.ErrTokenRequiredClaimMissing
	}
	var iat int64
	if issued, ierr := token.Claims.GetIssuedAt(); ierr == nil && issued != nil {
		iat = issued.Unix()
	}
	return sub, iat, nil
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

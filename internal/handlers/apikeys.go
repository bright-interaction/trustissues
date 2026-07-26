package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
	"github.com/go-chi/chi/v5"
)

// APIKeyHandler handles API key management. API keys let programmatic clients
// (most importantly the browser extension) authenticate with an X-API-Key
// header instead of a session cookie.
type APIKeyHandler struct {
	queries *db.Queries
}

// NewAPIKeyHandler creates a new APIKeyHandler.
func NewAPIKeyHandler(queries *db.Queries) *APIKeyHandler {
	return &APIKeyHandler{queries: queries}
}

type createAPIKeyRequest struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expires_in_days"`
}

type apiKeyResponse struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	KeyPrefix  string  `json:"key_prefix"`
	LastUsedAt *string `json:"last_used_at"`
	ExpiresAt  *string `json:"expires_at"`
	// RevokedAt is nil while the key is live. Revoked keys stay in the list
	// (marked, not hidden) so the owner can see that a key existed and when it
	// was cut off; the auth path rejects them.
	RevokedAt *string `json:"revoked_at"`
	CreatedAt string  `json:"created_at"`
}

// apiKeyCreateResponse carries the full key. The plaintext key is returned
// exactly once, at creation; only its SHA-256 hash is stored.
type apiKeyCreateResponse struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Key       string  `json:"key"`
	KeyPrefix string  `json:"key_prefix"`
	ExpiresAt *string `json:"expires_at"`
	CreatedAt string  `json:"created_at"`
}

// List handles GET /api/api-keys and returns the authenticated user's keys
// (prefixes only, never the secret).
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	rows, err := h.queries.ListAPIKeysByUser(r.Context(), userID)
	if err != nil {
		logError(r, "apikeys.list: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, apiKeyResponses(rows))
}

// apiKeyResponses maps key rows to the wire shape shared by the per-user and
// admin list endpoints. It never carries the secret, only the prefix.
func apiKeyResponses(rows []db.ListAPIKeysByUserRow) []apiKeyResponse {
	keys := make([]apiKeyResponse, 0, len(rows))
	for _, row := range rows {
		k := apiKeyResponse{ID: row.ID, Name: row.Name, KeyPrefix: row.KeyPrefix}
		if row.LastUsedAt.Valid {
			s := row.LastUsedAt.Time.Format(time.RFC3339)
			k.LastUsedAt = &s
		}
		if row.ExpiresAt.Valid {
			s := row.ExpiresAt.Time.Format(time.RFC3339)
			k.ExpiresAt = &s
		}
		if row.RevokedAt.Valid {
			s := row.RevokedAt.Time.Format(time.RFC3339)
			k.RevokedAt = &s
		}
		if row.CreatedAt.Valid {
			k.CreatedAt = row.CreatedAt.Time.Format(time.RFC3339)
		}
		keys = append(keys, k)
	}
	return keys
}

// Create handles POST /api/api-keys and mints a new key for the browser
// extension or other programmatic clients.
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}
	if req.Name == "" {
		writeBadRequest(w, r, "name is required")
		return
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		logError(r, "apikeys.create: failed to generate id", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	id := hex.EncodeToString(idBytes)

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		logError(r, "apikeys.create: failed to generate key", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	rawKey := hex.EncodeToString(keyBytes)
	fullKey := "ti_" + rawKey

	// Store only the SHA-256 hash; the middleware hashes the incoming header the
	// same way and looks up key_hash.
	hash := sha256.Sum256([]byte(fullKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := rawKey[:8]

	now := time.Now().UTC()
	createdAt := now.Format(time.RFC3339)

	var expiresAt *string
	var expiresAtDB sql.NullTime
	if req.ExpiresInDays > 0 {
		exp := now.AddDate(0, 0, req.ExpiresInDays)
		expStr := exp.Format(time.RFC3339)
		expiresAt = &expStr
		expiresAtDB = sql.NullTime{Time: exp, Valid: true}
	}

	if err := h.queries.CreateAPIKeyForUser(r.Context(), db.CreateAPIKeyForUserParams{
		ID:        id,
		UserID:    userID,
		Name:      req.Name,
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		ExpiresAt: expiresAtDB,
		CreatedAt: sql.NullTime{Time: now, Valid: true},
	}); err != nil {
		logError(r, "apikeys.create: insert failed", "error", err)
		writeInternalError(w, r, "failed to create API key")
		return
	}

	LogActivityFromRequest(h.queries, r, "api_key.create", fmt.Sprintf("API key created: %s", req.Name))

	writeJSON(w, http.StatusCreated, apiKeyCreateResponse{
		ID:        id,
		Name:      req.Name,
		Key:       fullKey,
		KeyPrefix: keyPrefix,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
	})
}

// Delete handles DELETE /api/api-keys/{keyId} and revokes a key owned by the
// authenticated user.
func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "not authenticated")
		return
	}

	keyID := chi.URLParam(r, "keyId")
	result, err := h.queries.DeleteAPIKey(r.Context(), db.DeleteAPIKeyParams{
		ID:     keyID,
		UserID: userID,
	})
	if err != nil {
		logError(r, "apikeys.delete: delete failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		writeNotFound(w, r, "API key not found")
		return
	}

	LogActivityFromRequest(h.queries, r, "api_key.delete", fmt.Sprintf("API key deleted: %s", keyID))
	w.WriteHeader(http.StatusNoContent)
}

// --- Admin incident response -------------------------------------------------
//
// A leaked key belonging to someone else has to be killable without waiting for
// that person to log in, and vault_only users cannot reach the settings UI at
// all. These handlers are wired under the admin route group; the IsAdmin check
// is repeated here as defense in depth so a future re-wire cannot silently
// expose another user's keys.

// AdminList handles GET /api/admin/users/{id}/api-keys and returns the target
// user's keys (prefixes only, never the secret), including revoked ones.
func (h *APIKeyHandler) AdminList(w http.ResponseWriter, r *http.Request) {
	if !middleware.IsAdmin(r.Context()) {
		writeForbidden(w, r, "admin access required")
		return
	}

	targetID := chi.URLParam(r, "id")
	rows, err := h.queries.ListAPIKeysByUser(r.Context(), targetID)
	if err != nil {
		logError(r, "apikeys.admin_list: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, apiKeyResponses(rows))
}

// AdminRevoke handles POST /api/admin/users/{id}/api-keys/{keyId}/revoke and
// revokes one key belonging to the target user. Revoking rather than deleting
// keeps the row for the audit trail. Idempotent: revoking an already-revoked
// key succeeds without moving its timestamp.
func (h *APIKeyHandler) AdminRevoke(w http.ResponseWriter, r *http.Request) {
	if !middleware.IsAdmin(r.Context()) {
		writeForbidden(w, r, "admin access required")
		return
	}

	targetID := chi.URLParam(r, "id")
	keyID := chi.URLParam(r, "keyId")
	result, err := h.queries.RevokeAPIKey(r.Context(), db.RevokeAPIKeyParams{
		ID:     keyID,
		UserID: targetID,
	})
	if err != nil {
		logError(r, "apikeys.admin_revoke: revoke failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		writeNotFound(w, r, "API key not found")
		return
	}

	LogActivityFromRequest(h.queries, r, "admin.api_key_revoked",
		fmt.Sprintf("API key %s revoked for user %s", keyID, targetID))
	w.WriteHeader(http.StatusNoContent)
}

// AdminRevokeAll handles POST /api/admin/users/{id}/api-keys/revoke-all and
// cuts off every live key for the target user in one step, which is what an
// admin actually needs when an account is compromised.
func (h *APIKeyHandler) AdminRevokeAll(w http.ResponseWriter, r *http.Request) {
	if !middleware.IsAdmin(r.Context()) {
		writeForbidden(w, r, "admin access required")
		return
	}

	targetID := chi.URLParam(r, "id")
	if err := h.queries.RevokeAPIKeysByUser(r.Context(), targetID); err != nil {
		logError(r, "apikeys.admin_revoke_all: revoke failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	LogActivityFromRequest(h.queries, r, "admin.api_keys_revoked",
		fmt.Sprintf("All API keys revoked for user %s", targetID))
	w.WriteHeader(http.StatusNoContent)
}

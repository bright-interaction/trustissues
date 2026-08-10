// service_secrets.go: scope-limited fetch-on-boot for production
// services. Each service runs an entrypoint that reads its dedicated
// trustissues API key from /etc/<svc>/trustissues.key (mode 400 root),
// POSTs to /api/service-identities/me/secrets with that key in
// X-Service-Key, and writes the response body to /run/<svc>/secrets.env
// (tmpfs). The service binary then reads /run/<svc>/secrets.env as
// its env file. Net: real secrets never persist to disk on the host.

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
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// ServiceSecretsHandler exposes these endpoints:
//   - POST /api/service-identities/me/secrets     (service-key auth, fetches own scope)
//   - POST /api/service-identities                (admin only, mints a new identity)
//   - GET  /api/service-identities                (admin only, lists identities)
//   - POST /api/service-identities/{id}/revoke    (admin only, sets revoked_at)
//   - DELETE /api/service-identities/{id}         (admin only, hard delete)
//   - GET  /api/service-identities/{id}/audit     (admin only, fetch history)
type ServiceSecretsHandler struct {
	queries *db.Queries
	vault   entrySecretSource
}

// NewServiceSecretsHandler constructs the handler. vault is the vault handler:
// the source of OPAQUE entry secrets, not the instance-config decrypter this
// used to take.
func NewServiceSecretsHandler(queries *db.Queries, vault entrySecretSource) *ServiceSecretsHandler {
	return &ServiceSecretsHandler{queries: queries, vault: vault}
}

// ServiceKeyPrefix is the leading marker on service-identity API keys
// so audit logs can distinguish them from user API keys (ti_) at a
// glance.
const ServiceKeyPrefix = "sk_"

// ============================================================================
// Service-side endpoint: fetch own allowed secrets
// ============================================================================

type fetchSecretsResponse struct {
	Secrets   map[string]string `json:"secrets"`
	FetchedAt string            `json:"fetched_at"`
}

// FetchOwnSecrets handles POST /api/service-identities/me/secrets. Returns the
// plaintext values for every secret in the calling service's
// allowed_secrets whitelist. Authentication is via X-Service-Key.
//
// This is the only trustissues endpoint that returns plaintext vault
// values in bulk. The response is meant to land in tmpfs (RAM-only) on
// the service host and never persist to disk.
func (h *ServiceSecretsHandler) FetchOwnSecrets(w http.ResponseWriter, r *http.Request) {
	remoteIP := requestRemoteIP(r)
	rawKey := r.Header.Get("X-Service-Key")
	if rawKey == "" {
		h.audit("", "", "invalid_key", nil, "missing X-Service-Key header", remoteIP)
		writeUnauthorized(w, r, "X-Service-Key header required")
		return
	}

	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	identity, err := h.queries.GetServiceIdentityByKeyHash(r.Context(), keyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			h.audit("", "", "invalid_key", nil, "no matching service identity", remoteIP)
			writeUnauthorized(w, r, "invalid service key")
			return
		}
		slog.Error("service_secrets: identity lookup failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Gate: revoked + expiry. Both are NULL columns; check Valid first.
	if identity.RevokedAt.Valid {
		h.audit(identity.ID, identity.Name, "revoked", nil, "key revoked", remoteIP)
		writeUnauthorized(w, r, "service key revoked")
		return
	}
	if identity.ExpiresAt.Valid && time.Now().After(identity.ExpiresAt.Time) {
		h.audit(identity.ID, identity.Name, "denied", nil, "key expired", remoteIP)
		writeUnauthorized(w, r, "service key expired")
		return
	}
	// Fail closed on a null-owner identity: without an owner we cannot
	// scope the secret fetch, and a name-only lookup would cross entry
	// owners.
	if !identity.CreatedByUserID.Valid || identity.CreatedByUserID.String == "" {
		h.audit(identity.ID, identity.Name, "denied", nil, "identity has no owner; cannot scope secret fetch", remoteIP)
		writeUnauthorized(w, r, "service identity is not owner-scoped; re-provision it")
		return
	}
	// The owner's account must still be live. This route resolves every secret
	// as CreatedByUserID, so without this check a service key outlives its
	// owner: disabling AND deleting the minting admin both left the key
	// returning their personal secrets in plaintext, including values rotated
	// after they left. revoked_at stayed NULL, so nothing in the UI showed it.
	//
	// This is the same property as the collection-removal, rotation-delivery
	// and capability-minting fixes, reached through a fourth door. It needs its
	// own check because this route never touches entryAccessFor (where round 4
	// put the equivalent gate) and never passes through the auth middleware
	// that rejects disabled users for session and API-key requests.
	owner, ownerErr := h.queries.GetUserByID(r.Context(), identity.CreatedByUserID.String)
	if ownerErr != nil || owner.Disabled != 0 {
		reason := "owner account is disabled"
		if ownerErr != nil {
			reason = "owner account no longer exists"
		}
		h.audit(identity.ID, identity.Name, "denied", nil, reason, remoteIP)
		writeUnauthorized(w, r, "service key owner is no longer active; re-provision this identity")
		return
	}

	// Parse the allowed_secrets whitelist.
	var allowed []string
	if err := json.Unmarshal([]byte(identity.AllowedSecrets), &allowed); err != nil {
		slog.Error("service_secrets: allowed_secrets JSON malformed",
			"service", identity.Name, "error", err)
		h.audit(identity.ID, identity.Name, "denied", nil, "allowed_secrets parse failed", remoteIP)
		writeInternalError(w, r, "service identity is misconfigured")
		return
	}
	if len(allowed) == 0 {
		h.audit(identity.ID, identity.Name, "denied", nil, "empty whitelist", remoteIP)
		writeBadRequest(w, r, "service has no allowed_secrets configured")
		return
	}

	// Resolve each name -> encrypted entry -> plaintext. Missing names
	// are silently skipped in the response BUT logged in the audit row
	// so operators can see "service asked for X but vault has no X".
	secrets := make(map[string]string, len(allowed))
	missing := make([]string, 0)
	// The deferred wipe that used to live here is gone, and this note is what
	// replaces it. It walked a `plaintexts [][]byte` slice that round 7 stopped
	// appending to when the decrypt started returning an opaque type, so it was a
	// loop over an always-empty slice under a comment describing a protection
	// that no longer happened there. Dead code claiming a security property is
	// worse than no code: the next reader takes the claim at face value.
	//
	// The wipe is now pt.Wipe() at the point of use below, which is strictly
	// better (immediately after the value is taken, not after the response is
	// written). What still cannot be wiped is the string copies in `secrets`, and
	// that was true before too.
	for _, name := range allowed {
		row, qerr := h.queries.GetVaultEntryForServiceFetch(r.Context(), db.GetVaultEntryForServiceFetchParams{
			Name:   name,
			UserID: identity.CreatedByUserID.String,
		})
		if qerr != nil {
			if qerr == sql.ErrNoRows {
				missing = append(missing, name)
				continue
			}
			slog.Error("service_secrets: vault lookup failed",
				"service", identity.Name, "name", name, "error", qerr)
			h.audit(identity.ID, identity.Name, "denied", nil, "vault lookup failed: "+qerr.Error(), remoteIP)
			writeInternalError(w, r, "vault lookup failed")
			return
		}

		// Decrypt. Encryption version handled by DecryptValue (v1 SHA-256
		// legacy, v2 PBKDF2 current). nonce + encrypted_value are []byte
		// in the row.
		encVersion := 2
		if row.EncryptionVersion.Valid {
			encVersion = int(row.EncryptionVersion.Int64)
		}
		pt, derr := h.vault.OpenEntrySecret(row.EncryptedValue, row.Nonce, encVersion,
			secretexit.Origin{EntryID: row.ID, Name: name})
		if derr != nil {
			slog.Error("service_secrets: decrypt failed",
				"service", identity.Name, "name", name, "error", derr)
			h.audit(identity.ID, identity.Name, "denied", nil, "decrypt failed for "+name, remoteIP)
			writeInternalError(w, r, "decrypt failed")
			return
		}
		// THE ONE EXIT, caller form. A service identity is a machine principal
		// minted by an admin and bound to the user who created it, so the read
		// question is asked about that user. The allowed_secrets list above says
		// which NAMES this identity may ask for; the exit says whether the
		// entry's owner admits the principal behind it.
		_, value, exitErr := secretexit.ExitString(r.Context(), pt,
			secretexit.ToCaller("POST /api/service/secrets", identity.CreatedByUserID.String))
		pt.Wipe()
		if exitErr != nil {
			slog.Error("service_secrets: the entry's owner did not authorise this fetch",
				"service", identity.Name, "name", name, "error", exitErr)
			h.audit(identity.ID, identity.Name, "denied", nil, "egress refused for "+name, remoteIP)
			writeError(w, r, http.StatusForbidden, "destination_not_authorized",
				"one of the requested secrets is not released to this service identity")
			return
		}
		secrets[name] = value
	}

	// Touch last_used_at (fire-and-forget; failure here is not fatal).
	if err := h.queries.TouchServiceIdentityLastUsed(r.Context(), identity.ID); err != nil {
		slog.Warn("service_secrets: last_used_at touch failed",
			"service", identity.Name, "error", err)
	}

	// Audit the success with the actual names returned (NOT values).
	returnedNames := make([]string, 0, len(secrets))
	for n := range secrets {
		returnedNames = append(returnedNames, n)
	}
	auditErr := ""
	if len(missing) > 0 {
		auditErr = "missing names: " + strings.Join(missing, ",")
	}
	h.audit(identity.ID, identity.Name, "fetch", returnedNames, auditErr, remoteIP)

	writeJSON(w, http.StatusOK, fetchSecretsResponse{
		Secrets:   secrets,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// ============================================================================
// Admin endpoint: mint a new service identity
// ============================================================================

type createServiceIdentityRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	AllowedSecrets []string `json:"allowed_secrets"`
	ExpiresInDays  int      `json:"expires_in_days"`
}

type serviceIdentityListResponse struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	AllowedSecrets []string `json:"allowed_secrets"`
	KeyPrefix      string   `json:"key_prefix"`
	LastUsedAt     *string  `json:"last_used_at"`
	ExpiresAt      *string  `json:"expires_at"`
	RevokedAt      *string  `json:"revoked_at"`
	CreatedAt      string   `json:"created_at"`
}

type serviceIdentityCreateResponse struct {
	serviceIdentityListResponse
	Key string `json:"key"`
}

// CreateServiceIdentity handles POST /api/service-identities. Admin only.
// Returns the freshly minted plaintext key ONCE (caller must store it
// immediately; no recovery path).
func (h *ServiceSecretsHandler) CreateServiceIdentity(w http.ResponseWriter, r *http.Request) {
	if !middleware.IsAdmin(r.Context()) {
		writeForbidden(w, r, "admin access required")
		return
	}
	userID := middleware.GetUserID(r.Context())

	var req createServiceIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}
	if req.Name == "" {
		writeBadRequest(w, r, "name is required")
		return
	}
	if len(req.AllowedSecrets) == 0 {
		writeBadRequest(w, r, "allowed_secrets must not be empty")
		return
	}

	// Generate ID (16 random bytes -> 32 hex) and key (32 random bytes -> 64 hex).
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		writeInternalError(w, r, "failed to generate id")
		return
	}
	id := hex.EncodeToString(idBytes)

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		writeInternalError(w, r, "failed to generate key")
		return
	}
	rawKey := hex.EncodeToString(keyBytes)
	fullKey := ServiceKeyPrefix + rawKey

	hash := sha256.Sum256([]byte(fullKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := rawKey[:8]

	allowedJSON, err := json.Marshal(req.AllowedSecrets)
	if err != nil {
		writeInternalError(w, r, "failed to encode allowed_secrets")
		return
	}

	var expiresAt sql.NullTime
	var expiresAtStr *string
	if req.ExpiresInDays > 0 {
		exp := time.Now().UTC().AddDate(0, 0, req.ExpiresInDays)
		expiresAt = sql.NullTime{Time: exp, Valid: true}
		s := exp.Format(time.RFC3339)
		expiresAtStr = &s
	}

	if err := h.queries.CreateServiceIdentity(r.Context(), db.CreateServiceIdentityParams{
		ID:              id,
		Name:            req.Name,
		Description:     req.Description,
		AllowedSecrets:  string(allowedJSON),
		KeyHash:         keyHash,
		KeyPrefix:       keyPrefix,
		ExpiresAt:       expiresAt,
		CreatedByUserID: sql.NullString{String: userID, Valid: userID != ""},
	}); err != nil {
		// Unique violation on name -> 409.
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "unique") {
			writeConflict(w, r, "service identity name already in use")
			return
		}
		slog.Error("service_secrets: create failed", "name", req.Name, "error", err)
		writeInternalError(w, r, "failed to create service identity")
		return
	}

	// Activity-log the mint (actor from request context, target identity,
	// event). The plaintext key is NEVER logged; only name + id + scope size.
	LogActivityFromRequest(h.queries, r, "service_identity.created",
		fmt.Sprintf("Service identity minted: %s (id: %s, allowed_secrets: %d)", req.Name, id, len(req.AllowedSecrets)))

	now := time.Now().UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusCreated, serviceIdentityCreateResponse{
		serviceIdentityListResponse: serviceIdentityListResponse{
			ID:             id,
			Name:           req.Name,
			Description:    req.Description,
			AllowedSecrets: req.AllowedSecrets,
			KeyPrefix:      keyPrefix,
			ExpiresAt:      expiresAtStr,
			CreatedAt:      now,
		},
		Key: fullKey,
	})
}

// ListServiceIdentities handles GET /api/service-identities. Admin only.
func (h *ServiceSecretsHandler) ListServiceIdentities(w http.ResponseWriter, r *http.Request) {
	if !middleware.IsAdmin(r.Context()) {
		writeForbidden(w, r, "admin access required")
		return
	}
	rows, err := h.queries.ListServiceIdentities(r.Context())
	if err != nil {
		slog.Error("service_secrets: list failed", "error", err)
		writeInternalError(w, r, "list failed")
		return
	}
	out := make([]serviceIdentityListResponse, 0, len(rows))
	for _, row := range rows {
		var allowed []string
		_ = json.Unmarshal([]byte(row.AllowedSecrets), &allowed)
		entry := serviceIdentityListResponse{
			ID:             row.ID,
			Name:           row.Name,
			Description:    row.Description,
			AllowedSecrets: allowed,
			KeyPrefix:      row.KeyPrefix,
			CreatedAt:      row.CreatedAt.Format(time.RFC3339),
		}
		if row.LastUsedAt.Valid {
			s := row.LastUsedAt.Time.Format(time.RFC3339)
			entry.LastUsedAt = &s
		}
		if row.ExpiresAt.Valid {
			s := row.ExpiresAt.Time.Format(time.RFC3339)
			entry.ExpiresAt = &s
		}
		if row.RevokedAt.Valid {
			s := row.RevokedAt.Time.Format(time.RFC3339)
			entry.RevokedAt = &s
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, out)
}

// RevokeServiceIdentity handles POST /api/service-identities/{id}/revoke.
// Admin only. Sets revoked_at on the row; subsequent FetchOwnSecrets
// calls with that key return 401. Idempotent in the "already revoked"
// sense: a second call returns 409 because the UPDATE filters on
// revoked_at IS NULL.
func (h *ServiceSecretsHandler) RevokeServiceIdentity(w http.ResponseWriter, r *http.Request) {
	if !middleware.IsAdmin(r.Context()) {
		writeForbidden(w, r, "admin access required")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeBadRequest(w, r, "id is required")
		return
	}

	identity, err := h.queries.GetServiceIdentityByID(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeNotFound(w, r, "service identity not found")
			return
		}
		slog.Error("service_secrets: revoke lookup failed", "id", id, "error", err)
		writeInternalError(w, r, "lookup failed")
		return
	}

	res, err := h.queries.RevokeServiceIdentity(r.Context(), id)
	if err != nil {
		slog.Error("service_secrets: revoke failed", "id", id, "error", err)
		writeInternalError(w, r, "revoke failed")
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		// Row exists (lookup succeeded) but revoked_at IS NULL filter
		// matched zero rows -> already revoked.
		writeConflict(w, r, "service identity already revoked")
		return
	}

	h.audit(id, identity.Name, "admin_revoked", nil, "", requestRemoteIP(r))
	LogActivityFromRequest(h.queries, r, "service_identity.revoked",
		fmt.Sprintf("Service identity revoked: %s (id: %s)", identity.Name, id))
	w.WriteHeader(http.StatusNoContent)
}

// DeleteServiceIdentity handles DELETE /api/service-identities/{id}.
// Admin only. Hard-deletes the row. Audit history rows in
// service_secret_audit retain service_identity_id as a dangling
// reference (no FK ON DELETE CASCADE) which is intentional: revocation
// records must survive identity deletion.
func (h *ServiceSecretsHandler) DeleteServiceIdentity(w http.ResponseWriter, r *http.Request) {
	if !middleware.IsAdmin(r.Context()) {
		writeForbidden(w, r, "admin access required")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeBadRequest(w, r, "id is required")
		return
	}

	identity, err := h.queries.GetServiceIdentityByID(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeNotFound(w, r, "service identity not found")
			return
		}
		slog.Error("service_secrets: delete lookup failed", "id", id, "error", err)
		writeInternalError(w, r, "lookup failed")
		return
	}

	res, err := h.queries.DeleteServiceIdentity(r.Context(), id)
	if err != nil {
		slog.Error("service_secrets: delete failed", "id", id, "error", err)
		writeInternalError(w, r, "delete failed")
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		writeNotFound(w, r, "service identity not found")
		return
	}

	h.audit(id, identity.Name, "admin_deleted", nil, "", requestRemoteIP(r))
	w.WriteHeader(http.StatusNoContent)
}

type auditEntryResponse struct {
	ID          string   `json:"id"`
	Event       string   `json:"event"`
	ServiceName string   `json:"service_name"`
	SecretNames []string `json:"secret_names"`
	Error       string   `json:"error,omitempty"`
	RemoteIP    string   `json:"remote_ip,omitempty"`
	OccurredAt  string   `json:"occurred_at"`
}

// GetServiceIdentityAudit handles GET /api/service-identities/{id}/audit.
// Admin only. Returns the most recent audit entries for the given
// identity (default 100, capped at 500 via the limit query param).
// Useful for forensics: "did this key ever fetch X?" and "when was the
// last successful fetch?". Audit rows survive identity deletion so
// querying a deleted identity's history still works as long as the
// caller holds the id.
func (h *ServiceSecretsHandler) GetServiceIdentityAudit(w http.ResponseWriter, r *http.Request) {
	if !middleware.IsAdmin(r.Context()) {
		writeForbidden(w, r, "admin access required")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeBadRequest(w, r, "id is required")
		return
	}

	limit := int64(100)
	if v := r.URL.Query().Get("limit"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil || parsed <= 0 {
			writeBadRequest(w, r, "limit must be a positive integer")
			return
		}
		if parsed > 500 {
			parsed = 500
		}
		limit = parsed
	}

	rows, err := h.queries.ListAuditForServiceIdentity(r.Context(), db.ListAuditForServiceIdentityParams{
		ServiceIdentityID: sql.NullString{String: id, Valid: true},
		Limit:             limit,
	})
	if err != nil {
		slog.Error("service_secrets: audit list failed", "id", id, "error", err)
		writeInternalError(w, r, "audit list failed")
		return
	}

	out := make([]auditEntryResponse, 0, len(rows))
	for _, row := range rows {
		var names []string
		_ = json.Unmarshal([]byte(row.SecretNames), &names)
		out = append(out, auditEntryResponse{
			ID:          row.ID,
			Event:       row.Event,
			ServiceName: row.ServiceName,
			SecretNames: names,
			Error:       row.Error,
			RemoteIP:    row.RemoteIp,
			OccurredAt:  row.OccurredAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// ============================================================================
// Helpers
// ============================================================================

// audit writes a service_secret_audit row. Fire-and-forget; failures
// are logged but never bubble up to break the caller's flow (the
// alternative would be to deny a legitimate fetch because the audit
// table had a hiccup, which is worse than missing one audit row).
func (h *ServiceSecretsHandler) audit(identityID, serviceName, event string, names []string, errMsg, remoteIP string) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return
	}
	id := hex.EncodeToString(idBytes)
	// A nil slice marshals to the literal `null`, not to `[]`, so the existing
	// guard never fired: every denial with no requested names stored "null" in a
	// column whose own DEFAULT and doc comment say "[]". Harmless to a reader
	// that unmarshals into a slice, and wrong to anybody reading the table.
	if names == nil {
		names = []string{}
	}
	namesJSON, _ := json.Marshal(names)
	if len(namesJSON) == 0 {
		namesJSON = []byte("[]")
	}
	var identityIDArg sql.NullString
	if identityID != "" {
		identityIDArg = sql.NullString{String: identityID, Valid: true}
	}
	ctx := context.Background()
	// The WHOLE JSON array is sealed, not each element. Sealing per element would
	// leave the array structure in the clear, so a reader still learns how many
	// secrets a service pulled in one fetch; that count is itself a useful signal
	// about a deployment. An empty list is left alone: "[]" says a name was never
	// recorded, which is true and reveals nothing.
	sealedNames := string(namesJSON)
	if len(names) > 0 {
		sealedNames = h.vault.SealAuditName(ctx, sealedNames)
	}
	if err := h.queries.InsertServiceSecretAudit(ctx, db.InsertServiceSecretAuditParams{
		ID:                id,
		ServiceIdentityID: identityIDArg,
		ServiceName:       serviceName,
		Event:             event,
		SecretNames:       sealedNames,
		Error:             errMsg,
		RemoteIp:          remoteIP,
	}); err != nil {
		slog.Warn("service_secrets: audit insert failed", "event", event, "error", err)
	}
}

// requestRemoteIP returns the client IP for the service-secret audit row.
//
// It delegates to middleware.ClientIP, which is THE single client-IP derivation
// for the whole codebase. This used to be a second implementation, which is
// precisely what rate_limit.go's doc warns against: "a second implementation
// that trusts the leftmost X-Forwarded-For entry (or X-Real-IP unconditionally)
// lets an attacker reset their own throttle bucket and write a forged source IP
// into the audit trail."
//
// This one took the rightmost XFF entry with NO trusted-peer gate, so unlike
// ClientIP it honoured a forwarded header even when TRUSTISSUES_TRUSTED_PROXY_HOPS
// is 0 or the socket peer is a public address. A caller reaching the server
// directly could therefore choose the IP recorded against their own
// service-secret access, which is the one column that trail exists to hold.
//
// Keeping the shim rather than inlining the call: it is the name the audit
// writers already use, and a single definition is what stops a third derivation
// appearing next to it.
func requestRemoteIP(r *http.Request) string {
	return middleware.ClientIP(r)
}

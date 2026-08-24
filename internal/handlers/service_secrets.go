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
	"crypto/subtle"
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

	// A service identity has no human to enrol, so it inherits the owner's
	// enrolment status: while require_totp is on, this fetch is refused for
	// every identity whose owner has not enrolled TOTP, exactly as it already
	// is for that owner's own session and X-API-Key requests.
	//
	// This route sits OUTSIDE the session-auth group by design (fetch-on-boot
	// has no cookie and no session), so RequireTOTPEnrollment never runs on
	// it and cannot be moved to cover it -- see the route comment in
	// cmd/server/main.go. Without an equivalent check here, X-Service-Key was
	// a standing, silent exemption from a policy whose UI reads "2FA required
	// for all users": exactly the credential-class exemption this codebase
	// already withdrew once for API keys (see RequireTOTPEnrollment's doc
	// comment). The difference from that withdrawal is that a service
	// identity cannot enrol on its own behalf, so the fix is not "gate it
	// like a session" but "bind it to the human who can act": the owner
	// enrols, every identity they created starts working again, with no
	// separate revalidation step and nothing for an admin to remember to
	// re-run.
	//
	// This CAN refuse a service container that was working a minute ago, if
	// an admin flips require_totp while the owner has not enrolled. That is
	// deliberate and must be loud: the response carries the same
	// machine-readable code the session/API-key gate uses (so an operator
	// grepping logs for totp_enrollment_required finds every affected
	// caller, not two different strings for the same condition), the audit
	// row and the log line both name the owner so the on-call knows whose
	// enrolment unblocks it, and ListServiceIdentities now reports each
	// identity's owner enrolment status so an admin can see every identity
	// this will affect BEFORE turning the policy on, not after a boot fails.
	if settingBool(r.Context(), h.queries, "require_totp", false) && owner.TotpEnabled.Int64 != 1 {
		reason := fmt.Sprintf(
			"vault policy requires two-factor authentication for all users; owner %s has not enrolled",
			identity.CreatedByUserID.String)
		slog.Warn("service_secrets: fetch refused, owner has not enrolled TOTP under require_totp policy",
			"service", identity.Name, "identity_id", identity.ID,
			"owner_user_id", identity.CreatedByUserID.String)
		h.audit(identity.ID, identity.Name, "denied", nil, reason, remoteIP)
		writeError(w, r, http.StatusForbidden, middleware.TOTPEnrollmentRequiredCode,
			"service identity owner has not enrolled two-factor authentication, which the vault "+
				"policy now requires; the owner must enrol to restore this identity's access")
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

	// Resolve each name -> encrypted entry -> plaintext.
	//
	// THE NAME IS MATCHED IN GO, NOT IN SQL, and it had to move. Since 00040
	// vault_entries.name holds randomized AES-GCM ciphertext, so the old
	// `WHERE name = ?` compared this whitelist's cleartext against a blob and
	// missed on every row of every fetch. The query below keeps BOTH
	// authorization predicates (the owning user, and personal entries only) and
	// drops only the name, which is not one of them.
	secrets := make(map[string]string, len(allowed))
	missing := make([]string, 0)
	rows, qerr := h.queries.ListPersonalVaultEntriesForServiceFetch(
		r.Context(), identity.CreatedByUserID.String)
	if qerr != nil {
		slog.Error("service_secrets: vault lookup failed",
			"service", identity.Name, "error", qerr)
		h.audit(identity.ID, identity.Name, "denied", nil, "vault lookup failed: "+qerr.Error(), remoteIP)
		writeInternalError(w, r, "vault lookup failed")
		return
	}
	// Open every candidate name once, up front, rather than per whitelist
	// entry. EntryNamePlain returns an UNSEALED value unchanged, which is what
	// keeps the rows the boot sweep deliberately leaves cleartext with an empty
	// name_bidx (see the UNIQUE-collision branch in vault.go) resolving here
	// forever. A name_bidx lookup would strand exactly those rows in silence.
	plainNames := make([]string, len(rows))
	for i := range rows {
		plainNames[i] = h.vault.EntryNamePlain(rows[i].Name)
	}
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
		idx, ambiguous := matchEntryName(plainNames, name)
		if ambiguous {
			// Two of this user's personal entries now open to the same name.
			// UNIQUE(user_id, name) went vacuous at 00040 (randomized
			// ciphertext never collides) and the blind index that replaced it
			// is empty on every row the boot sweep skipped, so this is
			// reachable. Handing a machine identity "whichever row SQLite
			// returned first" is the defect lookupSecretByName was changed to
			// refuse; refuse it here too rather than resolve it by luck.
			slog.Error("service_secrets: whitelisted name matches more than one personal entry",
				"service", identity.Name, "owner", identity.CreatedByUserID.String)
			// THE NAME GOES IN secret_names, WHICH IS SEALED. It used to be
			// concatenated into the error column, which h.audit does not touch
			// and 00021 gives no crypto, in an append-only table: a permanent
			// cleartext copy of an entry name sitting beside the encrypted
			// inventory it describes, out of the same stolen file
			// audit_name_crypto.go exists to defend against. secret_names is
			// documented at 00021:45 as "secrets returned (success) or requested
			// (denied)", and this denial is exactly the second case.
			h.audit(identity.ID, identity.Name, "denied", []string{name},
				"a requested name matches more than one entry", remoteIP)
			writeError(w, r, http.StatusConflict, "ambiguous_secret_name",
				"one of the requested secrets matches more than one entry; rename one of them")
			return
		}
		if idx < 0 {
			missing = append(missing, name)
			continue
		}
		row := rows[idx]

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
			h.audit(identity.ID, identity.Name, "denied", []string{name}, "decrypt failed", remoteIP)
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
			h.audit(identity.ID, identity.Name, "denied", []string{name}, "egress refused", remoteIP)
			writeError(w, r, http.StatusForbidden, "destination_not_authorized",
				"one of the requested secrets is not released to this service identity")
			return
		}
		secrets[name] = value
	}

	// A MISS IS NOT A SUCCESS.
	//
	// This used to skip missing names, answer 200 with whatever it had, and
	// audit the whole request under "fetch", the SUCCESS verb, with the misses
	// recorded only in the audit row's error column. Together with the
	// ciphertext-versus-cleartext lookup fixed above, that meant every fetch
	// since 00040 returned 200 {"secrets":{}} and wrote a green audit row: the
	// service container booted with no credentials at all, and neither the
	// response nor the trail said anything had gone wrong.
	//
	// allowed_secrets is the contract an admin wrote for this identity. A name
	// in it the vault cannot resolve is an unfulfillable boot whether it is one
	// name or all of them, so the fetch is refused rather than partially
	// served, and the audit verb is the DENIAL one.
	//
	// The missing names go in the audit row's SEALED secret_names column, where
	// the operator who can fix the whitelist looks and where a keyless reader of
	// the database file cannot. They are deliberately not echoed to the caller:
	// the response now carries no per-name existence information at all, which
	// is strictly less than the partial map it replaces (whose keys told the
	// caller exactly which of its names the vault held).
	if len(missing) > 0 {
		slog.Error("service_secrets: whitelisted secrets do not resolve; refusing the fetch",
			"service", identity.Name, "missing_count", len(missing))
		h.audit(identity.ID, identity.Name, "denied", missing,
			"one or more requested names did not resolve", remoteIP)
		writeError(w, r, http.StatusNotFound, "secret_not_found",
			"one or more of this identity's allowed_secrets does not resolve; "+
				"the fetch is refused rather than serving a partial set")
		return
	}

	// Touch last_used_at (fire-and-forget; failure here is not fatal).
	if err := h.queries.TouchServiceIdentityLastUsed(r.Context(), identity.ID); err != nil {
		slog.Warn("service_secrets: last_used_at touch failed",
			"service", identity.Name, "error", err)
	}

	// Audit the success with the actual names returned (NOT values). Reaching
	// here means every whitelisted name resolved, so "fetch" is honest.
	returnedNames := make([]string, 0, len(secrets))
	for n := range secrets {
		returnedNames = append(returnedNames, n)
	}
	h.audit(identity.ID, identity.Name, "fetch", returnedNames, "", remoteIP)

	writeJSON(w, http.StatusOK, fetchSecretsResponse{
		Secrets:   secrets,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// matchEntryName finds the ONE candidate whose opened name equals want, where
// candidates are the decrypted names of the rows a scoped query already
// authorized. It returns the index, or -1 with ambiguous=false for no match.
//
// It scans every candidate and never stops at the first hit, and it compares
// with crypto/subtle rather than ==. A vault entry NAME is secret-adjacent
// material: 00040 encrypts it precisely so that a keyless reader learns neither
// the inventory nor its contents, and "Stripe live key" is most of what an
// attacker wants to know. So the loop must not run for a length that depends on
// where the match sits, nor on how many leading bytes of a near-miss matched.
// Name LENGTH is still observable, from the ciphertext length as much as from
// here, and that is unchanged by this function.
//
// It reports ambiguity instead of picking a winner. UNIQUE(user_id, name) went
// vacuous at 00040 (randomized ciphertext never collides) and the blind index
// that replaced it is empty on every row the boot sweep skipped, so one user
// really can hold two personal entries with the same name. Resolving that by
// row order is how a machine identity silently receives the wrong credential.
//
// AN EMPTY STRING IS NOT A NAME, ON EITHER SIDE, and that is not a style
// preference. subtle.ConstantTimeCompare returns 1 for TWO ZERO-LENGTH slices:
// it short-circuits only on a length MISMATCH, so two empty inputs fall through
// the loop with v still 0 and compare EQUAL. Every candidate here is
// EntryNamePlain output, and EntryNamePlain returns "" for any row whose name no
// configured key opens (decryptColumnOrLog's fallback). So a whitelist entry of
// "" matched the first unopenable row, idx came back >= 0, the miss check never
// fired, and the handler decrypted and returned THAT row's value under the name
// "": the service identity received the wrong credential, with a green "fetch"
// audit row over it and the all-or-nothing 404 contract silently defeated.
//
// It gets MORE likely after a master-key rotation, not less: the name column is
// opened against current+previous only, so any row still sealed under an older
// key opens to "" here.
func matchEntryName(candidates []string, want string) (idx int, ambiguous bool) {
	// Nothing to look for. Refusing here rather than in the loop also means the
	// caller's "" reaches the miss path and the 404, which is the correct answer
	// for a whitelist entry that names nothing.
	if len(want) == 0 {
		return -1, false
	}
	found := -1
	hits := 0
	wantBytes := []byte(want)
	for i := range candidates {
		// An UNOPENED NAME IS NOT A NAME. Skipping these leaks nothing the
		// ciphertext length did not already give away, and it is what stops an
		// undecryptable row from being matchable at all.
		if len(candidates[i]) == 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidates[i]), wantBytes) == 1 {
			hits++
			if found < 0 {
				found = i
			}
		}
	}
	if hits > 1 {
		return -1, true
	}
	return found, false
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
	// OwnerEmail and OwnerTOTPEnabled let an admin see, from the list they
	// already use to manage service identities, which ones FetchOwnSecrets
	// will start refusing the moment require_totp is turned on: every
	// identity whose OwnerTOTPEnabled is false. No omitempty on the bool:
	// this codebase already has a documented latent trap where omitempty on
	// a status flag silently drops the `false` case, which is exactly the
	// value that matters here.
	OwnerEmail       *string `json:"owner_email"`
	OwnerTOTPEnabled bool    `json:"owner_totp_enabled"`
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
	// A NON-EMPTY ARRAY OF EMPTY NAMES IS NOT A WHITELIST. This validated only
	// the array's length, so `["" ]` minted an identity whose contract named
	// nothing, and matchEntryName then had to be the thing that refused it. It
	// does refuse it now, but a name that can never resolve has no business
	// being written into allowed_secrets in the first place: the fetch path is
	// the wrong place to discover that an admin's contract was malformed.
	// Whitespace counts as empty for the same reason it does everywhere a name
	// is compared: " X" and "X" are different keys here and the same intent.
	for _, n := range req.AllowedSecrets {
		if strings.TrimSpace(n) == "" {
			writeBadRequest(w, r, "allowed_secrets must not contain empty names")
			return
		}
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
			ID:               row.ID,
			Name:             row.Name,
			Description:      row.Description,
			AllowedSecrets:   allowed,
			KeyPrefix:        row.KeyPrefix,
			CreatedAt:        row.CreatedAt.Format(time.RFC3339),
			OwnerTOTPEnabled: row.OwnerTotpEnabled,
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
		if row.OwnerEmail.Valid {
			s := row.OwnerEmail.String
			entry.OwnerEmail = &s
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
		// Opened here and nowhere else, exactly as capability_audit_read.go does
		// for its twin column.
		//
		// This used to be a bare json.Unmarshal of the STORED value with the
		// error discarded into `_`. Since the seal landed the stored value is
		// `enc:v1:<base64>`, which is not JSON, so the unmarshal failed on every
		// row of every read and the response shipped "secret_names": null. The
		// trail was WRITE-ONLY: a name was sealed into an append-only table and
		// nothing in the product could show it back. That is not
		// confidentiality, it is a table nobody can consult -- the same defect
		// capability_log had before OpenAuditName was added to the interface for
		// precisely this reason.
		names := decodeAuditSecretNames(h.vault.OpenAuditName(r.Context(), row.SecretNames))
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

// decodeAuditSecretNames turns an OPENED service_secret_audit.secret_names value
// into the list the operator sees.
//
// The column holds the WHOLE JSON array sealed as one value (see h.audit for why
// it is not sealed per element), so the opened form is the array's JSON text.
// Three cases, and the marker is why this is a function rather than an inline
// unmarshal:
//
//   - "[unavailable]" is what OpenAuditName returns when the audit DEK cannot be
//     loaded or the row will not open. It is deliberately NOT the empty string,
//     because "a name was recorded and this process cannot show it" and "no name
//     was recorded" are different facts and the operator has to be able to tell
//     them apart. So it is surfaced as a name rather than swallowed into an
//     empty list, which is what the discarded-error unmarshal did to every row.
//   - Anything that will not parse as a JSON array gets the same marker, for the
//     same reason: silently returning nil here is what made this endpoint claim
//     for months that no fetch had ever named a secret.
//   - Otherwise the parsed list, normalised to non-nil so the field marshals as
//     [] rather than null.
func decodeAuditSecretNames(opened string) []string {
	if opened == "" {
		return []string{}
	}
	if opened == auditNameUnavailable {
		return []string{auditNameUnavailable}
	}
	var names []string
	if err := json.Unmarshal([]byte(opened), &names); err != nil {
		slog.Warn("service_secrets: audit secret_names did not parse after opening", "error", err)
		return []string{auditNameUnavailable}
	}
	if names == nil {
		return []string{}
	}
	return names
}

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

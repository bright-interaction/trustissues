package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/capability"
	dbpkg "github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// CapabilityHandler exposes the trustissues secrets bridge:
//
//   - POST /api/secrets/issue mints a short-lived signed capability
//     token bound to a specific destination, method, and agent.
//   - POST/GET/PUT/DELETE /proxy/{host}/{path...} consumes a token,
//     looks up the secret + injection spec, swaps in the real header,
//     forwards upstream. The model never sees the secret bytes.
//
// See internal/capability/token.go for the token format and
// internal/database/migrations/00020_capability.sql for the schema.
type CapabilityHandler struct {
	db    *sql.DB
	vault entrySecretSource
	// settings reads the ai_key_* rows that PIN an entry to one provider host.
	// See secret_egress.go: the pin is what stops an editor who can rewrite
	// destination_patterns from choosing where the operator's key is delivered.
	settings    settingReader
	signingKey  capability.SigningKey
	httpClient  *http.Client
	defaultTTL  time.Duration
	maxBodySize int64
}

// SetHTTPClient replaces the upstream HTTP client. Used by tests to
// inject one with InsecureSkipVerify for httptest.NewTLSServer; never
// called from production code.
func (h *CapabilityHandler) SetHTTPClient(c *http.Client) { h.httpClient = c }

// NewCapabilityHandler builds the bridge against a decrypter (the vault
// handler, which satisfies alerts.ConfigDecrypter) and a fresh signing
// key derived from the same source the vault uses (cfg.VaultKey), but
// via a separate HKDF context so a leak of one does not yield the other.
func NewCapabilityHandler(db *sql.DB, vault entrySecretSource, signingKeySource string) (*CapabilityHandler, error) {
	key, err := capability.DeriveSigningKey(signingKeySource)
	if err != nil {
		return nil, fmt.Errorf("capability: derive signing key: %w", err)
	}
	return &CapabilityHandler{
		db:         db,
		vault:      vault,
		settings:   dbpkg.New(db),
		signingKey: key,
		// SSRF-hardened: the proxy injects the real decrypted secret into the
		// outbound request, so the destination must never be reachable at a
		// private/metadata host (via a widened dest or a redirect). The
		// platform's guarded client refuses redirects and re-checks the
		// resolved IP at dial time.
		httpClient:  alerts.GuardedWebhookClient(60 * time.Second),
		defaultTTL:  5 * time.Minute,
		maxBodySize: 16 * 1024 * 1024, // 16 MiB; covers OpenAI streaming chunk sizes
	}, nil
}

// ──────────────────────────────────────────────────────────────────────
// /api/secrets/issue
// ──────────────────────────────────────────────────────────────────────

type issueRequest struct {
	// Either Secret (vault entry name) or auto-routing on Dest.
	Secret      string   `json:"secret,omitempty"`
	AgentID     string   `json:"agent_id"`
	Destination string   `json:"destination,omitempty"` // host+path used for auto-routing when Secret is empty
	Dests       []string `json:"dests,omitempty"`       // explicit override; defaults to per-secret patterns
	Method      string   `json:"method,omitempty"`      // defaults to "*"
	TTLSeconds  int      `json:"ttl_seconds,omitempty"` // capped at 600s; defaults to 300s
}

type issueResponse struct {
	Token       string `json:"token"`
	ProxyURL    string `json:"proxy_url"`
	Secret      string `json:"secret"`
	ExpiresAt   string `json:"expires_at"`
	NonceLength int    `json:"nonce_length"`
}

// Issue handles POST /api/secrets/issue. Auth is the same
// session/user-bearing middleware the rest of /api uses.
func (h *CapabilityHandler) Issue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.GetUserID(ctx)
	if userID == "" {
		writeUnauthorized(w, r, "authentication required")
		return
	}
	// The role check the review asked for, in the HANDLER and not only on the
	// route.
	//
	// /api/secrets and /api/mcp are mounted behind VaultOnlyBlock in
	// cmd/server/main.go and TestServerRoutesKeepTheirGuards pins that. This is
	// the second lock on the same door, and it is worth its four lines because
	// of how the first one failed: /api/ai was blocked while its sibling mint
	// route was not, so a vault_only account defeated the gateway's block by
	// minting a capability for the team key and driving /proxy with it. That was
	// a property of the ROUTER, invisible from every handler test in this
	// package. A handler that refuses on its own cannot be un-refused by moving
	// a line in main.go.
	if middleware.IsVaultOnly(ctx) {
		writeForbidden(w, r, "vault-only accounts cannot mint capability tokens; "+
			"minting spends a secret this account may use but may not redirect")
		return
	}

	var req issueRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	if req.AgentID == "" {
		writeBadRequest(w, r, "agent_id required")
		return
	}
	// Same authorization-boundary rule the proxy applies: a destination whose
	// path is not normalized would be matched against the secret's allow-list as
	// one endpoint and resolve upstream as another, so it never gets minted into
	// a token.
	if req.Destination != "" && !destPathNormalized(req.Destination) {
		writeError(w, r, http.StatusBadRequest, "invalid_destination",
			"destination path must be normalized (no '.' or '..' segments, no duplicate slashes)")
		return
	}
	for _, d := range req.Dests {
		if !destPathNormalized(d) {
			writeError(w, r, http.StatusBadRequest, "invalid_destination",
				"destination path must be normalized (no '.' or '..' segments, no duplicate slashes)")
			return
		}
	}

	var entry capabilityEntryRow
	var lookupErr error
	if req.Secret != "" {
		entry, lookupErr = h.lookupSecretByName(ctx, userID, req.Secret)
	} else if req.Destination != "" {
		entry, lookupErr = h.lookupSecretByDestination(ctx, userID, req.Destination)
	} else {
		writeBadRequest(w, r, "either secret or destination required")
		return
	}
	if errors.Is(lookupErr, sql.ErrNoRows) {
		h.logCapabilityEvent(ctx, req.AgentID, nil, req.Secret, req.Destination, req.Method, "denied", 0, "secret_not_found", "")
		writeError(w, r, http.StatusNotFound, "secret_not_found", "no secret matches the requested name or destination")
		return
	}
	if errors.Is(lookupErr, errAmbiguousDestination) {
		h.logCapabilityEvent(ctx, req.AgentID, nil, "", req.Destination, req.Method, "denied", 0, "ambiguous_destination", "")
		writeError(w, r, http.StatusConflict, "ambiguous_destination", "multiple secrets match this destination; pass an explicit secret name")
		return
	}
	if errors.Is(lookupErr, errAmbiguousSecretName) {
		h.logCapabilityEvent(ctx, req.AgentID, nil, req.Secret, req.Destination, req.Method, "denied", 0, "ambiguous_secret_name", "")
		writeError(w, r, http.StatusConflict, "ambiguous_secret_name",
			"more than one secret you can reach is called that (for example a personal one and a shared one); rename one of them or request it by destination")
		return
	}
	if lookupErr != nil {
		slog.Error("capability.issue: lookup", "error", lookupErr)
		writeInternalError(w, r, "lookup failed")
		return
	}

	// ACL: presence of a (agent_id, secret_id) row in capability_grants
	// authorises. Nothing writes that table today, so in practice every caller
	// takes the implicit branch, which permits whoever can currently reach the
	// entry (see agentCanUse). The table stays as the narrowing mechanism for
	// multi-agent setups; when a writer ships, granting one agent starts
	// excluding the others for that agent id.
	allowed, err := h.agentCanUse(ctx, req.AgentID, entry.ID, userID)
	if err != nil {
		slog.Error("capability.issue: acl", "error", err)
		writeInternalError(w, r, "acl check failed")
		return
	}
	if !allowed {
		h.logCapabilityEvent(ctx, req.AgentID, &entry.ID, entry.Name, req.Destination, req.Method, "denied", 0, "agent_not_granted", "")
		writeError(w, r, http.StatusForbidden, "agent_not_granted", "agent has no grant for this secret")
		return
	}

	// Enforce the secret's destination allow-list as a HARD ceiling. A caller-
	// supplied req.Dests may only NARROW it, never widen it: otherwise a token
	// could be minted for an attacker/internal host and the proxy would inject
	// the real decrypted secret toward it. Default to the full ceiling when the
	// caller passes nothing.
	ceiling := parseDestinationPatterns(entry.DestinationPatterns)
	dests := ceiling
	if len(req.Dests) > 0 {
		if len(ceiling) == 0 {
			// This pair used to contradict itself: asking for dests said "a custom
			// dests request cannot be honored" while asking for none said "pass
			// dests explicitly", so neither branch told the caller what to do and
			// both were unreachable states. There is exactly one fix, and it is on
			// the entry, not in the request.
			writeError(w, r, http.StatusForbidden, "no_ceiling",
				"this secret has no agent destination allow-list, so no capability token can be minted for it. "+
					"Set one on the secret (Vault, edit the entry, Agent access) and try again")
			return
		}
		var allowed []string
		for _, d := range req.Dests {
			host, path := splitHostPath(d)
			if destMatches(ceiling, host, path) {
				allowed = append(allowed, d)
			}
		}
		if len(allowed) == 0 {
			writeError(w, r, http.StatusForbidden, "dests_exceed_ceiling",
				"requested destinations are not covered by the secret's allow-list")
			return
		}
		dests = allowed
	}
	if len(dests) == 0 {
		writeError(w, r, http.StatusBadRequest, "no_destinations",
			"this secret has no agent destination allow-list, so no capability token can be minted for it. "+
				"Set one on the secret (Vault, edit the entry, Agent access) and try again")
		return
	}
	// The pin again, at mint time. The proxy is the authority (it sees the real
	// request and it is the door a stolen token would use), but a token that can
	// never be spent should not be handed out: an agent gets one honest refusal
	// naming the reason instead of a 403 per attempt. This also refuses a token
	// whose CEILING has already been rewritten off-pin, which is the state the
	// attack leaves the row in.
	pin, pinErr := providerPinFor(ctx, h.settings, entry.ID)
	if pinErr != nil {
		slog.Error("capability.issue: could not read the entry's provider pin, denying",
			"secret_id", entry.ID, "error", pinErr)
		writeError(w, r, http.StatusForbidden, "destination_pinned", "the secret's provider binding could not be read")
		return
	}
	if bad, outside := firstDestinationOutsidePin(pin, dests); outside {
		h.logCapabilityEvent(ctx, req.AgentID, &entry.ID, entry.Name, bad, req.Method, "denied", 0, "destination_outside_provider_pin", "")
		writeError(w, r, http.StatusForbidden, "destination_pinned",
			fmt.Sprintf("%s is the instance's AI provider key; it is only ever delivered to %s, and %q is not that. "+
				"If this key is meant to be a general-purpose secret, unwire it in Settings > AI gateway first",
				entry.Name, pin.describe(), bad))
		return
	}

	method := req.Method
	if method == "" {
		method = "*"
	}

	// A CONCRETE destination on an LLM provider is held to the inference
	// allowlist at mint time too, so an agent gets one clear refusal here rather
	// than a token the proxy will always reject. The proxy is the authority (it
	// sees the real request); this is the early, honest error.
	//
	// Globbed dests ("api.openai.com/*") and method "*" still mint: the ceiling
	// is a host+path shape rather than a route, and narrowing it to the
	// allowlist here would refuse every legitimate default. Every request spent
	// against such a token still passes allowedProviderRoute in Proxy.
	if method != "*" {
		for _, d := range dests {
			dHost, dPath := splitHostPath(d)
			if strings.Contains(d, "*") {
				continue
			}
			if _, isProvider, ok := allowedProviderRoute(dHost, method, dPath); isProvider && !ok {
				h.logCapabilityEvent(ctx, req.AgentID, &entry.ID, entry.Name, d, method, "denied", 0, "not_an_inference_route", "")
				writeError(w, r, http.StatusForbidden, "route_not_allowed",
					fmt.Sprintf("%s only proxies inference calls; %s %s is not one of them", dHost, strings.ToUpper(method), dPath))
				return
			}
		}
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = h.defaultTTL
	}
	if ttl > 600*time.Second {
		ttl = 600 * time.Second
	}

	tok := capability.Token{
		Secret:   entry.Name,
		SecretID: entry.ID,
		Agent:    req.AgentID,
		Dests:    dests,
		Method:   strings.ToUpper(method),
	}
	signed, err := capability.Sign(tok, h.signingKey, ttl)
	if err != nil {
		slog.Error("capability.issue: sign", "error", err)
		writeInternalError(w, r, "sign failed")
		return
	}
	verified, _ := capability.Verify(signed, h.signingKey, time.Now())

	h.logCapabilityEvent(ctx, req.AgentID, &entry.ID, entry.Name, joinDests(dests), method, "issued", 0, "", verified.Nonce)

	writeJSON(w, http.StatusCreated, issueResponse{
		Token:       signed,
		ProxyURL:    proxyBaseURL(r),
		Secret:      entry.Name,
		ExpiresAt:   time.Unix(verified.EXP, 0).UTC().Format(time.RFC3339),
		NonceLength: len(verified.Nonce),
	})
}

// ──────────────────────────────────────────────────────────────────────
// /proxy/{host}/{path...}
// ──────────────────────────────────────────────────────────────────────

// Proxy handles every method against /proxy/{host}/{path...}. The host
// segment is the lowercased upstream host (e.g. api.cloudflare.com); the
// remaining path must already be normalized and is forwarded unchanged.
// Token comes in the `Authorization: Capability <token>` request header;
// we strip it and inject the secret-bound header before forwarding.
//
// This is the heart of the bridge. Every branch that is attributable to a
// token we signed logs to capability_log, so the audit trail is complete even
// when nothing user-visible happens. Requests that fail signature or format
// verification are NOT persisted: the route is reachable anonymously, so an
// audit row there would be an unauthenticated, attacker-controlled DB write.
func (h *CapabilityHandler) Proxy(w http.ResponseWriter, r *http.Request) {
	// Just above this client's 60s GuardedWebhookClient budget. The same global
	// 30s write deadline silently truncated any upstream call taking 30-60s,
	// including the OpenAI streaming case its 16 MiB body cap was sized for.
	extendProxyDeadlines(w, 70*time.Second, time.Minute)

	ctx := r.Context()
	host := chi.URLParam(r, "host")
	rest := chi.URLParam(r, "*")

	// Normalize the path BEFORE it is matched against the token's dests and
	// before it is forwarded, and reject instead of rewriting. chi hands us the
	// raw wildcard, so "/v1/../../admin" matches an allow-listed "/v1/*" prefix
	// here but resolves to a different endpoint upstream, and the real secret
	// would be injected toward it. This is an authorization boundary, so a
	// caller whose path is not already normalized gets a 400 rather than a
	// silently re-pointed request.
	upstreamPath, normalized := normalizePath("/" + rest)
	if !normalized {
		writeError(w, r, http.StatusBadRequest, "invalid_path",
			"request path must be normalized (no '.' or '..' segments, no duplicate slashes)")
		return
	}

	tokenStr := extractCapabilityToken(r.Header.Get("Authorization"))
	if tokenStr == "" {
		writeError(w, r, http.StatusUnauthorized, "missing_capability", "Authorization: Capability <token> required")
		return
	}

	tok, err := capability.Verify(tokenStr, h.signingKey, time.Now())
	if err != nil {
		// Only persist an audit row when the request is attributable to a token
		// this server actually signed. These routes sit outside session auth, so
		// a malformed or badly-signed token means an anonymous caller: writing a
		// capability_log row for it would hand anyone an unauthenticated,
		// attacker-controlled DB write (log flooding + audit-trail poisoning).
		// An expired token still carries our signature, so it stays audited.
		if errors.Is(err, capability.ErrExpired) {
			h.logCapabilityEvent(ctx, "", nil, "", host+upstreamPath, r.Method, "expired", 0, err.Error(), "")
		} else {
			slog.Debug("capability.proxy: token verification failed", "error", err, "method", r.Method)
		}
		writeError(w, r, http.StatusUnauthorized, "invalid_capability", err.Error())
		return
	}

	if !destMatches(tok.Dests, host, upstreamPath) {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "destination_mismatch", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "destination_mismatch", "token does not authorise this destination")
		return
	}
	// Defense-in-depth: also require the destination to be within the secret's
	// CURRENT allow-list, not just the token's issue-time Dests. This confines a
	// token minted before the owner tightened the allow-list (enforcement was
	// issue-time only) to the current policy. Skipped when the secret has no
	// allow-list (nothing to tighten against).
	// The secret's CURRENT allow-list is the ceiling, and an EMPTY one means no agent
	// access at all.
	//
	// This used to be guarded by len(patterns) > 0, so the check was skipped exactly
	// when the list was empty. Clearing the allow-list is the ONLY way the product
	// offers to revoke an agent's access to one secret, so the single action meaning
	// "revoke everything" was the one case not enforced, while merely tightening from
	// three hosts to one WAS. Every token already outstanding (TTL up to 600s) kept
	// spending the credential.
	//
	// Denying on empty is exactly consistent with issuance, which already refuses:
	// "this secret has no agent destination allow-list, so no capability token can be
	// minted for it". A token for a pattern-less secret could never legitimately
	// exist, so nothing is lost by rejecting one.
	//
	// A read error denies too. It used to return nil and skip, so a transient database
	// error opened the gate.
	patterns, patErr := h.currentDestinationPatterns(ctx, tok.SecretID)
	if patErr != nil {
		slog.Error("capability.proxy: could not read the secret's current allow-list, denying",
			"secret_id", tok.SecretID, "error", patErr)
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "allowlist_unreadable", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "destination_mismatch", "the secret's current allow-list could not be read")
		return
	}
	if len(patterns) == 0 || !destMatches(patterns, host, upstreamPath) {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "destination_not_in_current_allowlist", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "destination_mismatch", "destination is not in the secret's current allow-list")
		return
	}
	if !capability.MethodMatches(tok, r.Method) {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "method_mismatch", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "method_mismatch", "token does not authorise this method")
		return
	}

	// THE PIN. An entry an admin wired into the AI gateway may only be delivered
	// to that provider's own API host, whatever destination_patterns says.
	//
	// Everything above this line trusts a column that any accepted collection
	// editor can rewrite through PUT /api/vault/{id}, including a public-signup
	// vault_only account. So the round-2 host-keyed allowlist held and the attack
	// simply moved the host: rewrite the ceiling to a collector the attacker
	// controls, mint, and the proxy delivered the OPERATOR's decrypted provider
	// key there in cleartext, with a 200. Both checks above (token dests and the
	// entry's CURRENT allow-list) said yes, because both read the rewritten
	// column.
	//
	// The pin comes from settings ai_key_* (an AdminOnly write) joined to the
	// compile-time aiProviders table, so no caller who can edit the entry can
	// move it. Enforced HERE, before the nonce is spent and before the secret is
	// decrypted: a refused call costs the caller nothing and leaks nothing. The
	// write path refuses the same patterns (VaultHandler.Update), but a delivery
	// gate is what makes the property hold for rows written by anything else:
	// an older binary, a restored backup, a future second writer.
	pin, pinErr := providerPinFor(ctx, h.settings, tok.SecretID)
	if pinErr != nil {
		slog.Error("capability.proxy: could not read the entry's provider pin, denying",
			"secret_id", tok.SecretID, "error", pinErr)
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "egress_pin_unreadable", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "destination_pinned", "the secret's provider binding could not be read")
		return
	}
	if pin.pinned() && !pin.allowsHost(host) {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+displayUpstreamPath(upstreamPath),
			r.Method, "denied", 0, "destination_outside_provider_pin", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "destination_pinned",
			fmt.Sprintf("this secret is the instance's AI provider key; it is only ever delivered to %s, never to %s",
				pin.describe(), providerAPIHost(host)))
		return
	}

	// An LLM provider host is held to the SAME inference allowlist the AI
	// gateway enforces. This is the second door onto one property.
	//
	// The vault entry an admin points ai_key_openai / ai_key_anthropic at is an
	// ordinary entry, and the natural way to manage a team key is to keep it in
	// a collection, where every accepted member resolves it through
	// accessibleEntriesPredicate. So a role-'user' client could mint a token for
	// api.openai.com/v1/files with DELETE and spend the operator's key on the
	// files, batch, fine-tuning and assistants APIs, while the gateway's
	// allowlist guarded a door that caller never used. Scoping one call site and
	// not its sibling is how this class of fix gets reported as closed and is
	// not.
	//
	// Enforced HERE, before the nonce is spent and before the secret is
	// decrypted, so a refused call costs the caller nothing and leaks nothing.
	// The normalized path is what gets forwarded, so the string checked and the
	// string sent are the same one.
	if clean, isProvider, allowed := allowedProviderRoute(host, r.Method, upstreamPath); isProvider {
		if !allowed {
			h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+displayUpstreamPath(upstreamPath),
				r.Method, "denied", 0, "not_an_inference_route", tok.Nonce)
			writeError(w, r, http.StatusForbidden, "route_not_allowed",
				fmt.Sprintf("%s only proxies inference calls; %s %s is not one of them",
					host, r.Method, displayUpstreamPath(upstreamPath)))
			return
		}
		upstreamPath = clean
	}

	// Replay protection: spend the nonce. Any concurrent re-use loses
	// the race on the PK insert and gets rejected here. Expired-nonce
	// rows are pruned by the PruneSpentNonces sweep.
	if err := h.spendNonce(ctx, tok.Nonce, time.Unix(tok.EXP, 0)); err != nil {
		if errors.Is(err, errNonceAlreadySpent) {
			h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "replay", 0, "nonce_already_spent", tok.Nonce)
			writeError(w, r, http.StatusForbidden, "replay", "capability token already used")
			return
		}
		slog.Error("capability.proxy: spend nonce", "error", err)
		writeInternalError(w, r, "nonce store failed")
		return
	}

	// Decrypt the secret + look up injection spec.
	pt, spec, err := h.resolveSecret(ctx, tok.SecretID, tok.Secret)
	if err != nil {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "resolve_failed: "+err.Error(), tok.Nonce)
		writeInternalError(w, r, "secret resolve failed")
		return
	}
	// Wipe the plaintext from memory once forwarding is done.
	defer pt.Wipe()

	// THE ONE EXIT. Everything above this line is the bridge's own machinery:
	// the token, the nonce, the method, the CURRENT allow-list, the pin, the
	// inference routes. All of it reads columns a caller with manage can write,
	// which is exactly how rounds 2 and 3 got in. This asks the other question,
	// once: did the OWNER of this entry authorise this host?
	//
	// The chooser is the entry's own record, because destination_patterns IS the
	// ceiling this route enforces, and the authority re-derives it here rather
	// than trusting that the write gate saw every row.
	exitCtx, value, exitErr := secretexit.Exit(ctx, pt,
		secretexit.ToHost("this capability token", secretexit.ChosenByTheEntrysOwnRecord(), host))
	if exitErr != nil {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+displayUpstreamPath(upstreamPath),
			r.Method, "denied", 0, "egress_refused", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "destination_not_authorized", exitErr.Error())
		return
	}
	ctx = exitCtx

	// Build upstream request. Body is bounded by maxBodySize; we copy
	// to a buffer so the upstream can be retried (not implemented yet,
	// but the buffer keeps the option open).
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, h.maxBodySize+1))
	if err != nil {
		writeBadRequest(w, r, "read body: "+err.Error())
		return
	}
	if int64(len(bodyBytes)) > h.maxBodySize {
		writeError(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds 16 MiB")
		return
	}

	upstreamURL := &url.URL{Scheme: "https", Host: host, Path: upstreamPath, RawQuery: r.URL.RawQuery}
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL.String(), strings.NewReader(string(bodyBytes)))
	if err != nil {
		writeInternalError(w, r, "build upstream request")
		return
	}
	copyForwardHeaders(r.Header, upstreamReq.Header)
	if err := injectSecret(upstreamReq, spec, value); err != nil {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "inject_failed: "+err.Error(), tok.Nonce)
		writeInternalError(w, r, "inject secret failed")
		return
	}

	// The receipt question, same as providerDo asks and same as the AI gateway
	// asks. The bridge has its own client, so it asks it itself rather than
	// growing a fourth answer.
	if cErr := secretexit.CheckHost(upstreamReq.Context(), upstreamReq.URL.Hostname()); cErr != nil {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method,
			"denied", 0, "egress_refused_at_send", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "destination_not_authorized", cErr.Error())
		return
	}
	resp, err := h.httpClient.Do(upstreamReq)
	if err != nil {
		// NEVER return or persist the raw client error. It is a *url.Error
		// whose Error() embeds the full outbound URL including RawQuery; for a
		// query-injected secret (InjectionSpec.Type == "query") that URL holds
		// the decrypted secret in cleartext, so err.Error() would leak the
		// secret to the calling agent (USE-without-SEE break) AND write it to
		// the capability_log.error audit column. The caller gets a generic
		// message; the log gets a URL/query-redacted rendering.
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "used", 0, "upstream_error: "+redactUpstreamError(err), tok.Nonce)
		writeError(w, r, http.StatusBadGateway, "upstream_error", "upstream request failed")
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "used", resp.StatusCode, "", tok.Nonce)
}

// ──────────────────────────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────────────────────────

var errNonceAlreadySpent = errors.New("capability: nonce already spent")
var errAmbiguousDestination = errors.New("capability: multiple secrets match destination")
var errAmbiguousSecretName = errors.New("capability: multiple reachable secrets share this name")

func extractCapabilityToken(authHeader string) string {
	const prefix = "Capability "
	if strings.HasPrefix(authHeader, prefix) {
		return strings.TrimSpace(authHeader[len(prefix):])
	}
	return ""
}

func proxyBaseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/proxy", scheme, r.Host)
}

// forwardableHeaders is the ALLOW-list of caller headers the proxy relays to
// the upstream. It is an allow-list, not a deny-list, because the upstream host
// is chosen by the capability token: anything we forward blindly is handed to a
// third party that may be hostile. A deny-list only ever blocks the names
// somebody thought of, so the caller's own Trustissues credentials (session
// Cookie, X-API-Key, X-Service-Key, any Authorization/Proxy-Authorization
// variant) rode along to whatever host the token targeted and could be replayed
// straight back at us. Only headers a plain API call genuinely needs are listed:
// content negotiation, the client's user agent, request idempotency, and the
// few provider protocol-version headers that carry no credential. The secret
// itself is added afterwards by injectSecret (Proxy calls it after this copy),
// so a spec-defined header/query is never affected by this filter.
var forwardableHeaders = map[string]struct{}{
	"Content-Type":    {},
	"Accept":          {},
	"Accept-Language": {},
	"Accept-Encoding": {},
	"User-Agent":      {},
	"Idempotency-Key": {},
	// Provider protocol selectors. Required by the upstream API, never a
	// credential, and never meaningful to Trustissues itself.
	"Anthropic-Version":    {},
	"Anthropic-Beta":       {},
	"Openai-Beta":          {},
	"Openai-Organization":  {},
	"X-Github-Api-Version": {},
}

// copyForwardHeaders relays only the headers in forwardableHeaders to the
// upstream request. Everything else is dropped, including every credential the
// caller used to reach us.
func copyForwardHeaders(src, dst http.Header) {
	for k, v := range src {
		canonical := http.CanonicalHeaderKey(k)
		if _, ok := forwardableHeaders[canonical]; !ok {
			continue
		}
		dst[canonical] = append([]string{}, v...)
	}
}

// normalizePath cleans an absolute path for an authorization decision and
// reports whether the input was already normalized. path.Clean resolves "." and
// ".." segments and collapses duplicate slashes, so when the cleaned form
// differs from the input, the string an allow-list check sees is not the
// resource the upstream resolves. Callers REJECT on a false second return
// rather than quietly substituting the cleaned value: silently rewriting an
// authorization boundary hides the mismatch from the caller and the audit
// trail. A meaningful trailing slash is preserved (some APIs require one, and
// it is not a traversal vector).
func normalizePath(p string) (string, bool) {
	if p == "" || p == "/" {
		return p, true
	}
	cleaned := path.Clean(p)
	if cleaned != "/" && strings.HasSuffix(p, "/") {
		cleaned += "/"
	}
	return cleaned, cleaned == p
}

// destPathNormalized reports whether the path portion of a "host/path"
// destination is already normalized. Used to reject a caller-supplied
// destination before it is matched against a secret's allow-list, so a ".."
// destination cannot be minted into a token in the first place.
func destPathNormalized(dest string) bool {
	_, p := splitHostPath(dest)
	_, ok := normalizePath(p)
	return ok
}

func copyResponseHeaders(src, dst http.Header) {
	skip := map[string]struct{}{
		"Connection":        {},
		"Keep-Alive":        {},
		"Transfer-Encoding": {},
		"Upgrade":           {},
		"Trailer":           {},
	}
	for k, v := range src {
		if _, drop := skip[http.CanonicalHeaderKey(k)]; drop {
			continue
		}
		dst[http.CanonicalHeaderKey(k)] = append([]string{}, v...)
	}
}

func injectSecret(req *http.Request, spec InjectionSpec, value []byte) error {
	spec = DefaultInjection(spec)
	subbed := strings.ReplaceAll(spec.Format, "{value}", string(value))
	switch spec.Type {
	case "header":
		req.Header.Set(spec.Name, subbed)
	case "query":
		q := req.URL.Query()
		q.Set(spec.Name, subbed)
		req.URL.RawQuery = q.Encode()
	default:
		return fmt.Errorf("unsupported injection type %q", spec.Type)
	}
	return nil
}

// redactUpstreamError renders an outbound proxy or delivery failure safe to
// persist to capability_log.error, last_rotation_error, and the
// rotation_log ring -- and safe to ship off-box to whatever notification
// webhook an admin configured (n8n, Zapier, Slack). All of those are
// OFF-BOX or admin-configured-webhook destinations, so nothing that comes
// out of here may carry a value, a URL path, an identity, or a destination
// set.
//
// This is an ALLOWLIST, not a blocklist. It used to strip only *url.Error,
// so every OTHER error type fell through the final `return err.Error()`
// unredacted: a disabled teammate's email address, another vault entry's
// name and UUID, an owner's whole authorised destination set, a referenced
// entry's name on an auth_token resolve failure. The rotFail* constants in
// vault_rotation_failure.go are the model this follows: a failure CLASS
// that carries no value, no URL, no identity. A new error type contributes
// NOTHING here until it is deliberately added below, so the failure mode of
// forgetting is "the operator sees a generic message", never "the
// operator's webhook receives a secret". The unredacted cause always goes
// to slog at the call site.
func redactUpstreamError(err error) string {
	if err == nil {
		return ""
	}

	// Stdlib context sentinels: fixed text, no dynamic content, genuinely
	// useful (distinguishes a cancelled/timed-out attempt from a hard
	// failure). Exact equality, deliberately NOT errors.Is: a *url.Error
	// unwraps to context.DeadlineExceeded on a timed-out dial, and errors.Is
	// would walk into it and match, returning uerr.Error() -- the raw URL,
	// query string and all -- instead of falling through to the *url.Error
	// branch below that redacts it.
	if err == context.Canceled || err == context.DeadlineExceeded {
		return err.Error()
	}

	// upstreamHTTPError is structural by construction: Error() is "upstream
	// returned HTTP %d ..." with the response body held back for LogValue
	// only. See upstream_error.go.
	var he *upstreamHTTPError
	if errors.As(err, &he) {
		return he.Error()
	}

	// secretexit.ExitRefusedError is structural by construction: the full
	// refusal reason (entry name/UUID, chooser id, destination set) is held
	// back for LogValue only. See internal/secretexit.
	var ee *secretexit.ExitRefusedError
	if errors.As(err, &ee) {
		return ee.Error()
	}

	// deliveryRefusalError (vault_targets.go) is a fixed, non-secret-bearing
	// structural string built at the refusal site: an unattributed or
	// disabled-configurer target, or an unrecognised/retired target type.
	var de *deliveryRefusalError
	if errors.As(err, &de) {
		return de.Error()
	}

	// *url.Error is a transport failure (DNS, connection refused/timeout,
	// TLS, the GuardedWebhookClient SSRF block) whose Error() embeds the
	// full request URL. When a secret is injected as a query parameter
	// (InjectionSpec.Type == "query", see injectSecret) that URL carries the
	// decrypted secret in cleartext. Reduced to scheme + host: the PATH is
	// not safe to keep either, because the path IS the credential for a
	// Slack webhook (https://hooks.slack.com/services/T00/B00/<secret>) or
	// an n8n webhook (https://n8n.example/webhook/<uuid>).
	var uerr *url.Error
	if errors.As(err, &uerr) {
		safeURL := "[redacted]"
		if u, perr := url.Parse(uerr.URL); perr == nil {
			safeURL = u.Scheme + "://" + u.Host
		}
		return fmt.Sprintf("%s %q: %v", uerr.Op, safeURL, uerr.Err)
	}

	// Everything else is unclassified: a generic vault-lookup error, an
	// fmt.Errorf wrapping who knows what. Default to a fixed structural
	// string rather than risk one more field slipping through unclassified.
	return "delivery target failed (details in server logs)"
}

func parseDestinationPatterns(raw string) []string {
	if raw == "" || raw == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func parseInjectionSpec(raw string) InjectionSpec {
	var s InjectionSpec
	if raw == "" || raw == "{}" {
		return s
	}
	_ = json.Unmarshal([]byte(raw), &s)
	return s
}

func joinDests(d []string) string {
	return strings.Join(d, ",")
}

// agentCanUse returns true when the (agent_id, secret_id) pair has an
// active grant. When no grants exist for the agent at all, a fresh install is
// permitted implicitly so day one does not require an extra step.
//
// That implicit permit follows ACCESS, not ownership. It used to end in
// `vault_entries WHERE id = ? AND user_id = ?`, i.e. the entry's creator, which
// made the whole capability bridge dead for every shared secret: an accepted
// editor or manager of a collection resolved the entry fine through
// accessibleEntriesPredicate, then got a hard 403 agent_not_granted from this
// ACL. list_secrets advertised a name that use_secret could never mint, and the
// grant the error asks for has no writer anywhere in the tree, so there was no
// operator workaround.
//
// The scope now comes from the SAME predicate as the lookups. That is the point:
// this property had already been closed at the lookup, and leaving a second
// ownership test behind it is how it stayed broken. A removed member fails both.
func (h *CapabilityHandler) agentCanUse(ctx context.Context, agentID, secretID, userID string) (bool, error) {
	row := h.db.QueryRowContext(ctx,
		`SELECT 1 FROM capability_grants WHERE agent_id = ? AND secret_id = ? AND revoked_at IS NULL`,
		agentID, secretID)
	var v int
	if err := row.Scan(&v); err == nil {
		return true, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	// No explicit grant. Permissive when no grants exist for this
	// agent at all (fresh install convention).
	row = h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM capability_grants WHERE agent_id = ?`, agentID)
	var n int
	if err := row.Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	// Anyone who can currently REACH the secret gets implicit access until
	// explicit grants are configured: the personal owner, or an accepted member
	// of the collection it lives in. Same predicate as lookupSecretByName, so
	// the two can never drift apart again.
	row = h.db.QueryRowContext(ctx,
		`SELECT 1 FROM vault_entries WHERE id = ? AND `+accessibleEntriesPredicate,
		secretID, userID, userID, userID)
	if err := row.Scan(&v); err == nil {
		return true, nil
	}
	return false, nil
}

// capabilityEntryRow is the minimal projection the bridge needs from a
// vault_entries row. Defined here rather than going through the sqlc
// generated selects because the destination_patterns + injection_spec
// columns live in this feature's migration; querying directly keeps the
// change isolated to this package (same choice dockyard made).
type capabilityEntryRow struct {
	ID                  string
	Name                string
	DestinationPatterns string
}

// accessibleEntriesPredicate is the collection-aware scope every capability
// lookup must use.
//
// These lookups previously matched on user_id alone, which bypassed
// entryAccess entirely (vault.go says in as many words: "the single
// authorization point for every single-entry operation; do not bypass it with a
// raw owner check"). Two bugs fell out of that, in opposite directions:
//
//   - a member removed from a collection kept LIVE USE of the shared secret,
//     because they were still its user_id. They vanished from the vault UI and
//     from unlock, but could still mint a capability token and have the proxy
//     inject the CURRENT, post-rotation value upstream. Rotation, the documented
//     revocation step, did not revoke them. This is the third distinct door onto
//     the same property (after the residual write right and the rotation
//     webhook), which is why the scope now comes from one shared predicate.
//   - a current viewer or editor of a collection could NOT mint for a shared
//     secret they legitimately have access to, because they are not its user_id.
//
// Bind params: userID twice.
// The SQL twin of grantFor's use column. It exists because a bulk lookup cannot
// call grantFor per row, which means the rule is encoded twice and the two can
// drift. TestSQLPredicateAgreesWithGrantFor pins them together.
//
// The disabled-account clause was missing for the whole audit: grantFor refuses
// a disabled user at row 2, this did not, so disabling an account left the
// capability bridge minting tokens for it. Bind params: userID three times.
const accessibleEntriesPredicate = `(
	EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.disabled = 0)
	AND (
		(collection_id IS NULL AND user_id = ?)
		OR collection_id IN (
			SELECT collection_id FROM collection_members
			WHERE user_id = ? AND accepted_at IS NOT NULL
		)
	)
)`

// lookupSecretByName resolves a secret by name within the caller's reach, and
// REFUSES when the name is ambiguous.
//
// It used to be a QueryRow, which takes whatever row SQLite happens to return
// first. A name is only unique per (user_id, name), so a user who is in a
// collection holding "stripe" and also keeps a personal "stripe" has two
// reachable entries with that name and nothing to choose between them. The
// agent asked for "stripe", got 201 and a proxy_url, and the proxy injected
// whichever key won: the sandbox key or the company's live one. Nothing in the
// tool result, the token or the capability_log row distinguished them, since
// secret_name is "stripe" either way, so the audit trail could not answer which
// key was actually spent.
//
// lookupSecretByDestination, two functions down, already refused its equivalent
// ambiguity with a 409. This is the same rule applied to the other lookup.
func (h *CapabilityHandler) lookupSecretByName(ctx context.Context, userID, name string) (capabilityEntryRow, error) {
	rows, err := h.db.QueryContext(ctx,
		`SELECT id, name, destination_patterns FROM vault_entries WHERE `+accessibleEntriesPredicate+` AND name = ?`,
		userID, userID, userID, name)
	if err != nil {
		return capabilityEntryRow{}, err
	}
	defer rows.Close()
	var matched []capabilityEntryRow
	for rows.Next() {
		var e capabilityEntryRow
		if err := rows.Scan(&e.ID, &e.Name, &e.DestinationPatterns); err != nil {
			return capabilityEntryRow{}, err
		}
		matched = append(matched, e)
	}
	if err := rows.Err(); err != nil {
		return capabilityEntryRow{}, err
	}
	switch len(matched) {
	case 0:
		// sql.ErrNoRows keeps the caller's existing not-found handling intact.
		return capabilityEntryRow{}, sql.ErrNoRows
	case 1:
		return matched[0], nil
	default:
		return capabilityEntryRow{}, errAmbiguousSecretName
	}
}

func (h *CapabilityHandler) lookupSecretByDestination(ctx context.Context, userID, dest string) (capabilityEntryRow, error) {
	rows, err := h.db.QueryContext(ctx,
		`SELECT id, name, destination_patterns FROM vault_entries WHERE `+accessibleEntriesPredicate+
			` AND destination_patterns != '' AND destination_patterns != '[]'`,
		userID, userID, userID)
	if err != nil {
		return capabilityEntryRow{}, err
	}
	defer rows.Close()
	host, path := splitHostPath(dest)
	var matched []capabilityEntryRow
	for rows.Next() {
		var e capabilityEntryRow
		if err := rows.Scan(&e.ID, &e.Name, &e.DestinationPatterns); err != nil {
			return capabilityEntryRow{}, err
		}
		patterns := parseDestinationPatterns(e.DestinationPatterns)
		if destMatches(patterns, host, path) {
			matched = append(matched, e)
		}
	}
	if err := rows.Err(); err != nil {
		return capabilityEntryRow{}, err
	}
	switch len(matched) {
	case 0:
		return capabilityEntryRow{}, sql.ErrNoRows
	case 1:
		return matched[0], nil
	default:
		return capabilityEntryRow{}, errAmbiguousDestination
	}
}

// currentDestinationPatterns returns the secret's current destination allow-list,
// used to re-validate a capability token against the owner's live policy at proxy
// time. Returns nil on any error or when unset (caller treats nil as "no ceiling").
// currentDestinationPatterns reads the secret's CURRENT agent allow-list.
//
// It returns an error rather than an empty slice on failure, because the caller
// treats "no patterns" as a policy decision and the two must not be confused. The
// old signature returned nil for a query error, a deleted row and a genuinely empty
// list alike, and the caller skipped its re-check for all three: a transient database
// error opened the gate.
func (h *CapabilityHandler) currentDestinationPatterns(ctx context.Context, secretID string) ([]string, error) {
	var raw sql.NullString
	if err := h.db.QueryRowContext(ctx,
		`SELECT destination_patterns FROM vault_entries WHERE id = ?`, secretID).Scan(&raw); err != nil {
		return nil, err
	}
	return parseDestinationPatterns(raw.String), nil
}

func splitHostPath(dest string) (host, path string) {
	if i := strings.Index(dest, "/"); i >= 0 {
		return dest[:i], dest[i:]
	}
	return dest, ""
}

// destMatches reports whether host+path is allowed by at least one of the given
// destination patterns.
//
// A HOST-WILDCARDED pattern is refused here, which makes this agree with
// validateDestinations rather than being a superset of it.
//
// The two used to disagree: the validator rejects any "*" in a host, and this
// matcher honoured a leading "*." via leadingWildcardMatch. So a stored row carrying
// "*.supabase.co/*" (written by an older binary, by hand, or restored from an old
// backup) was still enforced as a valid ceiling even though the product would refuse
// to save it today, and nothing normalised existing rows. capability_providers.go
// spells out why that shape is dangerous: anyone can register
// attacker.supabase.co, and a token minted for one tenant's key would happily send
// it there.
//
// Nothing needs the wildcard any more. The three presets that once required it
// (grafana, auth0, supabase) ship a tenant placeholder instead, and
// ExpandCapabilityDestinations refuses a "*" in a substituted tenant value, so no
// code path emits one. Refusing at MATCH time is what closes the gap for rows that
// already exist, since a validator only guards new writes.
//
// The exact and trailing-glob cases still delegate to the audited package matcher,
// so its grammar is not re-implemented here.
func destMatches(dests []string, host, path string) bool {
	safe := make([]string, 0, len(dests))
	for _, pat := range dests {
		if hostIsWildcarded(pat) {
			slog.Warn("capability: ignoring a stored destination whose host is wildcarded; "+
				"it would allow every sibling domain on that suffix", "pattern", pat)
			continue
		}
		safe = append(safe, pat)
	}
	if len(safe) == 0 {
		return false
	}
	return capability.DestMatches(capability.Token{Dests: safe}, host, path)
}

// hostIsWildcarded reports whether a destination pattern wildcards its HOST, which
// is the shape validateDestinations refuses. A "*" in the PATH is a legitimate
// trailing glob and is left alone.
func hostIsWildcarded(pat string) bool {
	host := pat
	if i := strings.Index(pat, "/"); i >= 0 {
		host = pat[:i]
	}
	return strings.Contains(host, "*")
}

func (h *CapabilityHandler) resolveSecret(ctx context.Context, secretID, secretName string) (secretexit.Plaintext, InjectionSpec, error) {
	row := h.db.QueryRowContext(ctx,
		`SELECT encrypted_value, nonce, encryption_version, injection_spec FROM vault_entries WHERE id = ?`,
		secretID)
	var ct, nonce []byte
	var encVer sql.NullInt64
	var injectionRaw string
	if err := row.Scan(&ct, &nonce, &encVer, &injectionRaw); err != nil {
		return secretexit.Plaintext{}, InjectionSpec{}, err
	}
	plain, err := h.vault.OpenEntrySecret(ct, nonce, int(encVer.Int64),
		secretexit.Origin{EntryID: secretID, Name: secretName})
	if err != nil {
		return secretexit.Plaintext{}, InjectionSpec{}, err
	}
	return plain, parseInjectionSpec(injectionRaw), nil
}

// spendNonce inserts the nonce into the spent set. PK collision means
// replay; any other error is a real DB problem.
func (h *CapabilityHandler) spendNonce(ctx context.Context, nonce string, expiresAt time.Time) error {
	_, err := h.db.ExecContext(ctx,
		`INSERT INTO capability_spent_nonces (nonce, expires_at) VALUES (?, ?)`,
		nonce, expiresAt.UTC().Format(time.RFC3339))
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "UNIQUE constraint") {
		return errNonceAlreadySpent
	}
	return err
}

// PruneSpentNonces deletes entries past their expiry. Safe to call
// often; cheap when the table is small.
func (h *CapabilityHandler) PruneSpentNonces(ctx context.Context) (int64, error) {
	res, err := h.db.ExecContext(ctx,
		`DELETE FROM capability_spent_nonces WHERE expires_at < datetime('now')`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (h *CapabilityHandler) logCapabilityEvent(ctx context.Context, agent string, secretID *string, secretName, dest, method, event string, statusCode int, errMsg, nonce string) {
	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)
	var sid sql.NullString
	if secretID != nil {
		sid.String = *secretID
		sid.Valid = true
	}
	var sc sql.NullInt64
	if statusCode > 0 {
		sc.Int64 = int64(statusCode)
		sc.Valid = true
	}
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO capability_log (id, agent_id, secret_id, secret_name, destination, method, event, status_code, error, nonce)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, agent, sid, secretName, dest, method, event, sc, errMsg, nonce); err != nil {
		slog.Warn("capability: log event failed", "error", err, "event", event)
	}
}

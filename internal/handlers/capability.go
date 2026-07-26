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

	"github.com/brightinteraction/trustissues/internal/alerts"
	"github.com/brightinteraction/trustissues/internal/capability"
	"github.com/brightinteraction/trustissues/internal/middleware"
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
	db          *sql.DB
	vault       alerts.ConfigDecrypter
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
func NewCapabilityHandler(db *sql.DB, vault alerts.ConfigDecrypter, signingKeySource string) (*CapabilityHandler, error) {
	key, err := capability.DeriveSigningKey(signingKeySource)
	if err != nil {
		return nil, fmt.Errorf("capability: derive signing key: %w", err)
	}
	return &CapabilityHandler{
		db:         db,
		vault:      vault,
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
	if lookupErr != nil {
		slog.Error("capability.issue: lookup", "error", lookupErr)
		writeInternalError(w, r, "lookup failed")
		return
	}

	// ACL: presence of a (agent_id, secret_id) row in capability_grants
	// authorises. Empty table for the owner = permissive; the bridge
	// install path inserts a "self-grant" so vibecoders never trip on
	// this on day one but the mechanism exists for multi-agent setups.
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
			writeError(w, r, http.StatusForbidden, "no_ceiling",
				"secret has no destination allow-list configured; a custom dests request cannot be honored")
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
			"secret has no default destinations configured; pass dests explicitly")
		return
	}
	method := req.Method
	if method == "" {
		method = "*"
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
	if patterns := h.currentDestinationPatterns(ctx, tok.SecretID); len(patterns) > 0 {
		if !destMatches(patterns, host, upstreamPath) {
			h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "destination_not_in_current_allowlist", tok.Nonce)
			writeError(w, r, http.StatusForbidden, "destination_mismatch", "destination is not in the secret's current allow-list")
			return
		}
	}
	if !capability.MethodMatches(tok, r.Method) {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "method_mismatch", tok.Nonce)
		writeError(w, r, http.StatusForbidden, "method_mismatch", "token does not authorise this method")
		return
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
	value, spec, err := h.resolveSecret(ctx, tok.SecretID)
	if err != nil {
		h.logCapabilityEvent(ctx, tok.Agent, &tok.SecretID, tok.Secret, host+upstreamPath, r.Method, "denied", 0, "resolve_failed: "+err.Error(), tok.Nonce)
		writeInternalError(w, r, "secret resolve failed")
		return
	}
	defer func() {
		// Wipe the plaintext from memory once forwarding is done.
		for i := range value {
			value[i] = 0
		}
	}()

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

// redactUpstreamError renders an outbound proxy error safe to persist to the
// capability_log.error audit column. net/http surfaces transport failures
// (DNS, connection refused/timeout, TLS, and the GuardedWebhookClient SSRF
// block) as *url.Error values whose Error() embeds the full request URL,
// including RawQuery. When a secret is injected as a query parameter
// (InjectionSpec.Type == "query", see injectSecret) that URL carries the
// decrypted secret in cleartext, so persisting err.Error() verbatim would
// write the secret at rest. This strips the query string and any userinfo
// from the embedded URL while keeping the operation + transport failure
// reason for debugging. Callers of the proxy still receive only a generic
// message, never this string.
func redactUpstreamError(err error) string {
	if err == nil {
		return ""
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		safeURL := "[redacted]"
		if u, perr := url.Parse(uerr.URL); perr == nil {
			u.RawQuery = ""
			u.User = nil
			safeURL = u.String()
		}
		return fmt.Sprintf("%s %q: %v", uerr.Op, safeURL, uerr.Err)
	}
	return err.Error()
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
// active grant. The owner of the secret implicitly has access when no
// grants exist for the agent at all, so a fresh install does not
// require an extra step.
func (h *CapabilityHandler) agentCanUse(ctx context.Context, agentID, secretID, ownerID string) (bool, error) {
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
	// Owner of the secret also gets implicit access until they
	// configure explicit grants.
	row = h.db.QueryRowContext(ctx,
		`SELECT 1 FROM vault_entries WHERE id = ? AND user_id = ?`, secretID, ownerID)
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

func (h *CapabilityHandler) lookupSecretByName(ctx context.Context, userID, name string) (capabilityEntryRow, error) {
	row := h.db.QueryRowContext(ctx,
		`SELECT id, name, destination_patterns FROM vault_entries WHERE user_id = ? AND name = ?`,
		userID, name)
	var e capabilityEntryRow
	if err := row.Scan(&e.ID, &e.Name, &e.DestinationPatterns); err != nil {
		return capabilityEntryRow{}, err
	}
	return e, nil
}

func (h *CapabilityHandler) lookupSecretByDestination(ctx context.Context, userID, dest string) (capabilityEntryRow, error) {
	rows, err := h.db.QueryContext(ctx,
		`SELECT id, name, destination_patterns FROM vault_entries WHERE user_id = ? AND destination_patterns != '' AND destination_patterns != '[]'`,
		userID)
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
func (h *CapabilityHandler) currentDestinationPatterns(ctx context.Context, secretID string) []string {
	var raw string
	if err := h.db.QueryRowContext(ctx,
		`SELECT destination_patterns FROM vault_entries WHERE id = ?`, secretID).Scan(&raw); err != nil {
		return nil
	}
	return parseDestinationPatterns(raw)
}

func splitHostPath(dest string) (host, path string) {
	if i := strings.Index(dest, "/"); i >= 0 {
		return dest[:i], dest[i:]
	}
	return dest, ""
}

// destMatches reports whether host+path is allowed by at least one of the
// given destination patterns. It is a superset of capability.DestMatches: the
// package matcher understands exact and trailing "/*" path globs but NOT a
// leading "*." host wildcard, so provider presets like "*.grafana.net/*",
// "*.auth0.com/*", and "*.supabase.co/*" would never match their per-tenant
// hosts. Every production destination check routes through here so those
// presets work; the exact/trailing-glob cases still delegate to the audited
// package matcher to avoid re-implementing (and diverging from) its grammar.
func destMatches(dests []string, host, path string) bool {
	if capability.DestMatches(capability.Token{Dests: dests}, host, path) {
		return true
	}
	dest := strings.ToLower(host + path)
	for _, pat := range dests {
		if leadingWildcardMatch(strings.ToLower(pat), dest) {
			return true
		}
	}
	return false
}

// leadingWildcardMatch matches a "*."-prefixed host preset such as
// "*.grafana.net/*" against a concrete "host/path" dest. The wildcard covers
// one or more subdomain labels: it matches "stack.grafana.net/..." and
// "eu.stack.grafana.net/..." but never the apex "grafana.net", nor a sibling
// suffix like "notgrafana.net", nor "grafana.net.evil.com". A pattern without a
// leading "*." returns false here (handled by capability.DestMatches instead).
// The path portion is matched with the same trailing-"/*" grammar the package
// matcher uses, so "*.host/*" and "*.host/v1" behave like their non-wildcard
// counterparts.
func leadingWildcardMatch(pat, dest string) bool {
	if !strings.HasPrefix(pat, "*.") {
		return false
	}
	patHost, patPath := splitHostPath(pat)
	destHost, destPath := splitHostPath(dest)
	suffix := patHost[1:] // ".grafana.net"
	// Require at least one non-empty label before the suffix so the apex and
	// bare-suffix impostors ("notgrafana.net") do not match.
	if len(destHost) <= len(suffix) || !strings.HasSuffix(destHost, suffix) {
		return false
	}
	if strings.HasSuffix(patPath, "/*") {
		prefix := strings.TrimSuffix(patPath, "/*")
		return destPath == prefix || strings.HasPrefix(destPath, prefix+"/")
	}
	return destPath == patPath || strings.HasPrefix(destPath, patPath+"/")
}

func (h *CapabilityHandler) resolveSecret(ctx context.Context, secretID string) ([]byte, InjectionSpec, error) {
	row := h.db.QueryRowContext(ctx,
		`SELECT encrypted_value, nonce, encryption_version, injection_spec FROM vault_entries WHERE id = ?`,
		secretID)
	var ct, nonce []byte
	var encVer sql.NullInt64
	var injectionRaw string
	if err := row.Scan(&ct, &nonce, &encVer, &injectionRaw); err != nil {
		return nil, InjectionSpec{}, err
	}
	plain, err := h.vault.DecryptValue(ct, nonce, int(encVer.Int64))
	if err != nil {
		return nil, InjectionSpec{}, err
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

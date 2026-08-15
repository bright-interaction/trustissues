package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/reflectguard"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/shield"
	"github.com/go-chi/chi/v5"
)

// maxAIBody caps the request body forwarded to an LLM provider.
const maxAIBody = 5 << 20 // 5 MB

// aiProvider describes one upstream LLM API the gateway can proxy to. The set is
// a fixed allowlist (no user-controlled host), so there is no SSRF surface.
type aiProvider struct {
	baseURL    string
	settingKey string // settings key holding the vault entry id of the API key
	inject     func(h http.Header, key string)
	// apiHost is the canonical provider host this entry speaks to, and the key
	// into providerInferenceRoutes. It is deliberately NOT derived from baseURL:
	// tests point baseURL at a local httptest server, and deriving it there
	// would silently disable the allowlist in exactly the tests that exist to
	// prove it works. TestAIProviderBaseURLMatchesItsAllowlistHost pins the two
	// together for the production table.
	apiHost string
}

var aiProviders = map[string]aiProvider{
	"anthropic": {
		baseURL:    "https://api.anthropic.com",
		apiHost:    "api.anthropic.com",
		settingKey: "ai_key_anthropic",
		inject: func(h http.Header, key string) {
			h.Set("x-api-key", key)
			if h.Get("anthropic-version") == "" {
				h.Set("anthropic-version", "2023-06-01")
			}
		},
	},
	"openai": {
		baseURL:    "https://api.openai.com",
		apiHost:    "api.openai.com",
		settingKey: "ai_key_openai",
		inject: func(h http.Header, key string) {
			h.Set("Authorization", "Bearer "+key)
		},
	},
}

// AIGatewayHandler proxies LLM requests to Claude/OpenAI while (1) injecting the
// team's provider key server-side so a caller never holds it, and (2) tokenizing
// PII in the prompt through Shield before it egresses, resolving markers in the
// response. Every call is attributed and usage-logged.
type AIGatewayHandler struct {
	queries     *db.Queries
	cfg         *config.Config
	vault       *VaultHandler
	shieldStore shield.Store // nil when Shield is disabled
	client      *http.Client
	// providers is initialized from the package default; tests override a
	// provider's baseURL to point at a mock upstream.
	providers map[string]aiProvider
}

func NewAIGatewayHandler(queries *db.Queries, cfg *config.Config, vault *VaultHandler, store shield.Store) *AIGatewayHandler {
	provs := make(map[string]aiProvider, len(aiProviders))
	for k, v := range aiProviders {
		provs[k] = v
	}
	return &AIGatewayHandler{
		queries:     queries,
		cfg:         cfg,
		vault:       vault,
		shieldStore: store,
		providers:   provs,
		client: &http.Client{
			Timeout: 5 * time.Minute,
			// Never follow redirects: Go copies the injected key header across a
			// 3xx, which would egress the provider key to an attacker-chosen host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Proxy handles /api/ai/{provider}/* for POST and GET, forwarding to the
// provider with the stored key injected.
func (h *AIGatewayHandler) Proxy(w http.ResponseWriter, r *http.Request) {
	// Above the upstream client's own 5-minute budget, so the client's timeout
	// is what bounds the call rather than the server cutting the socket.
	extendProxyDeadlines(w, 6*time.Minute, time.Minute)

	ctx := r.Context()
	providerName := chi.URLParam(r, "provider")
	p, ok := h.providers[providerName]
	if !ok {
		writeBadRequest(w, r, "unknown AI provider (supported: anthropic, openai)")
		return
	}

	// Scope the caller BEFORE the operator's key is decrypted, so a refused call
	// never touches the vault and never bills anyone. See providerInferenceRoutes.
	//
	// isProvider false is a REFUSAL, not a skip: a provider added to aiProviders
	// without an entry in providerInferenceRoutes would otherwise inherit the
	// unrestricted behaviour this allowlist exists to remove.
	rawUpstreamPath := "/" + chi.URLParam(r, "*")
	upstreamPath, isProvider, allowed := allowedProviderRoute(p.apiHost, r.Method, rawUpstreamPath)
	if !isProvider || !allowed {
		shown := displayUpstreamPath(rawUpstreamPath)
		logError(r, "ai_gateway: refused a call outside the inference allowlist",
			"provider", providerName, "method", r.Method, "path", shown)
		// Attributed, same as a successful call. A client reaching for the
		// operator's files or fine-tuning API is the shape an operator most needs
		// to see, and it would otherwise leave no trace in the audit trail at all
		// while every ordinary completion does.
		LogActivityFromRequest(h.queries, r, "ai.gateway_refused",
			fmt.Sprintf("AI call refused: provider=%s method=%s path=%s user=%s (not an inference route)",
				providerName, r.Method, shown, middleware.GetUserID(ctx)))
		writeError(w, r, http.StatusForbidden, "route_not_allowed",
			fmt.Sprintf("the AI gateway only proxies inference calls; %s %s is not one of them", r.Method, shown))
		return
	}

	// Resolve the provider key: an admin points a setting at a vault entry that
	// holds the key. It is decrypted server-side and never returned to the caller.
	entryID, _ := h.queries.GetSetting(ctx, p.settingKey)
	if entryID == "" {
		writeError(w, r, http.StatusBadGateway, "provider_not_configured",
			fmt.Sprintf("no %s key configured; an admin must set it in Settings > AI gateway", providerName))
		return
	}
	pt, err := h.vault.EntrySecretByID(ctx, entryID)
	if err != nil {
		logError(r, "ai_gateway: provider key resolve failed", "provider", providerName, "error", err)
		writeInternalError(w, r, "provider key is not available")
		return
	}
	defer pt.Wipe()
	// THE ONE EXIT. The destination is fixed by the DEPLOYMENT and by nothing
	// else: p.baseURL is a compile-time constant in the aiProviders table and the
	// entry is named by an AdminOnly settings row, so no caller and nobody who
	// can edit the entry moves it. That is what ChosenByTheInstance means, and it
	// is the only chooser kind this route can legitimately use.
	//
	// The host comes from the URL that is ACTUALLY about to be built, not from a
	// second constant that could drift from it. p.apiHost is the other half of
	// the same pair and TestAIProviderBaseURLMatchesItsAllowlistHost pins them
	// together for the production table; deriving the receipt from baseURL is
	// what lets a test point baseURL at a loopback upstream without the receipt
	// silently describing somewhere the request is not going.
	upCtx, key, err := secretexit.ExitString(ctx, pt,
		secretexit.ToHost("the AI gateway's "+providerName+" key",
			secretexit.ChosenByTheInstance("settings "+p.settingKey+" is an AdminOnly write, and the host "+
				"is the compile-time aiProviders baseURL"), baseURLHost(p.baseURL)))
	if err != nil || key == "" {
		logError(r, "ai_gateway: provider key not released", "provider", providerName, "error", err)
		writeInternalError(w, r, "provider key is not available")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAIBody))
	if err != nil {
		writeBadRequest(w, r, "request body too large or unreadable")
		return
	}

	// Parse the body ONCE, with Shield's parser, and decide everything below on
	// the value that comes back.
	//
	// The streaming guard used to run json.Unmarshal over the raw bytes while
	// Shield parsed the SAME bytes with a json.Decoder. Those two disagree:
	// Unmarshal rejects anything after the JSON value, a Decoder reading one
	// value does not care what follows. So
	//
	//	{"model":"gpt-4","stream":true,"messages":[]}x
	//
	// failed to Unmarshal (the ignored error left probe.Stream false, so the
	// guard said "not streaming"), then Shield decoded it happily, dropped the
	// trailing "x" in its re-marshal, and handed the provider a clean
	// stream:true. One byte moved the request onto the path the guard exists to
	// keep it off. A body is now one value to both layers by construction, so
	// there is no second reading of it to disagree with.
	//
	// Fail CLOSED on a body that will not parse. The old code fell open: an
	// unparseable body sailed past the guard, and with Shield off it went
	// upstream verbatim. A gate on redaction may not pass what it could not read.
	// An EMPTY body stays legal, because the allowlisted GET routes
	// (/v1/models) carry none.
	var parsedBody any
	if len(body) > 0 {
		parsedBody, err = shield.DecodeJSON(body)
		if err != nil {
			logError(r, "ai_gateway: refused an unparseable request body", "provider", providerName)
			writeBadRequest(w, r, "request body must be a single valid JSON value")
			return
		}
	}

	// Streaming responses cannot be reliably tokenized/resolved across chunks, so
	// v1 supports non-streaming only. Reject stream:true up front.
	if requestsStreaming(parsedBody) {
		writeBadRequest(w, r, "the AI gateway supports non-streaming requests only; set \"stream\": false")
		return
	}

	// Shield: tokenize PII in the outbound body before it reaches the provider.
	var session *shield.Session
	if h.shieldStore != nil && len(body) > 0 {
		session, err = shield.NewSession(ctx, h.shieldStore, randSessionID(),
			[]byte(h.cfg.ShieldKey), 30*time.Minute, shield.ParseHintLevel(h.cfg.ShieldHintLevel))
		if err != nil {
			logError(r, "ai_gateway: shield session failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		// ShieldValue, not ShieldJSON: redact the value the guard just cleared,
		// not a fresh parse of the bytes.
		shielded, sErr := session.ShieldValue(ctx, parsedBody)
		if sErr != nil {
			// Fail closed: never forward un-tokenized PII when Shield is on.
			logError(r, "ai_gateway: shield tokenization failed", "error", sErr)
			writeBadRequest(w, r, "request body could not be processed for tokenization")
			return
		}
		body = shielded
	}

	// Carry the caller's query string. Concatenating baseURL+path dropped it, so
	// every documented GET through the gateway (pagination cursors, filters,
	// limits) silently returned an unfiltered first page with a 200 and no hint
	// that the parameters had been discarded.
	upstreamURL := p.baseURL + upstreamPath
	if raw := r.URL.RawQuery; raw != "" {
		if strings.Contains(upstreamURL, "?") {
			upstreamURL += "&" + raw
		} else {
			upstreamURL += "?" + raw
		}
	}
	upReq, err := http.NewRequestWithContext(upCtx, r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		writeInternalError(w, r, "internal server error")
		return
	}
	// Only carry a minimal, safe header set upstream. The caller's Authorization
	// is intentionally dropped; the gateway injects the real key.
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json")
	if v := r.Header.Get("anthropic-version"); v != "" {
		upReq.Header.Set("anthropic-version", v)
	}
	if v := r.Header.Get("anthropic-beta"); v != "" {
		upReq.Header.Set("anthropic-beta", v)
	}
	p.inject(upReq.Header, key)

	// CheckHost, not a bare client.Do. The gateway has its own client (redirects
	// refused, long timeout), so it cannot reuse providerDo, but the RECEIPT
	// question is the same one and asking it here is what keeps this door and the
	// capability bridge's door from diverging the way they did in round 2.
	if err := secretexit.CheckHost(upReq.Context(), upReq.URL.Hostname()); err != nil {
		logError(r, "ai_gateway: refused an upstream host outside the exit receipt",
			"provider", providerName, "error", err)
		writeError(w, r, http.StatusForbidden, "destination_pinned", err.Error())
		return
	}
	resp, err := h.client.Do(upReq)
	if err != nil {
		logError(r, "ai_gateway: upstream request failed", "provider", providerName, "error", err)
		writeError(w, r, http.StatusBadGateway, "upstream_error", "the AI provider could not be reached")
		return
	}
	defer resp.Body.Close()

	// Read ONE byte past the ceiling so truncation is detectable.
	//
	// io.LimitReader stops silently at the limit, so a provider response over
	// maxAIBody was cut mid-JSON and then handed to the caller as a completed
	// request: status 200, delivered, with a body that will not parse or, worse,
	// that parses into a partial answer. The caller has no way to tell that from
	// a genuine short response. A gateway may refuse to carry an oversized
	// payload, but it must not report success for something it truncated.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAIBody+1))
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "upstream_error", "could not read the provider response")
		return
	}
	if int64(len(respBody)) > maxAIBody {
		logError(r, "ai_gateway: provider response exceeded the ceiling", "provider", providerName,
			"limit_bytes", maxAIBody)
		writeError(w, r, http.StatusBadGateway, "upstream_response_too_large",
			fmt.Sprintf("the AI provider returned more than %d bytes; the response was not delivered", maxAIBody))
		return
	}

	// Resolve markers back to plaintext for the (trusted) caller.
	//
	// Take the resolved body even on error. UnshieldJSON now returns the partial
	// result plus the first failure, and one unresolvable marker must not cost
	// the caller every marker that DID resolve. Discarding the whole body meant a
	// model that abbreviated or mistyped a single marker, or untrusted text that
	// merely contained a marker-shaped string, silently downgraded the entire
	// response to [shield:...] placeholders with a 200 and no explanation.
	if session != nil && len(respBody) > 0 {
		resolved, uErr := session.UnshieldJSON(ctx, respBody)
		if len(resolved) > 0 {
			respBody = resolved
		}
		if uErr != nil {
			logError(r, "ai_gateway: some shield markers did not resolve (partial body returned)", "error", uErr)
		}
	}

	// ── THE RETURN TRIP ───────────────────────────────────────────────
	//
	// One property, two doors, and this is the second one. The capability
	// bridge's /proxy had exactly this hole: it injected the operator's key and
	// then relayed the upstream's answer to the caller verbatim, so any upstream
	// that echoes what it received handed the credential to a principal who is
	// not entitled to it. This handler's caller is that same kind of principal
	// (GetConfig withholds even the ENTRY ID from a non-admin, precisely because
	// it points at the most valuable secret in the vault), and the caller
	// chooses the endpoint, the query string and the whole request body. A
	// provider that quotes the offending key back in a 401 is not exotic.
	//
	// Scoping one call site and not its sibling is how this class of fix gets
	// reported as closed and is not, which is the note already written above
	// about the inference allowlist. So: same guard, same fail-closed posture,
	// recorded in the activity log rather than silently.
	//
	// The bytes scanned are the bytes WRITTEN: after Shield resolution, not
	// before. This handler builds a fresh outbound header set and never forwards
	// the caller's Accept-Encoding, so Go's transport negotiates and decodes
	// gzip itself and respBody is already plaintext; the Content-Encoding branch
	// is for a provider that compresses unbidden, where scanning would find
	// nothing and report clean.
	guard := reflectguard.New([]byte(key))
	defer guard.Wipe()

	// Every Content-Encoding value, not just the first. Header.Get reads one
	// line, so a provider sending "identity" and then "gzip" walked straight
	// past this refusal -- and past net/http's transparent decompression, which
	// tests the same first value -- leaving the scan below to look for a
	// plaintext needle in gzip bytes and report clean. reflectguard owns the
	// question so this door and the capability bridge's door cannot drift apart
	// on it again.
	if ce, unscannable := reflectguard.UnscannableEncoding(resp.Header); unscannable {
		logError(r, "ai_gateway: provider response is content-encoded and could not be checked for the injected key",
			"provider", providerName, "content_encoding", ce)
		LogActivityFromRequest(h.queries, r, "ai.gateway_response_withheld",
			fmt.Sprintf("AI call withheld: provider=%s status=%d reason=unscannable content-encoding %s",
				providerName, resp.StatusCode, ce))
		writeError(w, r, http.StatusBadGateway, "upstream_unscannable",
			"the provider response is content-encoded and could not be checked for the injected key, so it was not delivered")
		return
	}
	if name, enc, hit := guard.ScanHeader(resp.Header); hit {
		logError(r, "ai_gateway: the provider reflected the injected key in a response header; response withheld",
			"provider", providerName, "header", name, "encoding", enc)
		LogActivityFromRequest(h.queries, r, "ai.gateway_response_withheld",
			fmt.Sprintf("AI call withheld: provider=%s status=%d reason=reflected key in response header %s (%s)",
				providerName, resp.StatusCode, name, enc))
		writeError(w, r, http.StatusBadGateway, "upstream_reflected_secret",
			"the provider returned the injected key in a response header; the response was not delivered")
		return
	}
	if enc, hit := guard.Scan(respBody); hit {
		logError(r, "ai_gateway: the provider reflected the injected key in the response body; response withheld",
			"provider", providerName, "encoding", enc)
		LogActivityFromRequest(h.queries, r, "ai.gateway_response_withheld",
			fmt.Sprintf("AI call withheld: provider=%s status=%d reason=reflected key in response body (%s)",
				providerName, resp.StatusCode, enc))
		writeError(w, r, http.StatusBadGateway, "upstream_reflected_secret",
			"the provider returned the injected key in the response body; the response was not delivered")
		return
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)

	// Log AFTER the write, with what actually happened. logUsage used to run
	// before it, so a response the caller never received was recorded as a clean
	// 200: an operator investigating "my calls keep failing" saw only successes,
	// while the provider had been billed and the prompt had already egressed.
	//
	// The explicit Flush matters: a body under the 4 KB bufio buffer is not
	// written to the socket until after the handler returns, so w.Write alone
	// reports success even when the connection is already dead.
	_, writeErr := w.Write(respBody)
	if writeErr == nil {
		if rc := http.NewResponseController(w); rc != nil {
			if fErr := rc.Flush(); fErr != nil && !errors.Is(fErr, http.ErrNotSupported) {
				writeErr = fErr
			}
		}
	}
	h.logUsage(r, providerName, resp.StatusCode, respBody, writeErr)
}

// baseURLHost is the host half of a provider baseURL. An unparseable value
// yields "", which secretexit.Exit refuses, so a malformed table entry stops the
// key rather than releasing it to nowhere in particular.
func baseURLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// requestsStreaming reports whether a request asks the provider to stream.
//
// It takes the PARSED body (shield.DecodeJSON's result), never raw bytes. That
// is the whole point: the value it inspects is the value Shield redacts and
// re-marshals onto the wire, so the guard cannot be reading a different document
// from the one that egresses. Handing this function []byte again would reopen
// the differential it was written to close.
//
// It answers "is this provably NOT streaming", and rejects everything else.
// Absent, null and boolean false are the only non-streaming answers; a string
// "true", a number, an object, anything at all under a stream key is refused.
// Those bodies are ill-formed for both providers and would 400 upstream anyway,
// so the cost of refusing them is nil and the cost of guessing wrong is a
// chunked response nothing can resolve markers across.
//
// The key match is case-insensitive on purpose, and only at the TOP level.
// Case-insensitive because the previous struct-tag probe matched that way
// (encoding/json folds case when matching fields) and losing it would be a
// silent loosening of a security gate; top-level only because that is the sole
// place either provider reads "stream" from, and a nested one is inert.
func requestsStreaming(parsed any) bool {
	obj, ok := parsed.(map[string]any)
	if !ok {
		// No body, or not a JSON object: no top-level stream key can exist.
		return false
	}
	for k, v := range obj {
		if !strings.EqualFold(k, "stream") {
			continue
		}
		switch t := v.(type) {
		case nil:
			continue
		case bool:
			if !t {
				continue
			}
		}
		return true
	}
	return false
}

// logUsage records an attributed, best-effort usage line in the activity log.
// It extracts token counts from the provider response (Anthropic and OpenAI use
// different field names) without logging any prompt or completion content.
func (h *AIGatewayHandler) logUsage(r *http.Request, provider string, status int, respBody []byte, writeErr error) {
	var u struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens      int `json:"input_tokens"`
			OutputTokens     int `json:"output_tokens"`
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(respBody, &u)
	in := u.Usage.InputTokens + u.Usage.PromptTokens
	out := u.Usage.OutputTokens + u.Usage.CompletionTokens
	userID := middleware.GetUserID(r.Context())
	delivered := "yes"
	if writeErr != nil {
		// The provider billed us and the prompt already left, but the caller got
		// nothing. Record that distinctly so it is not read as a clean success.
		delivered = "NO (response not delivered to the caller)"
		logError(r, "ai_gateway: response could not be delivered", "provider", provider, "error", writeErr)
	}
	LogActivityFromRequest(h.queries, r, "ai.gateway_call",
		fmt.Sprintf("AI call: provider=%s model=%s status=%d in=%d out=%d user=%s delivered=%s",
			provider, u.Model, status, in, out, userID, delivered))
}

func randSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// aiConfigResponse is the operator-facing status of the AI surface: which
// provider keys are wired, whether Shield is on, and the connection URLs a user
// needs to point a client (SDK, extension, or MCP connector) at this instance.
type aiConfigResponse struct {
	AnthropicConfigured bool   `json:"anthropic_configured"`
	OpenAIConfigured    bool   `json:"openai_configured"`
	AnthropicEntryID    string `json:"anthropic_entry_id"`
	OpenAIEntryID       string `json:"openai_entry_id"`
	ShieldEnabled       bool   `json:"shield_enabled"`
	ShieldHintLevel     string `json:"shield_hint_level"`
	GatewayBaseURL      string `json:"gateway_base_url"`
	MCPURL              string `json:"mcp_url"`
}

// GetConfig handles GET /api/settings/ai for any authenticated user (they need
// the connection URLs + status to wire a client). It never returns key values.
func (h *AIGatewayHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	anth, _ := h.queries.GetSetting(ctx, "ai_key_anthropic")
	oai, _ := h.queries.GetSetting(ctx, "ai_key_openai")
	// The entry ids point at the vault entries holding the team LLM keys. Every
	// authenticated user needs the connection URLs and the configured flags to
	// wire a client, but only an admin needs (or should see) which entry holds
	// the key: it is a pointer straight at the most valuable secret in the vault.
	entryAnth, entryOAI := "", ""
	if middleware.IsAdmin(ctx) {
		entryAnth, entryOAI = anth, oai
	}
	writeJSON(w, http.StatusOK, aiConfigResponse{
		AnthropicConfigured: anth != "",
		OpenAIConfigured:    oai != "",
		AnthropicEntryID:    entryAnth,
		OpenAIEntryID:       entryOAI,
		ShieldEnabled:       h.cfg.ShieldEnabled(),
		ShieldHintLevel:     h.cfg.ShieldHintLevel,
		GatewayBaseURL:      strings.TrimRight(h.cfg.BaseURL, "/") + "/api/ai",
		MCPURL:              strings.TrimRight(h.cfg.BaseURL, "/") + "/api/mcp",
	})
}

// UpdateConfig handles PUT /api/settings/ai (admin only, enforced by the route).
// It points a provider at a vault entry that holds its key. An empty id clears
// the provider. A non-empty id must reference an existing vault entry.
func (h *AIGatewayHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		AnthropicEntryID *string `json:"anthropic_entry_id"`
		OpenAIEntryID    *string `json:"openai_entry_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	set := func(settingKey string, id *string) bool {
		if id == nil {
			return true
		}
		if *id != "" {
			if _, err := h.queries.GetVaultEntryForRotation(ctx, *id); err != nil {
				writeBadRequest(w, r, "the selected vault entry does not exist")
				return false
			}
		}
		if err := h.queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: settingKey, Value: *id}); err != nil {
			logError(r, "ai_gateway: setting update failed", "key", settingKey, "error", err)
			writeInternalError(w, r, "internal server error")
			return false
		}
		return true
	}
	if !set("ai_key_anthropic", req.AnthropicEntryID) {
		return
	}
	if !set("ai_key_openai", req.OpenAIEntryID) {
		return
	}
	LogActivityFromRequest(h.queries, r, "ai.config_updated", "AI gateway provider keys updated")
	h.GetConfig(w, r)
}

// extendProxyDeadlines lifts the server's global 30s write deadline for a single
// long-running proxied request.
//
// http.Server applies WriteTimeout once, when the request headers are read, so
// it bounds handler execution plus the response flush for the WHOLE request. The
// shared server sets 30s, which is right for ordinary API calls but far below
// what these two routes need: the AI gateway gives its upstream client a
// 5-minute budget and rejects stream:true, so the only supported mode is the one
// that blocks longest, and a 4000-token completion routinely exceeds 30s. The
// caller then got a bare EOF with no status code and no JSON error body, which
// an SDK treats as a transport failure and retries, doubling the spend on a
// provider call that had already succeeded and already received the prompt.
//
// Raising the global value instead would hand every other route a multi-minute
// slow-loris window, so the extension is per-handler and explicit. The read
// deadline stays short: the request body is small and bounded, and only the
// response is slow.
func extendProxyDeadlines(w http.ResponseWriter, write, read time.Duration) {
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(write)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.Warn("proxy: could not extend write deadline; long responses may be truncated", "error", err)
	}
	if err := rc.SetReadDeadline(time.Now().Add(read)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.Warn("proxy: could not extend read deadline", "error", err)
	}
}

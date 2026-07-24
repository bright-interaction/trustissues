package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
	"github.com/brightinteraction/trustissues/internal/shield"
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
}

var aiProviders = map[string]aiProvider{
	"anthropic": {
		baseURL:    "https://api.anthropic.com",
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
	ctx := r.Context()
	providerName := chi.URLParam(r, "provider")
	p, ok := h.providers[providerName]
	if !ok {
		writeBadRequest(w, r, "unknown AI provider (supported: anthropic, openai)")
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
	key, err := h.vault.DecryptedValueByID(ctx, entryID)
	if err != nil || key == "" {
		logError(r, "ai_gateway: provider key resolve failed", "provider", providerName, "error", err)
		writeInternalError(w, r, "provider key is not available")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAIBody))
	if err != nil {
		writeBadRequest(w, r, "request body too large or unreadable")
		return
	}

	// Streaming responses cannot be reliably tokenized/resolved across chunks, so
	// v1 supports non-streaming only. Reject stream:true up front.
	if requestsStreaming(body) {
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
		shielded, sErr := session.ShieldJSON(ctx, body)
		if sErr != nil {
			// Fail closed: never forward un-tokenized PII when Shield is on.
			logError(r, "ai_gateway: shield tokenization failed", "error", sErr)
			writeBadRequest(w, r, "request body could not be processed for tokenization")
			return
		}
		body = shielded
	}

	upstreamPath := "/" + chi.URLParam(r, "*")
	upReq, err := http.NewRequestWithContext(ctx, r.Method, p.baseURL+upstreamPath, bytes.NewReader(body))
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

	resp, err := h.client.Do(upReq)
	if err != nil {
		logError(r, "ai_gateway: upstream request failed", "provider", providerName, "error", err)
		writeError(w, r, http.StatusBadGateway, "upstream_error", "the AI provider could not be reached")
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAIBody))
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "upstream_error", "could not read the provider response")
		return
	}

	// Resolve markers back to plaintext for the (trusted) caller.
	if session != nil && len(respBody) > 0 {
		if resolved, uErr := session.UnshieldJSON(ctx, respBody); uErr == nil {
			respBody = resolved
		} else {
			logError(r, "ai_gateway: shield resolve failed (returning shielded body)", "error", uErr)
		}
	}

	h.logUsage(r, providerName, resp.StatusCode, respBody)

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// requestsStreaming reports whether the JSON body sets "stream": true.
func requestsStreaming(body []byte) bool {
	var probe struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &probe)
	return probe.Stream
}

// logUsage records an attributed, best-effort usage line in the activity log.
// It extracts token counts from the provider response (Anthropic and OpenAI use
// different field names) without logging any prompt or completion content.
func (h *AIGatewayHandler) logUsage(r *http.Request, provider string, status int, respBody []byte) {
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
	LogActivityFromRequest(h.queries, r, "ai.gateway_call",
		fmt.Sprintf("AI call: provider=%s model=%s status=%d in=%d out=%d user=%s",
			provider, u.Model, status, in, out, userID))
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
	writeJSON(w, http.StatusOK, aiConfigResponse{
		AnthropicConfigured: anth != "",
		OpenAIConfigured:    oai != "",
		AnthropicEntryID:    anth,
		OpenAIEntryID:       oai,
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

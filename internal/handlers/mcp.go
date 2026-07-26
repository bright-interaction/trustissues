package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
	"github.com/brightinteraction/trustissues/internal/shield"
)

// MCPHandler serves a remote HTTP MCP endpoint (JSON-RPC 2.0 over a single POST)
// so both Claude and ChatGPT connectors can reach it. It exposes the vault to an
// AI assistant WITHOUT ever handing it a plaintext secret:
//   - list_secrets: the names of secrets the caller may use (never values)
//   - use_secret:   mints a single-use, destination-bound capability token so
//     the assistant can act with a secret it never sees (via /proxy)
//
// Tool results cross to the external model through Shield: any PII is tokenized
// on the way out. Auth is the same X-API-Key / session middleware as the rest of
// /api, so the caller is a real Trustissues user.
type MCPHandler struct {
	queries     *db.Queries
	cfg         *config.Config
	capability  *CapabilityHandler
	shieldStore shield.Store // nil when Shield is disabled
	// mintLimiter is the SAME sensitive-op limiter the HTTP mint route
	// (/api/secrets/issue) is wrapped in. use_secret calls Issue in-process and
	// would otherwise skip that middleware entirely, letting an agent mint
	// unlimited capability tokens. nil disables the check (tests only).
	mintLimiter *middleware.RateLimiter
}

func NewMCPHandler(queries *db.Queries, cfg *config.Config, capability *CapabilityHandler, store shield.Store, mintLimiter *middleware.RateLimiter) *MCPHandler {
	return &MCPHandler{queries: queries, cfg: cfg, capability: capability, shieldStore: store, mintLimiter: mintLimiter}
}

const mcpProtocolVersion = "2024-11-05"

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Handle serves POST /api/mcp.
func (h *MCPHandler) Handle(w http.ResponseWriter, r *http.Request) {
	var req jsonrpcRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, jsonrpcResponse{JSONRPC: "2.0", Error: &jsonrpcError{Code: -32700, Message: "parse error"}})
		return
	}

	switch req.Method {
	case "initialize":
		h.reply(w, req.ID, map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "trustissues", "version": "1"},
		})
	case "notifications/initialized", "notifications/cancelled":
		// Notifications carry no id and expect no response.
		w.WriteHeader(http.StatusAccepted)
	case "ping":
		h.reply(w, req.ID, map[string]any{})
	case "tools/list":
		h.reply(w, req.ID, map[string]any{"tools": mcpTools})
	case "tools/call":
		h.callTool(w, r, req)
	default:
		h.replyErr(w, req.ID, -32601, "method not found")
	}
}

func (h *MCPHandler) reply(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, http.StatusOK, jsonrpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func (h *MCPHandler) replyErr(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeJSON(w, http.StatusOK, jsonrpcResponse{JSONRPC: "2.0", ID: id, Error: &jsonrpcError{Code: code, Message: msg}})
}

var mcpTools = []map[string]any{
	{
		"name":        "list_secrets",
		"description": "List the names of secrets you are allowed to use. Values are never returned. Use a name with use_secret to act with a secret without seeing it.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
	},
	{
		"name":        "use_secret",
		"description": "Mint a short-lived, single-use, destination-bound capability token for a secret. You never receive the secret value: send your HTTP request to the returned proxy_url with header 'Authorization: Capability <token>' and Trustissues injects the real secret server-side toward the allowed destination.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":        map[string]any{"type": "string", "description": "secret name from list_secrets"},
				"destination": map[string]any{"type": "string", "description": "optional host+path this token may be used against; must fall within the secret's allow-list"},
			},
			"required": []string{"name"},
		},
	},
}

// mcpToolResult is the MCP tools/call result shape.
func mcpToolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func (h *MCPHandler) callTool(w http.ResponseWriter, r *http.Request, req jsonrpcRequest) {
	ctx := r.Context()
	userID := middleware.GetUserID(ctx)
	if userID == "" {
		h.replyErr(w, req.ID, -32000, "authentication required")
		return
	}

	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	_ = json.Unmarshal(req.Params, &params)

	var resultText string
	var isErr bool
	switch params.Name {
	case "list_secrets":
		resultText, isErr = h.toolListSecrets(ctx, userID)
	case "use_secret":
		resultText, isErr = h.toolUseSecret(r, userID, params.Arguments)
	default:
		h.replyErr(w, req.ID, -32602, "unknown tool")
		return
	}

	// Shield: tokenize any PII in the result before it reaches the external model.
	if h.shieldStore != nil && resultText != "" {
		if session, err := shield.NewSession(ctx, h.shieldStore, randSessionID(),
			[]byte(h.cfg.ShieldKey), 30*time.Minute, shield.ParseHintLevel(h.cfg.ShieldHintLevel)); err == nil {
			if red, rErr := session.RedactString(ctx, resultText); rErr == nil && red != "" {
				resultText = red
			}
		}
	}

	h.reply(w, req.ID, mcpToolResult(resultText, isErr))
}

func (h *MCPHandler) toolListSecrets(ctx context.Context, userID string) (string, bool) {
	names, err := h.queries.ListAccessibleVaultEntryNames(ctx, db.ListAccessibleVaultEntryNamesParams{
		UserID: userID, UserID_2: userID,
	})
	if err != nil {
		return "could not list secrets", true
	}
	if len(names) == 0 {
		return "You have no secrets available.", false
	}
	out, _ := json.Marshal(map[string]any{"secrets": names})
	return string(out), false
}

func (h *MCPHandler) toolUseSecret(r *http.Request, userID string, args json.RawMessage) (string, bool) {
	var a struct {
		Name        string `json:"name"`
		Destination string `json:"destination"`
	}
	_ = json.Unmarshal(args, &a)
	if a.Name == "" {
		return "the 'name' argument is required", true
	}
	if !h.mintAllowed(r) {
		return "rate limited: too many capability tokens minted, try again later", true
	}

	// Reuse the audited capability Issue path in-process. A synthetic request
	// carries the authenticated context so the same auth, ACL, and destination-
	// ceiling checks run; a capture writer collects the JSON response.
	issue := issueRequest{
		Secret:      a.Name,
		AgentID:     "mcp:" + userID,
		Destination: a.Destination,
	}
	// A caller-supplied destination must actually NARROW the token. Dests is
	// what drives the ceiling logic in Issue (which can only narrow the secret's
	// allow-list, never widen it); leaving it unset meant an assistant asking
	// for a single endpoint silently received a token carrying the secret's full
	// destination ceiling and every method. A destination outside the ceiling
	// now comes back as an error tool-result instead of a wider token.
	if a.Destination != "" {
		issue.Dests = []string{a.Destination}
	}
	reqBody, _ := json.Marshal(issue)
	subReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "/api/secrets/issue", bytes.NewReader(reqBody))
	if err != nil {
		return "internal error", true
	}
	subReq.Host = r.Host
	subReq.Header.Set("X-Forwarded-Proto", schemeOf(r))
	cw := &captureWriter{header: http.Header{}}
	h.capability.Issue(cw, subReq)

	if cw.status != http.StatusCreated {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(cw.body.Bytes(), &e)
		if e.Error == "" {
			e.Error = "could not mint a capability token"
		}
		// Surface the machine-readable code (dests_exceed_ceiling,
		// agent_not_granted, ...) so the model can tell "ask for less" apart
		// from "you have no access".
		if e.Code != "" {
			return e.Code + ": " + e.Error, true
		}
		return e.Error, true
	}
	// Pass the token response straight through; it contains no secret value.
	return cw.body.String(), false
}

// mintAllowed spends one unit of the sensitive-op rate-limit budget and reports
// whether this request may mint a capability token. It runs the real request
// through the SAME limiter instance the /api/secrets/issue route is wrapped in,
// so the HTTP and MCP entry points share one budget instead of the in-process
// call bypassing the middleware. Keying matches that route exactly (the
// limiter's own trusted-hop client-IP derivation), so a caller cannot get a
// second allowance simply by switching entry point.
func (h *MCPHandler) mintAllowed(r *http.Request) bool {
	if h.mintLimiter == nil {
		return true
	}
	cw := &captureWriter{header: http.Header{}}
	limited := middleware.RateLimit(h.mintLimiter)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	limited.ServeHTTP(cw, r)
	return cw.status != http.StatusTooManyRequests
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}

// captureWriter is a minimal http.ResponseWriter that records the status and
// body of an in-process handler call (used to reuse the Issue handler without a
// network round-trip or a refactor of the security-critical path).
type captureWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (c *captureWriter) Header() http.Header { return c.header }
func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}
func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(b)
}

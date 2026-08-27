package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/shield"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
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
	queries    *db.Queries
	cfg        *config.Config
	capability *CapabilityHandler
	// shieldStore is nil when Shield is disabled. It is deliberately unused on
	// the tools/call path: see the comment in callTool for why a blanket redact
	// there breaks the feature. Kept because any future field-level shielding of
	// tool arguments would need it, and because the constructor is called from
	// main.go and the tests.
	shieldStore shield.Store
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

	// Deliberately NOT Shield-redacted. This used to run RedactString over the
	// whole tool result, which broke the feature outright in any deployment with
	// TRUSTISSUES_SHIELD_KEY set (which is every real one, including prod).
	//
	// Why it was wrong here. Shield exists to keep third-party PII out of an
	// external model. These two tools return no PII and no secret VALUE: that is
	// the entire point of the capability bridge. list_secrets returns names of
	// the caller's own entries, and use_secret returns
	// {token, proxy_url, secret (the NAME), expires_at, nonce_length}. Every one
	// of those fields has to survive verbatim for the feature to work.
	//
	// What it actually did. The redactor's catch-all FQDN pattern rewrote our
	// own proxy_url into "https://[shield:hostname:tok_...]/proxy", so the agent
	// had no address to send the request to, and it rewrote any secret whose
	// name contains a dotted domain ("api.openai.com key") into a marker, so
	// feeding that name back to use_secret returned secret_not_found. Worse, the
	// session id was randSessionID() per call and discarded with the response,
	// and callTool never unshields arguments on the way back in, so the markers
	// were permanently unresolvable by anyone.
	//
	// If PII filtering is ever wanted on this path it has to be field-level on
	// the JSON (never proxy_url, never the name), with a session id derived
	// stably from the authenticated principal and an unshield pass over incoming
	// arguments. A blanket string redact cannot work here.
	h.reply(w, req.ID, mcpToolResult(resultText, isErr))
}

// nameOpener returns the door that opens vault_entries.name, or nil if this
// handler has none.
//
// It is the SAME door the capability mint path uses (lookupSecretByName reaches
// h.vault.EntryNamePlain through this very field), deliberately: a second
// decryption door next to the first is what the vaultfield ledger exists to
// prevent, and the two paths have to agree on what a name is or list_secrets
// advertises strings use_secret cannot resolve.
//
// It can be nil, and BOTH callers enforce nil as a refusal. NewMCPHandler takes
// the capability handler as a pointer and callers do pass nil (the tests do), so
// a bare h.capability.vault dereference panics into chi's Recoverer and answers
// a content-free 500. toolListSecrets refuses before it reads a single row;
// toolUseSecret refuses before it reaches h.capability.Issue, which dereferences
// that same pointer. That second guard was missing while this comment claimed
// otherwise, so the sentence is now a statement about code that exists:
// TestMCPListSecretsFailsClosedWithoutADecryptionDoor and
// TestMCPUseSecretFailsClosedWithoutACapabilityHandler are what hold it true.
//
// Production cannot reach nil (main.go os.Exit(1)s when NewCapabilityHandler
// fails), which is exactly why the guards are cheap and why the interesting
// failure is the one below: a door that is PRESENT and cannot open a given row.
func (h *MCPHandler) nameOpener() entrySecretSource {
	if h.capability == nil {
		return nil
	}
	return h.capability.vault
}

func (h *MCPHandler) toolListSecrets(ctx context.Context, userID string) (string, bool) {
	// THE DECRYPT DOOR IS FETCHED FIRST, AND ITS ABSENCE FAILS CLOSED.
	//
	// vault_entries.name has been randomized AES-GCM ciphertext since 00040.
	// This tool used to marshal the stored column straight into the tool result,
	// and a tool result crosses to Anthropic or OpenAI: the model provider
	// received one "enc:v1:..." blob per entry, and so learned the caller's
	// exact secret inventory COUNT and each name's exact plaintext length, from
	// the one product whose whole point is that a keyless third party learns
	// neither. The blobs were also useless to the agent, since use_secret
	// matches on the cleartext name and can never be handed one that matches.
	//
	// If the door is missing there is no safe degradation, because returning the
	// stored column IS the bug. The tool refuses instead.
	opener := h.nameOpener()
	if opener == nil {
		slog.Error("mcp: list_secrets has no name-decryption door; refusing rather than " +
			"returning stored vault_entries.name to the model provider")
		return "could not list secrets", true
	}
	// Scope note: the capability minting path (lookupSecretByName) resolves only
	// the caller's OWN entries, so advertising collection secrets here would list
	// names the agent can never obtain a token for, and would leak the names of
	// shared secrets to a model for no benefit. Keep the list to what is usable.
	// Accessible scope, not user_id alone: the advertised set must match what the
	// capability bridge will actually mint for. Listing by owner meant a member
	// removed from a collection still saw the shared entry offered to their agent
	// (and, before the lookup fix, could still mint for it).
	stored, err := h.queries.ListAccessibleVaultEntryNames(ctx, db.ListAccessibleVaultEntryNamesParams{
		UserID: userID, UserID_2: userID, PrivateIngress: privateIngressSQLFlag(ctx),
	})
	if err != nil {
		return "could not list secrets", true
	}

	// A DROPPED NAME IS COUNTED, BECAUSE "I COULD NOT READ IT" AND "YOU DO NOT
	// HAVE ONE" ARE DIFFERENT ANSWERS AND ONLY ONE OF THEM IS TRUE.
	//
	// Both continues below are failures to READ a row that exists. Silently
	// swallowing them let a partial listing look complete and, in the limit, let
	// an unreadable inventory answer "You have no secrets available." with
	// isError:false: a flat, authoritative denial that the caller has any
	// credentials at all. An agent believing that goes to its fallback, and the
	// realistic fallback is asking the human to paste the key into the chat,
	// which puts a live secret into the model provider's transcript. That is a
	// worse outcome than the refusal thirty lines up, and it is far more likely
	// to happen: nil is impossible in production (main.go exits if the handler
	// fails to build) while a name that will not open is not. A row damaged in
	// place, or a master-key rotation observed mid-sweep, produces exactly this.
	names := make([]string, 0, len(stored))
	dropped := 0
	for _, raw := range stored {
		// EntryNamePlain returns an UNSEALED value unchanged, which keeps a
		// pre-backfill or interrupted legacy row with an empty/stale name_bidx
		// listed until the boot repair converges it, and it returns "" when a
		// sealed value will not open under the current key.
		plain := opener.EntryNamePlain(raw)
		if plain == "" {
			dropped++
			continue
		}
		// Belt and braces, and not decoration: this is the line that makes "no
		// ciphertext reaches the model provider" true regardless of what a
		// future opener decides to do with a value it cannot read. A name the
		// agent cannot feed back to use_secret is worth nothing to it anyway.
		if vaultfield.IsSealedColumn(plain) {
			slog.Error("mcp: list_secrets dropped a name that is still sealed after opening it")
			dropped++
			continue
		}
		names = append(names, plain)
	}

	if len(names) == 0 {
		// Nothing readable. If rows were dropped this is a failure, not an empty
		// vault, and it fails closed the same way the missing-door branch does.
		// Only a genuinely empty result set may say the inventory is empty.
		if dropped > 0 {
			slog.Error("mcp: list_secrets could not open any accessible name; refusing rather than "+
				"reporting an empty inventory", "dropped", dropped, "rows", len(stored))
			return fmt.Sprintf("could not list secrets: %d could not be read. "+
				"This is NOT an empty vault; do not conclude that no credential exists.", dropped), true
		}
		return "You have no secrets available.", false
	}

	// Some names opened and some did not. The readable ones are still usable, so
	// this stays a success, but the incompleteness is stated in the payload
	// rather than left for the agent to infer. The count only: a name that would
	// not open must not be described by anything that came out of the column.
	payload := map[string]any{"secrets": names}
	if dropped > 0 {
		slog.Error("mcp: list_secrets returned a partial inventory",
			"listed", len(names), "dropped", dropped)
		noun := "secrets"
		if dropped == 1 {
			noun = "secret"
		}
		payload["omitted"] = dropped
		payload["warning"] = fmt.Sprintf(
			"%d %s could not be read and are omitted from this list; it is incomplete.", dropped, noun)
	}
	out, _ := json.Marshal(payload)
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
	// THE DOOR IS CHECKED HERE TOO. h.capability.Issue below dereferences the
	// same pointer nameOpener guards, and lookupSecretByName inside it reaches
	// h.vault.EntryNamePlain, so a nil either way is a panic into chi's
	// Recoverer and a bare 500 rather than a refusal the agent can read. This
	// costs one comparison and it is what makes nameOpener's contract enforced
	// instead of merely documented.
	if h.nameOpener() == nil {
		slog.Error("mcp: use_secret has no capability handler; refusing rather than panicking")
		return "could not mint a capability token", true
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
	// RemoteAddr too, not just the header. This request never touches a socket,
	// so without it the peer-trust gate behind proxyBaseURL sees an empty
	// RemoteAddr, refuses to believe any forwarding header, and hands the agent
	// an http:// proxy URL that it then sends a live capability token to. The
	// X-Forwarded-Proto set on the next line is only meaningful once the gate
	// has a peer it can place.
	subReq.RemoteAddr = r.RemoteAddr
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
	if middleware.ForwardedProtoHTTPS(r) {
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

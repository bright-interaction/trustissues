package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// aiCallerRequest builds a request from an ordinary role-'user' client, which is
// the role every client of a shared instance gets. vault_only is already refused
// by VaultOnlyBlock on the route group, so it is not the interesting caller.
func aiCallerRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	ctx := context.WithValue(r.Context(), timw.UserIDKey, "client-a-user")
	ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
	return r.WithContext(ctx)
}

// TestAIGatewayRefusesNonInferenceRoutes locks the per-caller scoping on the AI
// gateway.
//
// The gateway injects the OPERATOR's provider key server-side, so every request
// runs with the operator's full account rights, and it applied no scoping at
// all: the caller named the method and the path and the gateway executed it.
//
//	curl -X DELETE -H 'X-API-Key: ti_<client>' https://host/api/ai/openai/v1/files/file-abc123
//
// deleted an object on the operator's OpenAI account. The same shape reaches
// fine-tuning jobs, assistants, uploads and the batch API, and unlimited POSTs
// to anything at all bill the operator. On a shared instance that is one client
// spending and destroying another's resources.
//
// The invariant: only the inference surface is reachable, the refusal happens
// BEFORE the operator's key is decrypted, and the legitimate non-streaming
// completion path still works.
func TestAIGatewayRefusesNonInferenceRoutes(t *testing.T) {
	conn := aiGatewayTestDB(t)
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: "test-vault-key"}
	vh := NewVaultHandler(conn, queries, cfg)
	seedProviderKey(t, conn, vh, "ai_key_openai", "sk-openai-REALKEY")
	seedProviderKey(t, conn, vh, "ai_key_anthropic", "sk-ant-REALKEY")

	// Any upstream hit at all is a failure for the refused cases: the operator's
	// key would already have egressed and the account already been touched.
	var upstreamHits []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits = append(upstreamHits, r.Method+" "+r.URL.Path)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"model":"m","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	h := NewAIGatewayHandler(queries, cfg, vh, nil)
	for _, name := range []string{"openai", "anthropic"} {
		p := h.providers[name]
		p.baseURL = upstream.URL
		h.providers[name] = p
	}
	router := gatewayRouter(h)

	refused := []struct {
		name, method, path, body string
	}{
		{
			name:   "the reported attack: deleting an object on the operator's account",
			method: http.MethodDelete,
			path:   "/api/ai/openai/v1/files/file-abc123",
		},
		{
			name:   "listing the operator's uploaded files",
			method: http.MethodGet,
			path:   "/api/ai/openai/v1/files",
		},
		{
			name:   "starting a fine-tune the operator pays for",
			method: http.MethodPost,
			path:   "/api/ai/openai/v1/fine_tuning/jobs",
			body:   `{"model":"gpt-4","training_file":"file-abc"}`,
		},
		{
			name:   "creating an assistant on the operator's account",
			method: http.MethodPost,
			path:   "/api/ai/openai/v1/assistants",
			body:   `{"model":"gpt-4"}`,
		},
		{
			name:   "overwriting something with PUT",
			method: http.MethodPut,
			path:   "/api/ai/openai/v1/models/gpt-4",
			body:   `{}`,
		},
		{
			name:   "anthropic batch results",
			method: http.MethodGet,
			path:   "/api/ai/anthropic/v1/messages/batches",
		},
		{
			name:   "deleting an anthropic batch",
			method: http.MethodDelete,
			path:   "/api/ai/anthropic/v1/messages/batches/batch-1",
		},
		{
			name:   "an allowed path reached with a destructive verb",
			method: http.MethodDelete,
			path:   "/api/ai/anthropic/v1/messages",
		},
		{
			// Deciding on a raw path and forwarding it is how allowlists get
			// walked past. The gateway must clean the path first and match and
			// forward the SAME string.
			name:   "traversal out of an allowed prefix",
			method: http.MethodDelete,
			path:   "/api/ai/openai/v1/chat/completions/../../v1/files/file-abc123",
		},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			upstreamHits = nil
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, aiCallerRequest(c.method, c.path, c.body))
			if rr.Code != http.StatusForbidden {
				t.Fatalf("%s %s: HTTP %d, want 403 (body: %s)", c.method, c.path, rr.Code, rr.Body.String())
			}
			if len(upstreamHits) != 0 {
				t.Fatalf("%s %s reached the provider anyway (%v): the operator's key already egressed",
					c.method, c.path, upstreamHits)
			}
			if !strings.Contains(rr.Body.String(), "route_not_allowed") {
				t.Errorf("refusal should name the reason, got %s", rr.Body.String())
			}
		})
	}

	// The legitimate inference path must be untouched, or the fix is a denial of
	// service on the feature it protects.
	allowed := []struct {
		name, method, path, body string
	}{
		{"anthropic messages", http.MethodPost, "/api/ai/anthropic/v1/messages",
			`{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}`},
		{"anthropic token count", http.MethodPost, "/api/ai/anthropic/v1/messages/count_tokens",
			`{"model":"claude-3","messages":[]}`},
		{"anthropic model list", http.MethodGet, "/api/ai/anthropic/v1/models", ""},
		{"openai chat completions", http.MethodPost, "/api/ai/openai/v1/chat/completions",
			`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`},
		{"openai embeddings", http.MethodPost, "/api/ai/openai/v1/embeddings",
			`{"model":"text-embedding-3-small","input":"hi"}`},
		{"openai single model", http.MethodGet, "/api/ai/openai/v1/models/gpt-4", ""},
	}
	for _, c := range allowed {
		t.Run(c.name+" still works", func(t *testing.T) {
			upstreamHits = nil
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, aiCallerRequest(c.method, c.path, c.body))
			if rr.Code != http.StatusOK {
				t.Fatalf("%s %s: HTTP %d, want 200 (body: %s)", c.method, c.path, rr.Code, rr.Body.String())
			}
			if len(upstreamHits) != 1 {
				t.Fatalf("%s %s did not reach the provider exactly once: %v", c.method, c.path, upstreamHits)
			}
		})
	}
}

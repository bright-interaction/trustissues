package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	//
	// RequestURI, not URL.Path: the whole bug class here is a path that MATCHES
	// as one string and TRAVELS as another, and only the wire form shows that.
	var upstreamHits []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits = append(upstreamHits, r.Method+" "+r.URL.RequestURI())
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
		// ── normalization ────────────────────────────────────────────────
		//
		// These are the cases that actually exercise the path handling, and the
		// first version of this test had none of them. It used
		// "DELETE /v1/chat/completions/../../v1/files/file-abc123", but
		// openaiRoutes contains no DELETE route at all, so the request was
		// refused on METHOD before any path work happened: ablating path.Clean
		// entirely left the subtest, and the whole package, green. A guard that
		// cannot fail is worse than no guard, because it is counted as coverage.
		//
		// Every case below uses GET against the one allowed PREFIX route
		// (GET /v1/models/{id}), so method and prefix both match and the only
		// thing standing between the caller and the operator's key is
		// normalizeUpstreamPath.
		{
			// Plain traversal. Cleaning alone catches this one.
			name:   "traversal out of an allowed prefix",
			method: http.MethodGet,
			path:   "/api/ai/openai/v1/models/../../v1/files",
		},
		{
			// The reviewer's live bypass: chi routes on RawPath, so the wildcard
			// param is ESCAPED and path.Clean does not collapse "%2e%2e". This
			// returned HTTP 200 with "Authorization: Bearer sk-..." on the wire.
			name:   "percent-encoded traversal out of an allowed prefix",
			method: http.MethodGet,
			path:   "/api/ai/openai/v1/models/%2e%2e/%2e%2e/v1/files",
		},
		{
			name:   "encoded slash traversal",
			method: http.MethodGet,
			path:   "/api/ai/openai/v1/models/..%2f..%2fv1/files",
		},
		{
			name:   "encoded traversal into the batch API",
			method: http.MethodGet,
			path:   "/api/ai/anthropic/v1/models/%2e%2e/messages/batches",
		},
		{
			// Decoding once is not enough on its own: "%252e" becomes "%2e",
			// which the provider decodes again. Refusing anything that still
			// carries a '%' after one decode is what closes the whole family.
			name:   "double-encoded traversal",
			method: http.MethodGet,
			path:   "/api/ai/openai/v1/models/%252e%252e/%252e%252e/v1/files",
		},
		{
			// The case that makes path.Clean itself load-bearing: ".." is a
			// single, charset-clean segment under the allowed prefix, so without
			// the clean it is forwarded as "/v1/models/.." and the PROVIDER
			// resolves it to "/v1".
			name:   "a bare parent segment as the model id",
			method: http.MethodGet,
			path:   "/api/ai/anthropic/v1/models/..",
		},
		{
			name:   "a bare encoded parent segment as the model id",
			method: http.MethodGet,
			path:   "/api/ai/openai/v1/models/%2e%2e",
		},
		{
			// A prefix route carries exactly one id segment. Anything deeper is
			// a different endpoint on the operator's account.
			name:   "a second segment under the model prefix",
			method: http.MethodGet,
			path:   "/api/ai/openai/v1/models/gpt-4/permissions",
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
	// service on the feature it protects. wire is what the provider must see:
	// the string the allowlist MATCHED, byte for byte, since a check that
	// decides on one path and sends another is the bug this test exists for.
	allowed := []struct {
		name, method, path, body, wire string
	}{
		{"anthropic messages", http.MethodPost, "/api/ai/anthropic/v1/messages",
			`{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}`, "/v1/messages"},
		{"anthropic token count", http.MethodPost, "/api/ai/anthropic/v1/messages/count_tokens",
			`{"model":"claude-3","messages":[]}`, "/v1/messages/count_tokens"},
		{"anthropic model list", http.MethodGet, "/api/ai/anthropic/v1/models", "", "/v1/models"},
		{"openai chat completions", http.MethodPost, "/api/ai/openai/v1/chat/completions",
			`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`, "/v1/chat/completions"},
		{"openai embeddings", http.MethodPost, "/api/ai/openai/v1/embeddings",
			`{"model":"text-embedding-3-small","input":"hi"}`, "/v1/embeddings"},
		{"openai single model", http.MethodGet, "/api/ai/openai/v1/models/gpt-4", "", "/v1/models/gpt-4"},
		// A fine-tuned OpenAI model id, which is the realistic shape of that id
		// segment: colons and dots must survive the normalization.
		{"openai fine-tuned model", http.MethodGet, "/api/ai/openai/v1/models/ft:gpt-4o-mini-2024-07-18:acme::9abc",
			"", "/v1/models/ft:gpt-4o-mini-2024-07-18:acme::9abc"},
		// The one allowed case where the caller's path and the matched path
		// DIFFER, which is what makes "forward what you matched" testable at
		// all. Forwarding the raw string here would send "/v1/./models/gpt-4",
		// a path this gateway never checked.
		{"a redundant segment is normalized before it travels", http.MethodGet,
			"/api/ai/openai/v1/./models/gpt-4", "", "/v1/models/gpt-4"},
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
			if want := c.method + " " + c.wire; upstreamHits[0] != want {
				t.Fatalf("the gateway matched one path and sent another: provider saw %q, want %q",
					upstreamHits[0], want)
			}
		})
	}

	// A provider with no allowlist must get NOTHING through. Adding a provider
	// to aiProviders is a two-line change; inheriting "everything is allowed"
	// because providerInferenceRoutes was not updated is exactly the default
	// this work removed, so the gate fails closed on an unknown host.
	t.Run("a provider with no allowlist is refused entirely", func(t *testing.T) {
		p := h.providers["openai"]
		p.apiHost = "api.groq.com" // no entry in providerInferenceRoutes
		h.providers["groq"] = p
		defer delete(h.providers, "groq")

		for _, path := range []string{"/api/ai/groq/v1/chat/completions", "/api/ai/groq/v1/models"} {
			upstreamHits = nil
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, aiCallerRequest(http.MethodPost, path, `{"model":"m"}`))
			if rr.Code != http.StatusForbidden {
				t.Fatalf("%s on a provider with no allowlist: HTTP %d, want 403 (body: %s)",
					path, rr.Code, rr.Body.String())
			}
			if len(upstreamHits) != 0 {
				t.Fatalf("%s reached the provider anyway: %v", path, upstreamHits)
			}
		}
	})
}

// TestAIProviderBaseURLMatchesItsAllowlistHost pins the two halves of a provider
// entry together.
//
// apiHost is what the inference allowlist is looked up by, and baseURL is where
// the request actually goes. They are separate fields on purpose (tests override
// baseURL to reach a local server), which means they can drift: a provider whose
// baseURL points at one host while its allowlist is keyed to another would be
// scoped by a policy written for somewhere else, or by no policy at all.
func TestAIProviderBaseURLMatchesItsAllowlistHost(t *testing.T) {
	for name, p := range aiProviders {
		u, err := url.Parse(p.baseURL)
		if err != nil {
			t.Fatalf("%s: baseURL %q does not parse: %v", name, p.baseURL, err)
		}
		if u.Hostname() != p.apiHost {
			t.Errorf("%s: baseURL host %q != apiHost %q, so the allowlist applied is not the one for the host called",
				name, u.Hostname(), p.apiHost)
		}
		if _, ok := providerInferenceRoutes[p.apiHost]; !ok {
			t.Errorf("%s: apiHost %q has no entry in providerInferenceRoutes, so every call to it is refused",
				name, p.apiHost)
		}
	}
}

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/capability"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// recordingTransport answers every outbound request from memory and records what
// was on the wire. No network, and no way for a "refused" case to quietly
// succeed against a real host: an entry in reqs at all means the operator's key
// left the process.
type recordingTransport struct {
	reqs []string
	auth []string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.reqs = append(rt.reqs, r.Method+" "+r.URL.Host+r.URL.RequestURI())
	rt.auth = append(rt.auth, r.Header.Get("Authorization")+r.Header.Get("x-api-key"))
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Request:    r,
	}, nil
}

// TestCapabilityBridgeAppliesTheInferenceAllowlist closes the SIBLING call site
// of the AI gateway scoping fix.
//
// The gateway allowlist only ever guarded /api/ai/*. The capability bridge
// carries the SAME key to the SAME host through a different door: the vault
// entry an admin points ai_key_openai at is an ordinary entry, and a team key is
// naturally kept in a collection, where every accepted member resolves it
// through accessibleEntriesPredicate. The caller supplies the method and the
// destination, so a role-'user' client minted a token for
// api.openai.com/v1/files with DELETE and spent the operator's account there
// while the gateway's allowlist watched a door they never used.
//
// One property, two doors. The invariant: an LLM provider host is held to the
// inference allowlist wherever the request comes from, the refusal happens
// before the secret is decrypted, and non-provider destinations (the other 25
// presets) are untouched.
func TestCapabilityBridgeAppliesTheInferenceAllowlist(t *testing.T) {
	tdb := newTestDB(t)
	defer tdb.Close()

	const (
		creator  = "owner-user"
		client   = "client-a-user"
		agentID  = "client-a-agent"
		secretID = "secret-team-openai"
		theKey   = "sk-openai-OPERATOR-KEY"
	)

	capH := setupCapabilityHandler(t, tdb)
	rt := &recordingTransport{}
	capH.SetHTTPClient(&http.Client{Timeout: 5 * time.Second, Transport: rt})

	// The team's OpenAI key, exactly as an operator manages it: one vault entry,
	// living in a collection so the team can use it, with the conservative
	// preset ceiling from CapabilityDefaults.
	mustExec(t, tdb, `INSERT INTO vault_entries
		(id, user_id, collection_id, name, encrypted_value, nonce, encryption_version,
		 destination_patterns, injection_spec)
		VALUES (?, ?, 'coll-team', ?, ?, ?, 2, ?, ?)`,
		secretID, creator, "team-openai", []byte(theKey), []byte("test-nonce"),
		`["api.openai.com/*"]`, `{"type":"bearer"}`)
	mustExec(t, tdb, `INSERT INTO users (id, email) VALUES (?, ?)`, client, "client-a@example.com")
	mustExec(t, tdb, `INSERT INTO collection_members (collection_id, user_id, role, accepted_at)
		VALUES ('coll-team', ?, 'editor', datetime('now'))`, client)

	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capH.Proxy)

	mintDirect := func(t *testing.T, method, dest string) string {
		t.Helper()
		// Signed in-package, deliberately bypassing Issue: the proxy is the
		// authority here, and a mint-time check that the proxy did not back
		// would only move the bypass one step.
		signingKey, _ := capability.DeriveSigningKey(testCapVaultKey)
		tok, err := capability.Sign(capability.Token{
			Secret: "team-openai", SecretID: secretID, Issuer: client, Agent: agentID,
			Dests: []string{dest}, Method: method,
		}, signingKey, time.Minute)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return tok
	}

	call := func(t *testing.T, method, path, token string) *httptest.ResponseRecorder {
		t.Helper()
		rt.reqs, rt.auth = nil, nil
		req := httptest.NewRequest(method, "/proxy/api.openai.com"+path, strings.NewReader(""))
		req.Header.Set("Authorization", "Capability "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	refused := []struct {
		name, method, path string
	}{
		{"deleting an object on the operator's account", http.MethodDelete, "/v1/files/file-abc123"},
		{"listing the operator's uploaded files", http.MethodGet, "/v1/files"},
		{"starting a fine-tune the operator pays for", http.MethodPost, "/v1/fine_tuning/jobs"},
		{"creating an assistant", http.MethodPost, "/v1/assistants"},
		{"an allowed path with a destructive verb", http.MethodDelete, "/v1/chat/completions"},
		// The bridge normalizes with the same helper as the gateway, so the
		// percent-encoded traversal cannot walk in through this door either.
		{"percent-encoded traversal out of an allowed prefix", http.MethodGet, "/v1/models/%2e%2e/%2e%2e/v1/files"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			rec := call(t, c.method, c.path, mintDirect(t, "*", "api.openai.com/*"))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s: HTTP %d, want 403 (body: %s)", c.method, c.path, rec.Code, rec.Body.String())
			}
			if len(rt.reqs) != 0 {
				t.Fatalf("%s %s reached the provider anyway (%v): the operator's key already egressed %v",
					c.method, c.path, rt.reqs, rt.auth)
			}
			if !strings.Contains(rec.Body.String(), "route_not_allowed") {
				t.Errorf("the refusal should name the reason, got %s", rec.Body.String())
			}
		})
	}

	t.Run("the legitimate inference call still works", func(t *testing.T) {
		rec := call(t, http.MethodPost, "/v1/chat/completions", mintDirect(t, "POST", "api.openai.com/*"))
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /v1/chat/completions: HTTP %d (body: %s)", rec.Code, rec.Body.String())
		}
		if len(rt.reqs) != 1 || rt.reqs[0] != "POST api.openai.com/v1/chat/completions" {
			t.Fatalf("the bridge sent %v, want exactly one POST api.openai.com/v1/chat/completions", rt.reqs)
		}
		if rt.auth[0] != "Bearer "+theKey {
			t.Fatalf("the real key must still be injected on an allowed call, got %q", rt.auth[0])
		}
	})

	t.Run("a non-provider destination is untouched", func(t *testing.T) {
		// The other 25 presets are ordinary REST APIs where DELETE is a normal
		// thing for an agent to do. Scoping LLM providers must not turn the
		// bridge into an inference-only proxy.
		mustExec(t, tdb, `INSERT INTO vault_entries
			(id, user_id, name, encrypted_value, nonce, encryption_version, destination_patterns, injection_spec)
			VALUES ('secret-cf', ?, 'cf-token', ?, ?, 2, ?, ?)`,
			client, []byte("cf-secret"), []byte("n"), `["api.cloudflare.com/*"]`, `{"type":"bearer"}`)
		signingKey, _ := capability.DeriveSigningKey(testCapVaultKey)
		tok, err := capability.Sign(capability.Token{
			Secret: "cf-token", SecretID: "secret-cf", Issuer: client, Agent: agentID,
			Dests: []string{"api.cloudflare.com/*"}, Method: "*",
		}, signingKey, time.Minute)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		rt.reqs, rt.auth = nil, nil
		req := httptest.NewRequest(http.MethodDelete, "/proxy/api.cloudflare.com/client/v4/zones/z1/dns_records/r1", nil)
		req.Header.Set("Authorization", "Capability "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("DELETE against a non-provider host: HTTP %d (body: %s)", rec.Code, rec.Body.String())
		}
		if len(rt.reqs) != 1 {
			t.Fatalf("a non-provider call should reach upstream exactly once, got %v", rt.reqs)
		}
	})

	t.Run("Issue refuses a concrete provider destination up front", func(t *testing.T) {
		body, _ := json.Marshal(issueRequest{
			Secret: "team-openai", AgentID: agentID,
			Dests:  []string{"api.openai.com/v1/files/file-abc123"},
			Method: "DELETE",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, client))
		rec := httptest.NewRecorder()
		capH.Issue(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("minting for DELETE /v1/files: HTTP %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "route_not_allowed") {
			t.Errorf("the mint refusal should name the reason, got %s", rec.Body.String())
		}
	})

	t.Run("Issue still mints the ordinary globbed ceiling", func(t *testing.T) {
		body, _ := json.Marshal(issueRequest{Secret: "team-openai", AgentID: agentID, Method: "POST"})
		req := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, client))
		rec := httptest.NewRecorder()
		capH.Issue(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("minting against the preset ceiling: HTTP %d, want 201 (body: %s)", rec.Code, rec.Body.String())
		}
	})
}

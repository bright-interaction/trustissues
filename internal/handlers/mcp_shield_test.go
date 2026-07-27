package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/middleware"
	"github.com/brightinteraction/trustissues/internal/shield"
)

// TestMCPToolResultSurvivesAnEnabledShield locks the fix for a shipped feature
// that was dead in production.
//
// callTool used to run Shield's RedactString over the ENTIRE tool result. The
// redactor ends in a catch-all FQDN pattern, so it rewrote our own proxy_url
// into "https://[shield:hostname:tok_...]/proxy" and rewrote any secret whose
// name contains a dotted domain into a marker. The session id was random per
// call and thrown away, and nothing unshields incoming arguments, so those
// markers were unresolvable by anyone. The agent got a capability token it had
// no address to use and a secret name that use_secret then rejected.
//
// It survived because BOTH existing MCP tests pass nil for the shield store,
// which is the one configuration where the bug cannot appear. Production sets
// TRUSTISSUES_SHIELD_KEY, so production had the broken path. This test runs with
// a REAL store, deliberately.
func TestMCPToolResultSurvivesAnEnabledShield(t *testing.T) {
	tdb := newTestDB(t)
	t.Cleanup(func() { tdb.Close() })
	capH := setupCapabilityHandler(t, tdb)

	// A secret whose name contains a dotted hostname: precisely what the
	// catch-all FQDN pattern used to destroy.
	const dottedName = "api.openai.com key"
	mustExec(t, tdb, `INSERT INTO vault_entries
		(id, user_id, name, encrypted_value, nonce, encryption_version, destination_patterns, injection_spec)
		VALUES (?, ?, ?, ?, ?, 2, ?, '{"type":"bearer"}')`,
		"s-shield", "u", dottedName, []byte("sk-never-seen"), []byte("n"),
		`["api.openai.com/*"]`)

	// A REAL shield store with a real key, matching the shipped configuration.
	store := shield.NewSQLStore(tdb)
	cfg := &config.Config{
		ShieldKey:       strings.Repeat("s", 32),
		ShieldHintLevel: "full",
	}
	h := NewMCPHandler(nil, cfg, capH, store, nil)

	// Guard the setup: if the store is nil this test silently becomes the old,
	// useless one.
	if store == nil {
		t.Fatal("ABORT: nil shield store, this test would not exercise the bug")
	}

	call := func(tool, args string) string {
		t.Helper()
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}`
		r := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(body))
		r.Host = "trustissues.brightinteraction.com"
		r = r.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, "u"))
		rr := httptest.NewRecorder()
		h.Handle(rr, r)

		var env struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("%s: decode envelope: %v (body %s)", tool, err, rr.Body.String())
		}
		if len(env.Result.Content) == 0 {
			t.Fatalf("%s: empty result (body %s)", tool, rr.Body.String())
		}
		return env.Result.Content[0].Text
	}

	got := call("use_secret", `{"name":"`+dottedName+`"}`)
	if strings.Contains(got, "[shield:") {
		t.Fatalf("SHIELD DESTROYED THE RESULT: %s", got)
	}

	var ir issueResponse
	if err := json.Unmarshal([]byte(got), &ir); err != nil {
		t.Fatalf("use_secret result is not the expected JSON: %v (%s)", err, got)
	}
	// proxy_url must be a usable address, not a marker. Parse it and check the
	// HOST specifically: that is the part the FQDN redactor destroyed. The
	// scheme follows the request (http under httptest, https behind the real
	// TLS proxy), so asserting on it would test the harness, not the fix.
	pu, err := url.Parse(ir.ProxyURL)
	if err != nil {
		t.Fatalf("proxy_url does not parse: %q (%v)", ir.ProxyURL, err)
	}
	if pu.Host != "trustissues.brightinteraction.com" {
		t.Fatalf("proxy_url host is unusable: %q (the agent has nowhere to send the request)", ir.ProxyURL)
	}
	// The name must round-trip, or the agent cannot call use_secret with what
	// list_secrets gave it.
	if ir.Secret != dottedName {
		t.Fatalf("secret name was mangled: %q, want %q", ir.Secret, dottedName)
	}
	if ir.Token == "" {
		t.Fatal("no capability token minted")
	}

	// And the value itself must never appear: that is the property Shield was
	// nominally protecting, and it is guaranteed by the capability design rather
	// than by redaction.
	if strings.Contains(got, "sk-never-seen") {
		t.Fatalf("SECRET VALUE LEAKED into the MCP result: %s", got)
	}
}

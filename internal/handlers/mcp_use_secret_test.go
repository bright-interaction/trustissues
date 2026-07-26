package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brightinteraction/trustissues/internal/capability"
	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/middleware"
)

// useSecretFixture wires an MCP handler over the real capability handler with
// one secret whose allow-list spans two hosts, so a narrowing request has
// something to narrow.
func useSecretFixture(t *testing.T) (*MCPHandler, *http.Request) {
	t.Helper()
	tdb := newTestDB(t)
	t.Cleanup(func() { tdb.Close() })
	capH := setupCapabilityHandler(t, tdb)
	mustExec(t, tdb, `INSERT INTO vault_entries
		(id, user_id, name, encrypted_value, nonce, encryption_version, destination_patterns, injection_spec)
		VALUES (?, ?, ?, ?, ?, 2, ?, '{"type":"bearer"}')`,
		"s-mcp", "u", "openai", []byte("sk-never-seen"), []byte("n"),
		`["api.openai.com/*","api.anthropic.com/*"]`)

	h := NewMCPHandler(nil, &config.Config{}, capH, nil, nil)
	r := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
	r = r.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, "u"))
	return h, r
}

func mustVerifyMintedToken(t *testing.T, resultText string) capability.Token {
	t.Helper()
	var ir issueResponse
	if err := json.Unmarshal([]byte(resultText), &ir); err != nil {
		t.Fatalf("decode use_secret result: %v (text: %s)", err, resultText)
	}
	key, err := capability.DeriveSigningKey(testCapVaultKey)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	tok, err := capability.Verify(ir.Token, key, time.Now())
	if err != nil {
		t.Fatalf("verify minted token: %v", err)
	}
	return tok
}

// TestMCPUseSecret_HonorsDestinationNarrowing locks the fix for a silent
// privilege widening: use_secret accepted a "destination" argument but never
// put it in the issue request's Dests, so the ceiling-narrowing logic never ran
// and an assistant asking for one endpoint received a token carrying the
// secret's FULL destination allow-list.
func TestMCPUseSecret_HonorsDestinationNarrowing(t *testing.T) {
	h, r := useSecretFixture(t)

	text, isErr := h.toolUseSecret(r, "u", json.RawMessage(
		`{"name":"openai","destination":"api.openai.com/v1/chat/completions"}`))
	if isErr {
		t.Fatalf("narrowing request should succeed, got error result: %s", text)
	}
	tok := mustVerifyMintedToken(t, text)
	if len(tok.Dests) != 1 || tok.Dests[0] != "api.openai.com/v1/chat/completions" {
		t.Fatalf("token must carry ONLY the requested destination, got %v", tok.Dests)
	}
	for _, d := range tok.Dests {
		if strings.Contains(d, "anthropic") {
			t.Fatalf("token widened back to the full ceiling: %v", tok.Dests)
		}
	}
}

// TestMCPUseSecret_RejectsDestinationOutsideCeiling proves the caller is told
// no instead of quietly handed a wider token.
func TestMCPUseSecret_RejectsDestinationOutsideCeiling(t *testing.T) {
	h, r := useSecretFixture(t)

	text, isErr := h.toolUseSecret(r, "u", json.RawMessage(
		`{"name":"openai","destination":"api.evil.example/exfil"}`))
	if !isErr {
		t.Fatalf("out-of-ceiling destination must be an error result, got: %s", text)
	}
	if !strings.Contains(text, "dests_exceed_ceiling") {
		t.Fatalf("error should name dests_exceed_ceiling so the model can react, got: %s", text)
	}
}

// TestMCPUseSecret_NoDestinationKeepsCeiling documents that behavior is
// unchanged when the caller asks for nothing narrower.
func TestMCPUseSecret_NoDestinationKeepsCeiling(t *testing.T) {
	h, r := useSecretFixture(t)

	text, isErr := h.toolUseSecret(r, "u", json.RawMessage(`{"name":"openai"}`))
	if isErr {
		t.Fatalf("plain request should succeed, got error result: %s", text)
	}
	tok := mustVerifyMintedToken(t, text)
	if len(tok.Dests) != 2 {
		t.Fatalf("without a destination the token keeps the full ceiling, got %v", tok.Dests)
	}
}

// TestMCPMintSharesSensitiveOpBudget proves the MCP use_secret path and the
// HTTP mint route spend ONE budget. use_secret calls the Issue handler
// in-process, so without this check it skipped the rate-limit middleware that
// guards POST /api/secrets/issue and an agent could mint capability tokens
// without limit.
func TestMCPMintSharesSensitiveOpBudget(t *testing.T) {
	limiter := middleware.NewRateLimiter(2, time.Minute)
	h := &MCPHandler{mintLimiter: limiter}

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
		r.RemoteAddr = "203.0.113.7:44321"
		return r
	}

	// Spend one unit the way the HTTP mint route does: through the middleware
	// wrapping POST /api/secrets/issue, against the same limiter instance.
	httpRoute := middleware.RateLimit(limiter)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	rec := httptest.NewRecorder()
	httpRoute.ServeHTTP(rec, newReq())
	if rec.Code != http.StatusCreated {
		t.Fatalf("first HTTP mint should be allowed, got %d", rec.Code)
	}

	// Budget of 2, one already spent over HTTP: MCP gets exactly one more.
	if !h.mintAllowed(newReq()) {
		t.Fatal("second mint (first over MCP) should be allowed")
	}
	if h.mintAllowed(newReq()) {
		t.Fatal("third mint must be rate limited: the MCP path shares the HTTP route's budget")
	}

	// A nil limiter (tests, or a caller that wires none) never blocks.
	if !(&MCPHandler{}).mintAllowed(newReq()) {
		t.Fatal("nil limiter should not block")
	}
}

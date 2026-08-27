package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"

	"github.com/bright-interaction/trustissues/internal/capability"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool // true when the input was already normalized
	}{
		{"/v1/chat/completions", "/v1/chat/completions", true},
		{"/", "/", true},
		{"", "", true},
		{"/v1/", "/v1/", true}, // trailing slash is meaningful, kept
		{"/v1/../../admin", "/admin", false},
		{"/v1/../admin", "/admin", false},
		{"/v1/./x", "/v1/x", false},
		{"/v1//x", "/v1/x", false},
		{"/..", "/", false},
	}
	for _, tc := range cases {
		got, ok := normalizePath(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("normalizePath(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

// TestProxy_RejectsPathTraversal is the exploit proof for the destination
// allow-list bypass: "/v1/../../admin" matches an allow-listed "/v1/*" prefix
// but resolves to "/admin" upstream, so before normalization the bridge injected
// the real secret toward an endpoint the token never authorised.
func TestProxy_RejectsPathTraversal(t *testing.T) {
	tdb := newTestDB(t)
	defer tdb.Close()

	const (
		userID   = "u"
		agentID  = "a"
		secretID = "s-traversal"
		host     = "api.example.com"
	)
	capH := setupCapabilityHandler(t, tdb)
	mustExec(t, tdb, `INSERT INTO vault_entries
		(id, user_id, name, encrypted_value, nonce, encryption_version, destination_patterns, injection_spec)
		VALUES (?, ?, ?, ?, ?, 2, ?, '{"type":"bearer"}')`,
		secretID, userID, "scoped_key", []byte("sk-must-not-escape"), []byte("n"),
		`["`+host+`/v1/*"]`)

	// Precondition: the raw traversal path DOES satisfy the allow-list check.
	// Without normalization the request sails past every destination gate.
	if !destMatches([]string{host + "/v1/*"}, host, "/v1/../../admin") {
		t.Fatal("precondition: raw traversal path should match the /v1/* pattern")
	}

	signingKey, _ := capability.DeriveSigningKey(testCapVaultKey)
	tok, err := capability.Sign(capability.Token{
		Secret: "scoped_key", SecretID: secretID, Issuer: userID, Agent: agentID,
		Dests:  []string{host + "/v1/*"},
		Method: "POST",
	}, signingKey, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capH.Proxy)

	req := httptest.NewRequest(http.MethodPost, "/proxy/"+host+"/v1/../../admin", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Capability "+tok)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal path should be rejected with 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_path") {
		t.Fatalf("body should name invalid_path, got %s", rec.Body.String())
	}

	// Rejected before the token is spent, so a legitimate retry on a clean path
	// is still possible and no audit row was written for the attempt.
	var spent int
	if err := tdb.QueryRow(`SELECT COUNT(*) FROM capability_spent_nonces`).Scan(&spent); err != nil {
		t.Fatalf("count nonces: %v", err)
	}
	if spent != 0 {
		t.Fatalf("traversal attempt should not spend a nonce, got %d", spent)
	}

	// A normalized path against the same token is still accepted: the check
	// rejects traversal, it does not break the bridge. The upstream host does
	// not exist, so a 502 (upstream_error) proves it got all the way past the
	// authorization gates to the outbound request.
	clean := httptest.NewRequest(http.MethodPost, "/proxy/"+host+"/v1/chat", strings.NewReader(`{}`))
	clean.Header.Set("Authorization", "Capability "+tok)
	cleanRec := httptest.NewRecorder()
	router.ServeHTTP(cleanRec, clean)
	if cleanRec.Code == http.StatusBadRequest {
		t.Fatalf("normalized path must not be rejected, got %d body=%s", cleanRec.Code, cleanRec.Body.String())
	}
}

// TestIssue_RejectsTraversalDestination keeps a ".." destination from being
// minted into a token in the first place (same boundary, earlier in the flow).
func TestIssue_RejectsTraversalDestination(t *testing.T) {
	tdb := newTestDB(t)
	defer tdb.Close()

	const userID, secretID, host = "u", "s-issue-traversal", "api.example.com"
	capH := setupCapabilityHandler(t, tdb)
	mustExec(t, tdb, `INSERT INTO vault_entries
		(id, user_id, name, encrypted_value, nonce, encryption_version, destination_patterns, injection_spec)
		VALUES (?, ?, ?, ?, ?, 2, ?, '{"type":"bearer"}')`,
		secretID, userID, "scoped_key", []byte("sk-x"), []byte("n"), `["`+host+`/v1/*"]`)

	for _, body := range []issueRequest{
		{Secret: "scoped_key", AgentID: "a", Dests: []string{host + "/v1/../../admin"}},
		{AgentID: "a", Destination: host + "/v1/../../admin"},
	} {
		raw, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", bytes.NewReader(raw))
		req = req.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, userID))
		capH.Issue(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("traversal destination should be rejected with 400, got %d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid_destination") {
			t.Fatalf("body should name invalid_destination, got %s", rec.Body.String())
		}
	}
}

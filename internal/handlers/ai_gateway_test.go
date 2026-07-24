package handlers

import (
	"database/sql"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/shield"
	"github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"
)

var markerRe = regexp.MustCompile(`\[shield:[^\]]+\]`)

func extractFirstMarker(s string) string {
	if m := markerRe.FindString(s); m != "" {
		return m
	}
	return "(no marker)"
}

func strconvQuote(s string) string { return strconv.Quote(s) }

// aiGatewayTestDB builds an in-memory DB with just the tables the gateway path
// touches: vault_entries (for the provider key), settings (the key pointer),
// activity_log (usage logging), and the shield tables.
func aiGatewayTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	schema := `
	CREATE TABLE vault_entries (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL DEFAULT '', name TEXT NOT NULL,
		encrypted_value BLOB NOT NULL, nonce BLOB NOT NULL, encryption_version INTEGER DEFAULT 2,
		provider TEXT DEFAULT '', provider_meta TEXT DEFAULT '{}',
		rotation_interval_days INTEGER, last_rotated_at DATETIME,
		rotation_log TEXT DEFAULT '[]', rotation_targets TEXT DEFAULT '[]'
	);
	CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at DATETIME);
	CREATE TABLE activity_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, action TEXT NOT NULL,
		detail TEXT, ip_address TEXT, user_agent TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE shield_sessions (
		id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT (datetime('now')),
		last_seen TEXT NOT NULL DEFAULT (datetime('now')), expires_at TEXT NOT NULL
	);
	CREATE TABLE shield_tokens (
		token TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES shield_sessions(id) ON DELETE CASCADE,
		kind TEXT NOT NULL, hint TEXT NOT NULL DEFAULT '', ciphertext TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	`
	if _, err := conn.Exec(schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return conn
}

// seedProviderKey encrypts a fake provider key into a vault entry and points the
// setting at it, mirroring what an admin does in the UI.
func seedProviderKey(t *testing.T, conn *sql.DB, vh *VaultHandler, settingKey, plaintextKey string) {
	t.Helper()
	ct, nonce, err := vh.encrypt([]byte(plaintextKey))
	if err != nil {
		t.Fatalf("encrypt key: %v", err)
	}
	id := "entry_" + hex.EncodeToString([]byte(settingKey))[:8]
	if _, err := conn.Exec(`INSERT INTO vault_entries (id, name, encrypted_value, nonce) VALUES (?,?,?,?)`,
		id, "provider-key", ct, nonce); err != nil {
		t.Fatalf("insert entry: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO settings (key, value) VALUES (?,?)`, settingKey, id); err != nil {
		t.Fatalf("insert setting: %v", err)
	}
}

func gatewayRouter(h *AIGatewayHandler) http.Handler {
	r := chi.NewRouter()
	r.HandleFunc("/api/ai/{provider}/*", h.Proxy)
	return r
}

// TestAIGatewayInjectsKeyAndPassesThroughWhenShieldOff proves the caller's
// request reaches the provider with the real key injected, and (Shield off) the
// body is forwarded unchanged.
func TestAIGatewayInjectsKeyAndPassesThroughWhenShieldOff(t *testing.T) {
	conn := aiGatewayTestDB(t)
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: "test-vault-key"}
	vh := NewVaultHandler(conn, queries, cfg)
	seedProviderKey(t, conn, vh, "ai_key_anthropic", "sk-ant-REALKEY-123")

	var gotKey, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"model":"claude","usage":{"input_tokens":10,"output_tokens":5}}`))
	}))
	defer upstream.Close()

	h := NewAIGatewayHandler(queries, cfg, vh, nil)
	p := h.providers["anthropic"]
	p.baseURL = upstream.URL
	h.providers["anthropic"] = p

	body := `{"model":"claude-3","messages":[{"role":"user","content":"email anna@example.se"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/ai/anthropic/v1/messages", strings.NewReader(body))
	rr := httptest.NewRecorder()
	gatewayRouter(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	if gotKey != "sk-ant-REALKEY-123" {
		t.Errorf("upstream x-api-key = %q, want the injected real key", gotKey)
	}
	// caller's raw request never carried the key
	if strings.Contains(body, "sk-ant") {
		t.Fatal("test bug: caller body should not contain the key")
	}
	// Shield off: email forwarded as-is
	if !strings.Contains(gotBody, "anna@example.se") {
		t.Errorf("shield off: upstream body should contain the raw email, got %q", gotBody)
	}
}

// TestAIGatewayShieldTokenizesPIIBeforeEgress proves that with Shield on, the
// provider never sees the raw PII (it sees a marker), and a marker echoed in the
// response is resolved back to plaintext for the caller.
func TestAIGatewayShieldTokenizesPIIBeforeEgress(t *testing.T) {
	conn := aiGatewayTestDB(t)
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: "test-vault-key", ShieldKey: "0123456789abcdef0123456789abcdef", ShieldHintLevel: "full"}
	vh := NewVaultHandler(conn, queries, cfg)
	seedProviderKey(t, conn, vh, "ai_key_anthropic", "sk-ant-REALKEY-123")

	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		// Echo whatever marker the provider received back in the completion.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"model":"claude","reply":` + strconvQuote(extractFirstMarker(gotBody)) + `,"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	h := NewAIGatewayHandler(queries, cfg, vh, shield.NewSQLStore(conn))
	p := h.providers["anthropic"]
	p.baseURL = upstream.URL
	h.providers["anthropic"] = p

	body := `{"model":"claude-3","messages":[{"role":"user","content":"reply to anna@example.se please"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/ai/anthropic/v1/messages", strings.NewReader(body))
	rr := httptest.NewRecorder()
	gatewayRouter(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	// The provider must NOT have seen the raw email.
	if strings.Contains(gotBody, "anna@example.se") {
		t.Fatalf("PII LEAK: provider saw the raw email in %q", gotBody)
	}
	if !strings.Contains(gotBody, "shield:email:") {
		t.Fatalf("expected a shield marker in the egress body, got %q", gotBody)
	}
	// The caller's response should have the marker resolved back to the email.
	if !strings.Contains(rr.Body.String(), "anna@example.se") {
		t.Errorf("caller response should resolve the marker back to the email, got %s", rr.Body.String())
	}
}

func TestAIGatewayRejectsStreaming(t *testing.T) {
	conn := aiGatewayTestDB(t)
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: "test-vault-key"}
	vh := NewVaultHandler(conn, queries, cfg)
	seedProviderKey(t, conn, vh, "ai_key_openai", "sk-openai-KEY")
	h := NewAIGatewayHandler(queries, cfg, vh, nil)

	body := `{"model":"gpt-4","stream":true,"messages":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/ai/openai/v1/chat/completions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	gatewayRouter(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("streaming should be rejected with 400, got %d", rr.Code)
	}
}

func TestAIGatewayUnknownProvider(t *testing.T) {
	conn := aiGatewayTestDB(t)
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: "test-vault-key"}
	vh := NewVaultHandler(conn, queries, cfg)
	h := NewAIGatewayHandler(queries, cfg, vh, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/ai/gemini/v1/x", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	gatewayRouter(h).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider should be 400, got %d", rr.Code)
	}
}

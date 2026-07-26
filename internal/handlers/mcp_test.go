package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
	_ "github.com/mattn/go-sqlite3"
)

func mcpTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	// Minimal schema for ListAccessibleVaultEntryNames (personal + collection).
	schema := `
	CREATE TABLE vault_entries (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL DEFAULT '', name TEXT NOT NULL,
		encrypted_value BLOB NOT NULL DEFAULT x'', nonce BLOB NOT NULL DEFAULT x'',
		collection_id TEXT
	);
	CREATE TABLE collection_members (
		collection_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
		PRIMARY KEY (collection_id, user_id)
	);
	`
	if _, err := conn.Exec(schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return conn
}

func newMCPHandler(t *testing.T, conn *sql.DB) *MCPHandler {
	t.Helper()
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: "test-vault-key"}
	// nil mint limiter: these tests exercise the protocol surface, not the
	// capability-minting rate limit (covered separately).
	return NewMCPHandler(queries, cfg, nil, nil, nil)
}

func doMCP(t *testing.T, h *MCPHandler, userID, method string, params any) jsonrpcResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(string(body)))
	if userID != "" {
		req = req.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, userID))
	}
	rr := httptest.NewRecorder()
	h.Handle(rr, req)
	var resp jsonrpcResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	return resp
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	h := newMCPHandler(t, mcpTestDB(t))

	init := doMCP(t, h, "", "initialize", map[string]any{})
	if init.Error != nil {
		t.Fatalf("initialize error: %+v", init.Error)
	}
	res, _ := json.Marshal(init.Result)
	if !strings.Contains(string(res), mcpProtocolVersion) || !strings.Contains(string(res), "trustissues") {
		t.Errorf("initialize result missing protocol/serverInfo: %s", res)
	}

	list := doMCP(t, h, "", "tools/list", map[string]any{})
	lb, _ := json.Marshal(list.Result)
	if !strings.Contains(string(lb), "list_secrets") || !strings.Contains(string(lb), "use_secret") {
		t.Errorf("tools/list missing tools: %s", lb)
	}
}

func TestMCPListSecretsReturnsNamesNotValues(t *testing.T) {
	conn := mcpTestDB(t)
	// Two personal secrets for userA, one for userB (must not appear).
	_, _ = conn.Exec(`INSERT INTO vault_entries (id, user_id, name) VALUES
		('e1','userA','GitHub Token'), ('e2','userA','AWS Prod'), ('e3','userB','Other User Secret')`)
	h := newMCPHandler(t, conn)

	resp := doMCP(t, h, "userA", "tools/call", map[string]any{"name": "list_secrets"})
	if resp.Error != nil {
		t.Fatalf("tools/call error: %+v", resp.Error)
	}
	rb, _ := json.Marshal(resp.Result)
	body := string(rb)
	if !strings.Contains(body, "GitHub Token") || !strings.Contains(body, "AWS Prod") {
		t.Errorf("expected userA's secret names, got %s", body)
	}
	if strings.Contains(body, "Other User Secret") {
		t.Errorf("LEAK: userB's secret name appeared in userA's list: %s", body)
	}
	// Never a value/ciphertext field.
	if strings.Contains(body, "encrypted_value") || strings.Contains(body, "\"value\"") {
		t.Errorf("list_secrets must never expose values: %s", body)
	}
}

func TestMCPCallRequiresAuth(t *testing.T) {
	h := newMCPHandler(t, mcpTestDB(t))
	resp := doMCP(t, h, "", "tools/call", map[string]any{"name": "list_secrets"})
	if resp.Error == nil {
		t.Fatal("tools/call without a user must error")
	}
}

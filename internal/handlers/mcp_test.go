package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/database"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	_ "github.com/mattn/go-sqlite3"
)

// mcpTestDB is a REAL database with the embedded migrations applied, not a
// hand-rolled subset of the schema. See newMCPHandler for why that matters.
func mcpTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := database.Connect(t.TempDir())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := database.RunMigrations(conn); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return conn
}

// newMCPHandler builds the MCP handler over a REAL migrated database, a real
// VaultHandler and a real CapabilityHandler.
//
// It used to hand-roll a four-table schema and pass a nil capability handler,
// and those were two of the three fixture defects that kept P1-11 invisible.
// The hand-rolled vault_entries had no name_bidx column, so the real create
// path could not run against it and every test seeded cleartext names with raw
// SQL; the nil capability meant there was no name-decryption door for
// list_secrets to use even in principle, so a correct implementation could not
// have been written against this fixture, let alone tested. The third defect
// was the raw-SQL cleartext seeding itself, which is why the seeding helpers
// now go through VaultHandler.Create.
//
// The cost is a real migration run per test. That is the price of a fixture
// that can fail.
func newMCPHandler(t *testing.T, conn *sql.DB) *MCPHandler {
	t.Helper()
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: strings.Repeat("k", 32), JWTSecret: strings.Repeat("j", 32)}
	vh := NewVaultHandler(conn, queries, cfg)
	// nil mint limiter: these tests exercise the protocol surface, not the
	// capability-minting rate limit (covered separately).
	return NewMCPHandler(queries, cfg, &CapabilityHandler{db: conn, vault: vh}, nil, nil)
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

// The list_secrets content test lives in entry_name_at_rest_lookup_test.go as
// TestMCPListSecretsNeverShipsCiphertext. It asserts everything the version
// that stood here did (the caller's own names present, another user's absent,
// no values) and adds the one this fixture could not express: that no enc:v1:
// blob reaches the model provider. Seeding cleartext names with raw SQL, as the
// old test did, made the name assertions pass against a tool that was shipping
// ciphertext in production.

func TestMCPCallRequiresAuth(t *testing.T) {
	h := newMCPHandler(t, mcpTestDB(t))
	resp := doMCP(t, h, "", "tools/call", map[string]any{"name": "list_secrets"})
	if resp.Error == nil {
		t.Fatal("tools/call without a user must error")
	}
}

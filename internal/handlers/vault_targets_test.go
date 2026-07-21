package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/database"
	"github.com/brightinteraction/trustissues/internal/db"
	timw "github.com/brightinteraction/trustissues/internal/middleware"
)

// swapProviderHTTP replaces the SSRF-guarded provider client with a plain one
// for the duration of a test, so httptest loopback servers are reachable. The
// guarded client stays the production default.
func swapProviderHTTP(t *testing.T) {
	t.Helper()
	orig := providerHTTP
	providerHTTP = &http.Client{}
	t.Cleanup(func() { providerHTTP = orig })
}

func TestParseRotationTargets(t *testing.T) {
	if got := ParseRotationTargets(""); got != nil {
		t.Fatalf("empty input should parse to nil, got %v", got)
	}
	if got := ParseRotationTargets("[]"); got != nil {
		t.Fatalf("empty array should parse to nil, got %v", got)
	}
	if got := ParseRotationTargets("not json"); got != nil {
		t.Fatalf("invalid JSON should parse to nil, got %v", got)
	}

	raw := `[{"type":"webhook","webhook_url":"https://example.com/hook","label":"ci"},{"type":"notify"}]`
	got := ParseRotationTargets(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(got))
	}
	if got[0].Type != "webhook" || got[0].WebhookURL != "https://example.com/hook" || got[0].Label != "ci" {
		t.Fatalf("first target parsed wrong: %+v", got[0])
	}
	if got[1].Type != "notify" {
		t.Fatalf("second target parsed wrong: %+v", got[1])
	}
}

func TestSummarizeDelivery(t *testing.T) {
	// All success -> "success", no error summary.
	status, summary := summarizeDelivery([]DeliveryResult{
		{Target: RotationTarget{Label: "a"}, Success: true},
		{Target: RotationTarget{Label: "b"}, Success: true},
	})
	if status != "success" || summary != "" {
		t.Fatalf("all-success = (%q, %q), want (success, \"\")", status, summary)
	}

	// Any failure -> "partial" and names the failed target.
	status, summary = summarizeDelivery([]DeliveryResult{
		{Target: RotationTarget{Label: "ok"}, Success: true},
		{Target: RotationTarget{Label: "ci-secret", Type: "forgejo_secret"}, Success: false, Error: "boom"},
	})
	if status != "partial" {
		t.Fatalf("with-failure status = %q, want partial", status)
	}
	if summary == "" || !strings.Contains(summary, "ci-secret") || !strings.Contains(summary, "boom") {
		t.Fatalf("summary %q should name failed target + error", summary)
	}

	// Unlabeled failure falls back to the type name.
	_, summary = summarizeDelivery([]DeliveryResult{
		{Target: RotationTarget{Type: "webhook"}, Success: false, Error: "HTTP 500"},
	})
	if !strings.Contains(summary, "webhook") {
		t.Fatalf("summary %q should fall back to target type", summary)
	}
}

// TestDeliverRotatedKeyRejectsRetiredTypes is the regression guard for the
// control-plane cut: env_var, file_write, and reload_endpoint were removed on
// purpose and must fail loudly (partial rotation), never silently succeed.
func TestDeliverRotatedKeyRejectsRetiredTypes(t *testing.T) {
	targets := []RotationTarget{
		{Type: "env_var", Label: "retired-env"},
		{Type: "file_write", Label: "retired-file"},
		{Type: "reload_endpoint", Label: "retired-reload"},
		{Type: "bogus"},
	}
	// nil queries/vault are safe: unknown types never reach the DB or crypto.
	results := DeliverRotatedKey(context.Background(), nil, nil, "entry", "old", "new", targets, "user1")
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Success {
			t.Fatalf("retired/unknown type %q must fail, got success", r.Target.Type)
		}
		if !strings.Contains(r.Error, "unknown target type") {
			t.Fatalf("type %q error = %q, want unknown-target-type", r.Target.Type, r.Error)
		}
	}

	status, _ := summarizeDelivery(results)
	if status != "partial" {
		t.Fatalf("rotation with retired targets must summarize as partial, got %q", status)
	}
}

// TestDeliverRotatedKeyNotifySkipped: notify targets produce no delivery
// result (the caller dispatches notifications separately) and never fail a
// rotation.
func TestDeliverRotatedKeyNotifySkipped(t *testing.T) {
	results := DeliverRotatedKey(context.Background(), nil, nil, "entry", "", "new", []RotationTarget{{Type: "notify"}}, "user1")
	if len(results) != 0 {
		t.Fatalf("notify target should be skipped, got %d results", len(results))
	}
	status, summary := summarizeDelivery(results)
	if status != "success" || summary != "" {
		t.Fatalf("notify-only rotation = (%q, %q), want (success, \"\")", status, summary)
	}
}

func TestDeliverToWebhook(t *testing.T) {
	swapProviderHTTP(t)

	const secret = "hook-secret"
	const newValue = "the-new-key"

	var gotBody []byte
	var gotSig, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Vault-Signature")
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := RotationTarget{Type: "webhook", WebhookURL: srv.URL, WebhookSecret: secret}
	if err := deliverToWebhook(context.Background(), target, "my-entry", newValue); err != nil {
		t.Fatalf("deliverToWebhook failed: %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if payload["event"] != "vault.key_rotated" || payload["entry_name"] != "my-entry" || payload["new_value"] != newValue {
		t.Fatalf("payload wrong: %v", payload)
	}
	if payload["rotated_at"] == "" {
		t.Fatal("payload missing rotated_at")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature = %q, want %q", gotSig, want)
	}
	if gotUA != "Trustissues-Vault/1.0" {
		t.Fatalf("user-agent = %q", gotUA)
	}
}

func TestDeliverToWebhookNoSecretNoSignature(t *testing.T) {
	swapProviderHTTP(t)

	var sigPresent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sigPresent = r.Header["X-Vault-Signature"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	target := RotationTarget{Type: "webhook", WebhookURL: srv.URL}
	if err := deliverToWebhook(context.Background(), target, "e", "v"); err != nil {
		t.Fatalf("deliverToWebhook failed: %v", err)
	}
	if sigPresent {
		t.Fatal("no secret configured, but a signature header was sent")
	}
}

func TestDeliverToWebhookErrors(t *testing.T) {
	swapProviderHTTP(t)

	// Missing URL fails without any HTTP call.
	if err := deliverToWebhook(context.Background(), RotationTarget{Type: "webhook"}, "e", "v"); err == nil {
		t.Fatal("missing webhook_url should fail")
	}

	// A 4xx/5xx response is a delivery failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := deliverToWebhook(context.Background(), RotationTarget{Type: "webhook", WebhookURL: srv.URL}, "e", "v")
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("expected HTTP 500 error, got %v", err)
	}
}

// newTestVaultEnv boots a real SQLite database with the embedded migrations
// and returns a VaultHandler plus an admin-owned vault entry ID.
func newTestVaultEnv(t *testing.T) (*VaultHandler, *db.Queries, string, string) {
	t.Helper()
	ctx := context.Background()

	dbConn, err := database.Connect(t.TempDir())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { dbConn.Close() })
	if err := database.RunMigrations(dbConn); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	queries := db.New(dbConn)
	cfg := &config.Config{VaultKey: strings.Repeat("k", 32), JWTSecret: strings.Repeat("j", 32)}
	h := NewVaultHandler(dbConn, queries, cfg)

	user, err := queries.CreateUser(ctx, db.CreateUserParams{
		Email:        "admin@example.com",
		PasswordHash: "not-a-real-hash",
		Name:         toNullString("Admin"),
		Role:         "admin",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	ct, nonce, err := h.EncryptValue([]byte("secret-value"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	const entryID = "entry-under-test"
	if err := queries.CreateVaultEntry(ctx, db.CreateVaultEntryParams{
		ID:             entryID,
		UserID:         user.ID,
		Name:           "test-entry",
		EncryptedValue: ct,
		Nonce:          nonce,
	}); err != nil {
		t.Fatalf("create entry: %v", err)
	}

	return h, queries, user.ID, entryID
}

// targetsRequest builds an authenticated PUT /api/vault/{id}/targets request
// with the chi URL param and the middleware context keys populated.
func targetsRequest(userID, role, entryID, body string) *http.Request {
	r := httptest.NewRequest("PUT", "/api/vault/"+entryID+"/targets", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", entryID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, timw.UserIDKey, userID)
	ctx = context.WithValue(ctx, timw.UserRoleKey, role)
	return r.WithContext(ctx)
}

// TestUpdateTargetsValidationSetMatchesDelivery drives the real UpdateTargets
// handler (vault.go) end to end and pins its validation switch to exactly the
// three types this file implements delivery for. If either side drifts (a
// type accepted at set time but undeliverable, or vice versa), this fails.
func TestUpdateTargetsValidationSetMatchesDelivery(t *testing.T) {
	h, queries, userID, entryID := newTestVaultEnv(t)

	// The full supported set is accepted and persisted encrypted.
	valid := `[
		{"type":"webhook","webhook_url":"https://example.com/hook","webhook_secret":"s","label":"hook"},
		{"type":"forgejo_secret","instance":"https://git.example.com","repo":"o/r","secret_name":"CI_KEY","auth_token":"forgejo-token"},
		{"type":"notify"}
	]`
	rec := httptest.NewRecorder()
	h.UpdateTargets(rec, targetsRequest(userID, "admin", entryID, valid))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid targets rejected: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	raw, err := queries.GetVaultEntryTargets(context.Background(), entryID)
	if err != nil {
		t.Fatalf("read back targets: %v", err)
	}
	if strings.Contains(raw.String, "webhook_url") {
		t.Fatal("rotation_targets stored in cleartext; expected encrypted column")
	}
	stored := ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", "rotation_targets"))
	if len(stored) != 3 {
		t.Fatalf("expected 3 stored targets, got %d", len(stored))
	}
	for _, tg := range stored {
		if tg.Type != "webhook" && tg.Type != "forgejo_secret" && tg.Type != "notify" {
			t.Fatalf("unexpected stored type %q", tg.Type)
		}
	}

	// Retired control-plane types and malformed targets are rejected with 400.
	rejected := []struct {
		name string
		body string
	}{
		{"env_var retired", `[{"type":"env_var","service_id":"svc","env_key":"K"}]`},
		{"file_write retired", `[{"type":"file_write","server_name":"s","file_path":"/opt/x.env","key_name":"K"}]`},
		{"reload_endpoint retired", `[{"type":"reload_endpoint","reload_url":"https://x/admin/reload-secrets","key_name":"K","admin_token_vault_ref":"ref"}]`},
		{"unknown type", `[{"type":"carrier-pigeon"}]`},
		{"webhook missing url", `[{"type":"webhook"}]`},
		{"forgejo missing fields", `[{"type":"forgejo_secret","instance":"https://git.example.com"}]`},
		{"not an array", `{"type":"notify"}`},
	}
	for _, c := range rejected {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.UpdateTargets(rec, targetsRequest(userID, "admin", entryID, c.body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}

	// A non-owner non-admin cannot see or set targets on someone else's entry.
	rec = httptest.NewRecorder()
	h.UpdateTargets(rec, targetsRequest("someone-else", "user", entryID, `[{"type":"notify"}]`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-owner should get 404, got %d", rec.Code)
	}
}

func TestDeliverToForgejoSecretValidation(t *testing.T) {
	// Field validation fires before any DB or HTTP access, so nil deps are safe.
	cases := []struct {
		name   string
		target RotationTarget
		want   string
	}{
		{"missing instance", RotationTarget{Type: "forgejo_secret", Repo: "o/r", SecretName: "S"}, "instance, repo, and secret_name"},
		{"missing repo", RotationTarget{Type: "forgejo_secret", Instance: "https://git.example.com", SecretName: "S"}, "instance, repo, and secret_name"},
		{"missing secret name", RotationTarget{Type: "forgejo_secret", Instance: "https://git.example.com", Repo: "o/r"}, "instance, repo, and secret_name"},
		{"missing auth token", RotationTarget{Type: "forgejo_secret", Instance: "https://git.example.com", Repo: "o/r", SecretName: "S"}, "auth_token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := deliverToForgejoSecret(context.Background(), nil, nil, c.target, "v", "user1")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want mention of %q", err, c.want)
			}
		})
	}
}

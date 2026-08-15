package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// withChiParam wraps a request context with a chi route context that
// has the given URL params set. Use this for handler tests that read
// chi.URLParam(r, "id") since httptest.NewRequest skips routing.
func withChiParam(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// newServiceTestDB returns an in-memory sqlite DB with vault_entries +
// service_identities + service_secret_audit schemas. Hand-rolled (not
// goose-migrated) so the tests do not depend on migration ordering.
func newServiceTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Per-test cache name so we don't collide with capability_test.go's
	// shared-cache pool (which also creates a vault_entries table).
	dsn := "file:service_" + randomHex(8) + "?mode=memory&cache=shared&_mutex=full"
	dbConn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	stmts := []string{
		`CREATE TABLE vault_entries (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			secret_owner_user_id TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL,
			encrypted_value BLOB NOT NULL,
			nonce BLOB NOT NULL,
			encryption_version INTEGER DEFAULT 2,
			destination_patterns TEXT NOT NULL DEFAULT '[]',
			injection_spec TEXT NOT NULL DEFAULT '{}',
			collection_id TEXT,
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
		`CREATE TABLE service_identities (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			allowed_secrets TEXT NOT NULL DEFAULT '[]',
			key_hash TEXT NOT NULL,
			key_prefix TEXT NOT NULL,
			last_used_at DATETIME,
			expires_at DATETIME,
			revoked_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_by_user_id TEXT
		)`,
		// The service fetch now verifies the identity's owner is a live account,
		// so this fixture needs a users table. Without it every FetchOwnSecrets
		// test 401s on "owner account no longer exists" and the suite fails
		// wholesale, which is how the gap it covers stayed invisible: the helper
		// modelled service_identities and vault_entries but not the user those
		// rows point at, so "does the owner still exist" was unaskable here.
		`CREATE TABLE users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL DEFAULT '',
			name TEXT,
			password_hash TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT 'user',
			disabled INTEGER NOT NULL DEFAULT 0,
			totp_enabled INTEGER DEFAULT 0,
			totp_secret TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE service_secret_audit (
			id TEXT PRIMARY KEY,
			service_identity_id TEXT,
			service_name TEXT NOT NULL DEFAULT '',
			event TEXT NOT NULL,
			secret_names TEXT NOT NULL DEFAULT '[]',
			error TEXT NOT NULL DEFAULT '',
			remote_ip TEXT NOT NULL DEFAULT '',
			occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, s := range stmts {
		if _, err := dbConn.Exec(s); err != nil {
			t.Fatalf("schema: %v\n%s", err, s)
		}
	}
	// The owner every seeded identity and secret belongs to. Live by default;
	// individual tests disable or delete it to exercise offboarding.
	if _, err := dbConn.Exec(
		`INSERT INTO users (id, email, role, disabled) VALUES (?, 'svc-owner@example.com', 'admin', 0)`,
		svcTestOwnerID); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	return dbConn
}

// seedSecret inserts a vault_entries row with the given name. The stub
// decrypter returns encrypted_value verbatim, so the plaintext bytes go
// straight into the column. Returns the row id.
func seedSecret(t *testing.T, dbConn *sql.DB, name, value string) string {
	t.Helper()
	id := randomHex(16)
	if _, err := dbConn.Exec(
		`INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, encryption_version)
		 VALUES (?, ?, ?, ?, ?, 2)`,
		id, svcTestOwnerID, name, []byte(value), []byte("n"),
	); err != nil {
		t.Fatalf("insert vault entry: %v", err)
	}
	return id
}

// svcTestOwnerID is the owner shared by seedSecret + seedServiceIdentity so the
// owner-scoped service fetch (name + user_id) resolves the seeded secrets.
const svcTestOwnerID = "svc-test-owner"

// seedServiceIdentity inserts a service_identities row with the given
// allowed_secrets whitelist + a freshly generated key. Returns the
// plaintext key the caller should send in X-Service-Key.
func seedServiceIdentity(t *testing.T, dbConn *sql.DB, name string, allowed []string) string {
	t.Helper()
	allowedJSON, err := json.Marshal(allowed)
	if err != nil {
		t.Fatalf("marshal allowed: %v", err)
	}
	rawKey := ServiceKeyPrefix + randomHex(32)
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])
	id := randomHex(16)
	if _, err := dbConn.Exec(
		`INSERT INTO service_identities (id, name, allowed_secrets, key_hash, key_prefix, created_by_user_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, name, string(allowedJSON), keyHash, rawKey[3:11], svcTestOwnerID,
	); err != nil {
		t.Fatalf("insert identity: %v", err)
	}
	return rawKey
}

func setupServiceHandler(t *testing.T) (*ServiceSecretsHandler, *sql.DB) {
	t.Helper()
	dbConn := newServiceTestDB(t)
	q := db.New(dbConn)
	return NewServiceSecretsHandler(q, stubDecrypter{}), dbConn
}

// ----------------------------------------------------------------------------
// Happy path
// ----------------------------------------------------------------------------

func TestFetchOwnSecrets_HappyPath(t *testing.T) {
	h, dbConn := setupServiceHandler(t)

	seedSecret(t, dbConn, "SHIELD_KEY", "shield-secret-value")
	seedSecret(t, dbConn, "POSTGRES_PASSWORD", "super-secret-pg-pass")
	key := seedServiceIdentity(t, dbConn, "webapp-prod",
		[]string{"SHIELD_KEY", "POSTGRES_PASSWORD"})

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp fetchSecretsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Secrets["SHIELD_KEY"] != "shield-secret-value" {
		t.Errorf("SHIELD_KEY = %q, want shield-secret-value", resp.Secrets["SHIELD_KEY"])
	}
	if resp.Secrets["POSTGRES_PASSWORD"] != "super-secret-pg-pass" {
		t.Errorf("POSTGRES_PASSWORD = %q, want super-secret-pg-pass", resp.Secrets["POSTGRES_PASSWORD"])
	}

	// Audit row must record a fetch event with both names.
	var event string
	var names string
	if err := dbConn.QueryRow(`SELECT event, secret_names FROM service_secret_audit ORDER BY occurred_at DESC LIMIT 1`).
		Scan(&event, &names); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if event != "fetch" {
		t.Errorf("audit event = %q, want fetch", event)
	}
	if !strings.Contains(names, "SHIELD_KEY") || !strings.Contains(names, "POSTGRES_PASSWORD") {
		t.Errorf("audit names = %q, want both secret names", names)
	}
}

// TestFetchOwnSecrets_CrossOwnerIsolation: vault_entries is unique only per
// (user_id, name), so a name-only fetch would return another user's
// same-named secret. A service identity must only resolve secrets owned by
// its creating user.
func TestFetchOwnSecrets_CrossOwnerIsolation(t *testing.T) {
	h, dbConn := setupServiceHandler(t)

	// Another user owns STRIPE_KEY; the identity (owned by svcTestOwnerID) does not.
	if _, err := dbConn.Exec(
		`INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, encryption_version)
		 VALUES (?, 'other-user', 'STRIPE_KEY', ?, ?, 2)`, randomHex(16), []byte("other-user-stripe-secret"), []byte("n")); err != nil {
		t.Fatalf("insert other-user secret: %v", err)
	}
	key := seedServiceIdentity(t, dbConn, "svc-a", []string{"STRIPE_KEY"})

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)

	// The identity does not own STRIPE_KEY, so the name does not resolve and the
	// fetch is refused outright. It used to be a 200 with an empty map; the
	// assertion that matters is the same either way and is made below on the raw
	// body, so it cannot be satisfied by a decode that quietly returns nothing.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "other-user-stripe-secret") {
		t.Fatalf("cross-owner leak: identity received another user's STRIPE_KEY: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "\"secrets\"") {
		t.Fatalf("a refused fetch must not carry a secrets map at all: %s", rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// Authentication errors
// ----------------------------------------------------------------------------

func TestFetchOwnSecrets_MissingKey(t *testing.T) {
	h, _ := setupServiceHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestFetchOwnSecrets_UnknownKey(t *testing.T) {
	h, _ := setupServiceHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", "sk_does_not_exist")
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestFetchOwnSecrets_RevokedKey(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	key := seedServiceIdentity(t, dbConn, "revoked-svc", []string{"X"})
	if _, err := dbConn.Exec(`UPDATE service_identities SET revoked_at = CURRENT_TIMESTAMP WHERE name = ?`,
		"revoked-svc"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "revoked") {
		t.Errorf("body should mention revocation: %s", rec.Body.String())
	}
}

func TestFetchOwnSecrets_ExpiredKey(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	key := seedServiceIdentity(t, dbConn, "expired-svc", []string{"X"})
	past := time.Now().UTC().Add(-1 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := dbConn.Exec(`UPDATE service_identities SET expires_at = ? WHERE name = ?`,
		past, "expired-svc"); err != nil {
		t.Fatalf("expire: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// Scope enforcement
// ----------------------------------------------------------------------------

func TestFetchOwnSecrets_ScopeWhitelist(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	// Seed THREE secrets in the vault.
	seedSecret(t, dbConn, "SECRET_A", "value-a")
	seedSecret(t, dbConn, "SECRET_B", "value-b")
	seedSecret(t, dbConn, "SECRET_C", "value-c")
	// But only allow access to two of them.
	key := seedServiceIdentity(t, dbConn, "scoped-svc", []string{"SECRET_A", "SECRET_C"})

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp fetchSecretsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp.Secrets["SECRET_B"]; ok {
		t.Error("SECRET_B leaked into response despite NOT being in allowed_secrets")
	}
	if resp.Secrets["SECRET_A"] != "value-a" {
		t.Errorf("SECRET_A missing or wrong")
	}
	if resp.Secrets["SECRET_C"] != "value-c" {
		t.Errorf("SECRET_C missing or wrong")
	}
}

func TestFetchOwnSecrets_EmptyWhitelist(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	key := seedServiceIdentity(t, dbConn, "empty-svc", []string{})
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty whitelist, got %d", rec.Code)
	}
}

func TestFetchOwnSecrets_MissingVaultEntry(t *testing.T) {
	// A whitelisted name the vault cannot resolve now REFUSES the whole fetch.
	//
	// This test used to assert the opposite: 200, a partial secrets map, and the
	// missing names recorded only in the audit row, whose event stayed "fetch".
	// That was the second half of P1-8. allowed_secrets is the contract an admin
	// wrote for this identity, so a name in it that does not resolve means the
	// container is about to boot without a credential it was promised, and 200
	// under the success verb is the one answer that guarantees nobody notices.
	// Partial is the same failure as total, one credential at a time.
	h, dbConn := setupServiceHandler(t)
	seedSecret(t, dbConn, "EXISTS", "real-value")
	key := seedServiceIdentity(t, dbConn, "partial-svc", []string{"EXISTS", "DOES_NOT_EXIST"})

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when a whitelisted name does not resolve, got %d: %s",
			rec.Code, rec.Body.String())
	}
	// No partial set, and in particular no value for the name that DID resolve:
	// a caller that cannot be served completely is served nothing.
	if strings.Contains(rec.Body.String(), "real-value") {
		t.Errorf("a refused fetch still shipped a secret value: %s", rec.Body.String())
	}

	// The audit row records the miss AND does not call it a success.
	var auditEvent, auditErr string
	if err := dbConn.QueryRow(
		`SELECT event, error FROM service_secret_audit ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&auditEvent, &auditErr); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if auditEvent == "fetch" {
		t.Error("a fetch that resolved nothing was audited under the SUCCESS verb; " +
			"that is what let a credential-less boot look like a good one")
	}
	if auditEvent != "denied" {
		t.Errorf("audit event = %q, want denied", auditEvent)
	}
	if !strings.Contains(auditErr, "DOES_NOT_EXIST") {
		t.Errorf("audit error should mention DOES_NOT_EXIST: %q", auditErr)
	}
}

// ----------------------------------------------------------------------------
// last_used_at touch
// ----------------------------------------------------------------------------

func TestFetchOwnSecrets_TouchesLastUsedAt(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedSecret(t, dbConn, "X", "x-value")
	key := seedServiceIdentity(t, dbConn, "touch-svc", []string{"X"})

	// Before: NULL.
	var beforeRaw sql.NullString
	_ = dbConn.QueryRow(`SELECT last_used_at FROM service_identities WHERE name = ?`,
		"touch-svc").Scan(&beforeRaw)
	if beforeRaw.Valid {
		t.Fatalf("expected last_used_at NULL before fetch, got %v", beforeRaw)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch failed: %d", rec.Code)
	}

	var afterRaw sql.NullString
	_ = dbConn.QueryRow(`SELECT last_used_at FROM service_identities WHERE name = ?`,
		"touch-svc").Scan(&afterRaw)
	if !afterRaw.Valid || afterRaw.String == "" {
		t.Errorf("expected last_used_at set after fetch, got %v", afterRaw)
	}
}

// ----------------------------------------------------------------------------
// Admin endpoint smoke (CreateServiceIdentity)
// ----------------------------------------------------------------------------

func TestCreateServiceIdentity_RequiresAdmin(t *testing.T) {
	h, _ := setupServiceHandler(t)
	body := strings.NewReader(`{"name":"x","allowed_secrets":["A"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities", body)
	rec := httptest.NewRecorder()
	// No admin context set: should 403.
	h.CreateServiceIdentity(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 without admin context, got %d", rec.Code)
	}
}

func TestCreateServiceIdentity_HappyPath(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	ctx := contextAsAdmin(t)
	body := bytes.NewBufferString(`{
		"name": "webapp-prod",
		"description": "webapp host in production",
		"allowed_secrets": ["SHIELD_KEY", "POSTGRES_PASSWORD"],
		"expires_in_days": 365
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities", body).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.CreateServiceIdentity(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp serviceIdentityCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(resp.Key, ServiceKeyPrefix) {
		t.Errorf("returned key must start with %q: %q", ServiceKeyPrefix, resp.Key)
	}
	if resp.ExpiresAt == nil {
		t.Error("expires_at should be set when expires_in_days > 0")
	}
	// Verify row landed in DB with correct hash.
	hash := sha256.Sum256([]byte(resp.Key))
	keyHash := hex.EncodeToString(hash[:])
	var stored string
	if err := dbConn.QueryRow(`SELECT key_hash FROM service_identities WHERE name = ?`,
		"webapp-prod").Scan(&stored); err != nil {
		t.Fatalf("query stored hash: %v", err)
	}
	if stored != keyHash {
		t.Errorf("stored key_hash %q != computed %q", stored, keyHash)
	}
}

func TestCreateServiceIdentity_RejectsEmptyAllowedSecrets(t *testing.T) {
	h, _ := setupServiceHandler(t)
	ctx := contextAsAdmin(t)
	body := strings.NewReader(`{"name":"x","allowed_secrets":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities", body).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.CreateServiceIdentity(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty allowed_secrets, got %d", rec.Code)
	}
}

// contextAsAdmin returns a context that mimics the result of
// JWTOrAPIKeyAuth for an admin user. We hand-set the keys instead of
// running the middleware so the test stays focused on the handler logic.
func contextAsAdmin(t *testing.T) context.Context {
	t.Helper()
	ctx := context.Background()
	ctx = context.WithValue(ctx, middleware.UserIDKey, "test-admin-id")
	ctx = context.WithValue(ctx, middleware.UserRoleKey, "admin")
	return ctx
}

// identityIDByName helper for tests that need the auto-generated id.
func identityIDByName(t *testing.T, dbConn *sql.DB, name string) string {
	t.Helper()
	var id string
	if err := dbConn.QueryRow(`SELECT id FROM service_identities WHERE name = ?`, name).Scan(&id); err != nil {
		t.Fatalf("lookup id for %q: %v", name, err)
	}
	return id
}

// ----------------------------------------------------------------------------
// RevokeServiceIdentity
// ----------------------------------------------------------------------------

func TestRevokeServiceIdentity_RequiresAdmin(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedServiceIdentity(t, dbConn, "rev-target", []string{"X"})
	id := identityIDByName(t, dbConn, "rev-target")

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/"+id+"/revoke", nil)
	req = withChiParam(req, "id", id)
	rec := httptest.NewRecorder()
	h.RevokeServiceIdentity(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 without admin, got %d", rec.Code)
	}
}

func TestRevokeServiceIdentity_HappyPath(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedServiceIdentity(t, dbConn, "rev-target", []string{"X"})
	id := identityIDByName(t, dbConn, "rev-target")

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/"+id+"/revoke", nil).
		WithContext(contextAsAdmin(t))
	req = withChiParam(req, "id", id)

	rec := httptest.NewRecorder()
	h.RevokeServiceIdentity(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// DB: revoked_at must be set.
	var revokedAt sql.NullString
	if err := dbConn.QueryRow(`SELECT revoked_at FROM service_identities WHERE id = ?`, id).Scan(&revokedAt); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if !revokedAt.Valid {
		t.Errorf("expected revoked_at to be set, got NULL")
	}

	// Audit: admin_revoked event recorded.
	var event string
	_ = dbConn.QueryRow(`SELECT event FROM service_secret_audit WHERE service_identity_id = ? ORDER BY occurred_at DESC LIMIT 1`,
		id).Scan(&event)
	if event != "admin_revoked" {
		t.Errorf("audit event = %q, want admin_revoked", event)
	}
}

func TestRevokeServiceIdentity_NotFound(t *testing.T) {
	h, _ := setupServiceHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/does-not-exist/revoke", nil).
		WithContext(contextAsAdmin(t))
	req = withChiParam(req, "id", "does-not-exist")

	rec := httptest.NewRecorder()
	h.RevokeServiceIdentity(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown id, got %d", rec.Code)
	}
}

func TestRevokeServiceIdentity_AlreadyRevoked(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedServiceIdentity(t, dbConn, "double-revoke", []string{"X"})
	id := identityIDByName(t, dbConn, "double-revoke")
	if _, err := dbConn.Exec(`UPDATE service_identities SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		t.Fatalf("pre-revoke: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/"+id+"/revoke", nil).
		WithContext(contextAsAdmin(t))
	req = withChiParam(req, "id", id)

	rec := httptest.NewRecorder()
	h.RevokeServiceIdentity(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 for already-revoked, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Revoke locks out the key: subsequent FetchOwnSecrets returns 401.
func TestRevokeServiceIdentity_DenyFetchAfter(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedSecret(t, dbConn, "X", "x-value")
	key := seedServiceIdentity(t, dbConn, "to-revoke", []string{"X"})
	id := identityIDByName(t, dbConn, "to-revoke")

	// Fetch works pre-revoke.
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-revoke fetch failed: %d", rec.Code)
	}

	// Revoke via handler.
	rev := httptest.NewRequest(http.MethodPost, "/api/service-identities/"+id+"/revoke", nil).
		WithContext(contextAsAdmin(t))
	rev = withChiParam(rev, "id", id)
	revRec := httptest.NewRecorder()
	h.RevokeServiceIdentity(revRec, rev)
	if revRec.Code != http.StatusNoContent {
		t.Fatalf("revoke failed: %d", revRec.Code)
	}

	// Fetch now 401.
	req2 := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req2.Header.Set("X-Service-Key", key)
	rec2 := httptest.NewRecorder()
	h.FetchOwnSecrets(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("post-revoke fetch should be 401, got %d", rec2.Code)
	}
}

// ----------------------------------------------------------------------------
// DeleteServiceIdentity
// ----------------------------------------------------------------------------

func TestDeleteServiceIdentity_RequiresAdmin(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedServiceIdentity(t, dbConn, "del-target", []string{"X"})
	id := identityIDByName(t, dbConn, "del-target")
	req := httptest.NewRequest(http.MethodDelete, "/api/service-identities/"+id, nil)
	req = withChiParam(req, "id", id)
	rec := httptest.NewRecorder()
	h.DeleteServiceIdentity(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 without admin, got %d", rec.Code)
	}
}

func TestDeleteServiceIdentity_HappyPath(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedServiceIdentity(t, dbConn, "del-target", []string{"X"})
	id := identityIDByName(t, dbConn, "del-target")

	req := httptest.NewRequest(http.MethodDelete, "/api/service-identities/"+id, nil).
		WithContext(contextAsAdmin(t))
	req = withChiParam(req, "id", id)

	rec := httptest.NewRecorder()
	h.DeleteServiceIdentity(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	var count int
	if err := dbConn.QueryRow(`SELECT COUNT(*) FROM service_identities WHERE id = ?`, id).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("row not deleted: count = %d", count)
	}

	// Audit row records admin_deleted AND survives identity deletion.
	var event string
	_ = dbConn.QueryRow(`SELECT event FROM service_secret_audit WHERE service_identity_id = ? ORDER BY occurred_at DESC LIMIT 1`,
		id).Scan(&event)
	if event != "admin_deleted" {
		t.Errorf("audit event = %q, want admin_deleted", event)
	}
}

func TestDeleteServiceIdentity_NotFound(t *testing.T) {
	h, _ := setupServiceHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/service-identities/does-not-exist", nil).
		WithContext(contextAsAdmin(t))
	req = withChiParam(req, "id", "does-not-exist")
	rec := httptest.NewRecorder()
	h.DeleteServiceIdentity(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// ----------------------------------------------------------------------------
// GetServiceIdentityAudit
// ----------------------------------------------------------------------------

func TestGetServiceIdentityAudit_RequiresAdmin(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedServiceIdentity(t, dbConn, "aud-target", []string{"X"})
	id := identityIDByName(t, dbConn, "aud-target")

	req := httptest.NewRequest(http.MethodGet, "/api/service-identities/"+id+"/audit", nil)
	req = withChiParam(req, "id", id)
	rec := httptest.NewRecorder()
	h.GetServiceIdentityAudit(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 without admin, got %d", rec.Code)
	}
}

func TestGetServiceIdentityAudit_ReturnsHistory(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedSecret(t, dbConn, "X", "x-value")
	key := seedServiceIdentity(t, dbConn, "aud-target", []string{"X"})
	id := identityIDByName(t, dbConn, "aud-target")

	// Generate two audit rows by fetching twice.
	for i := 0; i < 2; i++ {
		f := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
		f.Header.Set("X-Service-Key", key)
		fr := httptest.NewRecorder()
		h.FetchOwnSecrets(fr, f)
		if fr.Code != http.StatusOK {
			t.Fatalf("fetch %d failed: %d", i, fr.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/service-identities/"+id+"/audit", nil).
		WithContext(contextAsAdmin(t))
	req = withChiParam(req, "id", id)

	rec := httptest.NewRecorder()
	h.GetServiceIdentityAudit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out []auditEntryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(out))
	}
	for _, e := range out {
		if e.Event != "fetch" {
			t.Errorf("event = %q, want fetch", e.Event)
		}
		if len(e.SecretNames) != 1 || e.SecretNames[0] != "X" {
			t.Errorf("secret_names = %v, want [X]", e.SecretNames)
		}
	}
}

// Audit survives identity deletion (the dangling-FK behavior is
// intentional so forensics still work after admin_deleted).
func TestGetServiceIdentityAudit_SurvivesDeletion(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedSecret(t, dbConn, "X", "x-value")
	key := seedServiceIdentity(t, dbConn, "to-delete", []string{"X"})
	id := identityIDByName(t, dbConn, "to-delete")

	f := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	f.Header.Set("X-Service-Key", key)
	fr := httptest.NewRecorder()
	h.FetchOwnSecrets(fr, f)
	if fr.Code != http.StatusOK {
		t.Fatalf("fetch failed: %d", fr.Code)
	}

	// Delete the identity row directly.
	if _, err := dbConn.Exec(`DELETE FROM service_identities WHERE id = ?`, id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Audit endpoint must still find the row.
	req := httptest.NewRequest(http.MethodGet, "/api/service-identities/"+id+"/audit", nil).
		WithContext(contextAsAdmin(t))
	req = withChiParam(req, "id", id)

	rec := httptest.NewRecorder()
	h.GetServiceIdentityAudit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var out []auditEntryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) == 0 {
		t.Error("audit history should survive identity deletion")
	}
}

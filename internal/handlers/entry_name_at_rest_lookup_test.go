package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// This file covers the two surfaces that still treated vault_entries.name as
// cleartext after 00040 sealed it: the service-identity secret fetch (P1-8) and
// the MCP list_secrets tool (P1-11).
//
// WHY IT DOES NOT REUSE THE EXISTING FIXTURES. Both features already had green
// test suites over the broken code, and in both cases the fixture was the
// reason. service_secrets_test.go hand-rolls a PRE-00040 schema (no name_bidx
// column, UNIQUE(user_id, name) still live) and seeds names as cleartext with
// raw SQL through a stub decrypter that hands the column back verbatim, so
// `WHERE name = ?` matched and nothing in that suite could ever see the miss.
// mcp_test.go did the same and, on top of it, built the handler with a nil
// capability, so there was no decryption door for a correct implementation to
// use even if one had been written.
//
// So everything here runs the REAL migrations, writes through the REAL create
// handler, and opens through a REAL VaultHandler holding a real vault key. Each
// test asserts up front that the stored column really is sealed, because a
// fixture that quietly stored cleartext would make every assertion below pass
// for the wrong reason. That guard is the whole difference between this file
// and the ones it replaces.

// createEntryThroughTheRealWritePath posts to VaultHandler.Create, the handler
// the UI and the API both use. Nothing here reaches around it: the name is
// sealed, and name_bidx is written, by the production code under test.
func createEntryThroughTheRealWritePath(t *testing.T, vh *VaultHandler, userID, name, value string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "value": value})
	if err != nil {
		t.Fatalf("marshal create body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/vault", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, userID))
	rec := httptest.NewRecorder()
	vh.Create(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create %q through the real write path: %d %s", name, rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v (%s)", err, rec.Body.String())
	}
	if created.ID == "" {
		t.Fatalf("create response carried no id: %s", rec.Body.String())
	}
	return created.ID
}

// storedName reads the raw name column, with no decryption anywhere in the path.
func storedName(t *testing.T, vh *VaultHandler, entryID string) string {
	t.Helper()
	var raw string
	if err := vh.db.QueryRow(`SELECT name FROM vault_entries WHERE id = ?`, entryID).Scan(&raw); err != nil {
		t.Fatalf("read stored name: %v", err)
	}
	return raw
}

// requireSealedName is the anti-blind-fixture guard. If it ever fires, every
// other assertion in the test that called it was meaningless.
func requireSealedName(t *testing.T, vh *VaultHandler, entryID, plain string) {
	t.Helper()
	raw := storedName(t, vh, entryID)
	if raw == plain || !vaultfield.IsSealedColumn(raw) {
		t.Fatalf("ABORT, the fixture is blind: vault_entries.name for %q is not sealed at rest (%q). "+
			"Every assertion in this test would pass against the cleartext lookup this test exists to catch",
			plain, raw)
	}
}

// mintServiceIdentityThroughTheRealPath uses the admin mint handler so the
// identity's created_by_user_id, key hash and whitelist are written the way
// production writes them. Returns the plaintext service key.
func mintServiceIdentityThroughTheRealPath(t *testing.T, sh *ServiceSecretsHandler,
	adminUserID, name string, allowed []string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "allowed_secrets": allowed})
	if err != nil {
		t.Fatalf("marshal mint body: %v", err)
	}
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, adminUserID)
	ctx = context.WithValue(ctx, middleware.UserRoleKey, "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities", bytes.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	sh.CreateServiceIdentity(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint service identity: %d %s", rec.Code, rec.Body.String())
	}
	var resp serviceIdentityCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	if resp.Key == "" {
		t.Fatal("mint returned no key")
	}
	return resp.Key
}

func fetchOwnSecrets(t *testing.T, sh *ServiceSecretsHandler, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	sh.FetchOwnSecrets(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// P1-8: the service-identity secret fetch
// ---------------------------------------------------------------------------

// TestServiceFetchResolvesASealedName is the regression test for P1-8.
//
// GetVaultEntryForServiceFetch used to carry `WHERE name = ?`, comparing the
// allowed_secrets whitelist's cleartext against a column that has held
// randomized AES-GCM ciphertext since 00040. Every fetch therefore missed on
// every name, and the handler answered 200 with an empty secrets map audited
// under "fetch", the SUCCESS verb: a service container booted with no
// credentials at all and both the response and the audit trail said it had
// worked.
//
// ABLATION: put `AND name = ?` back in the query (or revert the Go-side match)
// and this test fails on the secrets map being empty.
func TestServiceFetchResolvesASealedName(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "svc-owner@example.com", "admin", "")

	entryID := createEntryThroughTheRealWritePath(t, vh, owner, "POSTGRES_PASSWORD", "super-secret-pg-pass")
	requireSealedName(t, vh, entryID, "POSTGRES_PASSWORD")

	sh := NewServiceSecretsHandler(queries, vh)
	key := mintServiceIdentityThroughTheRealPath(t, sh, owner, "webapp-prod", []string{"POSTGRES_PASSWORD"})

	rec := fetchOwnSecrets(t, sh, key)
	if rec.Code != http.StatusOK {
		t.Fatalf("service fetch of an existing secret: %d %s", rec.Code, rec.Body.String())
	}
	var resp fetchSecretsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Secrets["POSTGRES_PASSWORD"] != "super-secret-pg-pass" {
		t.Fatalf("the service booted without its credential: secrets = %v. "+
			"This is P1-8: the name lookup compared cleartext against ciphertext and missed",
			resp.Secrets)
	}
}

// TestServiceFetchStillResolvesAPre00040Row is the guard against somebody
// "simplifying" the Go-side name match into `WHERE name_bidx = ?`.
//
// A pre-backfill, interrupted, or manually damaged row can have a cleartext
// name and empty name_bidx. The current boot sweep repairs that state, including
// same-scope collisions, but request-time lookup must remain safe before the
// repair has run successfully. Such rows sit outside the partial unique index;
// a bidx-only lookup returns nothing for them while the fetch they belong to
// reports success, a quieter version of the exact bug this test guards.
func TestServiceFetchStillResolvesAPre00040Row(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "legacy-owner@example.com", "admin", "")

	// A row in the shape found before a successful sweep: cleartext name, empty bidx.
	// Written with raw SQL because production has no way to create one any more,
	// which is precisely why it needs a test. Only the NAME is legacy-shaped:
	// the value is sealed properly so the test fails on the lookup if it fails
	// at all, rather than on an undecryptable value.
	const legacyID = "entry-pre-00040"
	seedUnsweptCleartextNameRow(t, vh, legacyID, owner, "LEGACY_UNSWEPT", "legacy-value")
	if raw := storedName(t, vh, legacyID); raw != "LEGACY_UNSWEPT" {
		t.Fatalf("ABORT: the legacy row is not in the pre-00040 shape (%q)", raw)
	}

	sh := NewServiceSecretsHandler(queries, vh)
	key := mintServiceIdentityThroughTheRealPath(t, sh, owner, "legacy-svc", []string{"LEGACY_UNSWEPT"})

	rec := fetchOwnSecrets(t, sh, key)
	if rec.Code != http.StatusOK {
		t.Fatalf("an unswept pre-00040 row stopped resolving: %d %s. "+
			"If this broke because the lookup moved to name_bidx, that is the wrong fix: "+
			"request-time compatibility must survive until the boot repair succeeds",
			rec.Code, rec.Body.String())
	}
	var resp fetchSecretsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Secrets["LEGACY_UNSWEPT"] != "legacy-value" {
		t.Fatalf("an unswept pre-00040 row did not resolve: secrets = %v", resp.Secrets)
	}
}

// seedUnsweptCleartextNameRow writes a pre-backfill/interrupted legacy shape:
// cleartext name and empty name_bidx. The VALUE is sealed normally, because the
// compatibility behavior being tested is about the name.
func seedUnsweptCleartextNameRow(t *testing.T, vh *VaultHandler, entryID, ownerID, name, value string) {
	t.Helper()
	ct, nonce, err := vh.EncryptValue([]byte(value))
	if err != nil {
		t.Fatalf("encrypt value: %v", err)
	}
	if _, err := vh.db.Exec(
		`INSERT INTO vault_entries (id, user_id, secret_owner_user_id, name, name_bidx, encrypted_value, nonce, encryption_version)
		 VALUES (?, ?, ?, ?, '', ?, ?, 2)`,
		entryID, ownerID, ownerID, name, ct, nonce); err != nil {
		t.Fatalf("seed unswept row %s: %v", entryID, err)
	}
}

// TestServiceFetchKeepsBothAuthorizationPredicates pins the part of the fix that
// is easiest to lose. Dropping the name from the SQL widens the query, so the
// two predicates that remain are the only thing standing between a machine
// identity and somebody else's secret.
func TestServiceFetchKeepsBothAuthorizationPredicates(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "own@example.com", "admin", "")
	stranger := mustUser(t, queries, "stranger@example.com", "user", "")

	// Same name, different owner. user_id is what must exclude it.
	strangerEntry := createEntryThroughTheRealWritePath(t, vh, stranger, "SHARED_NAME", "stranger-value")
	requireSealedName(t, vh, strangerEntry, "SHARED_NAME")

	// Same owner, but the entry lives in a collection. collection_id IS NULL is
	// what must exclude it: any editor of a shared collection could otherwise
	// choose what a machine identity fetches by editing the shared entry.
	collectionEntry := createEntryThroughTheRealWritePath(t, vh, owner, "COLLECTION_NAME", "collection-value")
	mustCollection(t, queries, "coll-svc", owner, map[string]string{owner: collRoleManager})
	placeInCollection(t, queries, collectionEntry, "coll-svc")

	sh := NewServiceSecretsHandler(queries, vh)

	key := mintServiceIdentityThroughTheRealPath(t, sh, owner, "cross-owner-svc", []string{"SHARED_NAME"})
	rec := fetchOwnSecrets(t, sh, key)
	if strings.Contains(rec.Body.String(), "stranger-value") {
		t.Fatalf("CROSS-TENANT LEAK: the owner predicate is gone from the fetch: %s", rec.Body.String())
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("a name owned by another user resolved: %d %s", rec.Code, rec.Body.String())
	}

	key2 := mintServiceIdentityThroughTheRealPath(t, sh, owner, "collection-svc", []string{"COLLECTION_NAME"})
	rec2 := fetchOwnSecrets(t, sh, key2)
	if strings.Contains(rec2.Body.String(), "collection-value") {
		t.Fatalf("the collection_id IS NULL predicate is gone: a machine identity fetched a "+
			"shared-collection entry, which any editor of that collection can rewrite: %s", rec2.Body.String())
	}
	if rec2.Code == http.StatusOK {
		t.Fatalf("a collection entry resolved for a service identity: %d %s", rec2.Code, rec2.Body.String())
	}
}

// TestServiceFetchRefusesAnAmbiguousName. Two of one user's personal entries
// can temporarily open to the same name before boot repair, and this test builds
// that compatibility shape: one entry written normally (sealed name, blind
// index) and one pre-backfill row with an empty name_bidx. The inline
// UNIQUE(user_id, name) does not fire, because "AMBIGUOUS"
// and "enc:v1:..." are different strings, and the partial unique index does not
// either, because it excludes the empty bidx. Resolving the tie by row order
// hands a machine identity whichever credential SQLite returned first, with
// nothing in the response or the audit trail to say which.
func TestServiceFetchRefusesAnAmbiguousName(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "dupe@example.com", "admin", "")

	sealed := createEntryThroughTheRealWritePath(t, vh, owner, "AMBIGUOUS", "sealed-value")
	requireSealedName(t, vh, sealed, "AMBIGUOUS")
	seedUnsweptCleartextNameRow(t, vh, "dupe-unswept", owner, "AMBIGUOUS", "unswept-value")

	sh := NewServiceSecretsHandler(queries, vh)
	key := mintServiceIdentityThroughTheRealPath(t, sh, owner, "dupe-svc", []string{"AMBIGUOUS"})

	rec := fetchOwnSecrets(t, sh, key)
	if rec.Code != http.StatusConflict {
		t.Fatalf("an ambiguous name must be refused, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ambiguous_secret_name") {
		t.Errorf("refusal should carry the machine-readable code: %s", rec.Body.String())
	}
	for _, v := range []string{"sealed-value", "unswept-value"} {
		if strings.Contains(rec.Body.String(), v) {
			t.Fatalf("a refused ambiguous fetch still shipped %q: %s", v, rec.Body.String())
		}
	}
}

// TestMatchEntryNameIsExhaustiveAndRefusesTies pins matchEntryName directly: it
// must scan the whole candidate list (no early exit on the first hit, which is
// what makes the running time independent of where a match sits) and it must
// report a tie rather than choose.
func TestMatchEntryNameIsExhaustiveAndRefusesTies(t *testing.T) {
	if idx, amb := matchEntryName([]string{"a", "b", "c"}, "b"); idx != 1 || amb {
		t.Errorf("single match: idx=%d ambiguous=%v, want 1 false", idx, amb)
	}
	if idx, amb := matchEntryName([]string{"a", "b"}, "zzz"); idx != -1 || amb {
		t.Errorf("no match: idx=%d ambiguous=%v, want -1 false", idx, amb)
	}
	if _, amb := matchEntryName([]string{"dup", "other", "dup"}, "dup"); !amb {
		t.Error("two candidates with the same name must report ambiguity, not pick the first")
	}
	if idx, amb := matchEntryName(nil, "anything"); idx != -1 || amb {
		t.Errorf("empty candidate list: idx=%d ambiguous=%v, want -1 false", idx, amb)
	}
	// A prefix must not match: the comparison is on the whole value.
	if idx, _ := matchEntryName([]string{"stripe"}, "stripe-live"); idx != -1 {
		t.Errorf("a prefix matched a longer name: idx=%d", idx)
	}
}

// ---------------------------------------------------------------------------
// P1-11: the MCP list_secrets tool
// ---------------------------------------------------------------------------

// newRealMCPEnv builds the MCP handler over real migrations, a real
// VaultHandler and a real CapabilityHandler, which is what gives list_secrets a
// decryption door at all.
func newRealMCPEnv(t *testing.T) (*MCPHandler, *VaultHandler, *db.Queries) {
	t.Helper()
	vh, queries := newCollectionAuthzEnv(t)
	capH := &CapabilityHandler{db: vh.db, vault: vh}
	return NewMCPHandler(queries, nil, capH, nil, nil), vh, queries
}

// TestMCPListSecretsNeverShipsCiphertext is the regression test for P1-11.
//
// toolListSecrets used to marshal the stored vault_entries.name column straight
// into the tool result. A tool result crosses to Anthropic or OpenAI, so the
// model provider received one "enc:v1:..." blob per entry: the caller's exact
// secret inventory count, and each name's exact plaintext length, handed to the
// keyless third party that 00040 exists to keep in the dark. use_secret matches
// on the cleartext name, so the blobs were useless to the agent as well.
//
// ABLATION: drop the EntryNamePlain call in toolListSecrets and this test fails
// on both halves, the missing cleartext name and the leaked enc:v1: prefix.
func TestMCPListSecretsNeverShipsCiphertext(t *testing.T) {
	h, vh, queries := newRealMCPEnv(t)
	userA := mustUser(t, queries, "a@example.com", "user", "")
	userB := mustUser(t, queries, "b@example.com", "user", "")

	idA := createEntryThroughTheRealWritePath(t, vh, userA, "GitHub Token", "ghp_secret")
	requireSealedName(t, vh, idA, "GitHub Token")
	createEntryThroughTheRealWritePath(t, vh, userA, "AWS Prod", "aws_secret")
	idB := createEntryThroughTheRealWritePath(t, vh, userB, "Other User Secret", "other")
	requireSealedName(t, vh, idB, "Other User Secret")

	resp := doMCP(t, h, userA, "tools/call", map[string]any{"name": "list_secrets"})
	if resp.Error != nil {
		t.Fatalf("tools/call error: %+v", resp.Error)
	}
	rb, _ := json.Marshal(resp.Result)
	body := string(rb)

	if strings.Contains(body, vaultfield.ColumnPrefix) {
		t.Fatalf("CIPHERTEXT SHIPPED TO THE MODEL PROVIDER: list_secrets returned a sealed column, "+
			"which hands a keyless third party the inventory count and every name's plaintext "+
			"length: %s", body)
	}
	if !strings.Contains(body, "GitHub Token") || !strings.Contains(body, "AWS Prod") {
		t.Fatalf("list_secrets did not return the caller's cleartext names, so use_secret can "+
			"never be given a name it will match: %s", body)
	}
	if strings.Contains(body, "Other User Secret") {
		t.Fatalf("LEAK: another user's secret name appeared: %s", body)
	}
	if strings.Contains(body, "ghp_secret") || strings.Contains(body, "aws_secret") {
		t.Fatalf("list_secrets must never expose values: %s", body)
	}
}

// TestMCPListSecretsListsAPre00040Row is the other half of the bidx guard: a
// row not yet repaired by the boot sweep is still the caller's secret and must
// still be advertised safely.
func TestMCPListSecretsListsAPre00040Row(t *testing.T) {
	h, vh, queries := newRealMCPEnv(t)
	user := mustUser(t, queries, "legacy@example.com", "user", "")

	seedUnsweptCleartextNameRow(t, vh, "mcp-legacy", user, "LEGACY_UNSWEPT", "legacy-value")

	resp := doMCP(t, h, user, "tools/call", map[string]any{"name": "list_secrets"})
	rb, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(rb), "LEGACY_UNSWEPT") {
		t.Fatalf("an unswept pre-00040 row vanished from list_secrets: %s", rb)
	}
}

// TestMCPListSecretsFailsClosedWithoutADecryptionDoor. NewMCPHandler takes the
// capability handler as a pointer and callers do pass nil, so the door can be
// absent. The two wrong answers are a panic (which chi's Recoverer turns into a
// bare 500) and a fallback to the stored column (which is the leak itself).
func TestMCPListSecretsFailsClosedWithoutADecryptionDoor(t *testing.T) {
	_, vh, queries := newRealMCPEnv(t)
	user := mustUser(t, queries, "nodoor@example.com", "user", "")
	id := createEntryThroughTheRealWritePath(t, vh, user, "Stripe live key", "sk_live_x")
	requireSealedName(t, vh, id, "Stripe live key")

	// nil capability: exactly the shape mcp_test.go's own handler had.
	doorless := NewMCPHandler(queries, nil, nil, nil, nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("list_secrets panicked without a decryption door (%v); "+
				"chi's Recoverer would answer 500 and the tool would be unusable", r)
		}
	}()
	text, isErr := doorless.toolListSecrets(context.Background(), user)
	if !isErr {
		t.Fatalf("list_secrets must fail CLOSED without a decryption door, got a success: %q", text)
	}
	if strings.Contains(text, vaultfield.ColumnPrefix) {
		t.Fatalf("the doorless path fell back to the stored column, which is the leak: %q", text)
	}
	if strings.Contains(text, "Stripe live key") {
		t.Fatalf("the doorless path produced a cleartext name from nowhere: %q", text)
	}
}

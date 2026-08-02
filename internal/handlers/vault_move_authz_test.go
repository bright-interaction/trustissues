package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/database"
	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/passwordhash"
)

// newCollectionAuthzEnv boots a real SQLite database with the embedded
// migrations (collections included) and returns a VaultHandler over it.
func newCollectionAuthzEnv(t *testing.T) (*VaultHandler, *db.Queries) {
	t.Helper()

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
	return NewVaultHandler(dbConn, queries, cfg), queries
}

func mustUser(t *testing.T, queries *db.Queries, email, role, password string) string {
	t.Helper()
	hash := "not-a-real-hash"
	if password != "" {
		h, err := passwordhash.Hash(password)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		hash = h
	}
	u, err := queries.CreateUser(context.Background(), db.CreateUserParams{
		Email:        email,
		PasswordHash: hash,
		Name:         toNullString(email),
		Role:         role,
	})
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return u.ID
}

func mustCollection(t *testing.T, queries *db.Queries, id, creator string, members map[string]string) {
	t.Helper()
	ctx := context.Background()
	if err := queries.CreateCollection(ctx, db.CreateCollectionParams{
		ID:          id,
		Name:        id,
		Description: "",
		CreatedBy:   toNullString(creator),
	}); err != nil {
		t.Fatalf("create collection %s: %v", id, err)
	}
	for userID, role := range members {
		// Established members: accepted immediately. Membership is an invitation
		// now, and a pending row grants nothing, so a test that wants a real
		// member has to accept on their behalf. The pending path has its own
		// coverage in the collection-consent tests.
		if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
			CollectionID: id,
			UserID:       userID,
			Role:         role,
			AcceptedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}); err != nil {
			t.Fatalf("add member %s to %s: %v", userID, id, err)
		}
	}
}

func mustEntry(t *testing.T, h *VaultHandler, queries *db.Queries, id, ownerID, name, value string) {
	t.Helper()
	ct, nonce, err := h.EncryptValue([]byte(value))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := queries.CreateVaultEntry(context.Background(), db.CreateVaultEntryParams{
		ID:             id,
		UserID:         ownerID,
		Name:           name,
		EncryptedValue: ct,
		Nonce:          nonce,
	}); err != nil {
		t.Fatalf("create entry %s: %v", id, err)
	}
}

func placeInCollection(t *testing.T, queries *db.Queries, entryID, collectionID string) {
	t.Helper()
	target := sql.NullString{String: collectionID, Valid: collectionID != ""}
	if err := queries.SetVaultEntryCollection(context.Background(), db.SetVaultEntryCollectionParams{
		CollectionID: target,
		ID:           entryID,
	}); err != nil {
		t.Fatalf("place entry in collection: %v", err)
	}
}

func entryCollection(t *testing.T, queries *db.Queries, entryID string) string {
	t.Helper()
	info, err := queries.GetVaultEntryAccess(context.Background(), entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if !info.CollectionID.Valid {
		return ""
	}
	return info.CollectionID.String
}

// vaultAuthzRequest builds an authenticated request with the chi {id} param and
// the middleware identity keys populated.
func vaultAuthzRequest(method, path, userID, role, entryID, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", entryID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, timw.UserIDKey, userID)
	ctx = context.WithValue(ctx, timw.UserRoleKey, role)
	return r.WithContext(ctx)
}

func moveRequest(userID, role, entryID, body string) *http.Request {
	return vaultAuthzRequest("PUT", "/api/vault/"+entryID+"/collection", userID, role, entryID, body)
}

// TestMoveToCollectionRequiresOwnerAdminOrManager proves the dispossession fix:
// a plain collection editor cannot take an entry out of the collection it lives
// in (neither to their personal vault nor to a collection the owner and the
// manager are not in), while the owner, a manager of the source collection, and
// an instance admin can.
func TestMoveToCollectionRequiresOwnerAdminOrManager(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	owner := mustUser(t, queries, "owner@example.com", "user", "")
	editor := mustUser(t, queries, "editor@example.com", "user", "")
	manager := mustUser(t, queries, "manager@example.com", "user", "")
	admin := mustUser(t, queries, "admin@example.com", "admin", "")

	// Shared collection holding the entry. The owner is only an editor here, so
	// the entry's recovery must come from the owner right, not a manager role.
	mustCollection(t, queries, "coll-a", owner, map[string]string{
		owner:   collRoleEditor,
		editor:  collRoleEditor,
		manager: collRoleManager,
	})
	// A second collection the editor manages, and neither the owner nor the
	// coll-a manager belongs to. This is the expropriation destination.
	mustCollection(t, queries, "coll-b", editor, map[string]string{editor: collRoleManager})

	const entryID = "entry-shared"
	mustEntry(t, h, queries, entryID, owner, "shared-secret", "value-1")
	placeInCollection(t, queries, entryID, "coll-a")

	denied := []struct {
		name string
		body string
	}{
		{"editor cannot move it to their personal vault", `{"collection_id":null}`},
		{"editor cannot move it to a collection they alone control", `{"collection_id":"coll-b"}`},
	}
	for _, c := range denied {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.MoveToCollection(rec, moveRequest(editor, "user", entryID, c.body))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
			}
			if got := entryCollection(t, queries, entryID); got != "coll-a" {
				t.Fatalf("entry moved despite denial: collection = %q", got)
			}
		})
	}

	t.Run("manager of the source collection can move it out", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.MoveToCollection(rec, moveRequest(manager, "user", entryID, `{"collection_id":null}`))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
		}
		if got := entryCollection(t, queries, entryID); got != "" {
			t.Fatalf("entry not moved out: collection = %q", got)
		}
	})

	t.Run("owner can move their own entry out", func(t *testing.T) {
		placeInCollection(t, queries, entryID, "coll-a")
		rec := httptest.NewRecorder()
		h.MoveToCollection(rec, moveRequest(owner, "user", entryID, `{"collection_id":null}`))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
		}
		if got := entryCollection(t, queries, entryID); got != "" {
			t.Fatalf("entry not moved out: collection = %q", got)
		}
	})

	t.Run("instance admin can move it out", func(t *testing.T) {
		placeInCollection(t, queries, entryID, "coll-a")
		rec := httptest.NewRecorder()
		h.MoveToCollection(rec, moveRequest(admin, "admin", entryID, `{"collection_id":null}`))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("move into a destination still needs editor or manager there", func(t *testing.T) {
		// Entry is personal again, owned by owner. Owner has no role in coll-b.
		placeInCollection(t, queries, entryID, "")
		rec := httptest.NewRecorder()
		h.MoveToCollection(rec, moveRequest(owner, "user", entryID, `{"collection_id":"coll-b"}`))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 on destination check, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("move is recorded in the activity log with both collection ids", func(t *testing.T) {
		placeInCollection(t, queries, entryID, "coll-a")
		rec := httptest.NewRecorder()
		h.MoveToCollection(rec, moveRequest(manager, "user", entryID, `{"collection_id":null}`))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
		}
		rows, err := queries.ListActivityEntriesByAction(context.Background(), db.ListActivityEntriesByActionParams{
			Action: "vault.entry_moved",
			Limit:  50,
			Offset: 0,
		})
		if err != nil {
			t.Fatalf("list activity: %v", err)
		}
		var found bool
		for _, row := range rows {
			d := row.Detail.String
			if strings.Contains(d, "shared-secret") && strings.Contains(d, "coll-a") && strings.Contains(d, "personal") {
				found = true
			}
		}
		if !found {
			t.Fatal("no vault.entry_moved activity naming the entry plus source and destination")
		}
	})
}

// TestOwnerRetainsAccessInsideCollection pins the residual owner right in
// entryAccess: the creator keeps READ on their entry even when it sits in a
// collection they are not a member of, so they can always recover it.
//
// The right is deliberately read-only. It used to carry write, which meant
// removing someone from a collection did not actually revoke them: a deleted
// membership row is indistinguishable from never having been a member, so the
// removed creator kept delete and rotate on the shared secret and could move it
// into their personal vault, where they would keep reading it after the team
// rotated. See TestRemovedMemberCannotRetainASharedSecret.
func TestOwnerRetainsAccessInsideCollection(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	owner := mustUser(t, queries, "owner@example.com", "user", "")
	viewer := mustUser(t, queries, "viewer@example.com", "user", "")
	editor := mustUser(t, queries, "editor@example.com", "user", "")
	stranger := mustUser(t, queries, "stranger@example.com", "user", "")

	// The owner is deliberately NOT a member of the collection.
	mustCollection(t, queries, "coll-x", editor, map[string]string{
		viewer: collRoleViewer,
		editor: collRoleEditor,
	})

	const entryID = "entry-owned"
	mustEntry(t, h, queries, entryID, owner, "owner-secret", "value-1")
	placeInCollection(t, queries, entryID, "coll-x")

	cases := []struct {
		name              string
		userID            string
		role              string
		wantRead, wantWri bool
	}{
		{"creating owner keeps read for recovery, but not write", owner, "user", true, false},
		{"viewer member reads only", viewer, "user", true, false},
		{"editor member reads and writes", editor, "user", true, true},
		{"non-member gets nothing", stranger, "user", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := vaultAuthzRequest("GET", "/api/vault/"+entryID, c.userID, c.role, entryID, "")
			gotRead, gotWrite := h.entryAccess(r, entryID)
			if gotRead != c.wantRead || gotWrite != c.wantWri {
				t.Fatalf("entryAccess = (%v, %v), want (%v, %v)", gotRead, gotWrite, c.wantRead, c.wantWri)
			}
		})
	}
}

// TestUpdateTargetsStampsConfiguringUser proves the rotation-target
// exfiltration fix: the configuring identity is recorded server-side (a
// client-supplied configured_by is ignored), the forgejo auth_token resolves
// against that identity, and changing WHICH credential is spent re-attributes
// the target to whoever changed it.
//
// PREMISE CHANGE, round 5. The editor used to be the one who created the target,
// because manage was enough to name a delivery destination. It is not any more:
// adding one is held to the same right as widening destination_patterns. So the
// owner configures it and the editor works on it afterwards, which is a sharper
// version of the same question, and it exposed a sibling of the round-5 defect
// that the old shape could not reach:
//
//	the target's DESTINATION is unchanged, so ConfiguredBy was preserved, so the
//	auth_token resolved as the OWNER, so an editor could swap auth_token for one
//	of the owner's unrelated personal secrets and have it spent as the bearer
//	token for the delivery.
//
// rotationTargetAttribution closes that: auth_token is part of what decides
// whose authority the delivery runs under, so editing it stamps the editor.
func TestUpdateTargetsStampsConfiguringUser(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "owner@example.com", "user", "")
	editor := mustUser(t, queries, "editor@example.com", "user", "")
	mustCollection(t, queries, "coll-a", owner, map[string]string{
		owner:  collRoleManager,
		editor: collRoleEditor,
	})

	const entryID = "entry-shared"
	mustEntry(t, h, queries, entryID, owner, "shared-secret", "value-1")
	placeInCollection(t, queries, entryID, "coll-a")

	// The owner's unrelated personal secret, the exfiltration objective.
	mustEntry(t, h, queries, "entry-personal", owner, "OWNER_PERSONAL", "owner-only-value")

	readStored := func() []RotationTarget {
		t.Helper()
		raw, err := queries.GetVaultEntryTargets(ctx, entryID)
		if err != nil {
			t.Fatalf("read back targets: %v", err)
		}
		return ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", "rotation_targets"))
	}

	// The owner configures delivery, and lies about who configured it. The
	// server-side stamp must overwrite the client value.
	body := fmt.Sprintf(`[{"type":"forgejo_secret","instance":"https://git.example.com","repo":"o/r",`+
		`"secret_name":"CI_KEY","auth_token":"OWNER_PERSONAL","configured_by":%q}]`, editor)
	rec := putTargets(t, h, owner, "user", entryID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner could not set targets: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	stored := readStored()
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored target, got %d", len(stored))
	}
	if stored[0].ConfiguredBy != owner {
		t.Fatalf("configured_by = %q, want the writing owner %q (client value must be overwritten)",
			stored[0].ConfiguredBy, owner)
	}
	// The positive half: the owner's own target resolves the owner's own secret.
	if _, err := h.resolveVaultReferenceFor(ctx, "OWNER_PERSONAL", stored[0].ConfiguredBy); err != nil {
		t.Fatalf("owner-configured target should resolve its own secret: %v", err)
	}

	// A legacy target with no recorded configurer fails closed instead of
	// falling back to the entry owner.
	legacy := stored[0]
	legacy.ConfiguredBy = ""
	if err := deliverToForgejoSecret(ctx, queries, h, legacy, "new-value", owner); err == nil ||
		!strings.Contains(err.Error(), "re-save") {
		t.Fatalf("legacy target should fail closed with a re-save hint, got %v", err)
	}

	// Re-saving an UNCHANGED target must NOT re-attribute it. This assertion used
	// to demand the opposite (attribution moves to whoever saved), which was the
	// laundering bug: the rotation panel PUTs every row it loaded, so an unrelated
	// save silently re-authorized a departed member's webhook and the next
	// rotation POSTed them the fresh plaintext. "Who set this up" must not change
	// because somebody else pressed Save.
	rec = putTargets(t, h, editor, "user", entryID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("editor could not re-save an unchanged target: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	stored = readStored()
	if stored[0].ConfiguredBy != owner {
		t.Fatalf("re-saving an unchanged target re-attributed it: configured_by = %q, want the original configurer %q",
			stored[0].ConfiguredBy, owner)
	}

	// THE SIBLING. Same destination, different auth_token. The destination did not
	// move, so the egress gate has nothing to refuse, and that is exactly why the
	// ATTRIBUTION has to move: the editor chose which credential gets spent, so
	// the lookup must run as the editor and find nothing.
	swapped := `[{"type":"forgejo_secret","instance":"https://git.example.com","repo":"o/r",` +
		`"secret_name":"CI_KEY","auth_token":"OWNER_PERSONAL_2"}]`
	mustEntry(t, h, queries, "entry-personal-2", owner, "OWNER_PERSONAL_2", "owner-only-value-2")
	rec = putTargets(t, h, editor, "user", entryID, swapped)
	if rec.Code != http.StatusOK {
		t.Fatalf("editor could not change the auth_token: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	stored = readStored()
	if stored[0].ConfiguredBy != editor {
		t.Fatalf("changing auth_token kept the previous attribution (configured_by = %q). The editor "+
			"picked which of the owner's credentials is spent as the delivery bearer token and the "+
			"lookup would run as the owner", stored[0].ConfiguredBy)
	}
	err := deliverToForgejoSecret(ctx, queries, h, stored[0], "new-value", owner)
	if err == nil {
		t.Fatal("an editor-chosen auth_token resolved the owner's personal secret")
	}
	if !strings.Contains(err.Error(), "OWNER_PERSONAL_2") {
		t.Fatalf("unexpected error: %v", err)
	}

	// A genuinely NEW destination is stamped to whoever created it, and only
	// someone with the widening right may create one.
	newBody := fmt.Sprintf(`[{"type":"forgejo_secret","instance":"https://git.example.com","repo":"o/r",`+
		`"secret_name":"OTHER_KEY","auth_token":"OWNER_PERSONAL","configured_by":%q}]`, editor)
	rec = putTargets(t, h, editor, "user", entryID, newBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an editor added a NEW delivery destination on somebody else's secret: HTTP %d (%s)",
			rec.Code, rec.Body.String())
	}
	rec = putTargets(t, h, owner, "user", entryID, newBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner could not set a new target: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	stored = readStored()
	if stored[0].ConfiguredBy != owner {
		t.Fatalf("a new target was not stamped to its creator: configured_by = %q, want %q",
			stored[0].ConfiguredBy, owner)
	}
	// Resolve through the handler helper, not the raw query: the query is now
	// name-only and access is decided by entryCurrentlyUsableBy, so calling the
	// query directly would assert nothing about authorization.
	if _, err := h.resolveVaultReferenceFor(ctx, "OWNER_PERSONAL", stored[0].ConfiguredBy); err != nil {
		t.Fatalf("owner-configured target should resolve its own secret: %v", err)
	}
}

// failingProvider is a KeyProvider whose Rotate always fails, standing in for a
// provider API that is down or rejects the request.
type failingProvider struct{}

func (p *failingProvider) Name() string                               { return "failing-test-provider" }
func (p *failingProvider) CanAutoRotate() bool                        { return true }
func (p *failingProvider) DashboardURL(meta map[string]string) string { return "" }
func (p *failingProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	return "", fmt.Errorf("upstream said no")
}
func (p *failingProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	return false, fmt.Errorf("upstream said no")
}

// TestManualRotateProviderFailureLeavesSecretIntact proves the manual rotate
// handler no longer overwrites a live provider credential with a locally
// generated random value when the provider API fails. It must 502, leave the
// stored value untouched, and record the failure.
func TestManualRotateProviderFailureLeavesSecretIntact(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const providerName = "failing-test-provider"
	ProviderRegistry[providerName] = &failingProvider{}
	t.Cleanup(func() { delete(ProviderRegistry, providerName) })

	const password = "correct-horse-battery-staple"
	owner := mustUser(t, queries, "owner@example.com", "user", password)

	const entryID = "entry-provider"
	mustEntry(t, h, queries, entryID, owner, "provider-key", "live-upstream-value")
	if err := queries.UpdateVaultEntryProvider(ctx, db.UpdateVaultEntryProviderParams{
		Provider:     toNullString(providerName),
		ProviderMeta: toNullString("{}"),
		AutoRotate:   sql.NullInt64{Int64: 1, Valid: true},
		ID:           entryID,
	}); err != nil {
		t.Fatalf("set provider: %v", err)
	}

	before, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("read entry before: %v", err)
	}

	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{"password":%q}`, password)
	h.Rotate(rec, vaultAuthzRequest("POST", "/api/vault/"+entryID+"/rotate", owner, "user", entryID, body))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when the provider rotation fails, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "upstream said no") {
		t.Fatalf("provider error detail leaked to the client: %s", rec.Body.String())
	}

	after, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("read entry after: %v", err)
	}
	plain, err := h.DecryptValue(after.EncryptedValue, after.Nonce, 2)
	if err != nil {
		t.Fatalf("decrypt after: %v", err)
	}
	if string(plain) != "live-upstream-value" {
		t.Fatalf("stored secret was overwritten with %q; the live credential would be destroyed", plain)
	}
	if string(after.EncryptedValue) != string(before.EncryptedValue) {
		t.Fatal("stored ciphertext changed on a failed provider rotation")
	}

	meta, err := queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	if meta.LastRotationError.String == "" {
		t.Fatal("last_rotation_error not persisted")
	}
	if strings.Contains(meta.LastRotationError.String, "upstream said no") {
		t.Fatalf("raw provider error persisted: %q", meta.LastRotationError.String)
	}

	var logEntries []RotationLogEntry
	if err := json.Unmarshal([]byte(after.RotationLog.String), &logEntries); err != nil {
		t.Fatalf("rotation_log not JSON: %v (%q)", err, after.RotationLog.String)
	}
	if len(logEntries) == 0 || logEntries[len(logEntries)-1].Status != "error" {
		t.Fatalf("rotation_log does not end with an error entry: %+v", logEntries)
	}
}

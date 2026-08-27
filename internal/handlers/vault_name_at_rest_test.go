package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// TestTheEntryNameIsNotReadableFromTheDatabaseFile is the property 00040 exists
// for.
//
// 00011 encrypted url, alias_url, username, category and notes so that a stolen
// database FILE is not a readable one, and left the name beside them in the
// clear. "Stripe live key" and "Acme prod DB" describe an entry better than any
// column that was encrypted, so a keyless reader still got the whole inventory
// and most of what the other columns were withholding.
func TestTheEntryNameIsNotReadableFromTheDatabaseFile(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "atrest@example.com", "user", "")

	// THROUGH THE REAL CREATE HANDLER, not through the fixture. The first version
	// of this test used mustEntry, which does its own encryption, so ablating the
	// handler's encryption left the test passing: it was asserting that the test
	// helper worked. The property belongs to the endpoint a user actually calls.
	const secretish = "Acme prod DB"
	body, _ := json.Marshal(map[string]any{"name": secretish, "value": "v"})
	r := httptest.NewRequest(http.MethodPost, "/api/vault", strings.NewReader(string(body)))
	ctx := context.WithValue(r.Context(), timw.UserIDKey, owner)
	ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
	rec := httptest.NewRecorder()
	h.Create(rec, r.WithContext(ctx))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("could not read the new entry id: %v %s", err, rec.Body.String())
	}

	// Read the column the way a thief with the file reads it: no handler, no key.
	var stored string
	if err := h.db.QueryRow(`SELECT name FROM vault_entries WHERE id = ?`, created.ID).
		Scan(&stored); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if strings.Contains(stored, secretish) {
		t.Fatalf("THE ENTRY NAME IS CLEARTEXT AT REST: %q. A keyless copy of the database still "+
			"reveals the inventory, which is what the other encrypted columns were for", stored)
	}
	if !strings.HasPrefix(stored, "enc:v1:") {
		t.Errorf("the name is neither cleartext nor the column-crypto format: %q", stored)
	}

	// And it still round-trips for a caller who holds the key.
	if got := entryNamePlain(t, h, queries, created.ID); got != secretish {
		t.Errorf("the name did not survive encryption: %q", got)
	}
}

// TestNameUniquenessIsStillPerUser. The inline UNIQUE(user_id, name) cannot fire
// any more (randomized ciphertext never collides), so all of this now rests on
// the partial unique index over name_bidx. Both halves matter: a duplicate
// within one user must be refused, and the SAME name under two different users
// must still be allowed, or shared instances break.
func TestNameUniquenessIsStillPerUser(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	alice := mustUser(t, queries, "alice-uniq@example.com", "user", "")
	bob := mustUser(t, queries, "bob-uniq@example.com", "user", "")

	create := func(userID, name string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"name": name, "value": "v"})
		r := httptest.NewRequest(http.MethodPost, "/api/vault", strings.NewReader(string(body)))
		ctx := context.WithValue(r.Context(), timw.UserIDKey, userID)
		ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
		rec := httptest.NewRecorder()
		h.Create(rec, r.WithContext(ctx))
		return rec
	}

	if rec := create(alice, "shared-label"); rec.Code != http.StatusCreated {
		t.Fatalf("first create: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	// SAME user, SAME name: refused.
	if rec := create(alice, "shared-label"); rec.Code != http.StatusConflict {
		t.Errorf("A DUPLICATE NAME WAS ACCEPTED for one user (HTTP %d). The inline UNIQUE(user_id, "+
			"name) cannot fire over ciphertext, so if the blind index is not enforcing it, nothing "+
			"is: %s", rec.Code, rec.Body.String())
	}
	// DIFFERENT user, same name: allowed.
	if rec := create(bob, "shared-label"); rec.Code != http.StatusCreated {
		t.Errorf("two users may not share an entry name (HTTP %d); uniqueness is per user, not "+
			"global: %s", rec.Code, rec.Body.String())
	}
}

// TestTheNameIndexIsUnlinkableAcrossUsers. The url index was reworked in
// 2026-07-26 because a global HMAC stored the SAME token for two users with an
// entry on the same site, so a stolen database revealed the co-occurrence
// without the vault key. A name index keyed globally would leak exactly the
// same way, and more legibly: entry names are chosen by people.
func TestTheNameIndexIsUnlinkableAcrossUsers(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	alice := mustUser(t, queries, "alice-link@example.com", "user", "")
	bob := mustUser(t, queries, "bob-link@example.com", "user", "")

	a := h.nameBlindIndex(alice, "Acme prod DB")
	b := h.nameBlindIndex(bob, "Acme prod DB")
	if a == "" || b == "" {
		t.Fatalf("ABORT: the index is empty, so this test proves nothing (a=%q b=%q)", a, b)
	}
	if a == b {
		t.Fatalf("TWO USERS WITH THE SAME ENTRY NAME STORE THE SAME TOKEN (%q): a keyless reader "+
			"learns they both hold an entry by that name", a)
	}
	// Deterministic within one user, or uniqueness could not be enforced at all.
	if again := h.nameBlindIndex(alice, "Acme prod DB"); again != a {
		t.Errorf("the index is not deterministic for one user: %q then %q", a, again)
	}
	// An empty user or name yields an empty index, which the partial unique
	// index deliberately excludes rather than treating as a value.
	if got := h.nameBlindIndex("", "x"); got != "" {
		t.Errorf("an unscoped index was produced: %q", got)
	}
	if got := h.nameBlindIndex(alice, ""); got != "" {
		t.Errorf("an empty name produced an index: %q", got)
	}
}

// TestTheBootBackfillEncryptsExistingNames covers the upgrade path. Every
// deployment that already exists reaches 00040 with cleartext names and an empty
// index, and BackfillMetadataAtRest at boot is the only thing that converts
// them. A row it misses keeps its name in the clear AND sits outside the unique
// index, so it is both readable and unconstrained.
func TestTheBootBackfillEncryptsExistingNames(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "backfill-name@example.com", "user", "")
	mustEntry(t, h, queries, "entry-bf", owner, "placeholder", "v")

	// Rewind the row to its pre-00040 shape: cleartext name, no index.
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET name = ?, name_bidx = '' WHERE id = ?`,
		"Legacy Cleartext Name", "entry-bf"); err != nil {
		t.Fatalf("rewind row: %v", err)
	}

	if _, err := h.BackfillMetadataAtRest(); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var stored, bidx string
	if err := h.db.QueryRow(`SELECT name, name_bidx FROM vault_entries WHERE id = ?`, "entry-bf").
		Scan(&stored, &bidx); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.Contains(stored, "Legacy Cleartext Name") {
		t.Errorf("the backfill left a pre-existing name in cleartext: %q", stored)
	}
	if bidx == "" {
		t.Errorf("the backfill left name_bidx empty, so this row is outside the unique index and " +
			"can be duplicated silently")
	}
	if want := h.nameBlindIndex(owner, "Legacy Cleartext Name"); bidx != want {
		t.Errorf("the backfilled index is not the one a lookup computes: got %q want %q", bidx, want)
	}
	if got := entryNamePlain(t, h, queries, "entry-bf"); got != "Legacy Cleartext Name" {
		t.Errorf("the backfill did not preserve the name: %q", got)
	}

	// IDEMPOTENT. It runs on every boot, and a second pass that re-encrypted an
	// already-encrypted name would double-wrap it permanently.
	if _, err := h.BackfillMetadataAtRest(); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if got := entryNamePlain(t, h, queries, "entry-bf"); got != "Legacy Cleartext Name" {
		t.Errorf("a second backfill pass corrupted the name: %q", got)
	}
}

// TestTheListIsOrderedByTheDecryptedName. Every list query used to say ORDER BY
// name and now says ORDER BY id, because ordering ciphertext orders by nonce.
// If the Go-side sort were missing, the vault would come back in a different
// arbitrary order on each request, which reads as corruption rather than as a
// missing sort.
func TestTheListIsOrderedByTheDecryptedName(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "sorted@example.com", "user", "")

	// Ids deliberately ordered opposite to the names, so a list that came back in
	// id order (or in storage order) cannot accidentally look sorted.
	mustEntry(t, h, queries, "id-1", owner, "zulu", "v")
	mustEntry(t, h, queries, "id-2", owner, "mike", "v")
	mustEntry(t, h, queries, "id-3", owner, "alpha", "v")

	r := httptest.NewRequest(http.MethodGet, "/api/vault", nil)
	ctx := context.WithValue(r.Context(), timw.UserIDKey, owner)
	ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
	rec := httptest.NewRecorder()
	h.List(rec, r.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	var got []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	names := make([]string, len(got))
	for i, e := range got {
		names[i] = e.Name
	}
	want := []string{"alpha", "mike", "zulu"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("the vault list is not alphabetical by name: got %v want %v", names, want)
	}
}

// TestAdoptionConvergesTheNameIndexToTheCollection. Adoption changes the
// custodian, not the shared vault namespace. It also gives legacy rows a chance
// to converge from a pre-00045 custodian token to the collection token.
func TestAdoptionConvergesTheNameIndexToTheCollection(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	creator := mustUser(t, queries, "adopt-from@example.com", "user", "")
	manager := mustUser(t, queries, "adopt-to@example.com", "user", "")

	mustCollection(t, queries, "coll-adopt", creator, map[string]string{
		creator: collRoleEditor,
		manager: collRoleManager,
	})
	mustEntry(t, h, queries, "entry-adopt", creator, "ci-token", "v")
	placeInCollection(t, queries, "entry-adopt", "coll-adopt")

	// The creator leaves, which is what makes the entry adoptable.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-adopt", UserID: creator,
	}); err != nil {
		t.Fatalf("remove creator: %v", err)
	}

	rec := httptest.NewRecorder()
	h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/entry-adopt", manager, "user",
		"entry-adopt", `{"name":"ci-token-adopted"}`))
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("adopt+rename: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	var bidx, custodian string
	if err := h.db.QueryRow(`SELECT name_bidx, user_id FROM vault_entries WHERE id = ?`, "entry-adopt").
		Scan(&bidx, &custodian); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if custodian != manager {
		t.Fatalf("ABORT: the entry was not adopted (custodian = %q), so this test is not about what "+
			"it says", custodian)
	}
	want := h.scopedNameBlindIndex(bidxScope(manager,
		sql.NullString{String: "coll-adopt", Valid: true}), "ci-token-adopted")
	if bidx != want {
		t.Errorf("THE NAME INDEX DID NOT CONVERGE TO THE COLLECTION: got %q, want %q", bidx, want)
	}
	// And it is NOT the pre-00045 value the departed creator's personal scope
	// would produce.
	if stale := h.nameBlindIndex(creator, "ci-token-adopted"); bidx == stale {
		t.Errorf("the index is still derived under the departed creator")
	}
}

// TestMovingAnEntryChangesItsNameScopeButKeepsItsName is the other side of the
// adoption rule. A move changes the namespace even though user_id stays fixed,
// so the opened name stays the same while every scope-keyed token changes.
func TestMovingAnEntryChangesItsNameScopeButKeepsItsName(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "mover@example.com", "user", "")
	mustCollection(t, queries, "coll-move-a", owner, map[string]string{owner: collRoleManager})
	mustEntry(t, h, queries, "entry-move", owner, "keep-this-name", "v")

	before := h.nameBlindIndex(owner, "keep-this-name")

	rec := httptest.NewRecorder()
	h.MoveToCollection(rec, moveRequest(owner, "user", "entry-move", `{"collection_id":"coll-move-a"}`))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("move: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	if got := entryNamePlain(t, h, queries, "entry-move"); got != "keep-this-name" {
		t.Errorf("THE MOVE BLANKED THE ENTRY NAME: %q", got)
	}
	var bidx string
	if err := h.db.QueryRow(`SELECT name_bidx FROM vault_entries WHERE id = ?`, "entry-move").
		Scan(&bidx); err != nil {
		t.Fatalf("read back: %v", err)
	}
	wantCollection := h.scopedNameBlindIndex(bidxScope(owner,
		sql.NullString{String: "coll-move-a", Valid: true}), "keep-this-name")
	if bidx != wantCollection {
		t.Errorf("the move left the wrong name scope: got %q, want collection token %q", bidx, wantCollection)
	}
	if bidx == before {
		t.Error("the move left the personal-vault name token on a collection entry")
	}

	back := httptest.NewRecorder()
	h.MoveToCollection(back, moveRequest(owner, "user", "entry-move", `{"collection_id":null}`))
	if back.Code != http.StatusNoContent {
		t.Fatalf("move back to personal: HTTP %d: %s", back.Code, back.Body.String())
	}
	if err := h.db.QueryRow(`SELECT name_bidx FROM vault_entries WHERE id = ?`, "entry-move").
		Scan(&bidx); err != nil {
		t.Fatalf("read back after personal move: %v", err)
	}
	if bidx != before {
		t.Errorf("moving back did not restore the personal scope: got %q want %q", bidx, before)
	}
}

// TestNameSurvivesAKeyRotation is the surface the rotation note calls the one
// everybody forgets. The name is ciphertext (re-encrypted) and name_bidx is a
// keyed HMAC (RECOMPUTED, not re-encrypted); getting the second one wrong
// produces no error at all, it just stops colliding, so duplicates appear
// silently after a rotation.
func TestNameSurvivesAKeyRotation(t *testing.T) {
	dbConn, queries := newRekeyDB(t)
	old := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	seedUnderKey(t, old, queries)

	// The sweep, running with the new key current and the old one available.
	fresh := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	if _, err := fresh.RekeyVault(context.Background()); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	rows, err := queries.ListVaultEntriesForRekey(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("ABORT: no rows to check")
	}
	for _, row := range rows {
		// Readable under the NEW key alone, which is what the operator is about to
		// be told is safe before they delete the old one.
		newOnly := rekeyHandler(dbConn, queries, rekeyNewKey, "")
		plain, dErr := newOnly.decryptColumn(row.Name, vaultFieldName)
		if dErr != nil {
			t.Fatalf("entry %s: the name does not open under the new key alone: %v", row.ID, dErr)
		}
		if plain == "" {
			continue
		}
		if want := newOnly.nameBlindIndex(row.UserID, plain); row.NameBidx != want {
			t.Errorf("entry %s: name_bidx was not recomputed under the new key (got %q want %q). "+
				"Nothing errors on a stale one; it just stops colliding, so duplicate names start "+
				"being accepted after the rotation", row.ID, row.NameBidx, want)
		}
	}
}

var _ = sql.ErrNoRows

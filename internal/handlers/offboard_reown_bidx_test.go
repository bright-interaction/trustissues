package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// WHAT 00040 QUIETLY TURNED OFF, AND WHAT 00045 PUTS BACK.
//
// Re-ownership on a hard delete has always had to answer one awkward case: the
// admin taking the leaver's shared entries may already hold an entry by the same
// name IN THAT COLLECTION, and "GitHub" collides constantly in a password
// manager. The answer is to catch the collection-scoped name-index violation,
// rename the incoming entry to "<name> (from <leaver>)" and retry, so the team
// keeps both.
//
// 00040 encrypted the name. That made the inline constraint vacuous ON PURPOSE
// (a fresh nonce per seal means two equal names no longer produce equal
// ciphertext) and moved real uniqueness to a partial index over name_bidx. Since
// 00045, shared names are keyed by COLLECTION rather than custodian: ownership
// transfer must converge old custodian-keyed rows to that stable scope without
// making personal entries with the same name collide.
//
// Both are asserted here against the real offboard path.

// TestReOwningConvergesTheNameIndexToTheCollection is the invariant. Shared
// namespace identity does not change merely because its custodian does.
func TestReOwningConvergesTheNameIndexToTheCollection(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	leaver := mustUser(t, queries, "leaver-bidx@example.com", "user", "")
	admin := mustUser(t, queries, "admin-bidx@example.com", "admin", "")
	mustCollection(t, queries, "coll-bidx", leaver, map[string]string{
		leaver: collRoleEditor, admin: collRoleManager,
	})

	const entryID = "entry-reown-bidx"
	const name = "Zzyzx shared deploy key"
	mustEntry(t, h, queries, entryID, leaver, name, "v")
	placeInCollection(t, queries, entryID, "coll-bidx")

	uh := newOffboardEnv(t, h, queries)
	uh.reassignCollectionEntries(offboardRequest(admin), leaver, "leaver-bidx@example.com", admin)

	var gotOwner, gotBidx string
	if err := h.db.QueryRow(`SELECT user_id, name_bidx FROM vault_entries WHERE id = ?`, entryID).
		Scan(&gotOwner, &gotBidx); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if gotOwner != admin {
		t.Fatalf("the entry was not re-owned at all: user_id = %q, want %q", gotOwner, admin)
	}
	want := h.scopedNameBlindIndex(bidxScope(admin,
		sql.NullString{String: "coll-bidx", Valid: true}), name)
	if gotBidx != want {
		if gotBidx == h.nameBlindIndex(leaver, name) {
			t.Fatalf("the entry moved to %s but its name_bidx is still keyed to the DELETED user; "+
				"collection-scoped uniqueness no longer constrains this legacy row", admin)
		}
		t.Fatalf("name_bidx = %q, want collection-scoped token %q", gotBidx, want)
	}
}

// TestReOwningStillDeDuplicatesACollidingName is the behaviour the product
// promises in its own confirmation dialog: the team keeps the shared entries,
// plural, even when a name is already taken.
func TestReOwningStillDeDuplicatesACollidingName(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	leaver := mustUser(t, queries, "leaver-dedup@example.com", "user", "")
	admin := mustUser(t, queries, "admin-dedup@example.com", "admin", "")
	mustCollection(t, queries, "coll-dedup", leaver, map[string]string{
		leaver: collRoleEditor, admin: collRoleManager,
	})

	const shared = "GitHub"
	// Model an existing legacy row which has already converged to the collection
	// token, while the leaver's row still carries its pre-00045 personal token.
	mustEntry(t, h, queries, "entry-admin-own", admin, shared, "admin-value")
	placeInCollection(t, queries, "entry-admin-own", "coll-dedup")
	if _, err := h.db.Exec(`UPDATE vault_entries SET name_bidx = ? WHERE id = ?`,
		h.scopedNameBlindIndex(bidxScope(admin,
			sql.NullString{String: "coll-dedup", Valid: true}), shared), "entry-admin-own"); err != nil {
		t.Fatalf("converge existing collection token: %v", err)
	}
	// And the leaver has one in the shared collection.
	mustEntry(t, h, queries, "entry-leaver-shared", leaver, shared, "leaver-value")
	placeInCollection(t, queries, "entry-leaver-shared", "coll-dedup")

	uh := newOffboardEnv(t, h, queries)
	uh.reassignCollectionEntries(offboardRequest(admin), leaver, "leaver-dedup@example.com", admin)

	// BOTH entries must survive, under the admin, with different names.
	var owner, storedName string
	if err := h.db.QueryRow(`SELECT user_id, name FROM vault_entries WHERE id = ?`, "entry-leaver-shared").
		Scan(&owner, &storedName); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if owner != admin {
		t.Fatalf("the colliding entry was not re-owned: user_id = %q", owner)
	}
	opened := h.EntryNamePlain(storedName)
	if opened == shared {
		t.Fatal("the colliding entry kept its original name. The de-duplication branch did not fire, " +
			"so the admin now holds two entries called \"GitHub\" and the index cannot tell them apart")
	}
	if !strings.Contains(opened, shared) || !strings.Contains(opened, "leaver-dedup@example.com") {
		t.Errorf("the de-duplicated name does not say what it is or where it came from: %q", opened)
	}
	// The stored form must still be openable. The previous version concatenated
	// the suffix onto the CIPHERTEXT, which produced a column no key could read.
	if strings.HasPrefix(opened, "enc:v1:") {
		t.Fatalf("the de-duplicated name is corrupt: the suffix was glued onto ciphertext and the "+
			"column can no longer be opened: %q", storedName)
	}
	// And its index is the new owner's, over the NEW name.
	var gotBidx string
	if err := h.db.QueryRow(`SELECT name_bidx FROM vault_entries WHERE id = ?`, "entry-leaver-shared").
		Scan(&gotBidx); err != nil {
		t.Fatalf("raw read bidx: %v", err)
	}
	if want := h.scopedNameBlindIndex(bidxScope(admin,
		sql.NullString{String: "coll-dedup", Valid: true}), opened); gotBidx != want {
		t.Errorf("name_bidx does not match the de-duplicated name in its collection")
	}

	// The admin's original is untouched.
	var adminName string
	if err := h.db.QueryRow(`SELECT name FROM vault_entries WHERE id = ?`, "entry-admin-own").
		Scan(&adminName); err != nil {
		t.Fatalf("raw read admin entry: %v", err)
	}
	if got := h.EntryNamePlain(adminName); got != shared {
		t.Errorf("the admin's own entry was renamed: %q", got)
	}
}

// newOffboardEnv builds a UserHandler wired to the vault, which is what the
// re-ownership path requires and refuses to run without.
func newOffboardEnv(t *testing.T, h *VaultHandler, queries *db.Queries) *UserHandler {
	t.Helper()
	uh := NewUserHandler(queries, nil)
	uh.SetVault(h)
	return uh
}

// offboardRequest carries the acting admin, which AuthorizeTransfer resolves
// from the users row rather than from this context; it is here because the
// handler reads the request for the activity log.
func offboardRequest(adminID string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, "/api/admin/users/leaver", nil)
	ctx := context.WithValue(r.Context(), timw.UserIDKey, adminID)
	ctx = context.WithValue(ctx, timw.UserRoleKey, "admin")
	return r.WithContext(ctx)
}

package handlers

import (
	"context"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestRemovedMemberCannotRetainASharedSecret locks the revocation property.
//
// entryAccess used to grant the creating user unconditional read+write on an
// entry inside a collection. A deleted membership row is indistinguishable from
// never having been a member, so removing someone from a collection did not
// revoke them at all if they had created the entry: they kept write, which means
// delete, rotate, and crucially MOVE. Moving the shared secret into their own
// personal vault made the removal permanent in the wrong direction, because from
// then on they held a private copy that kept working even after the team
// rotated the credential.
//
// The invariant: after removal the creator may still READ (so a creator who was
// never a member cannot be stranded by someone else's move), but may not write,
// and therefore cannot move the entry out of the collection. Removal followed by
// a rotation ends their access, which is the whole point of removal.
func TestRemovedMemberCannotRetainASharedSecret(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "creator@example.com", "user", "")
	manager := mustUser(t, queries, "manager@example.com", "user", "")

	// Both are members; the creator is an editor and makes the entry.
	mustCollection(t, queries, "coll-team", manager, map[string]string{
		manager: collRoleManager,
		creator: collRoleEditor,
	})
	const entryID = "entry-shared"
	mustEntry(t, h, queries, entryID, creator, "Shared prod key", "TEAM-SECRET")
	placeInCollection(t, queries, entryID, "coll-team")

	// While a member, the creator can write. Guard the setup: if they cannot,
	// the revocation assertion below proves nothing.
	r := vaultAuthzRequest("GET", "/api/vault/"+entryID, creator, "user", entryID, "")
	if read, write := h.entryAccess(r, entryID); !read || !write {
		t.Fatalf("ABORT: creator lacks access while still a member (read=%v write=%v)", read, write)
	}

	// Now remove them from the collection.
	res, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-team", UserID: creator,
	})
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("ABORT: removal affected %d rows, want 1; the test would not be exercising revocation", n)
	}
	if _, err := queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: "coll-team", UserID: creator,
	}); err == nil {
		t.Fatal("ABORT: membership row still present after removal, the test is not exercising revocation")
	}

	read, write := h.entryAccess(r, entryID)
	if write {
		t.Fatal("REVOCATION FAILED: a removed member kept WRITE on the shared secret; " +
			"they can delete it, rotate it, or move it into their personal vault and keep reading it after the team rotates")
	}
	if !read {
		t.Fatal("the creator lost read entirely: a creator stranded by someone else's move could never recover their own secret")
	}

	// The manager who is still a member keeps full access.
	rm := vaultAuthzRequest("GET", "/api/vault/"+entryID, manager, "user", entryID, "")
	if mr, mw := h.entryAccess(rm, entryID); !mr || !mw {
		t.Fatalf("remaining manager lost access: read=%v write=%v", mr, mw)
	}
}

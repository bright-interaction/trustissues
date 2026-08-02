package handlers

import (
	"context"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestPendingInviteCanBeRescinded locks the fix for an invitation that could
// never be withdrawn.
//
// Membership is consent-based: an invite sits with accepted_at NULL until the
// invitee accepts. RemoveMember checked existence with the AUTHORIZATION query,
// which deliberately ignores pending rows, so a pending invitee looked like they
// did not exist and the handler 404'd "member not found". The invitation stayed
// acceptable forever and the UI's Remove button just failed. Inviting the wrong
// person was therefore irreversible.
//
// The invariant: a pending invitation is visible to management operations and
// can be withdrawn, while authorization keeps ignoring it entirely.
func TestPendingInviteCanBeRescinded(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	manager := mustUser(t, queries, "mgr@example.com", "user", "")
	invitee := mustUser(t, queries, "oops@example.com", "user", "")

	mustCollection(t, queries, "coll-r", manager, map[string]string{manager: collRoleManager})
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: "coll-r", UserID: invitee, Role: collRoleViewer,
	}); err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Guard the setup: the row must exist AND be pending, or this proves nothing.
	m, err := queries.GetCollectionMembership(ctx, db.GetCollectionMembershipParams{
		CollectionID: "coll-r", UserID: invitee,
	})
	if err != nil {
		t.Fatalf("ABORT: membership row missing, nothing to rescind: %v", err)
	}
	if m.AcceptedAt.Valid {
		t.Fatal("ABORT: invitation is already accepted, the test is not exercising the pending path")
	}

	// Authorization must still ignore it entirely: pending grants nothing.
	if _, err := queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: "coll-r", UserID: invitee,
	}); err == nil {
		t.Fatal("a pending invitation resolved a role: it would grant access before acceptance")
	}

	// And it must be removable. This is the call RemoveMember makes after the
	// existence check that used to fail.
	res, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-r", UserID: invitee,
	})
	if err != nil {
		t.Fatalf("rescind: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("rescind affected %d rows, want 1: the invitation is still live", n)
	}

	// Gone for good: it can no longer be accepted.
	if _, err := queries.GetCollectionMembership(ctx, db.GetCollectionMembershipParams{
		CollectionID: "coll-r", UserID: invitee,
	}); err == nil {
		t.Fatal("membership row survived the rescind: the invitee could still accept")
	}
	accept, err := queries.AcceptCollectionInvite(ctx, db.AcceptCollectionInviteParams{
		CollectionID: "coll-r", UserID: invitee,
	})
	if err != nil {
		t.Fatalf("accept after rescind: %v", err)
	}
	if n, _ := accept.RowsAffected(); n != 0 {
		t.Fatal("a rescinded invitation was still acceptable")
	}
}

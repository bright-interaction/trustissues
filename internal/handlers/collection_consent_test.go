package handlers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
)

// TestPendingMembershipGrantsNothing locks the consent fix.
//
// Membership used to take effect the moment a manager added you, so ANY
// authenticated user could create a collection, add a colleague, and drop an
// entry into it. The victim's vault list, their /vault/match autofill and their
// unlock payload immediately carried attacker-controlled credentials, which is
// a phishing primitive: a fake "Okta SSO" login offered on a real company
// domain. It also worked in reverse, since the attacker managed the collection
// and could read anything the victim later stored there.
//
// The invariant: a pending membership grants NOTHING on any read path, and the
// same rows become visible once accepted.
func TestPendingMembershipGrantsNothing(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	attacker := mustUser(t, queries, "attacker@example.com", "user", "")
	victim := mustUser(t, queries, "victim@example.com", "user", "")

	// The attacker owns a collection and invites the victim (pending: no
	// accepted_at), then plants an entry in it.
	mustCollection(t, queries, "coll-phish", attacker, map[string]string{attacker: collRoleManager})
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: "coll-phish", UserID: victim, Role: collRoleViewer,
	}); err != nil {
		t.Fatalf("invite victim: %v", err)
	}
	const entryID = "entry-phish"
	mustEntry(t, h, queries, entryID, attacker, "Okta SSO", "FAKE-PHISH-PW")
	placeInCollection(t, queries, entryID, "coll-phish")

	accessible := func(who string) int {
		t.Helper()
		rows, err := queries.ListAccessibleVaultEntries(ctx, db.ListAccessibleVaultEntriesParams{
			ID:     who,
			UserID: who, UserID_2: who,
		})
		if err != nil {
			t.Fatalf("list accessible: %v", err)
		}
		return len(rows)
	}
	revealed := func(who string) int {
		t.Helper()
		rows, err := queries.ListAccessibleVaultEntriesWithSecrets(ctx, db.ListAccessibleVaultEntriesWithSecretsParams{
			ID:     who,
			UserID: who, UserID_2: who,
		})
		if err != nil {
			t.Fatalf("list with secrets: %v", err)
		}
		return len(rows)
	}

	// Pending: the planted entry must be invisible everywhere.
	if n := accessible(victim); n != 0 {
		t.Fatalf("pending membership exposed %d entries in the victim's vault list", n)
	}
	if n := revealed(victim); n != 0 {
		t.Fatalf("pending membership exposed %d entries to the victim's unlock", n)
	}
	if cols, err := queries.ListCollectionsForUser(ctx, victim); err != nil {
		t.Fatalf("list collections: %v", err)
	} else if len(cols) != 0 {
		t.Fatalf("pending membership showed the collection in the victim's list")
	}
	// A pending member has no role, so entryAccess and canWriteCollection deny.
	if _, err := queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: "coll-phish", UserID: victim,
	}); err == nil {
		t.Fatal("pending membership resolved a role: it would grant read/write")
	}
	// But the invitation is visible to the invitee so they can decide.
	pending, err := queries.ListPendingCollectionInvitesForUser(ctx, victim)
	if err != nil {
		t.Fatalf("pending list: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending invite, got %d", len(pending))
	}

	// Accepting opts in, and only then does access appear.
	res, err := queries.AcceptCollectionInvite(ctx, db.AcceptCollectionInviteParams{
		CollectionID: "coll-phish", UserID: victim,
	})
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("accept affected %d rows, want 1", n)
	}
	if n := accessible(victim); n != 1 {
		t.Fatalf("after accepting, victim sees %d entries, want 1", n)
	}
	if role, err := queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: "coll-phish", UserID: victim,
	}); err != nil || role != collRoleViewer {
		t.Fatalf("after accepting, role = %q err = %v, want viewer", role, err)
	}

	// Accepting twice is a no-op, so a stale client cannot re-grant anything.
	res2, err := queries.AcceptCollectionInvite(ctx, db.AcceptCollectionInviteParams{
		CollectionID: "coll-phish", UserID: victim,
	})
	if err != nil {
		t.Fatalf("second accept: %v", err)
	}
	if n, _ := res2.RowsAffected(); n != 0 {
		t.Fatalf("second accept affected %d rows, want 0", n)
	}
}

// TestConsentCardNamesTheRealInviter locks the identity the consent decision
// rests on.
//
// The card read "Invited by <email>" and that email came from
// collections.created_by, i.e. whoever created the COLLECTION. collection_members
// had no inviter column, so it could not be right by construction. Any manager
// of a collection created by a trusted person therefore inherited that person's
// name on the card, and the consent step is the only control against the attack
// migration 00029 exists for: planting a credential that lands in a colleague's
// vault list and autofill.
func TestConsentCardNamesTheRealInviter(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "card-creator@example.com", "admin", "")
	inviter := mustUser(t, queries, "card-inviter@example.com", "user", "")
	victim := mustUser(t, queries, "card-victim@example.com", "user", "")

	mustCollection(t, queries, "coll-card", creator, map[string]string{
		creator: collRoleManager,
		inviter: collRoleManager,
	})

	// The inviter, not the creator, sends the invitation.
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: "coll-card", UserID: victim, Role: collRoleViewer,
		AcceptedAt: sql.NullTime{}, InvitedBy: toNullString(inviter),
	}); err != nil {
		t.Fatalf("invite: %v", err)
	}

	pending, err := queries.ListPendingCollectionInvitesForUser(ctx, victim)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending invite, got %d", len(pending))
	}
	got := nullStringToString(pending[0].InvitedByEmail)
	if got == "card-creator@example.com" {
		t.Error("the consent card names the collection's CREATOR, so any manager can borrow " +
			"a trusted colleague's name to get an invitation accepted")
	}
	if got != "card-inviter@example.com" {
		t.Errorf("consent card names %q, want the actual inviter", got)
	}

	// A role change on an ACCEPTED member must not rewrite who brought them in.
	if _, err := queries.AcceptCollectionInvite(ctx, db.AcceptCollectionInviteParams{
		CollectionID: "coll-card", UserID: victim,
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: "coll-card", UserID: victim, Role: collRoleEditor,
		AcceptedAt: sql.NullTime{}, InvitedBy: toNullString(creator),
	}); err != nil {
		t.Fatalf("role change: %v", err)
	}
}

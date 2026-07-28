package handlers

import (
	"context"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
)

// TestRotationSweepSkipsEntriesWithNoLiveOwner locks the safety half of the
// user-delete fix.
//
// vault_entries.user_id has no foreign key (every other user-owned table has
// one) and DeleteUser is a bare DELETE FROM users, so a departed person's
// personal entries used to survive with a dangling user_id. Nothing could read
// them afterwards, because unlock, the capability lookups and the service fetch
// are all scoped to a live user. But the rotation sweep had no owner filter at
// all, so it kept rolling those secrets AT THE PROVIDER forever: invalidating
// whatever was deployed with the old value, writing the new value into a row
// nobody can decrypt, then failing delivery and firing a rotation_partial alert
// on every pass, from an account that no longer exists.
//
// The disposal in the delete handler now prevents orphans being created. This
// asserts the sweep itself also refuses them, so no orphan produced any other
// way (a restored backup, a manual DB edit, a future code path) can churn a
// live third-party credential unattended.
func TestRotationSweepSkipsEntriesWithNoLiveOwner(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	live := mustUser(t, queries, "sweep-live@example.com", "user", "")
	suspended := mustUser(t, queries, "sweep-suspended@example.com", "user", "")

	// Three auto-rotating entries, all long overdue.
	seed := func(id, owner, name string) {
		mustEntry(t, h, queries, id, owner, name, "sk_live_"+id)
		if _, err := h.db.ExecContext(ctx,
			`UPDATE vault_entries SET auto_rotate = 1, provider = 'cloudflare',
			 rotation_interval_days = 30, created_at = datetime('now', '-400 days') WHERE id = ?`, id); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("sweep-ok", live, "Live owner key")
	seed("sweep-suspended", suspended, "Suspended owner key")
	seed("sweep-orphan", "user-that-never-existed", "Orphan key")

	due := func() map[string]bool {
		rows, err := queries.ListVaultEntriesNeedingRotation(ctx)
		if err != nil {
			t.Fatalf("sweep query: %v", err)
		}
		got := map[string]bool{}
		for _, r := range rows {
			got[r.ID] = true
		}
		return got
	}

	// Guard the fixture: the healthy entry MUST be due, or "the others are
	// absent" would prove nothing (an empty result would pass every assertion).
	got := due()
	if !got["sweep-ok"] {
		t.Fatalf("ABORT: the live-owner entry is not due, so this test cannot detect over-filtering: %+v", got)
	}
	if got["sweep-orphan"] {
		t.Error("an entry whose owner does not exist is still scheduled for rotation; " +
			"it would be rolled at the provider forever and written into a row nobody can decrypt")
	}

	// Now disable the second owner. A suspended account's credentials must stop
	// moving, for the same reason offboarding revokes their delivery targets.
	if _, err := queries.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: 1, ID: suspended}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got = due()
	if got["sweep-suspended"] {
		t.Error("a disabled user's secret is still auto-rotating")
	}
	if !got["sweep-ok"] {
		t.Error("the live-owner entry stopped being due; the owner filter is over-broad and rotation is now dead for everyone")
	}

	// A shared collection entry must keep rotating regardless of its creator's
	// account, since it is team property rather than personal.
	mustCollection(t, queries, "coll-sweep", live, map[string]string{live: collRoleManager})
	seed("sweep-shared", suspended, "Shared team key")
	placeInCollection(t, queries, "sweep-shared", "coll-sweep")
	if !due()["sweep-shared"] {
		t.Error("a shared collection secret stopped rotating because its ORIGINAL creator was disabled; " +
			"the team still depends on it")
	}
}

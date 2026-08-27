package handlers

import (
	"context"
	"sync"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// The instance must never be left with zero active admins.
//
// ensureNotLastAdmin was a check-then-act: CountAdmins in one statement, the write in
// another, no transaction and no CAS between them. Two admins demoting each other at the
// same moment (or one admin demoted from two tabs) both read count = 2, both passed the
// check, and both writes landed.
//
// There is no way back from that inside the product. CreateFirstAdmin is gated on the
// users table being EMPTY, every admin route requires an admin, and role changes are an
// admin route. The recovery is hand-editing the database, which for a hosted secrets
// manager means the vendor opening a customer's database.
//
// Driven concurrently on purpose: a sequential test passes against the broken version,
// which is why the property survived this long.
func TestTheLastAdminSurvivesConcurrentDemotion(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	a := mustUser(t, queries, "admin-a@example.com", "admin", "")
	b := mustUser(t, queries, "admin-b@example.com", "admin", "")

	before, err := queries.CountAdmins(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if before != 2 {
		t.Fatalf("ABORT: fixture has %d active admins, want exactly 2; the race below needs "+
			"both demotions to look legal", before)
	}

	// Both demotions fire together. Exactly one must win.
	var wg sync.WaitGroup
	applied := make([]int64, 2)
	start := make(chan struct{})
	for i, id := range []string{a, b} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			<-start
			res, qErr := queries.UpdateUserRoleIfNotLastAdmin(ctx, db.UpdateUserRoleIfNotLastAdminParams{
				Role: "user", ID: id, Column3: "user",
			})
			if qErr != nil {
				return
			}
			applied[i], _ = res.RowsAffected()
		}(i, id)
	}
	close(start)
	wg.Wait()

	after, err := queries.CountAdmins(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if after == 0 {
		t.Fatalf("both demotions applied (%v) and the instance has ZERO active admins.\n"+
			"Nothing in the product can create one back: CreateFirstAdmin requires an empty "+
			"users table and every admin route requires an admin.", applied)
	}
	if after != 1 {
		t.Errorf("ended with %d active admins, want exactly 1 (one demotion should win)", after)
	}
}

// The guard must refuse the last admin, and only the last admin.
//
// A guard that refuses everything would pass the race test above, so the ordinary
// cases are pinned too: demoting one of two admins works, and the refusal is reported
// rather than silently doing nothing.
func TestLastAdminGuardRefusesOnlyTheLastOne(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	a := mustUser(t, queries, "solo-admin@example.com", "admin", "")

	// One admin: the demotion must be refused.
	res, err := queries.UpdateUserRoleIfNotLastAdmin(ctx, db.UpdateUserRoleIfNotLastAdminParams{
		Role: "user", ID: a, Column3: "user",
	})
	if err != nil {
		t.Fatalf("demote: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Fatal("the only active admin was demoted, leaving the instance with none")
	}

	// Disabling the only admin is the same hole by another verb.
	dres, err := queries.SetUserDisabledIfNotLastAdmin(ctx, db.SetUserDisabledIfNotLastAdminParams{
		Disabled: 1, ID: a, Column3: int64(1),
	})
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if n, _ := dres.RowsAffected(); n != 0 {
		t.Error("the only active admin was disabled, which locks the instance the same way")
	}

	// Deleting is the third verb.
	delres, err := queries.DeleteUserIfNotLastAdmin(ctx, db.DeleteUserIfNotLastAdminParams{
		ID:             a,
		PrivateIngress: 1,
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n, _ := delres.RowsAffected(); n != 0 {
		t.Error("the only active admin was deleted")
	}

	// With a second admin present, the demotion must go through, or the guard is
	// just "no admin may ever be demoted".
	mustUser(t, queries, "second-admin@example.com", "admin", "")
	ok, err := queries.UpdateUserRoleIfNotLastAdmin(ctx, db.UpdateUserRoleIfNotLastAdminParams{
		Role: "user", ID: a, Column3: "user",
	})
	if err != nil {
		t.Fatalf("demote with two admins: %v", err)
	}
	if n, _ := ok.RowsAffected(); n != 1 {
		t.Error("demoting one of TWO admins was refused; the guard is too broad and admins " +
			"can never be demoted at all")
	}

	// And promoting is never blocked by a guard about removal.
	up, err := queries.UpdateUserRoleIfNotLastAdmin(ctx, db.UpdateUserRoleIfNotLastAdminParams{
		Role: "admin", ID: a, Column3: "admin",
	})
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if n, _ := up.RowsAffected(); n != 1 {
		t.Error("promoting a user to admin was refused")
	}
}

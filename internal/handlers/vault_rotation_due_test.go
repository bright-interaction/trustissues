package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
)

// TestNeverRotatedEntryIsNotInstantlyDue locks the fix for the worst rotation
// trap: an operator enrols a credential, ticks auto-rotate, picks a long
// interval, and deploys the value to their infrastructure. Within the hour the
// scheduler rotated it at the provider and the deployed value was dead, while
// the UI showed the entry as "fresh".
//
// Cause: last_rotated_at has no DEFAULT and CreateVaultEntry never set it, so a
// new entry was NULL, and the sweep predicate read `last_rotated_at IS NULL` as
// "due now". Rotation is destructive upstream (Cloudflare rolls the token in
// place; other providers DELETE the predecessor), so this burned a live
// credential with no warning.
//
// The invariant: a freshly enrolled entry waits out its interval, an entry
// genuinely older than its interval still comes due, and the status the UI
// shows agrees with what the scheduler decides.
func TestNeverRotatedEntryIsNotInstantlyDue(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "rot@example.com", "user", "")

	arm := func(id, name string, intervalDays int64) {
		t.Helper()
		mustEntry(t, h, queries, id, owner, name, "THE-KEY-I-JUST-DEPLOYED")
		if _, err := h.db.ExecContext(ctx,
			`UPDATE vault_entries SET provider='cloudflare_token', auto_rotate=1,
			 rotation_interval_days=?, last_rotated_at=NULL WHERE id=?`,
			intervalDays, id); err != nil {
			t.Fatalf("arm %s: %v", id, err)
		}
	}

	due := func() []db.ListVaultEntriesNeedingRotationRow {
		t.Helper()
		rows, err := queries.ListVaultEntriesNeedingRotation(ctx)
		if err != nil {
			t.Fatalf("list due: %v", err)
		}
		return rows
	}

	// Guard the setup: if arming did not take, every assertion below is vacuous.
	arm("entry-fresh", "Cloudflare token", 365)
	var armed int
	if err := h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vault_entries WHERE auto_rotate=1 AND provider!='' AND last_rotated_at IS NULL`,
	).Scan(&armed); err != nil {
		t.Fatalf("count armed: %v", err)
	}
	if armed != 1 {
		t.Fatalf("ABORT: setup did not arm the entry (%d armed), the test would prove nothing", armed)
	}

	// THE BUG: this used to return the entry immediately.
	if rows := due(); len(rows) != 0 {
		t.Fatalf("a just-enrolled entry with a 365 day interval is already due (%d rows): "+
			"the scheduler would roll the operator's freshly deployed key within the hour", len(rows))
	}

	// An entry enrolled longer ago than its interval MUST still come due,
	// otherwise the fix would silently disable auto-rotation for everyone.
	arm("entry-stale", "Old token", 30)
	if _, err := h.db.ExecContext(ctx,
		`UPDATE vault_entries SET created_at = datetime('now', '-400 days') WHERE id='entry-stale'`,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	rows := due()
	if len(rows) != 1 || rows[0].ID != "entry-stale" {
		t.Fatalf("a 400-day-old entry with a 30 day interval is not due (%d rows): auto-rotation is now dead", len(rows))
	}

	// And the UI must agree with the scheduler in both directions.
	days365, days30 := 365, 30
	created := time.Now().AddDate(0, 0, -400).Format("2006-01-02 15:04:05")
	recent := time.Now().Format("2006-01-02 15:04:05")
	if got := computeRotationStatus(&days365, nil, nil, &recent); got != "fresh" {
		t.Fatalf("just-enrolled entry shows %q, want fresh", got)
	}
	if got := computeRotationStatus(&days30, nil, nil, &created); got == "fresh" {
		t.Fatal("an entry enrolled long before its interval still shows fresh: " +
			"the UI would say fresh while the scheduler rotates it")
	}
}

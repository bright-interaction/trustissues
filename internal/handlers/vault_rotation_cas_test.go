package handlers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
)

// TestSweepActuallyPersistsTheRotatedValue is the test the round-11 CAS needed
// and did not have.
//
// That CAS compared `updated_at = ?` binding a Go time.Time. SQLite stores the
// column as the literal text CURRENT_TIMESTAMP produces ("2026-07-29 13:06:22"),
// and the driver scans it into a time.Time then binds it back in a different
// layout, so the predicate NEVER matched. Every scheduled rotation reported a
// conflict and wrote nothing: a rare lost-update was traded for a total silent
// outage of auto-rotation, and it shipped.
//
// The round-11 test only checked that a CONFLICT was detected. It never asserted
// the happy path still persisted, so a CAS that always fails looked correct.
// Assert the write lands.
func TestSweepActuallyPersistsTheRotatedValue(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "cas@example.com", "user", "")
	const entryID = "cas-1"
	mustEntry(t, h, queries, entryID, owner, "Shared", "old-value")

	// Make it due, with a provider that rotates locally.
	if err := queries.UpdateVaultEntryProvider(ctx, db.UpdateVaultEntryProviderParams{
		Provider:     toNullString("shared-secret"),
		ProviderMeta: toNullString("{}"),
		AutoRotate:   sql.NullInt64{Int64: 1, Valid: true},
		ID:           entryID,
	}); err != nil {
		t.Fatalf("set provider: %v", err)
	}
	if err := queries.UpdateVaultEntryRotationInterval(ctx, db.UpdateVaultEntryRotationIntervalParams{
		RotationIntervalDays: sql.NullInt64{Int64: 1, Valid: true}, ID: entryID,
	}); err != nil {
		t.Fatalf("set interval: %v", err)
	}
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET last_rotated_at = datetime('now','-30 days') WHERE id = ?`, entryID); err != nil {
		t.Fatalf("age the entry: %v", err)
	}

	due, err := queries.ListVaultEntriesNeedingRotation(ctx)
	if err != nil {
		t.Fatalf("due list: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("ABORT: %d entries due, want 1; the sweep would be a no-op and this test vacuous", len(due))
	}
	if due[0].UpdatedAtText == "" {
		t.Fatal("ABORT: the snapshot carries no updated_at text, so the CAS cannot bind anything")
	}

	rotateOneEntry(ctx, queries, h, due[0])

	// The whole point: the new value must be STORED.
	after, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	plain, err := h.DecryptValue(after.EncryptedValue, after.Nonce, 2)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) == "old-value" {
		t.Error("the sweep did not persist the rotated value: the CAS is rejecting its own snapshot, " +
			"so scheduled auto-rotation silently does nothing")
	}

	meta, err := queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.LastRotationError.String != "" {
		t.Errorf("a successful rotation recorded an error: %q", meta.LastRotationError.String)
	}
}

// TestSweepStillDetectsARealConflict keeps the other half honest: the CAS must
// still refuse when the row genuinely changed during the pass.
func TestSweepStillDetectsARealConflict(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "cas2@example.com", "user", "")
	const entryID = "cas-2"
	mustEntry(t, h, queries, entryID, owner, "Shared", "old-value")

	if err := queries.UpdateVaultEntryProvider(ctx, db.UpdateVaultEntryProviderParams{
		Provider:     toNullString("shared-secret"),
		ProviderMeta: toNullString("{}"),
		AutoRotate:   sql.NullInt64{Int64: 1, Valid: true},
		ID:           entryID,
	}); err != nil {
		t.Fatalf("set provider: %v", err)
	}
	if err := queries.UpdateVaultEntryRotationInterval(ctx, db.UpdateVaultEntryRotationIntervalParams{
		RotationIntervalDays: sql.NullInt64{Int64: 1, Valid: true}, ID: entryID,
	}); err != nil {
		t.Fatalf("set interval: %v", err)
	}
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET last_rotated_at = datetime('now','-30 days') WHERE id = ?`, entryID); err != nil {
		t.Fatalf("age: %v", err)
	}
	due, err := queries.ListVaultEntriesNeedingRotation(ctx)
	if err != nil || len(due) != 1 {
		t.Fatalf("ABORT: due list %d (%v)", len(due), err)
	}

	// Someone saves the entry during the pass, moving updated_at.
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET updated_at = datetime('now','+1 second') WHERE id = ?`, entryID); err != nil {
		t.Fatalf("concurrent save: %v", err)
	}

	rotateOneEntry(ctx, queries, h, due[0])

	meta, err := queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.LastRotationError.String == "" {
		t.Error("a rotation that raced a concurrent save reported success; the stale value would " +
			"have overwritten the one the user just saved")
	}
}

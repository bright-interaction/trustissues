package handlers

import (
	"context"
	"testing"
)

// The rotation CAS must refuse a stale token even inside ONE second.
//
// The token was updated_at alone, and updated_at is CURRENT_TIMESTAMP, which SQLite
// renders at whole-second resolution ("2026-07-29 13:06:22"). Two writes committed in
// the same wall-clock second therefore leave the column byte-identical, so a snapshot
// taken between them still matches and the swap applies: persistRotatedValue returns
// applied = true for exactly the lost update the predicate was added to refuse.
//
// This is not exotic. The manual rotate handler and the scheduled sweep can both touch
// one entry, and a sweep pass over a handful of entries completes well inside a second.
//
// The test drives both writes without sleeping, which is the point: a version that
// sleeps between them passes against the broken code and proves nothing.
func TestRotationCASRefusesAStaleTokenWithinOneSecond(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	ct0, nonce0, err := h.encrypt([]byte("ORIGINAL"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := h.db.Exec(
		`INSERT INTO vault_entries (id, name, encrypted_value, nonce, encryption_version)
		 VALUES ('subsec-1','subsec',?,?,2)`, ct0, nonce0); err != nil {
		t.Fatalf("seed: %v", err)
	}

	read := func() (updatedAt string, value []byte) {
		t.Helper()
		if err := h.db.QueryRow(
			`SELECT CAST(updated_at AS TEXT), encrypted_value FROM vault_entries WHERE id='subsec-1'`,
		).Scan(&updatedAt, &value); err != nil {
			t.Fatalf("read: %v", err)
		}
		return
	}

	// The token, taken before anyone else writes.
	tokenUpdatedAt, tokenValue := read()
	snap := snapshotFromRotationRow("subsec-1", tokenUpdatedAt, tokenValue)

	// A COMPETING write lands first, in the same second.
	ctB, nonceB, err := h.encrypt([]byte("SOMEONE ELSE'S ROTATION"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	appliedB, err := persistRotatedValue(ctx, queries,
		snapshotFromRotationRow("subsec-1", tokenUpdatedAt, tokenValue), ctB, nonceB)
	if err != nil || !appliedB {
		t.Fatalf("ABORT: the competing write did not apply (%v %v), so there is no conflict to detect",
			appliedB, err)
	}

	// Guard the fixture: if the clock ticked between the two writes, the timestamp
	// alone would catch this and the test would pass for the wrong reason.
	afterUpdatedAt, _ := read()
	if afterUpdatedAt != tokenUpdatedAt {
		t.Skipf("the second boundary fell between the writes (%q -> %q); this case needs both "+
			"inside one second to be meaningful", tokenUpdatedAt, afterUpdatedAt)
	}

	// Now the stale caller replays. It MUST be refused.
	ctC, nonceC, err := h.encrypt([]byte("STALE OVERWRITE"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	appliedC, err := persistRotatedValue(ctx, queries, snap, ctC, nonceC)
	if err != nil {
		t.Fatalf("stale replay errored: %v", err)
	}
	if appliedC {
		t.Fatal("a STALE rotation overwrote a newer one inside the same second.\n" +
			"updated_at has whole-second resolution, so the timestamp token cannot see the " +
			"competing write, and the caller is told applied=true for the exact lost update " +
			"the compare-and-swap exists to refuse.")
	}

	// And the winner's value is what survived.
	_, finalValue := read()
	plain, err := h.decrypt(finalValue, nonceB)
	if err == nil && string(plain) != "SOMEONE ELSE'S ROTATION" {
		t.Errorf("the surviving value is %q, want the competing write's", plain)
	}
}

// A token missing its ciphertext half must be an ERROR, not a silent no-op.
//
// The ciphertext predicate compares against the value passed in, so an empty one would
// match only rows whose encrypted_value is empty, i.e. nothing at all. That would turn
// every rotation into a silent "conflict detected" and stop auto-rotation product-wide
// while reporting nothing, which is the shape that already happened once here when the
// first version of this CAS compared a time.Time against stored text.
func TestRotationCASRefusesATokenWithNoCiphertext(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	ct, nonce, _ := h.encrypt([]byte("x"))

	_, err := persistRotatedValue(ctx, queries,
		snapshotFromRotationRow("some-id", "2026-07-31 10:00:00", nil), ct, nonce)
	if err == nil {
		t.Error("a snapshot with no prior ciphertext was accepted; it can never match a row, " +
			"so every rotation would silently report a conflict and persist nothing")
	}
}

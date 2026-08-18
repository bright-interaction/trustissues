package handlers

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// These tests exercise persistRotatedValueAuthoritative directly rather than
// through the Rotate handler or the scheduled sweep, because BOTH of those
// still refuse a predecessorDestroysInPlace provider before ever minting (see
// the providerAuto guards in vault.go and vault_rotation.go). That refusal is
// deliberately staying in place: this function alone closes the CAS-miss
// data-loss path, but does not yet close the encrypt-failure or
// post-roll-transport-failure paths, so the live rotation path for Cloudflare
// remains gated. What is tested here is the mechanism itself, proven in
// isolation, so the next pass can wire it in once the remaining gaps are
// closed.

// TestPersistRotatedValueAuthoritativeSurvivesASingleConflict is the realistic
// case: one concurrent write lands on the row between this function's first
// read and its first CAS attempt (the same race
// TestSweepStillDetectsARealConflict proves is fatal for every OTHER
// provider's plain persistRotatedValue call). For a predecessorDestroysInPlace
// provider that must not be fatal, because the old value is already dead
// upstream by the time this runs: there is no "reload and retry" available to
// the caller, only this function's own retry.
//
// Before persistRotatedValueAuthoritative existed, the only code path for this
// provider class was the pre-mint refusal (e5ea1b1ee): nothing was ever
// minted, so the question this test asks could not even be posed. This test
// pins the property the retry loop exists to provide: a single conflict does
// not cost the credential.
func TestPersistRotatedValueAuthoritativeSurvivesASingleConflict(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "authoritative-single@example.com", "user", "")
	const entryID = "auth-single-1"
	mustEntry(t, h, queries, entryID, owner, "Cloudflare token", "old-value")

	attempts := 0
	t.Cleanup(func() { persistRotatedValueAuthoritativeTestHook = nil })
	persistRotatedValueAuthoritativeTestHook = func(attempt int) {
		attempts++
		if attempt == 0 {
			// Simulate a concurrent write landing between this function's
			// read and its write, on the FIRST attempt only. Bumping
			// updated_at is enough to invalidate the CAS predicate the read
			// just captured, the same mechanism TestSweepStillDetectsARealConflict
			// uses.
			if _, err := h.db.Exec(
				`UPDATE vault_entries SET updated_at = datetime('now', '+1 second'), encrypted_value = ? WHERE id = ?`,
				[]byte("a-genuinely-different-ciphertext"), entryID); err != nil {
				t.Fatalf("inject conflict: %v", err)
			}
		}
	}

	newValue := h.MintedEntrySecret([]byte("cf-rolled-value-1"), entryID, "Cloudflare token")
	stored, err := persistRotatedValueAuthoritative(ctx, h, queries, entryID, newValue)
	if err != nil {
		t.Fatalf("persistRotatedValueAuthoritative returned an error: %v", err)
	}
	if !stored {
		t.Fatal("stored = false, want true: a single conflict must be absorbed by the retry")
	}
	if attempts < 2 {
		t.Errorf("hook fired %d time(s), want at least 2 (the loop must have actually retried, "+
			"not just landed the write with no conflict ever having occurred)", attempts)
	}

	after, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	plain, err := h.openForTest(after.EncryptedValue, after.Nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !plain.EqualsString("cf-rolled-value-1") {
		t.Error("the stored value after a resolved conflict is not the rolled value: " +
			"the credential the retry was supposed to protect is gone")
	}
}

// TestPersistRotatedValueAuthoritativeSurvivesARepeatedConflict pins the
// backstop: every optimistic CAS attempt loses the race (a writer that keeps
// winning for the whole retry budget), so the loop exhausts and this function
// must still not drop the value. This is exactly the scenario a plain
// persistRotatedValue call cannot recover from and the original bug report
// describes as "no copy anywhere": this proves the forced, unconditional
// write actually lands.
func TestPersistRotatedValueAuthoritativeSurvivesARepeatedConflict(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "authoritative-repeat@example.com", "user", "")
	const entryID = "auth-repeat-1"
	mustEntry(t, h, queries, entryID, owner, "Cloudflare token", "old-value")

	attempts := 0
	t.Cleanup(func() { persistRotatedValueAuthoritativeTestHook = nil })
	persistRotatedValueAuthoritativeTestHook = func(attempt int) {
		attempts++
		// Every single attempt must land a change that the CAS this function is
		// about to issue cannot already match, including relative to what a
		// PRIOR hook call just wrote. A bare "+1 second" offset collides with
		// itself across attempts inside the same wall-clock second (SQLite's
		// datetime('now', ...) is whole-second resolution), which let a later
		// attempt's CAS match the state THIS hook had just set and short-circuit
		// the loop early. Keying the offset AND the ciphertext off the attempt
		// number guarantees every attempt sees a state distinct from the one it
		// just read, for the full retry budget.
		junk := []byte(fmt.Sprintf("racer-write-%d", attempt))
		if _, err := h.db.Exec(
			`UPDATE vault_entries SET updated_at = datetime('now', '+' || ? || ' seconds'), encrypted_value = ? WHERE id = ?`,
			attempt+2, junk, entryID); err != nil {
			t.Fatalf("inject conflict: %v", err)
		}
	}

	newValue := h.MintedEntrySecret([]byte("cf-rolled-value-2"), entryID, "Cloudflare token")
	stored, err := persistRotatedValueAuthoritative(ctx, h, queries, entryID, newValue)
	if err != nil {
		t.Fatalf("persistRotatedValueAuthoritative returned an error: %v", err)
	}
	if !stored {
		t.Fatal("stored = false, want true: a repeated conflict must fall through to the forced write, " +
			"not drop the only copy of the credential")
	}
	if attempts != maxDestroysInPlaceCASRetries {
		t.Errorf("hook fired %d time(s), want exactly %d (the loop's full retry budget)",
			attempts, maxDestroysInPlaceCASRetries)
	}

	after, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	plain, err := h.openForTest(after.EncryptedValue, after.Nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !plain.EqualsString("cf-rolled-value-2") {
		t.Error("the stored value after the retry budget was exhausted is not the rolled value: " +
			"the forced write did not land it, so the credential exists nowhere")
	}
}

// TestPersistRotatedValueAuthoritativeReportsGenuineDeletionHonestly is the one
// case this function truly cannot repair: the row was deleted, not merely
// edited, so there is no id left for the forced write to target. It must
// report this as the distinct errEntryDeletedDuringRotation rather than
// silently "succeeding" (the forced UPDATE would affect zero rows and say
// nothing) or misreporting it as an ordinary, retryable conflict the way
// rotFailConflict's text does for every other provider.
func TestPersistRotatedValueAuthoritativeReportsGenuineDeletionHonestly(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "authoritative-deleted@example.com", "user", "")
	const entryID = "auth-deleted-1"
	mustEntry(t, h, queries, entryID, owner, "Cloudflare token", "old-value")

	if _, err := h.db.Exec(`DELETE FROM vault_entries WHERE id = ?`, entryID); err != nil {
		t.Fatalf("delete entry: %v", err)
	}

	newValue := h.MintedEntrySecret([]byte("cf-rolled-value-3"), entryID, "Cloudflare token")
	stored, err := persistRotatedValueAuthoritative(ctx, h, queries, entryID, newValue)
	if stored {
		t.Fatal("stored = true for a row that does not exist; there is nowhere for the value to have landed")
	}
	if !errors.Is(err, errEntryDeletedDuringRotation) {
		t.Errorf("err = %v, want errEntryDeletedDuringRotation: a genuinely deleted row must be reported "+
			"honestly, not folded into an ordinary conflict message that falsely promises a retry", err)
	}
}

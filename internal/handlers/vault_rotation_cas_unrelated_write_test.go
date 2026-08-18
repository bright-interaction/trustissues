package handlers

import (
	"context"
	"testing"
)

// TestAnUnrelatedColumnWriteDoesNotFailARotationsValueCAS pins the reason the
// updated_at predicate was dropped from RotateVaultEntryValueUnchecked.
//
// The CAS exists to refuse ONE thing: a rotation overwriting a value somebody
// else stored while it was minting. It used to compare updated_at as well as
// encrypted_value, and every UPDATE on the row bumps updated_at, so a name
// edit, a schedule edit, or the pending-revoke endpoints persisting
// provider_meta all made the rotation lose. Losing at that point is not benign:
// the replacement credential has ALREADY been minted upstream, the CAS miss
// discards it, and its id lived only in the map being thrown away, so the
// entry ends up with an orphaned live key and no record of its identity.
//
// encrypted_value is AES-GCM under a fresh random nonce, so it is an ABA-free
// token on its own and the timestamp added nothing except false negatives.
func TestAnUnrelatedColumnWriteDoesNotFailARotationsValueCAS(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "casunrel-"+randomHex(6)+"@example.com", "user", "")
	entryID := "casunrel-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "ORIGINAL")

	before, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	snap := snapshotFromRotationRow(entryID, before.UpdatedAtText, before.EncryptedValue)

	// Something unrelated writes the row: this is the shape a concurrent name
	// edit, schedule edit or provider_meta persist has. The VALUE is untouched.
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET updated_at = datetime('now','+5 seconds'), name = ? WHERE id = ?`,
		"renamed-by-someone-else", entryID); err != nil {
		t.Fatalf("unrelated write: %v", err)
	}

	newCipher, newNonce, err := h.encrypt([]byte("THE-ROTATED-VALUE"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	applied, err := persistRotatedValue(ctx, queries, snap, newCipher, newNonce)
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	if !applied {
		t.Fatalf("a rotation lost its value CAS to a write that never touched the value. The " +
			"replacement credential has already been minted upstream at this point, so the miss " +
			"orphans a live key whose id exists only in the map now being discarded.")
	}

	after, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	plain, err := h.openForTest(after.EncryptedValue, after.Nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !plain.EqualsString("THE-ROTATED-VALUE") {
		t.Errorf("the rotated value did not land")
	}

	t.Run("positive control: a write that DOES move the value still loses", func(t *testing.T) {
		// Without this, the assertion above passes just as well against a CAS
		// that has stopped comparing anything at all.
		id2 := "casunrel2-" + randomHex(6)
		mustEntry(t, h, queries, id2, owner, "Entry "+id2, "ORIGINAL")
		row, err := queries.GetVaultEntryForRotation(ctx, id2)
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		snap2 := snapshotFromRotationRow(id2, row.UpdatedAtText, row.EncryptedValue)

		rivalCipher, rivalNonce, err := h.encrypt([]byte("SAVED-BY-SOMEONE-ELSE"))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if _, err := h.db.Exec(
			`UPDATE vault_entries SET encrypted_value = ?, nonce = ? WHERE id = ?`,
			rivalCipher, rivalNonce, id2); err != nil {
			t.Fatalf("rival save: %v", err)
		}

		c3, n3, err := h.encrypt([]byte("THE-ROTATED-VALUE"))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		applied, err := persistRotatedValue(ctx, queries, snap2, c3, n3)
		if err != nil {
			t.Fatalf("persist: %v", err)
		}
		if applied {
			t.Fatalf("a rotation overwrote a value somebody else had just saved; this is the exact " +
				"lost update the CAS exists to refuse")
		}
	})
}

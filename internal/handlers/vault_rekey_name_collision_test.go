package handlers

import (
	"context"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestOneDuplicateNameCannotWedgeTheRekeySweep is the rekey twin of
// TestOneDuplicateNameCannotWedgeTheAtRestBackfill, and it exists because the
// backfill was taught this lesson and the sweep was not.
//
// The state, which is what a store that was ever imported into before the name
// seal landed actually looks like: one entry with a SEALED name and its index,
// and one entry with the SAME name in cleartext and an empty index. The inline
// UNIQUE(user_id, name) compares randomized ciphertext against cleartext and
// never fires, and the partial UNIQUE(user_id, name_bidx) index excludes the
// empty one, so nothing in the schema forbids the pair.
//
// Both sweeps then recompute the identical token from the identical cleartext.
// The backfill skips the row it cannot write. The sweep used to return the
// error, and applyPlan's caller rolls back the WHOLE transaction, so RekeyVault
// could never complete again for that store.
//
// That is worse in the sweep than in the backfill. RekeyVault is the only
// recovery mechanism trustissues has for its own master key: a wedged sweep
// means a compromised key can never be retired, for every secret in the store,
// because two entries share a name.
//
// The rotation here is real (old key -> new key) rather than a repair in place,
// so the test also pins the part a naive skip would get wrong: the row whose
// NAME INDEX cannot be written must still have its SECRET re-encrypted. A sweep
// that abandoned the row would leave a value sealed under a key the operator is
// about to delete, which is precisely the silent partial conversion
// ErrRekeyBlocked exists to prevent.
func TestOneDuplicateNameCannotWedgeTheRekeySweep(t *testing.T) {
	ctx := context.Background()
	dbConn, queries := newRekeyDB(t)
	old := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	seeded := seedUnderKey(t, old, queries)

	const (
		duplicateID = "00000000000000000000000000000001"
		bystanderID = "00000000000000000000000000000002"
	)
	// The pre-fix import shape, planted the way a real one lands: cleartext
	// name, empty name_bidx. The value is sealed for real under the OLD key,
	// because a dummy ciphertext would classify as unreadable and the sweep
	// would refuse for a reason that has nothing to do with this test.
	legacy := func(id, name, secret string) {
		t.Helper()
		ct, nonce, err := old.EncryptValue([]byte(secret))
		if err != nil {
			t.Fatalf("encrypt legacy value: %v", err)
		}
		if err := queries.ImportVaultEntry(ctx, db.ImportVaultEntryParams{
			ID:                id,
			UserID:            seeded.userID,
			SecretOwnerUserID: seeded.userID,
			Name:              name,
			EncryptedValue:    ct,
			Nonce:             nonce,
		}); err != nil {
			t.Fatalf("seed legacy row %s: %v", id, err)
		}
	}
	const duplicateSecret = "legacy-duplicate-secret"
	// seedUnderKey's entry is named "prod api token" and holds the index for it.
	legacy(duplicateID, "prod api token", duplicateSecret)
	// Inserted AFTER the collision, so a sweep that aborted is distinguishable
	// from one that carried on.
	legacy(bystanderID, "Innocent Bystander", "bystander-secret")

	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	rep, err := rotating.RekeyVault(ctx)
	if err != nil {
		t.Fatalf(`THE SWEEP WEDGED: %v

Two entries sharing a name compute one blind index. The UNIQUE constraint
refuses the second write, the error rolls the whole transaction back, and
master-key rotation becomes impossible for this store until somebody finds and
renames the pair by hand. Rotation is the ONE recovery path for a compromised
master key.`, err)
	}
	if rep.Status != "converted" {
		t.Errorf("Status = %q, want converted", rep.Status)
	}
	if rep.NameIndexCollisions != 1 {
		t.Errorf("NameIndexCollisions = %d, want 1. An index the sweep gave up on and did not "+
			"report is a silent skip: the operator never learns that two entries share a name "+
			"and that uniqueness is not being enforced for the pair", rep.NameIndexCollisions)
	}

	// The bystander sits after the collision in insertion order, so a sweep that
	// aborted never reached it.
	var bystanderBidx string
	if err := dbConn.QueryRow(`SELECT name_bidx FROM vault_entries WHERE id = ?`, bystanderID).
		Scan(&bystanderBidx); err != nil {
		t.Fatalf("raw read bystander: %v", err)
	}
	if bystanderBidx != rotating.nameBlindIndex(seeded.userID, "Innocent Bystander") {
		t.Error("A ROW AFTER THE COLLIDING ONE CARRIES NO CURRENT NAME INDEX. The sweep stopped " +
			"at the duplicate instead of stepping over it, which is the wedge")
	}

	// Exactly one of the colliding pair holds the token, and it is the one that
	// already held it. Writing both would mean the constraint was defeated;
	// writing neither would mean the sweep gave up more than it had to.
	var winner, loser string
	if err := dbConn.QueryRow(`SELECT name_bidx FROM vault_entries WHERE id = ?`, seeded.entryID).
		Scan(&winner); err != nil {
		t.Fatalf("raw read seeded entry index: %v", err)
	}
	if err := dbConn.QueryRow(`SELECT name_bidx FROM vault_entries WHERE id = ?`, duplicateID).
		Scan(&loser); err != nil {
		t.Fatalf("raw read duplicate index: %v", err)
	}
	if want := rotating.nameBlindIndex(seeded.userID, "prod api token"); winner != want {
		t.Error("the entry that already held the name index did not get it re-derived under the " +
			"new key; the collision cost the WRONG row its index")
	}
	if loser != "" {
		t.Error("both entries of the colliding pair carry a name index, so the per-user " +
			"uniqueness constraint was written around rather than respected")
	}

	// The secret of the row whose index was refused moved anyway. This is the
	// assertion that separates "deferred the one write it could not make" from
	// "skipped the row", and only the first is safe: the operator is about to
	// delete the old key.
	rows, err := queries.ListVaultEntriesForRekey(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	newOnly := rekeyHandler(dbConn, queries, rekeyNewKey, "")
	for _, row := range rows {
		if row.ID != duplicateID {
			continue
		}
		found = true
		plain, oErr := newOnly.openVersionForTest(row.EncryptedValue, row.Nonce, 2)
		if oErr != nil || !plain.EqualsString(duplicateSecret) {
			t.Errorf(`THE COLLIDING ROW'S SECRET WAS LEFT ON THE OLD KEY (err %v).

A name collision is a metadata problem. Letting it cost the row its
re-encryption turns a duplicate label into data loss the moment
TRUSTISSUES_VAULT_KEY_PREVIOUS is removed.`, oErr)
		}
		plain.Wipe()
	}
	if !found {
		t.Fatal("the duplicate row is gone from the store entirely")
	}

	// Nothing is left on the old key, so the operator can retire it. The one
	// piece of outstanding work is the collision, and it is reported as its own
	// number rather than as staleness the next sweep would pretend to fix.
	status, err := newOnly.RekeyStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.ValuesOnPrevious != 0 || status.ValuesUnreadable != 0 {
		t.Errorf("after the sweep: %d value(s) on the previous key, %d unreadable, want 0 and 0",
			status.ValuesOnPrevious, status.ValuesUnreadable)
	}
	if status.ValuesStale != 0 || status.NameIndexCollisions != 1 {
		t.Errorf("status reports %d stale value(s) and %d collision(s), want 0 and 1. An index "+
			"no sweep can write is not work outstanding; counting it as stale is what leaves a "+
			"permanent \"needs rekey\" banner over a button that cannot help",
			status.ValuesStale, status.NameIndexCollisions)
	}

	// And the sweep stays idempotent: a second run finds the same collision,
	// still completes, and still writes nothing new.
	second, err := newOnly.RekeyVault(ctx)
	if err != nil {
		t.Fatalf("the SECOND sweep wedged: %v", err)
	}
	if second.RowsConverted != 0 {
		t.Errorf("the second sweep converted %d row(s); a store already on the current key must "+
			"be a no-op", second.RowsConverted)
	}
}

package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// Probe 1 must see EVERY vault row, at every encryption version.
//
// The probe is the only thing standing between a mistyped TRUSTISSUES_VAULT_KEY and a
// permanently unreadable vault, and it had two independent holes that both ended in the
// same unrecoverable state. Probe 3 got a per-family test after the same class of bug;
// probe 1 never got one, and TestSentinelStillBootstrapsOnAnEmptyDatabase actively passes
// on the database that triggers hole 1, because a v1-only vault IS "empty" to the old
// query. A guard that asserts the bug's precondition is safe is worse than no guard.
//
// Both cases below are driven through VerifyVaultKey, not just the probe, because the
// damage is done by what VerifyVaultKey WRITES when the probe understates the database.
func TestProbe1SeesEveryVaultRow(t *testing.T) {
	const correctKey = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
	const wrongKey = "wrong-key-that-opens-nothing-here"

	// HOLE 1: the query filtered encryption_version = 2, so a database carried over
	// from dockyard (all v1 rows, which MigrateEncryption exists to convert) reported
	// "no ciphertext at all". The gate then sealed its sentinel under whatever key was
	// configured, and from that boot on the CORRECT key is refused forever.
	t.Run("a v1-only vault is not mistaken for an empty one", func(t *testing.T) {
		vh, queries := newCollectionAuthzEnv(t)
		ctx := context.Background()
		seedLegacyVaultRow(t, vh, "legacy-1", correctKey, "the-legacy-secret")

		has, opens, err := vaultKeyOpensExistingData(ctx, queries, correctKey)
		if err != nil {
			t.Fatalf("probe: %v", err)
		}
		if !has {
			t.Fatal("a v1-only vault reported NO ciphertext.\n" +
				"VerifyVaultKey reads that as 'nothing to protect yet' and seals the sentinel " +
				"under whatever key is configured, which locks the correct key out permanently.")
		}
		if !opens {
			t.Error("the CORRECT key did not open a v1 row; the legacy derivation is wrong, " +
				"so a valid key would be reported as a mismatch")
		}

		// And the wrong key must be caught rather than cemented.
		if err := VerifyVaultKey(ctx, queries, wrongKey); err == nil {
			t.Fatal("VerifyVaultKey ACCEPTED a wrong key against a v1 vault and wrote a sentinel; " +
				"the correct key can never be used again")
		}
	})

	// HOLE 2: `:one` with LIMIT 1 sampled ONE arbitrary row, while probes 2 and 3 both
	// iterate. One row sealed under an older key, or a single bit flip, made the gate
	// refuse a key that opens every other row in the vault. The row order here puts the
	// unopenable row FIRST, which is exactly the arrangement the old query lost on.
	t.Run("one unopenable row does not refuse a key that opens the rest", func(t *testing.T) {
		vh, queries := newCollectionAuthzEnv(t)
		ctx := context.Background()

		// A foreign row first: sealed under a DIFFERENT key, as a pre-gate boot would
		// have left behind. Then rows the correct key opens.
		seedLegacyVaultRow(t, vh, "aaa-foreign", "some-other-key-entirely-here!!", "old")
		for _, id := range []string{"bbb-good", "ccc-good"} {
			ct, nonce, err := vh.EncryptValue([]byte("current-secret"))
			if err != nil {
				t.Fatalf("seed v2: %v", err)
			}
			if _, err := vh.db.Exec(
				`INSERT INTO vault_entries (id, name, encrypted_value, nonce, encryption_version)
				 VALUES (?,?,?,?,2)`, id, id, ct, nonce); err != nil {
				t.Fatalf("seed v2 row: %v", err)
			}
		}

		has, opens, err := vaultKeyOpensExistingData(ctx, queries, correctKey)
		if err != nil {
			t.Fatalf("probe: %v", err)
		}
		if !has {
			t.Fatal("ABORT: no ciphertext seen, the fixture is not exercising the probe")
		}
		if !opens {
			t.Fatal("the probe refused a key that opens 2 of 3 rows because it sampled the " +
				"one it does not open.\n" +
				"On a real deployment that is EnforceVaultKey calling os.Exit(1) under the " +
				"correct key, and the documented way out (TRUSTISSUES_ALLOW_KEY_MISMATCH) " +
				"overwrites the data it could not read.")
		}
	})
}

// seedLegacyVaultRow writes a vault row sealed the way version 1 rows are: raw
// AES-GCM under sha256(key + ":secrets-vault"), which is NewVaultHandler's legacyKey.
func seedLegacyVaultRow(t *testing.T, vh *VaultHandler, id, key, plaintext string) {
	t.Helper()
	derived := sha256.Sum256([]byte(key + ":secrets-vault"))
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		t.Fatalf("legacy cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("legacy gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	if _, err := vh.db.Exec(
		`INSERT INTO vault_entries (id, name, encrypted_value, nonce, encryption_version)
		 VALUES (?,?,?,?,1)`, id, id, ct, nonce); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
}

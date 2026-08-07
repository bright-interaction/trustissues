package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
)

// totpMarker mirrors columncrypto's unexported marker constant. Tests in this
// package cannot reach it directly, and the literal is already public through
// columncrypto's own doc comments (const marker = "tienc:v1:"), so hardcoding
// it here to strip it back off is the documented storage format, not a guess.
const totpMarker = "tienc:v1:"

// seedUnmarkedLegacyTOTPSecret writes a TOTP seed the way a build that
// predates the "tienc:v1:" marker would have: real columncrypto ciphertext,
// sealed under key, with the marker stripped back off. columncrypto.IsEncrypted
// returns false for it, which is precisely the row shape that hid from the
// probe before this fix.
func seedUnmarkedLegacyTOTPSecret(t *testing.T, queries *db.Queries, userID, seed, key string) {
	t.Helper()
	sealed, err := columncrypto.EncryptString(seed, key)
	if err != nil {
		t.Fatalf("seed: encrypt: %v", err)
	}
	unmarked := strings.TrimPrefix(sealed, totpMarker)
	if unmarked == sealed {
		t.Fatal("ABORT: marker was not present on freshly-sealed ciphertext, setup is wrong")
	}
	if columncrypto.IsEncrypted(unmarked) {
		t.Fatal("ABORT: stripped value is still recognized as marked ciphertext, setup is wrong")
	}
	if err := queries.StoreTOTPSecret(context.Background(), db.StoreTOTPSecretParams{
		TotpSecret: sql.NullString{String: unmarked, Valid: true},
		ID:         userID,
	}); err != nil {
		t.Fatalf("seed: store: %v", err)
	}
}

// TestUnmarkedLegacyTOTPCiphertextBlocksWrongKeyBeforeDoubleEncryption
// reproduces the full defect chain this fix closes:
//
//  1. A wrong-but-well-formed key boots against a database whose ONLY
//     ciphertext is an unmarked legacy TOTP secret. Before the fix, probe 2
//     `continue`d on the unmarked row without setting hasCiphertext, so the
//     gate concluded "empty database" and sealed its sentinel under the WRONG
//     key.
//  2. MigrateTOTPSecrets runs next in the real boot sequence. Finding the row
//     still unmarked, it treats it as genuine plaintext and encrypts it AGAIN,
//     producing Enc_wrong(Enc_right(seed)) on disk.
//  3. The correct key, which opened the data fine a moment ago, is now
//     refused forever: the sentinel says "wrong key" and the seed itself is
//     buried under a second layer of encryption the correct key was never
//     meant to peel.
//
// The attack must now fail at step 1: VerifyVaultKey must refuse the wrong
// key outright, before any migration ever touches the row. If it does not
// (i.e. this is running against the pre-fix code), the test drives the rest
// of the chain through to completion and fails loudly with the full picture,
// so a regression here is never silently downgraded to "probe returned the
// wrong bool".
func TestUnmarkedLegacyTOTPCiphertextBlocksWrongKeyBeforeDoubleEncryption(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const correctKey = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
	const wrongKey = "wrong-key-that-opens-nothing-here"
	const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

	userID := mustUser(t, queries, "legacy-totp@example.com", "user", "")
	seedUnmarkedLegacyTOTPSecret(t, queries, userID, seed, correctKey)

	// Guard the setup: there must be no sentinel yet (this is the bootstrap
	// boot), and the probe must actually see the row as ciphertext under the
	// correct key, or the rest of this test proves nothing.
	if _, err := queries.GetSetting(ctx, vaultKeyCheckSetting); err == nil {
		t.Fatal("ABORT: a sentinel already exists, this is not the bootstrap boot")
	}
	if has, opens, err := vaultKeyOpensExistingData(ctx, queries, correctKey); err != nil {
		t.Fatalf("probe: %v", err)
	} else if !has || !opens {
		t.Fatalf("ABORT: setup did not produce ciphertext the correct key opens (has=%v opens=%v)", has, opens)
	}

	// STEP 1 of the attack: boot under the WRONG key.
	step1Err := VerifyVaultKey(ctx, queries, wrongKey)
	if !errors.Is(step1Err, ErrVaultKeyMismatch) {
		// THE ATTACK SUCCEEDED PAST STEP 1: this is the pre-fix behaviour.
		// Drive it through to the end so the failure message states the whole
		// chain, not just "step 1 misbehaved".
		authHandler := NewAuthHandler(queries, &config.Config{VaultKey: wrongKey})
		migrateErr := authHandler.MigrateTOTPSecrets()

		step3Err := VerifyVaultKey(ctx, queries, correctKey)

		t.Fatalf("ATTACK REPRODUCED END TO END:\n"+
			"  step 1: wrong key %q was ACCEPTED (err=%v), sentinel sealed under it\n"+
			"  step 2: MigrateTOTPSecrets ran (err=%v) and double-encrypted the unmarked seed\n"+
			"  step 3: the CORRECT key %q is now refused (err=%v)\n"+
			"This is the irreversible corruption the fix in vault_keycheck.go probes 2/3 exists to prevent.",
			wrongKey, step1Err, migrateErr, correctKey, step3Err)
	}

	// The attack is blocked at step 1. Confirm steps 2 and 3 never got a
	// chance to happen: no sentinel was written under the wrong key, the
	// stored seed is byte-for-byte unchanged (no double-encryption), and the
	// correct key still boots and opens the data.
	if _, err := queries.GetSetting(ctx, vaultKeyCheckSetting); err == nil {
		t.Fatal("a sentinel was written despite the wrong key being refused")
	}
	row, err := queries.ListUsersWithTOTPSecret(ctx)
	if err != nil {
		t.Fatalf("re-read totp secret: %v", err)
	}
	if len(row) != 1 {
		t.Fatalf("expected exactly one TOTP row, got %d", len(row))
	}
	if got := nullStringToString(row[0].TotpSecret); columncrypto.IsEncrypted(got) {
		t.Fatalf("the seed was re-encrypted (now marked) despite the gate refusing the wrong key: %q", got)
	}

	if err := VerifyVaultKey(ctx, queries, correctKey); err != nil {
		t.Fatalf("the CORRECT key was refused after the wrong-key attempt was blocked: %v", err)
	}
	if dec, err := columncrypto.DecryptStringAny(nullStringToString(row[0].TotpSecret), vaultFieldTOTPSecret, correctKey); err != nil || dec != seed {
		t.Fatalf("seed did not survive intact: got (%q, %v), want %q", dec, err, seed)
	}
}

// TestEmptyDatabaseSealsFirstSentinel guards the direction opposite the P0
// bug: a genuinely empty database (no ciphertext anywhere, of any family)
// must still complete its first boot and seal a sentinel, so the fix for
// "unmarked ciphertext is invisible" does not turn into "every fresh install
// refuses to start".
func TestEmptyDatabaseSealsFirstSentinel(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const key = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"

	if _, err := queries.GetSetting(ctx, vaultKeyCheckSetting); err == nil {
		t.Fatal("ABORT: a sentinel already exists on a fresh database")
	}
	has, _, err := vaultKeyOpensExistingData(ctx, queries, key)
	if err != nil {
		t.Fatalf("probe on an empty database errored: %v", err)
	}
	if has {
		t.Fatal("ABORT: the fresh database already reports ciphertext, fixture is not empty")
	}

	if err := VerifyVaultKey(ctx, queries, key); err != nil {
		t.Fatalf("a new install could not bootstrap: %v", err)
	}

	sealed, err := queries.GetSetting(ctx, vaultKeyCheckSetting)
	if err != nil {
		t.Fatalf("first boot did not seal a sentinel: %v", err)
	}
	if sealed == "" {
		t.Fatal("sentinel was persisted empty")
	}
	if !columncrypto.IsEncrypted(sealed) {
		t.Fatalf("sentinel was not sealed as ciphertext: %q", sealed)
	}
	plain, err := columncrypto.DecryptStringAny(sealed, vaultFieldKeySentinel, key)
	if err != nil || plain != vaultKeyCheckPlaintext {
		t.Fatalf("sentinel does not decrypt to the expected constant under the key that sealed it: (%q, %v)", plain, err)
	}

	// And the sealed sentinel actually gates later boots, proving this was a
	// real self-heal and not a no-op.
	if err := VerifyVaultKey(ctx, queries, key); err != nil {
		t.Fatalf("second boot on the same key was refused: %v", err)
	}
	if err := VerifyVaultKey(ctx, queries, "a-completely-different-key-value"); !errors.Is(err, ErrVaultKeyMismatch) {
		t.Fatalf("a wrong key was accepted after the first-boot sentinel was sealed: %v", err)
	}
}

// TestStoreWithOnlyUnmarkedLegacyTOTPCiphertextBootsUnderCorrectKey is the
// regression guard for the risk in this change: fixing the fail-open must not
// create a fail-closed that bricks a legacy install booting under its own
// correct key. A database whose ONLY ciphertext anywhere is an unmarked
// legacy TOTP secret must still bootstrap cleanly when TRUSTISSUES_VAULT_KEY
// is the key that actually sealed it.
func TestStoreWithOnlyUnmarkedLegacyTOTPCiphertextBootsUnderCorrectKey(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const correctKey = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
	const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

	userID := mustUser(t, queries, "legacy-only@example.com", "user", "")
	seedUnmarkedLegacyTOTPSecret(t, queries, userID, seed, correctKey)

	// Guard: the probe must see this row as ciphertext AND open it under the
	// correct key. If either is false, the fix regressed into fail-closed.
	has, opens, err := vaultKeyOpensExistingData(ctx, queries, correctKey)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !has {
		t.Fatal("the probe did not see the unmarked legacy TOTP row at all: back to fail-open")
	}
	if !opens {
		t.Fatal("the probe saw the row but could not open it under its CORRECT key: " +
			"a legitimate legacy install would be refused startup (fail-closed regression)")
	}

	if err := VerifyVaultKey(ctx, queries, correctKey); err != nil {
		t.Fatalf("a store with only unmarked legacy TOTP ciphertext refused its CORRECT key: %v", err)
	}
	sealed, err := queries.GetSetting(ctx, vaultKeyCheckSetting)
	if err != nil || sealed == "" {
		t.Fatalf("first boot under the correct key did not seal a sentinel: %v", err)
	}

	// Idempotent on the next boot, and the original (still-unmarked) seed is
	// untouched: this gate does not rewrite data, only MigrateTOTPSecrets does.
	if err := VerifyVaultKey(ctx, queries, correctKey); err != nil {
		t.Fatalf("second boot under the correct key was refused: %v", err)
	}
	rows, err := queries.ListUsersWithTOTPSecret(ctx)
	if err != nil {
		t.Fatalf("re-read totp secret: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one TOTP row, got %d", len(rows))
	}
	if columncrypto.IsEncrypted(nullStringToString(rows[0].TotpSecret)) {
		t.Fatal("VerifyVaultKey rewrote the TOTP row; it must only read, never migrate")
	}
}

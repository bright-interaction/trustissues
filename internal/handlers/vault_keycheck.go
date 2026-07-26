package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/brightinteraction/trustissues/internal/columncrypto"
	"github.com/brightinteraction/trustissues/internal/db"
)

// vaultKeyCheckSetting is the settings row holding the key sentinel.
const vaultKeyCheckSetting = "vault_keycheck"

// vaultKeyCheckPlaintext is the known constant sealed under the vault key. Its
// content does not matter, only that we know what it must decrypt back to.
const vaultKeyCheckPlaintext = "trustissues-vault-keycheck-v1"

// allowKeyMismatchEnv lets an operator boot anyway. Deliberately awkward: the
// only legitimate use is a deliberate re-key where the old data is already
// exported, or a disaster recovery where losing the metadata is accepted.
const allowKeyMismatchEnv = "TRUSTISSUES_ALLOW_KEY_MISMATCH"

// ErrVaultKeyMismatch reports that the configured vault key cannot decrypt data
// this database was written with.
var ErrVaultKeyMismatch = errors.New("vault key does not match the data in this database")

// VerifyVaultKey proves the configured TRUSTISSUES_VAULT_KEY is the same key
// this data directory was encrypted with, BEFORE any migration or backfill runs.
//
// Why this exists. Nothing used to check. Booting the same data dir under a
// different but well-formed key started cleanly and reported
// {"status":"ok"} on /health. GET /api/vault then returned blank url, username,
// category and notes (the decryptColumnOrLog fallback) and unlock returned
// "[decryption error]". The frontend seeds its edit form from that blanked
// response and always submits every metadata field, so the first save by any
// teammate wrote NULL over ciphertext that was still perfectly recoverable.
// Restarting on the right key got the secret values back but not the metadata.
//
// So the failure mode was: a mistyped, restored, or regenerated key produced a
// server that looked healthy to every monitor while quietly converting a
// recoverable situation into permanent data loss. A warning in .env.example
// cannot prevent that, because the destructive path is a normal-looking UI save.
//
// Behaviour:
//   - sentinel absent: write it. This self-heals every existing deployment on
//     its next boot, and is the correct state for a brand new database.
//   - sentinel decrypts to the expected constant: correct key, proceed.
//   - sentinel fails to decrypt: wrong key. Refuse to start, so the data stays
//     recoverable, unless the operator explicitly sets the escape hatch.
//
// Call this immediately after RunMigrations and before MigrateTOTPSecrets,
// MigrateEncryption and the backfills. Those all rewrite rows under the current
// key, so running them under a wrong key is itself destructive.
func VerifyVaultKey(ctx context.Context, queries *db.Queries, vaultKey string) error {
	stored, err := queries.GetSetting(ctx, vaultKeyCheckSetting)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read vault keycheck: %w", err)
	}

	if errors.Is(err, sql.ErrNoRows) || stored == "" {
		sealed, encErr := columncrypto.EncryptString(vaultKeyCheckPlaintext, vaultKey)
		if encErr != nil {
			return fmt.Errorf("seal vault keycheck: %w", encErr)
		}
		if upErr := queries.UpsertSetting(ctx, db.UpsertSettingParams{
			Key: vaultKeyCheckSetting, Value: sealed,
		}); upErr != nil {
			return fmt.Errorf("persist vault keycheck: %w", upErr)
		}
		slog.Info("vault: key sentinel written; future boots will verify the vault key before touching data")
		return nil
	}

	plain, decErr := columncrypto.DecryptString(stored, vaultKey)
	if decErr != nil || plain != vaultKeyCheckPlaintext {
		return ErrVaultKeyMismatch
	}
	return nil
}

// EnforceVaultKey runs VerifyVaultKey and stops the process on a mismatch,
// printing what the operator actually needs to do. Split from VerifyVaultKey so
// the check itself stays testable without exiting the test binary.
func EnforceVaultKey(ctx context.Context, queries *db.Queries, vaultKey string) {
	err := VerifyVaultKey(ctx, queries, vaultKey)
	if err == nil {
		return
	}
	if !errors.Is(err, ErrVaultKeyMismatch) {
		// Could not complete the check (DB trouble). Do not run the destructive
		// migrations on an unverified key.
		slog.Error("vault: key verification could not run", "error", err)
		os.Exit(1)
	}

	if os.Getenv(allowKeyMismatchEnv) == "1" {
		slog.Warn("vault: KEY MISMATCH OVERRIDDEN via " + allowKeyMismatchEnv + "=1. " +
			"Existing encrypted data will read as blank and the first edit will overwrite it permanently.")
		return
	}

	slog.Error("vault: REFUSING TO START, the configured vault key does not match this database")
	fmt.Fprintf(os.Stderr, `
TRUSTISSUES_VAULT_KEY does not match the data in this database.

Your data is NOT lost. It is encrypted with a different key. Starting anyway
would show every entry as blank, and the first edit any teammate makes would
overwrite that still-recoverable ciphertext with empty values.

What to do:
  1. Restore the original TRUSTISSUES_VAULT_KEY and restart. This is almost
     always the answer: check your secrets store, the deploy env, and any
     backup of the .env file.
  2. If you are deliberately re-keying, follow the export / re-import
     procedure in SECURITY.md using the ORIGINAL key first.
  3. Only if the original key is gone for good and you accept losing every
     stored secret, set %s=1 to boot anyway.

`, allowKeyMismatchEnv)
	os.Exit(1)
}

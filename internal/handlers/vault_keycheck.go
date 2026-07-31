package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"

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
		// No sentinel yet. This is the ONE boot where the gate does not exist,
		// and it is exactly the boot where sealing blindly is dangerous: on an
		// already-populated database (every deployment upgrading into this
		// feature) booting under the WRONG key would stamp a sentinel for that
		// wrong key, and from then on the CORRECT key would be rejected forever
		// while the real data sat there undecryptable. The gate would have failed
		// open on the only occasion it mattered, then locked out the fix.
		//
		// So probe the data first. Only seal when the configured key is either
		// demonstrably correct, or there is nothing yet to be wrong about.
		hasCiphertext, opens, probeErr := vaultKeyOpensExistingData(ctx, queries, vaultKey)
		if probeErr != nil {
			return fmt.Errorf("probe existing ciphertext: %w", probeErr)
		}
		if hasCiphertext && !opens {
			// Deliberately do NOT write the sentinel: the data must stay
			// recoverable under whatever key actually sealed it.
			return ErrVaultKeyMismatch
		}

		sealed, encErr := columncrypto.EncryptString(vaultKeyCheckPlaintext, vaultKey)
		if encErr != nil {
			return fmt.Errorf("seal vault keycheck: %w", encErr)
		}
		if upErr := queries.UpsertSetting(ctx, db.UpsertSettingParams{
			Key: vaultKeyCheckSetting, Value: sealed,
		}); upErr != nil {
			return fmt.Errorf("persist vault keycheck: %w", upErr)
		}
		if hasCiphertext {
			slog.Info("vault: key sentinel written after confirming the configured key opens existing data")
		} else {
			slog.Info("vault: key sentinel written on an empty database; future boots will verify the vault key before touching data")
		}
		return nil
	}

	plain, decErr := columncrypto.DecryptString(stored, vaultKey)
	if decErr != nil || plain != vaultKeyCheckPlaintext {
		return ErrVaultKeyMismatch
	}
	return nil
}

// vaultKeyOpensExistingData reports whether this database already holds
// ciphertext, and if so whether the configured key opens any of it.
//
// It is the guard for the bootstrap boot. Two independent probes are used so a
// deployment that happens to have one but not the other is still covered:
//
//   - a sealed vault secret, opened with the derivation matching ITS version:
//     PBKDF2 salt "trustissues:vault:v2" for v2, the legacy SHA-256 key for v1.
//   - a columncrypto-marked TOTP seed, opened with the columncrypto derivation.
//
// hasCiphertext false means there is genuinely nothing to protect yet, so
// sealing is safe. Errors reading the database are returned rather than treated
// as "no data": failing to read must never be mistaken for an empty vault, or
// the guard silently degrades back into the fail-open it exists to prevent.
func vaultKeyOpensExistingData(ctx context.Context, queries *db.Queries, vaultKey string) (hasCiphertext, opens bool, err error) {
	// Probe 1: every sealed vault secret, at whatever version it carries.
	//
	// This used to ask for ONE row (LIMIT 1) filtered to encryption_version = 2,
	// and both halves of that were wrong in the same direction.
	//
	// The version filter meant a database whose vault rows are ALL v1 answered
	// "no ciphertext", so the gate sealed the sentinel under whatever key was
	// configured and then refused the CORRECT key forever. v1 rows are a
	// supported carried-over input (see vault_rotation_cas.go and the
	// MigrateEncryption boot step), and they are ciphertext whether or not the
	// v2 derivation opens them. They are now tested under the LEGACY derivation
	// instead of being treated as absent.
	//
	// Sampling one row meant a single row sealed under an older key, or one bit
	// flip, made the gate refuse a key that opens everything else. Probes 2 and
	// 3 both iterate; this one now does too, so the question asked is "does this
	// key open ANY existing ciphertext", which is what the gate is deciding.
	rows, vErr := queries.AnyEncryptedVaultEntry(ctx)
	if vErr != nil {
		return false, false, fmt.Errorf("read vault ciphertext: %w", vErr)
	}
	for _, row := range rows {
		hasCiphertext = true
		if row.EncryptionVersion.Valid && row.EncryptionVersion.Int64 == 1 {
			if vaultSecretOpensLegacy(row.EncryptedValue, row.Nonce, vaultKey) {
				return true, true, nil
			}
			continue
		}
		if vaultSecretOpens(row.EncryptedValue, row.Nonce, vaultKey) {
			return true, true, nil
		}
	}

	// Probe 2: a columncrypto-sealed TOTP seed.
	seeds, sErr := queries.ListUsersWithTOTPSecret(ctx)
	if sErr != nil {
		return hasCiphertext, false, fmt.Errorf("read totp secrets: %w", sErr)
	}
	for _, s := range seeds {
		v := nullStringToString(s.TotpSecret)
		if !columncrypto.IsEncrypted(v) {
			continue
		}
		hasCiphertext = true
		if _, decErr := columncrypto.DecryptString(v, vaultKey); decErr == nil {
			return true, true, nil
		}
	}

	// Probe 3: every OTHER encrypted surface, across all three crypto families.
	//
	// Probes 1 and 2 look only at v2 vault secrets and marked TOTP seeds. A
	// database whose only ciphertext is an SMTP password, an invitation code or a
	// notification channel config satisfied neither, so the gate concluded "no
	// ciphertext at all", sealed the sentinel under whatever key happened to be
	// configured, and thereafter refused the CORRECT key permanently. The gate
	// exists to prevent exactly that, so it has to see every surface, not the two
	// that happened to exist when it was written.
	//
	// If a new encrypted column is added anywhere, add it to the query AND give it a
	// family label below, in the same commit.
	// Each surface is checked by ITS OWN family's rules.
	//
	// This loop used to run columncrypto.IsEncrypted over all three, which is a
	// prefix check for "tienc:v1:". Only settings.smtp_password is written by
	// columncrypto. invitations.code is written by the vault handler's own column
	// crypto ("enc:v1:") and a notification config is raw AES-GCM bytes with its
	// nonce in a separate column and no marker at all, so both failed the prefix
	// check and were skipped by `continue`.
	//
	// The probe therefore reported "no ciphertext" for a database whose only
	// ciphertext was an invite code or a channel config, the gate sealed a sentinel
	// under whatever key was configured, and the CORRECT key was refused from then
	// on. The comment above says the gate has to see every surface; it saw one of
	// three.
	//
	// PRESENCE is the half that prevents the data loss. Being able to decrypt only
	// tells us the configured key is right; failing to RECOGNISE ciphertext is what
	// lets the gate seal over live data. So every family sets hasCiphertext, and
	// only the families we can open here attempt a decrypt.
	blobs, bErr := queries.AnyEncryptedColumnSample(ctx)
	if bErr != nil {
		return hasCiphertext, false, fmt.Errorf("read columncrypto surfaces: %w", bErr)
	}
	for _, b := range blobs {
		switch b.Family {
		case "columncrypto":
			if !columncrypto.IsEncrypted(b.Blob) {
				continue
			}
			hasCiphertext = true
			if _, decErr := columncrypto.DecryptString(b.Blob, vaultKey); decErr == nil {
				return true, true, nil
			}
		case "vaultcolumn":
			if !strings.HasPrefix(b.Blob, vaultColumnEncPrefix) {
				continue
			}
			hasCiphertext = true
			if vaultColumnOpens(b.Blob, vaultKey) {
				return true, true, nil
			}
		case "rawgcm":
			// No marker to check: the query already filtered on
			// encryption_version > 0 and a non-empty column, which IS the
			// statement that this value is ciphertext. The nonce lives in another
			// column, so it cannot be decrypted from here; presence is what
			// matters and presence is established.
			hasCiphertext = true
		}
	}

	return hasCiphertext, false, nil
}

// vaultSecretOpens mirrors VaultHandler.decrypt for a v2 row without needing a
// constructed handler (the key check runs before one exists).
func vaultSecretOpens(ciphertext, nonce []byte, vaultKey string) bool {
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return false
	}
	derived := pbkdf2.Key([]byte(vaultKey), []byte("trustissues:vault:v2"), 600_000, 32, sha256.New)
	defer func() {
		for i := range derived {
			derived[i] = 0
		}
	}()
	block, err := aes.NewCipher(derived)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return false
	}
	_, err = gcm.Open(nil, nonce, ciphertext, nil)
	return err == nil
}

// vaultSecretOpensLegacy is the v1 counterpart of vaultSecretOpens.
//
// v1 rows are sealed under sha256(key + ":secrets-vault"), the derivation
// NewVaultHandler still builds as legacyKey for MigrateEncryption. The probe
// needs it so a v1-only database can answer "yes, this key opens my data"
// rather than "I contain nothing", which is what cemented a wrong key.
func vaultSecretOpensLegacy(ciphertext, nonce []byte, vaultKey string) bool {
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return false
	}
	derived := sha256.Sum256([]byte(vaultKey + ":secrets-vault"))
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return false
	}
	_, err = gcm.Open(nil, nonce, ciphertext, nil)
	return err == nil
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
		// Re-seal under the key actually in use, so the override is a one-time
		// deliberate act rather than a flag that has to stay set forever with
		// the gate disabled. Leaving the old sentinel in place would mean every
		// later boot needed the override too, and an operator who set it once in
		// a compose file would silently keep running with no gate at all.
		if sealed, encErr := columncrypto.EncryptString(vaultKeyCheckPlaintext, vaultKey); encErr == nil {
			if upErr := queries.UpsertSetting(ctx, db.UpsertSettingParams{
				Key: vaultKeyCheckSetting, Value: sealed,
			}); upErr == nil {
				slog.Warn("vault: key sentinel re-sealed under the current key; remove " +
					allowKeyMismatchEnv + " from the environment so the gate is active again")
			} else {
				slog.Error("vault: could not re-seal the key sentinel", "error", upErr)
			}
		}
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

// vaultColumnOpens reports whether an "enc:v1:" column value decrypts under
// vaultKey, without needing a constructed VaultHandler (the key check runs before
// one exists). It mirrors VaultHandler.decryptColumn, and the v2 derivation is the
// same one vaultSecretOpens uses.
func vaultColumnOpens(stored, vaultKey string) bool {
	if !strings.HasPrefix(stored, vaultColumnEncPrefix) {
		return false
	}
	packed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, vaultColumnEncPrefix))
	if err != nil {
		return false
	}
	derived := pbkdf2.Key([]byte(vaultKey), []byte("trustissues:vault:v2"), 600_000, 32, sha256.New)
	defer func() {
		for i := range derived {
			derived[i] = 0
		}
	}()
	block, err := aes.NewCipher(derived)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	if len(packed) < gcm.NonceSize() {
		return false
	}
	_, err = gcm.Open(nil, packed[:gcm.NonceSize()], packed[gcm.NonceSize():], nil)
	return err == nil
}

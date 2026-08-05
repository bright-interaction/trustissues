package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
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
//
// vaultKeys is the keyring: the CURRENT key first, then TRUSTISSUES_VAULT_KEY_PREVIOUS
// when a rotation is configured. Accepting the previous key here is what makes
// rotation possible at all. Without it, the first boot after a key change is
// refused by this very gate, so the operator can never reach the admin UI to run
// the re-encrypt sweep and the only remaining route is the escape hatch that
// re-seals the sentinel and blanks the data.
func VerifyVaultKey(ctx context.Context, queries *db.Queries, vaultKeys ...string) error {
	vaultKey := ""
	if len(vaultKeys) > 0 {
		vaultKey = vaultKeys[0]
	}
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
		hasCiphertext, opens, probeErr := vaultKeyOpensExistingData(ctx, queries, vaultKeys...)
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

	plain, decErr := columncrypto.DecryptStringAny(stored, vaultFieldKeySentinel, vaultKeys...)
	if decErr != nil || plain != vaultKeyCheckPlaintext {
		return ErrVaultKeyMismatch
	}
	return nil
}

// SentinelOnPreviousKey reports whether the key sentinel opens under the
// PREVIOUS master key but not the current one, i.e. whether this store still
// needs the re-encrypt sweep.
//
// It is a separate question from VerifyVaultKey, which only answers "may this
// process safely touch the data". A store that boots fine on the previous key is
// exactly the state an operator must not be left unaware of: everything works,
// nothing is broken, and the old key (the one they are trying to retire) is
// still the only thing holding the data together. Both the boot log and the
// admin status endpoint read this so the operator does not have to know the
// feature exists to discover they are mid-rotation.
//
// A missing sentinel (fresh database) answers false: there is nothing to sweep.
func SentinelOnPreviousKey(ctx context.Context, queries *db.Queries, currentKey, previousKey string) (bool, error) {
	if previousKey == "" || previousKey == currentKey {
		return false, nil
	}
	stored, err := queries.GetSetting(ctx, vaultKeyCheckSetting)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && stored == "") {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read vault keycheck: %w", err)
	}
	if plain, decErr := columncrypto.DecryptString(stored, currentKey, vaultFieldKeySentinel); decErr == nil &&
		plain == vaultKeyCheckPlaintext {
		return false, nil
	}
	plain, decErr := columncrypto.DecryptString(stored, previousKey, vaultFieldKeySentinel)
	return decErr == nil && plain == vaultKeyCheckPlaintext, nil
}

// ResealVaultKeycheck stamps the sentinel under the CURRENT key. The rekey sweep
// calls it LAST, inside the same transaction as the data conversion, so the
// sentinel and the data can never disagree about which key this store is on.
//
// Ordering matters in one direction only: if the sentinel moved first and the
// conversion then failed, the transaction rolls back and both revert together.
// If the sentinel were written OUTSIDE the transaction it would survive a
// rollback, and the next boot would accept a key that no longer opens the data.
func ResealVaultKeycheck(ctx context.Context, queries *db.Queries, vaultKey string) error {
	sealed, err := columncrypto.EncryptString(vaultKeyCheckPlaintext, vaultKey)
	if err != nil {
		return fmt.Errorf("seal vault keycheck: %w", err)
	}
	return queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: vaultKeyCheckSetting, Value: sealed})
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
//
// vaultKeys is the keyring (current first, then the previous key when a rotation
// is configured). Every probe tries all of them: a store mid-rotation is holding
// ciphertext that only the previous key opens, and reporting "this key does not
// open my data" for that state would refuse the boot that is supposed to fix it.
func vaultKeyOpensExistingData(ctx context.Context, queries *db.Queries, vaultKeys ...string) (hasCiphertext, opens bool, err error) {
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
			if vaultSecretOpensLegacy(row.EncryptedValue, row.Nonce, vaultKeys...) {
				return true, true, nil
			}
			continue
		}
		if vaultSecretOpens(row.EncryptedValue, row.Nonce, vaultKeys...) {
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
		if _, decErr := columncrypto.DecryptStringAny(v, vaultFieldTOTPSecret, vaultKeys...); decErr == nil {
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
			if _, decErr := columncrypto.DecryptStringAny(b.Blob, vaultFieldBootProbe, vaultKeys...); decErr == nil {
				return true, true, nil
			}
		case "vaultcolumn":
			if !strings.HasPrefix(b.Blob, vaultColumnEncPrefix) {
				continue
			}
			hasCiphertext = true
			if vaultColumnOpens(b.Blob, vaultKeys...) {
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

// vaultV2Key is the PBKDF2 derivation NewVaultHandler builds as encryptionKey,
// repeated here because the key check runs before a handler exists.
func vaultV2Key(vaultKey string) [32]byte {
	var out [32]byte
	copy(out[:], pbkdf2.Key([]byte(vaultKey), []byte("trustissues:vault:v2"), 600_000, 32, sha256.New))
	return out
}

// vaultSecretOpens mirrors VaultHandler.decrypt for a v2 row without needing a
// constructed handler (the key check runs before one exists). It returns true if
// ANY key on the ring opens the row, so a store mid-rotation still answers yes.
//
// The crypto is vaultfield's, and the probe entry point returns a BOOL: it wipes
// the plaintext rather than handing it back, so this cannot become a second way
// to read an entry's value when somebody edits the caller. It names
// vault_entries.encrypted_value because that is the column it opens, and it
// names it on EVERY key attempt: which key opened a row is not a different
// column, so the ledger entry is the same one either way.
func vaultSecretOpens(ciphertext, nonce []byte, vaultKeys ...string) bool {
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return false
	}
	for _, vaultKey := range vaultKeys {
		if vaultKey == "" {
			continue
		}
		if vaultSecretOpensOne(ciphertext, nonce, vaultKey) {
			return true
		}
	}
	return false
}

func vaultSecretOpensOne(ciphertext, nonce []byte, vaultKey string) bool {
	key := vaultV2Key(vaultKey)
	defer wipeKey(&key)
	return vaultfield.Opens(key, ciphertext, nonce, vaultFieldEntryValueProbe)
}

// vaultSecretOpensLegacy is the v1 counterpart of vaultSecretOpens.
//
// v1 rows are sealed under sha256(key + ":secrets-vault"), the derivation
// NewVaultHandler still builds as legacyKey for MigrateEncryption. The probe
// needs it so a v1-only database can answer "yes, this key opens my data"
// rather than "I contain nothing", which is what cemented a wrong key.
func vaultSecretOpensLegacy(ciphertext, nonce []byte, vaultKeys ...string) bool {
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return false
	}
	for _, vaultKey := range vaultKeys {
		if vaultKey == "" {
			continue
		}
		key := sha256.Sum256([]byte(vaultKey + ":secrets-vault"))
		opened := vaultfield.Opens(key, ciphertext, nonce, vaultFieldEntryValueProbe)
		wipeKey(&key)
		if opened {
			return true
		}
	}
	return false
}

func wipeKey(k *[32]byte) {
	for i := range k {
		k[i] = 0
	}
}

// EnforceVaultKey runs VerifyVaultKey and stops the process on a mismatch,
// printing what the operator actually needs to do. Split from VerifyVaultKey so
// the check itself stays testable without exiting the test binary.
//
// vaultKeys is the keyring, current key first.
func EnforceVaultKey(ctx context.Context, queries *db.Queries, vaultKeys ...string) {
	vaultKey := ""
	if len(vaultKeys) > 0 {
		vaultKey = vaultKeys[0]
	}
	previousKey := ""
	if len(vaultKeys) > 1 {
		previousKey = vaultKeys[1]
	}

	err := VerifyVaultKey(ctx, queries, vaultKeys...)
	if err == nil {
		// The gate passed, but it may have passed on the OLD key. That state boots
		// clean, serves every request, and looks identical to a healthy instance,
		// which is precisely why it has to be said out loud on every boot: the key
		// the operator is trying to retire is still the only one that opens this
		// data, and removing TRUSTISSUES_VAULT_KEY_PREVIOUS now would orphan
		// everything. The admin status endpoint says the same thing in the UI, for
		// the operator who never reads container logs.
		if onPrev, sErr := SentinelOnPreviousKey(ctx, queries, vaultKey, previousKey); sErr != nil {
			slog.Error("vault: could not determine which key this store is sealed under", "error", sErr)
		} else if onPrev {
			slog.Warn("vault: THIS STORE IS STILL SEALED UNDER THE PREVIOUS KEY. " +
				"Reads work only because TRUSTISSUES_VAULT_KEY_PREVIOUS is set. " +
				"Run the re-encrypt sweep (Settings -> Encryption, or POST /api/admin/vault-key/rekey, " +
				"or set TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT=1) and only then remove the previous key.")
		} else if previousKey != "" {
			// The sweep is DONE and the previous key is still in the environment.
			//
			// Said on every boot, not once. After the sweep re-seals the sentinel
			// SentinelOnPreviousKey answers false forever, so the only thing that
			// ever mentioned the retired key was the sweep's own one-shot log line
			// in whichever process happened to run it. The admin UI covers this
			// with a green banner, which is no help at all to a headless deploy
			// driven by TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT: exactly the
			// deployments where nobody opens Settings. A retired key that stays
			// loaded still opens this data and still opens every pre-sweep backup,
			// which is the whole thing a rotation after a compromise is meant to
			// end.
			slog.Warn("vault: rotation is complete but TRUSTISSUES_VAULT_KEY_PREVIOUS is STILL SET. " +
				"Every value in this store is now sealed under the current key, so the retired key is no " +
				"longer needed for anything: it is simply still loaded and still opens this data. " +
				"Remove it from the environment and restart.")
		}
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

// vaultColumnOpens reports whether an "enc:v1:" column value decrypts under any
// key on the ring, without needing a constructed VaultHandler (the key check runs
// before one exists). It mirrors VaultHandler.decryptColumn, and the v2 derivation
// is the same one vaultSecretOpens uses.
//
// It used to do its own AES-GCM, which made it a decryption door the round-18
// ledger could not see (it matched none of the four call shapes that guard
// derived from). It goes through vaultfield now, with the probe field, and
// returns a bool. The ring loop is on the outside of that, so adding the
// previous key added key attempts and not a second door.
func vaultColumnOpens(stored string, vaultKeys ...string) bool {
	for _, k := range vaultKeys {
		if k == "" {
			continue
		}
		if vaultColumnOpensOne(stored, k) {
			return true
		}
	}
	return false
}

func vaultColumnOpensOne(stored, vaultKey string) bool {
	key := vaultV2Key(vaultKey)
	defer wipeKey(&key)
	return vaultfield.ColumnOpens(key, stored, vaultFieldBootProbe)
}

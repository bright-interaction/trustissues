package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

// vaultColumnEncPrefix marks a vault metadata column (provider_meta,
// rotation_targets) as encrypted-at-rest. These columns sit next to the
// encrypted secret value and can themselves carry sensitive material
// (rotation_targets embeds webhook HMAC secrets; provider_meta embeds account
// ids and key ids), so a raw DB-file leak should not expose them in cleartext.
//
// The prefix lets decryptColumn stay safe to apply at every read choke: an
// UNPREFIXED value (pre-migration cleartext, or a row written by an older
// binary) is returned unchanged.
//
// SECURITY: the prefix is a storage-format marker ONLY. It must NEVER be used
// to decide whether to encrypt a value that came from a client. encryptColumn
// used to pass through any input already carrying the prefix, which turned the
// server into a universal decryption oracle: an attacker holding ciphertext
// from an offline DB copy could POST "enc:v1:<base64 nonce||ct>" as a notes/url
// field, have it stored verbatim, then read it back decrypted with the server's
// vault key, defeating at-rest encryption for every user's secrets. User input
// is now ALWAYS encrypted (encryptColumn); only the backfill, which reads values
// out of the database, may skip already-encrypted values
// (encryptColumnIfNeeded).
const vaultColumnEncPrefix = "enc:v1:"

// encryptColumn encrypts a cleartext column into a single self-describing
// string: prefix + base64(nonce || ciphertext) using the vault's AES-256-GCM key.
//
// It ALWAYS encrypts a non-empty input, including one that happens to start with
// the marker prefix. Never make this content-dependent: this function is on the
// path from client input to storage, so a passthrough here is a decryption
// oracle (see the note on vaultColumnEncPrefix). A caller that legitimately
// holds an already-encrypted value from the database must not call this at all,
// or must call encryptColumnIfNeeded.
func (h *VaultHandler) encryptColumn(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(h.encryptionKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	packed := make([]byte, 0, len(nonce)+len(ciphertext))
	packed = append(packed, nonce...)
	packed = append(packed, ciphertext...)
	return vaultColumnEncPrefix + base64.StdEncoding.EncodeToString(packed), nil
}

// decryptColumn reverses encryptColumn. An unprefixed value (pre-migration
// cleartext, empty, or a passthrough) is returned as-is, so it is safe to apply
// at every read choke unconditionally.
//
// When a rotation is configured it also tries the PREVIOUS master key, so an
// unswept row still reads. Every read choke in the vault funnels through here,
// so this one fallback is what keeps a half-rotated store serving instead of
// blanking url/username/category/notes (and then having the edit form write
// those blanks back over recoverable ciphertext, which is the data loss
// VerifyVaultKey exists to stop).
func (h *VaultHandler) decryptColumn(stored string) (string, error) {
	plain, _, err := h.decryptColumnWithKeyAge(stored)
	return plain, err
}

// decryptColumnWithKeyAge is decryptColumn plus WHICH key opened the value.
//
// The rekey sweep needs this: "did this open under the current key" is the only
// self-describing statement about a row's key, because nothing stamps a key id
// on the row. Trial decryption is the authority rather than a stored marker on
// purpose. A stored key id is a second source of truth that can disagree with
// the bytes, and this codebase has been bitten repeatedly by a declared property
// nothing enforces; the ciphertext cannot lie about which key opens it.
//
// onPrevious is false for cleartext and empty values: there is nothing to
// convert, so they must not be counted as needing a rewrite.
func (h *VaultHandler) decryptColumnWithKeyAge(stored string) (plain string, onPrevious bool, err error) {
	if !strings.HasPrefix(stored, vaultColumnEncPrefix) {
		return stored, false, nil
	}
	packed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, vaultColumnEncPrefix))
	if err != nil {
		return "", false, fmt.Errorf("decode encrypted column: %w", err)
	}
	if out, oErr := openVaultColumn(h.encryptionKey, packed); oErr == nil {
		return out, false, nil
	}
	if h.previous != nil {
		if out, oErr := openVaultColumn(h.previous.value, packed); oErr == nil {
			return out, true, nil
		}
	}
	return "", false, fmt.Errorf("decrypt column: %w", errVaultColumnUndecryptable)
}

// errVaultColumnUndecryptable is the sentinel wrapped by decryptColumnWithKeyAge
// when no configured key opens a marked column. It carries no key material and
// no ciphertext: this string reaches logs.
var errVaultColumnUndecryptable = errors.New("no configured vault key opens this column")

// openVaultColumn opens a packed nonce||ciphertext blob under one derived key.
func openVaultColumn(key [32]byte, packed []byte) (string, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(packed) < ns {
		return "", fmt.Errorf("encrypted column too short")
	}
	nonce, ciphertext := packed[:ns], packed[ns:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// decryptColumnOrLog decrypts a stored column, returning fallback (and logging)
// on a decrypt error so a single corrupted row never emits ciphertext to a
// client, breaks JSON parsing, or blocks a list. Cleartext/empty inputs pass
// through unchanged (decryptColumn is idempotent-safe on them).
func (h *VaultHandler) decryptColumnOrLog(stored, fallback, field string) string {
	out, err := h.decryptColumn(stored)
	if err != nil {
		slog.Error("vault: metadata column decrypt failed", "field", field, "error", err)
		return fallback
	}
	return out
}

// encryptColumnIfNeeded encrypts a value READ FROM THE DATABASE unless it is
// already ciphertext or carries no data. This is the idempotent variant used by
// the startup backfills and by internal re-store paths that copy a stored column
// forward without ever decrypting it.
//
// It is safe ONLY because its input comes from storage, never from a client.
// Do not call it on request data: deciding by content whether to encrypt is what
// created the decryption oracle described on vaultColumnEncPrefix.
func (h *VaultHandler) encryptColumnIfNeeded(stored string) (string, error) {
	if !metaColumnNeedsEncrypt(stored) {
		return stored, nil
	}
	return h.encryptColumn(stored)
}

// metaColumnNeedsEncrypt reports whether a STORED column value holds real
// cleartext that should be encrypted at rest. Empty, the empty-JSON defaults,
// and already-encrypted values are skipped so the backfill is idempotent and
// does not churn rows that carry no data. Storage-side only: never use this to
// gate encryption of client input.
func metaColumnNeedsEncrypt(v string) bool {
	switch v {
	case "", "{}", "[]":
		return false
	}
	return !strings.HasPrefix(v, vaultColumnEncPrefix)
}

// BackfillMetadataEncryption encrypts any vault provider_meta / rotation_targets
// columns still stored in cleartext (rows written before at-rest encryption
// landed). Idempotent: already-encrypted and empty-default columns are skipped,
// so it is safe to run on every startup. Returns the number of rows updated.
func (h *VaultHandler) BackfillMetadataEncryption() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rows, err := h.queries.ListVaultEntriesForMetaBackfill(ctx)
	if err != nil {
		return 0, fmt.Errorf("listing vault entries for backfill: %w", err)
	}

	updated := 0
	for _, row := range rows {
		if metaColumnNeedsEncrypt(row.ProviderMeta.String) {
			enc, encErr := h.encryptColumnIfNeeded(row.ProviderMeta.String)
			if encErr != nil {
				return updated, fmt.Errorf("encrypt provider_meta for %s: %w", row.ID, encErr)
			}
			if err := h.queries.UpdateVaultEntryProviderMeta(ctx, db.UpdateVaultEntryProviderMetaParams{
				ProviderMeta: toNullString(enc),
				ID:           row.ID,
			}); err != nil {
				return updated, fmt.Errorf("persist provider_meta for %s: %w", row.ID, err)
			}
			updated++
		}
		if metaColumnNeedsEncrypt(row.RotationTargets.String) {
			enc, encErr := h.encryptColumnIfNeeded(row.RotationTargets.String)
			if encErr != nil {
				return updated, fmt.Errorf("encrypt rotation_targets for %s: %w", row.ID, encErr)
			}
			if err := h.queries.UpdateVaultEntryRotationTargets(ctx, db.UpdateVaultEntryRotationTargetsParams{
				RotationTargets: toNullString(enc),
				ID:              row.ID,
			}); err != nil {
				return updated, fmt.Errorf("persist rotation_targets for %s: %w", row.ID, err)
			}
			updated++
		}
	}
	if updated > 0 {
		slog.Info("vault: backfilled metadata column encryption", "columns_encrypted", updated)
	}
	return updated, nil
}

// anyMetaColumnUndecryptable reports whether any encrypted metadata column on a
// stored row fails to open, i.e. whether the entry is partially damaged.
//
// The secret VALUE has had a refuse-to-overwrite guard since round 1: a save
// that cannot decrypt the current value is refused with 409 rather than writing
// over ciphertext that is still recoverable with the right key. The metadata
// columns had no equivalent, and they are strictly worse off, because
// decryptColumnOrLog renders a failure as "" and the edit form ALWAYS resubmits
// url, alias_url, username, category and notes. So an operator who opened a
// damaged entry, saw blank fields, fixed an unrelated typo and pressed Save
// replaced the still-recoverable ciphertext with NULL. Permanently, with a 200
// and a success toast.
//
// custom_fields is included because it can hold secret:true values, so this is
// not merely metadata loss.
//
// Whole-database key mismatch is already caught at boot by EnforceVaultKey.
// What reaches here is the case that gate cannot see: one damaged row, a torn
// write, or a row still sealed under an older key after an operator used the
// documented TRUSTISSUES_ALLOW_KEY_MISMATCH escape hatch, which re-seals the
// sentinel and therefore makes every later boot look healthy.
func (h *VaultHandler) anyMetaColumnUndecryptable(cols map[string]string) (string, bool) {
	for field, stored := range cols {
		if stored == "" {
			continue
		}
		if _, err := h.decryptColumn(stored); err != nil {
			return field, true
		}
	}
	return "", false
}

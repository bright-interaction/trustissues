package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
)

// vaultColumnEncPrefix marks a vault metadata column (provider_meta,
// rotation_targets) as encrypted-at-rest. These columns sit next to the
// encrypted secret value and can themselves carry sensitive material
// (rotation_targets embeds webhook HMAC secrets; provider_meta embeds account
// ids and key ids), so a raw DB-file leak should not expose them in cleartext.
//
// The prefix makes the two helpers below IDEMPOTENT, which is what makes the
// column-wide sweep safe:
//   - decryptColumn on an UNPREFIXED value returns it unchanged, so a read
//     choke can be applied everywhere before the backfill has run and to rows
//     that were written cleartext by an older binary.
//   - encryptColumn on an ALREADY-PREFIXED value returns it unchanged, so a
//     passthrough write that re-stores a column it never decrypted (e.g. the
//     rotate-now handler copying current.ProviderMeta) never double-wraps it.
const vaultColumnEncPrefix = "enc:v1:"

// encryptColumn encrypts a cleartext metadata column into a single self-describing
// string: prefix + base64(nonce || ciphertext) using the vault's AES-256-GCM key.
// Empty, empty-default ("{}"/"[]"), and already-encrypted inputs pass through
// unchanged (nothing to protect / no double-wrap).
func (h *VaultHandler) encryptColumn(plaintext string) (string, error) {
	if !metaColumnNeedsEncrypt(plaintext) {
		return plaintext, nil
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
func (h *VaultHandler) decryptColumn(stored string) (string, error) {
	if !strings.HasPrefix(stored, vaultColumnEncPrefix) {
		return stored, nil
	}
	packed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, vaultColumnEncPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted column: %w", err)
	}
	block, err := aes.NewCipher(h.encryptionKey[:])
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
		return "", fmt.Errorf("decrypt column: %w", err)
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

// metaColumnNeedsEncrypt reports whether a metadata column value holds real
// cleartext that should be encrypted at rest. Empty, the empty-JSON defaults,
// and already-encrypted values are skipped so the backfill is idempotent and
// does not churn rows that carry no data.
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
			enc, encErr := h.encryptColumn(row.ProviderMeta.String)
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
			enc, encErr := h.encryptColumn(row.RotationTargets.String)
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

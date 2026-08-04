package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
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
//
// The constant is an alias of vaultfield.ColumnPrefix so the format has one
// definition. The crypto moved to that package because it is the only file in
// the module allowed to import crypto/aes and crypto/cipher, which is what makes
// "every way a value becomes plaintext" a set the compiler and one import guard
// maintain rather than a list of wrapper names.
const vaultColumnEncPrefix = vaultfield.ColumnPrefix

// encryptColumn encrypts a cleartext column into a single self-describing
// string: prefix + base64(nonce || ciphertext) using the vault's AES-256-GCM key.
//
// It ALWAYS encrypts a non-empty input, including one that happens to start with
// the marker prefix. Never make this content-dependent: this function is on the
// path from client input to storage, so a passthrough here is a decryption
// oracle (see the note on vaultColumnEncPrefix). A caller that legitimately
// holds an already-encrypted value from the database must not call this at all,
// or must call encryptColumnIfNeeded.
//
// Sealing takes no vaultfield.Field on purpose. The ledger records what can
// become PLAINTEXT; putting a value back under the key produces none. Only the
// decrypt half names a field.
func (h *VaultHandler) encryptColumn(plaintext string) (string, error) {
	return vaultfield.SealColumn(h.encryptionKey, plaintext)
}

// decryptColumn reverses encryptColumn for one DECLARED field. An unprefixed
// value (pre-migration cleartext, empty, or a passthrough) is returned as-is, so
// it is safe to apply at every read choke unconditionally.
//
// The field argument is not decoration and it is not a log label. It is the
// handle vaultfield demands before it will decrypt anything, and the only way to
// obtain one is vaultfield.Declare, which is what writes the ledger. This
// function used to take no field at all: it was the RAW door, decryptColumnOrLog
// was its logging wrapper, and the round-18 ledger derived its coverage by
// matching the wrapper's name. UserHandler.openInviteCode called this one, so
// invitations.code, a bearer credential that redeems into an account, was
// decrypted by a door the ledger could not see.
func (h *VaultHandler) decryptColumn(stored string, field vaultfield.Field) (string, error) {
	return vaultfield.OpenColumn(h.encryptionKey, stored, field)
}

// decryptColumnOrLog decrypts a stored column, returning fallback (and logging)
// on a decrypt error so a single corrupted row never emits ciphertext to a
// client, breaks JSON parsing, or blocks a list. Cleartext/empty inputs pass
// through unchanged (decryptColumn is idempotent-safe on them).
func (h *VaultHandler) decryptColumnOrLog(stored, fallback string, field vaultfield.Field) string {
	out, err := h.decryptColumn(stored, field)
	if err != nil {
		slog.Error("vault: metadata column decrypt failed", "field", field.Name(), "error", err)
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
	return !vaultfield.IsSealedColumn(v)
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
			// This backfill changes the ENCODING of a stored value, never the
			// value, so both sides of the decision are derived from the one
			// string it is about to encrypt. Nothing is added and the authority
			// oracle is never consulted, which is what a re-encryption pass
			// should look like from the gate's point of view.
			meta := ParseProviderMeta(row.ProviderMeta.String)
			tk, tkErr := egressgate.Decide(egressgate.Request{
				EntryID: row.ID,
				What:    egressFieldProviderMeta,
				Before:  providerDestinations(row.Provider.String, meta),
				After:   providerDestinations(row.Provider.String, meta),
				Covers:  providerDestinationCovers,
			})
			if tkErr != nil {
				return updated, fmt.Errorf("egress decision for provider_meta on %s: %w", row.ID, tkErr)
			}
			if err := vaultegress.SetProviderMeta(ctx, h.queries, tk, vaultegress.ProviderMetaParams{
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
			same := deliveryDestinations(ParseRotationTargets(row.RotationTargets.String))
			tk, tkErr := egressgate.Decide(egressgate.Request{
				EntryID: row.ID,
				What:    egressFieldRotationTarget,
				Before:  same,
				After:   same,
			})
			if tkErr != nil {
				return updated, fmt.Errorf("egress decision for rotation_targets on %s: %w", row.ID, tkErr)
			}
			if err := vaultegress.SetRotationTargets(ctx, h.queries, tk, vaultegress.RotationTargetsParams{
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
// The map is keyed by the DECLARED field rather than by a display string, so a
// column can only be checked here if it has a ledger entry.
func (h *VaultHandler) anyMetaColumnUndecryptable(cols map[vaultfield.Field]string) (string, bool) {
	for field, stored := range cols {
		if stored == "" {
			continue
		}
		if _, err := h.decryptColumn(stored, field); err != nil {
			return shortColumnName(field), true
		}
	}
	return "", false
}

// shortColumnName renders "vault_entries.notes" as "notes" for a message aimed
// at an operator looking at an edit form.
func shortColumnName(f vaultfield.Field) string {
	name := f.Name()
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

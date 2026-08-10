package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// The audit tables name the secrets they record, and until now they named them
// in cleartext.
//
// 00040 encrypted vault_entries.name so a stolen database file would not hand a
// reader the inventory. It did not finish the job: capability_log.secret_name
// records the name of every secret a capability token was minted for, and
// service_secret_audit.secret_names records the name of every secret a service
// fetched. Both are written on the busiest paths in the product, so between them
// they reconstruct most of the inventory that 00040 just protected, from the same
// stolen file. This is the shape this codebase keeps finding: the fix lands on
// one of two twins.
//
// WHY THE OBVIOUS FIXES ARE BOTH WRONG.
//
// Dropping the name and resolving it from vault_entries at read time looks
// tidier: one copy, already encrypted. It destroys the property the
// denormalisation exists for. Both columns are commented "audit-after-delete" at
// the point of definition, and an audit trail that reads
// "agent X used <deleted-entry-id>" is worthless in the one scenario it exists
// for, which is an attacker who used a credential and then deleted the entry.
// Post-incident forensics is not a nice-to-have for a password manager; it is
// most of what the log is.
//
// Encrypting them under the master key directly is the other trap. 00039 made
// both tables append-only at the database level, which means the rekey sweep
// cannot UPDATE them, which means a master-key rotation would orphan every audit
// row it could not rewrite. Carving an exception into the triggers so the sweep
// may rewrite them would reopen the exact cover-up path 00039 closed, since
// "the application may rewrite secret_name" is indistinguishable from an
// attacker with application access rewriting secret_name.
//
// ENVELOPE ENCRYPTION IS THE ANSWER TO EXACTLY THIS.
//
// A long-lived random data-encryption key (the DEK) encrypts the audit values.
// The DEK itself is stored wrapped under the master key, in settings, which IS a
// mutable registered rekey surface. Rotating the master key rewraps ONE settings
// row; not a single audit row is touched, so the append-only triggers are never
// in conflict with the rotation and the rows stay immutable forever. The name
// still lives in the audit row, so audit-after-delete keeps working. This is the
// standard key-hierarchy answer (NIST SP 800-57) and it is already the estate's
// pattern: Pare wraps a per-company DEK under PARE_MASTER_KEY for the same
// reason.
//
// ON THE SHARED enc:v1: PREFIX. These values carry the same marker as
// master-key columns because they go through the same audited SealColumn, which
// is the only door in this module allowed to do the arithmetic. That is not
// ambiguity: AES-GCM is authenticated, so opening one of these with the master
// key fails the tag check loudly rather than returning plausible garbage, and
// nothing in the product scans for the prefix across tables (the boot key probe
// samples three named sources, none of them these).

// auditDEKSetting is the settings row holding the wrapped audit DEK.
const auditDEKSetting = "audit_name_dek"

// vaultFieldAuditDEK is the ledger handle for unwrapping the DEK itself. The DEK
// is not a credential anybody uses; it is key material this process holds so it
// can read back its own audit trail.
var vaultFieldAuditDEK = vaultfield.Declare(
	"settings.audit_name_dek", vaultfield.NotACredential, "",
	"the data-encryption key for the audit name columns, wrapped under the master key. It exists so "+
		"capability_log.secret_name and service_secret_audit.secret_names can be encrypted at rest "+
		"WITHOUT a master-key rotation having to rewrite append-only audit rows: rotating rewraps this "+
		"one settings value and leaves the rows untouched.")

// vaultFieldAuditName is the ledger handle for the audit names themselves.
var vaultFieldAuditName = vaultfield.Declare(
	"capability_log.secret_name", vaultfield.NotACredential, "",
	"the entry name recorded beside a credential access, in capability_log and in "+
		"service_secret_audit.secret_names. Denormalised on purpose so the trail survives the entry "+
		"being deleted, which is exactly the case an attacker creates. Encrypted under the audit DEK "+
		"rather than the master key so the rows never have to be rewritten.")

// auditNameKey caches the unwrapped DEK for the process lifetime. It is loaded
// lazily rather than at boot: an audit write must never be the thing that takes
// the server down, and a startup that hard-fails on key material has already
// produced a fleet-wide crash loop elsewhere in the estate.
type auditNameKey struct {
	once sync.Once
	key  [32]byte
	err  error
}

// auditNameDEK returns the process's audit DEK, creating and persisting one on
// first use.
//
// Concurrency: sync.Once serialises the load, so two simultaneous first writes
// cannot generate two DEKs and race to persist them. The persisted row is the
// authority; a caller that loses a race would otherwise encrypt under a key that
// is about to be overwritten, and those rows could never be read again.
func (h *VaultHandler) auditNameDEK(ctx context.Context) ([32]byte, error) {
	h.auditKey.once.Do(func() {
		h.auditKey.key, h.auditKey.err = loadOrCreateAuditDEK(ctx, h.queries, h.vaultKeyRing()...)
	})
	return h.auditKey.key, h.auditKey.err
}

// vaultKeyRing is the current master key first, then the previous one when a
// rotation is configured. The DEK is unwrapped against the WHOLE ring for the
// same reason every other columncrypto reader is: between changing the key and
// finishing the sweep, this row is still sealed under the old one, and a reader
// that only knew the current key would report the audit key unavailable on every
// store mid-rotation.
func (h *VaultHandler) vaultKeyRing() []string {
	ring := []string{h.keySource}
	if h.previous != nil && h.previous.source != "" {
		ring = append(ring, h.previous.source)
	}
	return ring
}

func loadOrCreateAuditDEK(ctx context.Context, queries *db.Queries, masterKeys ...string) ([32]byte, error) {
	var out [32]byte
	if len(masterKeys) == 0 {
		return out, fmt.Errorf("no master key configured to unwrap the audit name key")
	}

	stored, err := queries.GetSetting(ctx, auditDEKSetting)
	if err == nil && stored != "" {
		raw, dErr := columncrypto.DecryptStringAny(stored, vaultFieldAuditDEK, masterKeys...)
		if dErr != nil {
			// Refuse rather than silently minting a second DEK. Overwriting the
			// row here would make every audit name written under the old one
			// permanently unreadable, which is a worse outcome than a logged
			// failure on a key the operator can still fix.
			return out, fmt.Errorf("unwrap audit name key: %w", dErr)
		}
		decoded, bErr := base64.StdEncoding.DecodeString(raw)
		if bErr != nil || len(decoded) != 32 {
			return out, fmt.Errorf("stored audit name key is malformed (%d bytes)", len(decoded))
		}
		copy(out[:], decoded)
		return out, nil
	}

	// First use on this instance: mint one and persist it wrapped.
	fresh := make([]byte, 32)
	if _, rErr := rand.Read(fresh); rErr != nil {
		return out, fmt.Errorf("generate audit name key: %w", rErr)
	}
	// Sealed under the CURRENT key (ring[0]), never the previous one: reads
	// tolerate a half-rotated store, writes always land on the current key.
	wrapped, eErr := columncrypto.EncryptString(base64.StdEncoding.EncodeToString(fresh), masterKeys[0])
	if eErr != nil {
		return out, fmt.Errorf("wrap audit name key: %w", eErr)
	}
	if uErr := queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: auditDEKSetting, Value: wrapped,
	}); uErr != nil {
		return out, fmt.Errorf("persist audit name key: %w", uErr)
	}
	copy(out[:], fresh)
	slog.Info("audit: minted the audit name encryption key", "setting", auditDEKSetting)
	return out, nil
}

// sealAuditName encrypts one audit value under the DEK.
//
// It FAILS CLOSED in the only direction that matters: if the key is unavailable
// the value is replaced with a fixed marker rather than written in cleartext.
// An audit row that says a name was recorded but cannot show it is a degraded
// audit row; a row that quietly writes the cleartext this function exists to
// prevent is the defect.
// SealAuditName is the exported form used through entrySecretSource.
func (h *VaultHandler) SealAuditName(ctx context.Context, plain string) string {
	if plain == "" {
		return ""
	}
	key, err := h.auditNameDEK(ctx)
	if err != nil {
		slog.Error("audit: could not seal the recorded secret name; storing a placeholder instead "+
			"of cleartext", "error", err)
		return auditNameUnavailable
	}
	sealed, sErr := vaultfield.SealColumn(key, plain)
	if sErr != nil {
		slog.Error("audit: sealing the recorded secret name failed", "error", sErr)
		return auditNameUnavailable
	}
	return sealed
}

// auditNameUnavailable is what a failed seal writes. It is deliberately not the
// empty string: empty reads as "no name was recorded", and the operator needs to
// be able to tell that apart from "a name was recorded and this process could
// not protect it".
const auditNameUnavailable = "[unavailable]"

// vaultKeySource is the master key string the DEK is wrapped under. columncrypto
// derives internally from the raw string rather than taking a derived key, which
// is the same reason the rekey sweep keeps keySource around.
// openAuditName reverses sealAuditName for display. An unprefixed value is
// returned as-is, so rows written before this existed still read.
func (h *VaultHandler) openAuditName(ctx context.Context, stored string) string {
	if stored == "" || !vaultfield.IsSealedColumn(stored) {
		return stored
	}
	key, err := h.auditNameDEK(ctx)
	if err != nil {
		return auditNameUnavailable
	}
	plain, oErr := vaultfield.OpenColumn(key, stored, vaultFieldAuditName)
	if oErr != nil {
		slog.Warn("audit: could not open a recorded secret name", "error", oErr)
		return auditNameUnavailable
	}
	return plain
}

package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// maxDestroysInPlaceCASRetries bounds persistRotatedValueAuthoritative's
// re-read/re-encrypt/re-CAS loop. It exists so a pathological, unending writer
// storm on one row cannot spin this forever; in practice a single retry
// resolves the realistic case (one concurrent edit landed between the read
// that started the rotation and the write that would persist it), the same
// shape TestSweepStillDetectsARealConflict already exercises for every other
// provider.
const maxDestroysInPlaceCASRetries = 5

// errEntryDeletedDuringRotation is returned when the row this rotation is
// trying to persist against no longer exists. This is the one case
// persistRotatedValueAuthoritative cannot make safe: there is no row left to
// hold the value, encrypted or otherwise. Callers must treat it as a loud,
// distinct failure, not as an ordinary "will be retried" conflict.
var errEntryDeletedDuringRotation = errors.New(
	"rotation: the entry was deleted before the rolled value could be stored anywhere in this vault")

// persistRotatedValueAuthoritativeTestHook, when non-nil, is called once per
// retry attempt, immediately after the fresh read and before the CAS write.
// Tests use it to deterministically force a specific attempt to miss (by
// mutating the row out from under the CAS this function is about to issue)
// without needing a real racing goroutine. nil in production: a production
// call pays nothing for this seam.
var persistRotatedValueAuthoritativeTestHook func(attempt int)

// persistRotatedValueAuthoritative is the CAS-safe persist path for a
// provider in predecessorDestroysInPlace (see vault_providers.go).
//
// For every OTHER auto-rotating provider, a CAS miss after a successful mint
// is a recoverable "both keys live" conflict: the revoke of the old key is
// deferred past the CAS (deferRevokeOldProviderKey), so losing this one write
// just means the entry gets picked up again with the OLD value still live at
// the provider, and rotFailConflict's "will be retried" promise is true.
//
// A provider in predecessorDestroysInPlace has no such fallback. By the time
// newValue exists, the predecessor is already dead upstream (the roll IS the
// revoke, atomically, in the same call). So the value this function is
// carrying is not "a" copy, it is the ONLY copy: the vault does not yet hold
// it, and the provider will never hand it back. Dropping it on a CAS miss
// would not be a retryable conflict, it would be the credential ceasing to
// exist anywhere. So a miss here re-reads the row, re-encrypts against the
// current key material, and re-CASes rather than surfacing the miss as a
// terminal conflict.
//
// If the row keeps losing the race for maxDestroysInPlaceCASRetries attempts,
// this makes one final unconditional write (by id, no ciphertext predicate),
// because the rolled value is authoritative by construction: the alternative
// to writing it is a credential that exists nowhere. The single case this
// cannot repair is the row having been deleted entirely, which is reported as
// errEntryDeletedDuringRotation rather than silently swallowed or misreported
// as an ordinary conflict.
//
// NOT YET WIRED into the live Rotate handler or the scheduled sweep. Both
// still refuse a predecessorDestroysInPlace provider before ever minting (see
// the providerAuto guards in vault.go and vault_rotation.go), because this
// function alone does not make the FULL mint-to-persist path loseproof: an
// encrypt failure or a transport failure inside the provider's own roll call
// are separate gaps this function does not cover. See
// vault_rotation_destroys_in_place_authoritative_test.go for the property
// this function itself guarantees.
func persistRotatedValueAuthoritative(ctx context.Context, h *VaultHandler, q *db.Queries,
	entryID string, newValue secretexit.Plaintext) (stored bool, err error) {

	var lastErr error
	for attempt := 0; attempt < maxDestroysInPlaceCASRetries; attempt++ {
		row, rerr := q.GetVaultEntryForRotation(ctx, entryID)
		if rerr != nil {
			if errors.Is(rerr, sql.ErrNoRows) {
				return false, errEntryDeletedDuringRotation
			}
			return false, fmt.Errorf("re-read entry for authoritative persist: %w", rerr)
		}

		if persistRotatedValueAuthoritativeTestHook != nil {
			persistRotatedValueAuthoritativeTestHook(attempt)
		}

		encrypted, nonce, encErr := h.encryptEntrySecret(newValue)
		if encErr != nil {
			// Retry: this is re-derived from the same in-memory key material
			// on every attempt, so a transient failure (not a structural one)
			// is the only kind worth looping on. A structural failure fails
			// the same way on every attempt and the loop simply exhausts.
			lastErr = fmt.Errorf("encrypt rolled value: %w", encErr)
			continue
		}

		applied, perr := persistRotatedValue(ctx, q,
			snapshotFromRotationRow(entryID, row.UpdatedAtText, row.EncryptedValue), encrypted, nonce)
		if perr != nil {
			lastErr = fmt.Errorf("persist rolled value: %w", perr)
			continue
		}
		if applied {
			return true, nil
		}
		// CAS missed: something else wrote this row between the read just
		// above and this write. Loop and re-read the fresh state rather than
		// reporting a conflict the caller cannot safely retry from (the old
		// value is already dead upstream, so "reload and try again" is not a
		// safe instruction to give the caller here).
	}

	// Retries exhausted. One more existence check, so a row that was
	// genuinely deleted during the storm is reported honestly instead of the
	// forced write below silently affecting zero rows and this function
	// claiming success anyway.
	if _, rerr := q.GetVaultEntryForRotation(ctx, entryID); rerr != nil {
		if errors.Is(rerr, sql.ErrNoRows) {
			return false, errEntryDeletedDuringRotation
		}
		return false, fmt.Errorf("re-read entry before forced persist: %w", rerr)
	}

	encrypted, nonce, encErr := h.encryptEntrySecret(newValue)
	if encErr != nil {
		if lastErr != nil {
			return false, fmt.Errorf("encrypt for forced persist: %w (previous attempt: %v)", encErr, lastErr)
		}
		return false, fmt.Errorf("encrypt for forced persist: %w", encErr)
	}
	// Unconditional by id: no ciphertext/updated_at predicate. The rolled
	// value is authoritative by construction (see doc comment above), so this
	// is not "last write wins by accident", it is the documented resolution
	// for this provider class: whatever is in the row loses to the value this
	// vault knows to be the current live credential at the provider.
	if uerr := q.UpdateVaultEntryValue(ctx, db.UpdateVaultEntryValueParams{
		EncryptedValue: encrypted,
		Nonce:          nonce,
		ID:             entryID,
	}); uerr != nil {
		return false, fmt.Errorf("forced persist: %w", uerr)
	}
	return true, nil
}

package handlers

import (
	"context"
	"errors"
	"fmt"

	"github.com/brightinteraction/trustissues/internal/db"
)

// errNoCASToken is returned when a caller tries to persist a rotated value
// without the token that proves which row version it read.
//
// This is a hard error, not a zero-row result, because those are the same thing
// to a caller and they mean opposite things. Binding an empty token makes the
// UPDATE match nothing, which the old code reported as "the entry changed" and
// before that as 404 "not found" for an entry the user was looking at.
var errNoCASToken = errors.New("rotation: no compare-and-swap token; the row snapshot was not carried through")

// rotationSnapshot is the read half of the rotate protocol: the row as it was
// when the caller decided to rotate it, carrying the token the write half needs.
//
// It exists so the token cannot be forgotten. RotateVaultEntryValueUnchecked
// took four parameters and one of them was easy to omit; two call sites had to
// agree and for three audit rounds they did not.
type rotationSnapshot struct {
	EntryID       string
	UpdatedAtText string
}

func snapshotFromRotationRow(id, updatedAtText string) rotationSnapshot {
	return rotationSnapshot{EntryID: id, UpdatedAtText: updatedAtText}
}

// persistRotatedValue is the ONLY way to write a rotated secret.
//
// It is the single call site of RotateVaultEntryValueUnchecked, enforced by
// TestRotateValueHasOneCallSite. Both rotation paths (the manual handler and the
// scheduled sweep) go through here, so the compare-and-swap contract is stated
// once instead of being re-derived at each caller.
//
// applied reports whether the row still matched the snapshot. false means
// somebody else wrote the row between the read and this call, which is a real
// conflict the caller must surface: for a provider-backed entry the replacement
// key has usually already been minted upstream by then, so a silent skip strands
// a live credential.
//
// IMPORTANT for callers: nothing may write to this row between taking the
// snapshot and calling this. Any UPDATE on vault_entries bumps updated_at, which
// is the column being compared, so a caller that persists provider_meta first
// invalidates its own swap. That is not a hypothetical; it is how manual rotate
// stayed dead for a third round.
func persistRotatedValue(ctx context.Context, q *db.Queries, snap rotationSnapshot, ciphertext, nonce []byte) (applied bool, err error) {
	if snap.EntryID == "" || snap.UpdatedAtText == "" {
		return false, fmt.Errorf("%w (entry %q)", errNoCASToken, snap.EntryID)
	}
	res, err := q.RotateVaultEntryValueUnchecked(ctx, db.RotateVaultEntryValueUncheckedParams{
		EncryptedValue: ciphertext,
		Nonce:          nonce,
		ID:             snap.EntryID,
		UpdatedAtText:  snap.UpdatedAtText,
	})
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

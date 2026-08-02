package handlers

import (
	"context"
	"errors"
	"fmt"

	"github.com/bright-interaction/trustissues/internal/db"
)

// providerRole is an entry's provider resolved ONCE, so no branch has to
// re-derive it from the (name, found, CanAutoRotate) triple and get the
// combination wrong.
//
// It exists because a branch written as `if p, ok := Registry[name]; ok && ...`
// silently does nothing for a name that is not in the registry, and "does
// nothing" in the manual rotate handler meant falling through to the local
// generator. That overwrote a real upstream credential with 32 bytes of random
// hex and answered 200. The scheduled sweep, reading the same row, refused it.
//
// The unknown case is not hypothetical. Trustissues is a fork of dockyard and
// the fork deleted the five internal:* providers (see cred_rotation.go), while
// nothing validates provider against the registry on write. A database carried
// over from dockyard holds entries in exactly this state.
//
// Both rotation paths classify through here so the four states are enumerated in
// one place and a new state cannot be handled by one path and forgotten by the
// other.
type providerRole int

const (
	// providerNone: no provider configured. A local secret this server owns, so
	// generating a fresh value IS the rotation.
	providerNone providerRole = iota
	// providerAuto: in the registry and able to mint its own successor upstream.
	providerAuto
	// providerReminder: in the registry but rotation must happen in the
	// provider's own dashboard. The server must not invent a value.
	providerReminder
	// providerUnknown: a provider name this build does not have. Same hazard as
	// providerReminder and reached by a different route, which is why it is its
	// own state rather than folded in.
	providerUnknown
)

// classifyProvider resolves a provider name into its role plus the provider
// itself (nil unless the name was found).
func classifyProvider(name string) (providerRole, KeyProvider) {
	if name == "" {
		return providerNone, nil
	}
	p, ok := ProviderRegistry[name]
	if !ok {
		return providerUnknown, nil
	}
	if !p.CanAutoRotate() {
		return providerReminder, p
	}
	return providerAuto, p
}

// mayGenerateLocally reports whether this server is entitled to invent a new
// value for the entry. Only a provider-less entry qualifies.
//
// Read this as the single question every caller of generateToken on a rotation
// path has to answer. The old code asked it implicitly, by falling through a
// chain of negative branches, which is how two of the four roles ended up in the
// generator.
func (r providerRole) mayGenerateLocally() bool { return r == providerNone }

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
	// PrevCiphertext is the value read at the start of the pass. The CAS
	// compares it because updated_at alone has whole-second resolution, so two
	// writes inside one second are invisible to a timestamp token.
	PrevCiphertext []byte
}

func snapshotFromRotationRow(id, updatedAtText string, prevCiphertext []byte) rotationSnapshot {
	return rotationSnapshot{EntryID: id, UpdatedAtText: updatedAtText, PrevCiphertext: prevCiphertext}
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
	if snap.EntryID == "" || snap.UpdatedAtText == "" || len(snap.PrevCiphertext) == 0 {
		// An empty PrevCiphertext would make the ciphertext half of the predicate
		// match only rows whose value is empty, i.e. nothing, so a missing token
		// has to be an error rather than a silently-never-applying update.
		return false, fmt.Errorf("%w (entry %q)", errNoCASToken, snap.EntryID)
	}
	res, err := q.RotateVaultEntryValueUnchecked(ctx, db.RotateVaultEntryValueUncheckedParams{
		EncryptedValue:     ciphertext,
		Nonce:              nonce,
		ID:                 snap.EntryID,
		UpdatedAtText:      snap.UpdatedAtText,
		PrevEncryptedValue: snap.PrevCiphertext,
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

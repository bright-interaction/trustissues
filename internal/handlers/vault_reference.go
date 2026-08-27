package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// errAmbiguousVaultReference is returned when a name resolves to more than one
// entry the user can reach. Picking one arbitrarily would mean the caller has no
// idea which credential was spent, so this refuses instead.
var errAmbiguousVaultReference = errors.New("vault reference is ambiguous: more than one accessible entry has that name")

// resolveVaultReferenceFor resolves a {{vault:NAME}} / auth_token reference to
// its plaintext, scoped to what userID can CURRENTLY reach.
//
// The query behind it matches on (name, user_id), and user_id is the CREATOR
// column, not a statement of current access. Removing somebody from a collection
// deletes only their collection_members row, so the entry they created keeps
// their id forever and the raw query kept resolving a shared secret for a member
// who had been removed from the collection holding it. That was reachable: a
// removed member could point a forgejo_secret target on their OWN personal entry
// at auth_token="the shared secret", rotate their own entry, and have the
// CURRENT post-rotation plaintext of the team's secret POSTed to a host they
// control as an Authorization header, with only a vault.rotated row for the
// carrier entry in the activity log and no mention of the exfiltrated one.
//
// So the row is gated on entryAccessFor rather than on a hand-rolled predicate.
// Seven earlier audit rounds each closed one door onto "removing someone ends
// their access" by adding another bespoke scope check; this reuses the single
// authorization point instead, which is also how it inherits the disabled-account
// check for free.
//
// AND THAT WAS STILL NOT ENOUGH, which is the round-6 finding. Everything above
// answers "may userID REACH this secret". An accepted vault_only VIEWER of a
// shared collection may, by design (grantFor row 6 gives a viewer read + use),
// and so the same forgejo_secret target on a PERSONAL entry of their own
// delivered the team's secret to a host they chose, with nothing on the victim's
// entry ever written.
//
// The answer is not a ninth scope check. What comes back is a
// secretexit.Plaintext carrying the ORIGIN OF THE REFERENCED ENTRY, so the
// question "may the destination receive THIS secret" is asked about the right
// row at the one place it is asked at all. See internal/secretexit.
func (h *VaultHandler) resolveVaultReferenceFor(ctx context.Context, name, userID string) (secretexit.Plaintext, error) {
	var none secretexit.Plaintext
	row, err := h.resolveVaultReferenceRowFor(ctx, name, userID)
	if err != nil {
		return none, err
	}

	// The origin is the REFERENCED entry, not the entry whose rotation is
	// running. That single argument is the round-6 fix: the exit asks the owner
	// of the secret it is about to send, and the secret it is about to send is
	// this one.
	plaintext, err := h.OpenEntrySecret(row.EncryptedValue, row.Nonce, 2,
		entryOrigin(row.ID, name))
	if err != nil {
		return none, fmt.Errorf("decrypt vault reference %q: %w", name, err)
	}
	return plaintext, nil
}

// resolveVaultReferenceRowFor performs the reference's name and authority
// resolution without opening its value. HTTP policy gates use this form to
// decide whether a target references protected metadata; decrypting the secret
// merely to learn its entry id would widen the amount of plaintext handled by
// a request that may ultimately be refused.
func (h *VaultHandler) resolveVaultReferenceRowFor(ctx context.Context, name, userID string) (db.ResolveVaultReferenceRow, error) {
	return h.resolveVaultReferenceRowForVisibility(ctx, name, userID, false)
}

// resolvePublicVaultReferenceRowFor is the metadata-safe form used only while
// deciding whether a public HTTP target-management request must move to private
// ingress. A fully-private row is removed before its encrypted name is opened or
// compared, so adding an accessible hidden entry with the same exact name cannot
// turn an otherwise-valid standard reference from 200 into 403 through an
// ambiguity. The ordinary resolver above intentionally keeps every row because
// scheduled delivery and private management are not public metadata probes.
func (h *VaultHandler) resolvePublicVaultReferenceRowFor(ctx context.Context, name, userID string) (db.ResolveVaultReferenceRow, error) {
	return h.resolveVaultReferenceRowForVisibility(ctx, name, userID, true)
}

func (h *VaultHandler) resolveVaultReferenceRowForVisibility(ctx context.Context, name, userID string,
	hideFullyPrivate bool) (db.ResolveVaultReferenceRow, error) {
	var none db.ResolveVaultReferenceRow
	if name == "" || userID == "" {
		return none, sql.ErrNoRows
	}
	all, err := h.queries.ResolveVaultReference(ctx)
	if err != nil {
		return none, err
	}

	// THE NAME MATCH, which SQL used to do. Since 00040 the name column is
	// randomized ciphertext and the blind index that replaced it for equality is
	// keyed per user, so there is no one token to look a name up by across the
	// several users whose entries this caller may legitimately reach. The
	// comparison is therefore done here, on the decrypted name, and it is exactly
	// the comparison the WHERE clause performed: byte equality, no folding.
	//
	// This narrows only. Every row that survives still goes through
	// entryCurrentlyUsableBy below, which is where authorization actually happens
	// and which is deliberately unchanged.
	var named []db.ResolveVaultReferenceRow
	for _, row := range all {
		if hideFullyPrivate && row.CollectionID.Valid && row.CollectionID.String != "" {
			if !row.PrivateAccessPolicy.Valid {
				return none, fmt.Errorf("vault reference %q collection policy is missing", name)
			}
			policy, err := storedPrivateAccessPolicy(row.PrivateAccessPolicy.String)
			if err != nil {
				return none, err
			}
			if policy == privateaccess.PolicyFullyPrivate {
				continue
			}
		}
		if h.decryptColumnOrLog(row.Name, "", vaultFieldName) == name {
			named = append(named, row)
		}
	}

	// Keep only entries this user may USE right now. Deliberately not
	// entryAccessFor's canRead: that grants a removed creator a residual recovery
	// read, and the entry keeps their user_id forever, so gating on it left the
	// exfiltration wide open. See entryCurrentlyUsableBy.
	var reachable []db.ResolveVaultReferenceRow
	for _, row := range named {
		if h.entryCurrentlyUsableBy(ctx, userID, row.ID) {
			reachable = append(reachable, row)
		}
	}
	switch len(reachable) {
	case 0:
		return none, sql.ErrNoRows
	case 1:
	default:
		return none, fmt.Errorf("%w: %q", errAmbiguousVaultReference, name)
	}

	return reachable[0], nil
}

// queuedActivity is an activity-log row queued during a transaction and written
// once it commits.
//
// LogActivityFromRequest deliberately runs on its own background context (so a
// cancelled request still gets audited), which means its own connection. Calling
// it while a write transaction is open on another connection makes it contend
// for the SQLite write lock: it burns the whole _busy_timeout and then loses the
// row. Queue, commit, then write.
type queuedActivity struct {
	action string
	detail string
}

// rotationTargetsVersion fingerprints the stored rotation_targets column so a
// client can prove it is editing the view it was shown.
//
// It hashes the CIPHERTEXT, which changes on every write (a fresh nonce per
// encryption), so any modification invalidates an outstanding view even if the
// decrypted target list happens to be identical.
func rotationTargetsVersion(storedCiphertext string) string {
	sum := sha256.Sum256([]byte(storedCiphertext))
	return hex.EncodeToString(sum[:8])
}

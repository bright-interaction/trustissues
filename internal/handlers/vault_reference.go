package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/brightinteraction/trustissues/internal/db"
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
func (h *VaultHandler) resolveVaultReferenceFor(ctx context.Context, name, userID string) ([]byte, error) {
	if name == "" || userID == "" {
		return nil, sql.ErrNoRows
	}
	rows, err := h.queries.ResolveVaultReference(ctx, name)
	if err != nil {
		return nil, err
	}

	// Keep only entries this user may USE right now. Deliberately not
	// entryAccessFor's canRead: that grants a removed creator a residual recovery
	// read, and the entry keeps their user_id forever, so gating on it left the
	// exfiltration wide open. See entryCurrentlyUsableBy.
	var reachable []db.ResolveVaultReferenceRow
	for _, row := range rows {
		if h.entryCurrentlyUsableBy(ctx, userID, row.ID) {
			reachable = append(reachable, row)
		}
	}
	switch len(reachable) {
	case 0:
		return nil, sql.ErrNoRows
	case 1:
	default:
		return nil, fmt.Errorf("%w: %q", errAmbiguousVaultReference, name)
	}

	plaintext, err := h.DecryptValue(reachable[0].EncryptedValue, reachable[0].Nonce, 2)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault reference %q: %w", name, err)
	}
	return plaintext, nil
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

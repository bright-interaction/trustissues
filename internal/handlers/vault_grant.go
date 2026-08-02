package handlers

import (
	"context"
	"database/sql"

	"github.com/bright-interaction/trustissues/internal/db"
)

// entryGrant is what one user may do with one vault entry, right now.
//
// Three rights, not two booleans, because the audit found that "can read" and
// "may spend" are genuinely different questions and conflating them was a live
// exfiltration path. A collection creator who is no longer a member keeps READ
// so they can recover a secret they own after someone moved it into a collection
// they are not in; they must not keep USE, because the entry carries their
// user_id forever and a removed member is otherwise indistinguishable from a
// current one.
type entryGrant struct {
	// read: may see this entry and its metadata, including recovery for a
	// creator who has been removed from the collection holding it.
	read bool
	// use: may SPEND the credential. Resolve it to plaintext, mint an agent
	// token for it, authenticate with it upstream, deliver it to a target.
	// Strictly narrower than read.
	use bool
	// manage: may modify the entry, its targets, or its schedule.
	manage bool
}

// grantFor is the single authorization decision for a vault entry.
//
// One security property, "removing someone ends their access", failed in TEN
// distinct places across thirteen audit rounds, each a different verb: remove,
// deliver, mint, access, fetch-as-service, leave, read-targets, resolve-by-name,
// validate, stale-panel-write. Every one of them was a surface that asked the
// question its own way. The rows below are the answer stated once.
//
// Order matters and is deliberate. Read top to bottom; the first matching row
// wins.
func (h *VaultHandler) grantFor(ctx context.Context, userID string, isAdmin bool, entryID string) entryGrant {
	var none entryGrant

	info, err := h.queries.GetVaultEntryAccess(ctx, entryID)
	if err != nil {
		// Row 1: no such entry. Nothing, and callers 404 uniformly so a probe
		// cannot distinguish "does not exist" from "not yours".
		return none
	}

	// Row 2: a disabled or deleted account has no rights at all, on any path.
	// The HTTP middleware already refuses disabled users, so this matters for
	// BACKGROUND callers asking about somebody who is not the caller. Without
	// it, Disable was a half-revocation: browser access cut instantly while the
	// rotation webhook kept receiving fresh plaintext.
	if userID != "" {
		if u, uErr := h.queries.GetUserByID(ctx, userID); uErr != nil || u.Disabled != 0 {
			return none
		}
	}

	// Row 3: an instance admin may do anything to any entry.
	if isAdmin {
		return entryGrant{read: true, use: true, manage: true}
	}

	inCollection := info.CollectionID.Valid && info.CollectionID.String != ""
	isCreator := userID != "" && info.UserID == userID

	// Row 4: a personal entry belongs to its owner and nobody else.
	if !inCollection {
		if isCreator {
			return entryGrant{read: true, use: true, manage: true}
		}
		return none
	}

	// The entry lives in a collection, so current membership decides.
	role, roleErr := h.queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: info.CollectionID.String,
		UserID:       userID,
	})
	if roleErr == nil {
		switch role {
		// Row 5: an accepted editor or manager gets everything.
		case collRoleManager, collRoleEditor:
			return entryGrant{read: true, use: true, manage: true}
		// Row 6: an accepted viewer may read and spend, but not modify.
		case collRoleViewer:
			return entryGrant{read: true, use: true}
		}
		return none
	}

	// Row 7: NOT a current member. The creator keeps a residual READ so a
	// secret they own cannot be taken from them by someone moving it into a
	// collection they are not in. It carries neither use nor manage: this is
	// recovery, not continued access, and it is the row that was re-derived at
	// ten call sites and got the answer wrong at several of them.
	if isCreator {
		return entryGrant{read: true}
	}

	// Row 8: everyone else, nothing.
	return none
}

// managerMayAdoptOrphanedEntry reports whether callerID may rename an entry that
// somebody else created, by taking ownership of it.
//
// True only when all three hold: the entry lives in a collection, the caller is
// an accepted MANAGER of that collection, and the creator is no longer an
// accepted member of it. The third condition is the whole point: while the
// creator is still on the team they can rename their own entry, and letting
// anyone else do it would put a uniqueness check against their private vault
// back on a path a colleague can drive (see the rule in VaultHandler.Update).
//
// Every fact it reads is one the caller can already read: they know their own
// role, and GET /api/collections/{id}/members lists who is a member. So the
// answer adds no information about anyone's private namespace.
func (h *VaultHandler) managerMayAdoptOrphanedEntry(ctx context.Context, callerID, creatorID string, collectionID sql.NullString) bool {
	if callerID == "" || !collectionID.Valid || collectionID.String == "" {
		return false
	}
	callerRole, err := h.queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: collectionID.String,
		UserID:       callerID,
	})
	if err != nil || callerRole != collRoleManager {
		return false
	}
	// GetCollectionMemberRole returns no row for a pending or absent membership,
	// which is exactly "cannot reach this entry through the collection".
	if _, err := h.queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: collectionID.String,
		UserID:       creatorID,
	}); err == nil {
		return false // the creator is still here; it is theirs to rename
	}
	return true
}

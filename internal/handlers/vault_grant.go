package handlers

import (
	"context"
	"database/sql"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
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

// mayDirectSecretEgress reports whether userID may ADD or WIDEN a destination
// this entry's secret is delivered to.
//
// It is deliberately narrower than manage. grantFor row 5 hands manage to every
// accepted editor of the collection an entry lives in, and that is right for
// editing an entry: name, notes, rotation schedule, even the value. It is not
// right for choosing where the plaintext GOES. An editor who can repoint the
// ceiling turns "use without seeing" into "see": /proxy injects the decrypted
// value into a request addressed at a host they named, and unlike
// /api/vault/unlock (which re-verifies the caller's password) the proxy path is
// reachable with an API key alone. That is the round-3 blocker in one sentence.
//
// The right belongs to the principal who deposited the plaintext (the entry's
// creator) or to an instance admin. Both must ALSO still have manage right now,
// so a departed creator's residual recovery read (row 7) does not carry a
// licence to redirect the secret of a collection they were removed from.
//
// Narrowing is not gated here: anyone with manage may shrink or clear the list,
// because clearing it is the only per-secret agent revocation the product has.
//
// # secret_owner_user_id, NOT user_id
//
// This is the line the whole exit hangs from, so the column it reads has to be
// one no principal below the owner can write. user_id is not that column: a
// collection MANAGER moves it to their own id with two ordinary calls,
//
//	DELETE /api/collections/{id}/members/{creator}  (manager-gated)
//	PUT    /api/vault/{entry}  {"name":"..."}       (managerMayAdoptOrphanedEntry
//	                                                -> AdoptAndRenameVaultEntry)
//
// and once they had, this function said yes and the exit authorised the exact
// round-6 cross-entry delivery it was built to refuse. An authority derived from
// data the attacker can write is not an authority.
//
// secret_owner_user_id is written when the row is created and moved afterwards
// by exactly one statement, in a package the compiler keeps out of reach of the
// handlers (internal/vaultegress). Adoption does not move it, on purpose:
// adoption exists so the uniqueness question lands in the renamer's namespace,
// which is a namespace concern and not an authority one.
//
// An EMPTY owner is refused rather than falling back to user_id. A row with no
// recorded owner is one no creating statement stamped, and the safe reading of
// that is "nobody may redirect this", not "whoever holds it now may".
func (h *VaultHandler) mayDirectSecretEgress(ctx context.Context, userID string, isAdmin bool, entryID string) bool {
	if entryID == "" {
		return false
	}
	g := h.grantFor(ctx, userID, isAdmin, entryID)
	if !g.manage {
		return false
	}
	if isAdmin {
		return true
	}
	info, err := h.queries.GetVaultEntryAccess(ctx, entryID)
	if err != nil {
		return false
	}
	return userID != "" && info.SecretOwnerUserID != "" && info.SecretOwnerUserID == userID
}

// instanceAdminByRecord reports whether userID is an instance admin RIGHT NOW,
// according to the users table.
//
// Not middleware.IsAdmin. A session carries the role it was minted with, and the
// question "may this identity choose where a secret is delivered" is asked twice
// about the same identity: once when the target is written, with a request in
// hand, and once at every later delivery, with no request at all. Two sources
// for one fact is how the two halves came to disagree, so there is one source
// and it is the row.
//
// A missing or disabled account is not an admin. Fail-closed, and it keeps this
// consistent with grantFor row 2, which refuses a disabled account everything.
func (h *VaultHandler) instanceAdminByRecord(ctx context.Context, userID string) bool {
	if userID == "" {
		return false
	}
	u, err := h.queries.GetUserByID(ctx, userID)
	if err != nil || u.Disabled != 0 {
		return false
	}
	return u.Role == middleware.RoleAdmin
}

// mayConfigureDelivery is THE answer to "may this identity add a delivery
// destination to this entry?", and the only one.
//
// THE RULE, stated once: the entry's creator, or an instance admin, and in both
// cases only while they still hold manage on the entry.
//
// It exists because round 5 implemented that sentence twice and the two copies
// disagreed about the second half of it. The write gate passed an admin
// (middleware.IsAdmin), the delivery gate hardcoded isAdmin false, so an admin
// could configure a target that was accepted, reported as saved, and then
// silently never delivered on every subsequent rotation. Of the three possible
// behaviours (deliver, refuse at the write, accept-then-silent) that is the
// worst: the operator is told it worked and the consumer never gets the key.
//
// There is deliberately NO isAdmin parameter. A parameter is a thing two call
// sites can pass differently, which is precisely what happened; the admin
// question is answered here, from the row, for both halves.
func (h *VaultHandler) mayConfigureDelivery(ctx context.Context, userID, entryID string) bool {
	return h.mayDirectSecretEgress(ctx, userID, h.instanceAdminByRecord(ctx, userID), entryID)
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

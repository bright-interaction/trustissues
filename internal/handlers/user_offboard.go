package handlers

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/brightinteraction/trustissues/internal/db"
)

// offboardUser runs every revocation step that must happen when a person loses
// access, and records what it did on the activity log.
//
// It exists because this one property, "when someone is offboarded their reach
// actually ends", has now been fixed FIVE times in five separate places:
// collection removal, rotation-target delivery, capability minting, the shared
// entryAccessFor gate, and now service identities. Each fix closed one door and
// the next audit round found another, because every caller re-implemented its
// own idea of what offboarding means. Anything added here is inherited by all
// three callers (disable, delete, password reset) instead of by whichever one
// the author happened to be editing.
//
// Best-effort by design: an offboarding that half-completes because a cleanup
// step errored is worse than one that finishes and reports what it could not
// tidy. Every step logs its own failure and none of them abort the caller.
//
// The authoritative controls are still the runtime gates (FetchOwnSecrets
// refuses a disabled or deleted owner, targetStillAuthorized refuses delivery,
// entryAccessFor refuses access). This function is what makes the revocation
// VISIBLE in the product rather than surfacing as a mystery 401 at the next
// boot, and what stops dead endpoints from sitting in the UI looking live.
func (h *UserHandler) offboardUser(r *http.Request, userID, email string) {
	if userID == "" {
		return
	}

	// 1. Service identities. FetchOwnSecrets resolves every secret as the
	// identity's created_by_user_id, so a live key outlives its owner and keeps
	// reading their personal vault, including values rotated after they left.
	names, listErr := h.queries.ListServiceIdentitiesByUser(r.Context(), sql.NullString{String: userID, Valid: true})
	if listErr != nil {
		slog.Error("offboard: could not list service identities", "user", userID, "error", listErr)
	} else if len(names) > 0 {
		if _, revErr := h.queries.RevokeServiceIdentitiesByUser(r.Context(), sql.NullString{String: userID, Valid: true}); revErr != nil {
			slog.Error("offboard: could not revoke service identities", "user", userID, "error", revErr)
		} else {
			labels := make([]string, 0, len(names))
			for _, n := range names {
				labels = append(labels, n.Name)
			}
			// Named explicitly: each one is a machine credential that will stop
			// working at its next boot, and the admin needs to know which
			// services to re-provision before that happens.
			LogActivityFromRequest(h.queries, r, "admin.service_identities_revoked",
				fmt.Sprintf("Offboarding %s: revoked %d service key(s), these services must be re-provisioned: %v",
					email, len(labels), labels))
			slog.Info("offboard: revoked service identities", "user", userID, "count", len(labels))
		}
	}

	// 2. Rotation delivery targets they configured, across every entry
	// including their own personal ones (auto-rotation keeps running on those).
	if h.vault != nil {
		if summary := h.vault.PurgeTargetsConfiguredByUser(r.Context(), userID); summary != "" {
			LogActivityFromRequest(h.queries, r, "admin.user_targets_purged",
				fmt.Sprintf("Offboarding cleanup for %s: %s", email, summary))
		}
	}
}

// disposeVaultEntriesOnDelete handles the departing user's secrets on a HARD
// delete, and is deliberately NOT part of offboardUser: disabling an account is
// reversible and must leave the entries exactly where they are.
//
// vault_entries.user_id has no foreign key (every other user-owned table has
// one) and DeleteUser is a bare DELETE FROM users, so entries used to survive
// with a dangling user_id. Nothing could read them afterwards, since unlock,
// the capability lookups and the service fetch are all scoped to a live user,
// so they were unrecoverable ciphertext retained forever, in a product that
// sells EU data sovereignty and whose own dialog promises the entries go with
// the user.
//
// Personal entries are therefore deleted (nothing readable is lost, and it
// gives the product a real erasure path) while entries the person created
// inside a SHARED collection are re-owned by the admin doing the delete, since
// those are team property and must not disappear with the leaver.
func (h *UserHandler) disposeVaultEntriesOnDelete(r *http.Request, targetID, email, newOwnerID string) {
	if targetID == "" {
		return
	}
	if newOwnerID != "" {
		h.reassignCollectionEntries(r, targetID, email, newOwnerID)
	}
	if res, err := h.queries.DeletePersonalVaultEntriesForUser(r.Context(), targetID); err != nil {
		slog.Error("offboard: could not delete personal entries", "user", targetID, "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		LogActivityFromRequest(h.queries, r, "admin.entries_deleted_with_user",
			fmt.Sprintf("Deleting %s: removed %d personal secret(s)", email, n))
	}
}

// reassignCollectionEntries re-owns the leaver's shared entries ONE AT A TIME.
//
// A single blanket UPDATE was all-or-nothing. vault_entries still carries
// UNIQUE(user_id, name), and generic names ("GitHub", "AWS", "Stripe") collide
// constantly in a password manager, so one clash aborted the whole statement:
// every shared entry kept the deleted user's id, no activity row was written,
// and the confirmation dialog had just promised the team would keep them. The
// failure was invisible and the entries were left orphaned, which is exactly the
// state the change was meant to eliminate.
//
// Per row, a collision is resolved by suffixing the leaver's address rather than
// skipping, so the team keeps the secret either way and the rename says where it
// came from. Anything that still fails is NAMED on the activity log instead of
// being swallowed.
func (h *UserHandler) reassignCollectionEntries(r *http.Request, targetID, email, newOwnerID string) {
	rows, err := h.queries.ListCollectionVaultEntriesForUser(r.Context(), targetID)
	if err != nil {
		slog.Error("offboard: could not list collection entries", "user", targetID, "error", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	moved := 0
	var renamed, failed []string
	for _, row := range rows {
		_, uErr := h.queries.ReassignCollectionVaultEntryOwner(r.Context(), db.ReassignCollectionVaultEntryOwnerParams{
			UserID: newOwnerID, ID: row.ID,
		})
		if uErr == nil {
			moved++
			continue
		}
		if !strings.Contains(uErr.Error(), "UNIQUE constraint") {
			slog.Error("offboard: could not re-own entry", "entry", row.ID, "error", uErr)
			failed = append(failed, row.Name)
			continue
		}
		// The new owner already has an entry by this name. Keep both.
		dedup := row.Name + " (from " + email + ")"
		if _, rErr := h.queries.RenameVaultEntry(r.Context(), db.RenameVaultEntryParams{
			Name: dedup, ID: row.ID,
		}); rErr != nil {
			slog.Error("offboard: could not de-duplicate entry name", "entry", row.ID, "error", rErr)
			failed = append(failed, row.Name)
			continue
		}
		if _, uErr2 := h.queries.ReassignCollectionVaultEntryOwner(r.Context(), db.ReassignCollectionVaultEntryOwnerParams{
			UserID: newOwnerID, ID: row.ID,
		}); uErr2 != nil {
			slog.Error("offboard: re-own failed after rename", "entry", row.ID, "error", uErr2)
			failed = append(failed, row.Name)
			continue
		}
		moved++
		renamed = append(renamed, row.Name+" -> "+dedup)
	}

	if moved > 0 {
		detail := fmt.Sprintf("Deleting %s: re-owned %d shared collection secret(s) so the team keeps them", email, moved)
		if len(renamed) > 0 {
			detail += fmt.Sprintf("; renamed %d to avoid a name clash: %v", len(renamed), renamed)
		}
		LogActivityFromRequest(h.queries, r, "admin.entries_reassigned", detail)
	}
	// Never silent. An entry left with a dangling owner is unreadable forever,
	// so the admin has to be told which ones by name.
	if len(failed) > 0 {
		LogActivityFromRequest(h.queries, r, "admin.entries_reassign_failed",
			fmt.Sprintf("Deleting %s: could NOT re-own %d shared secret(s), they are now orphaned and unreadable: %v",
				email, len(failed), failed))
		slog.Error("offboard: some collection entries could not be re-owned",
			"user", targetID, "count", len(failed))
	}
}

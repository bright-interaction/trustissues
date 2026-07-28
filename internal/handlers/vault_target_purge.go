package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/brightinteraction/trustissues/internal/db"
)

// PurgeTargetsConfiguredByUser detaches every rotation delivery target that the
// given user configured, across EVERY entry rather than one collection.
//
// This is the account-level counterpart to CollectionHandler.purgeTargetsConfiguredBy.
// Removing someone from a collection is scoped, so a scoped purge fits; disabling
// an account is not, and a per-collection purge would miss two cases that matter:
// entries in collections the caller is not looking at, and the disabled user's
// OWN personal entries, where auto-rotation keeps running after the account is
// disabled and would keep POSTing fresh plaintext to their endpoint.
//
// The authoritative control is still targetStillAuthorized, which refuses at
// delivery time and therefore also covers targets planted before this existed.
// This purge is what stops the dead endpoint from sitting in the rotation panel
// looking active and from marking every future rotation "partial".
//
// Best-effort by design: it must never fail the disable itself. A half-completed
// offboarding because a cleanup step errored is worse than one that finishes and
// logs what it could not tidy.
func (h *VaultHandler) PurgeTargetsConfiguredByUser(ctx context.Context, userID string) string {
	if userID == "" {
		return ""
	}
	rows, err := h.queries.ListAllVaultEntryTargets(ctx)
	if err != nil {
		slog.Error("vault: could not list entries for account target purge", "user", userID, "error", err)
		return ""
	}

	dropped := 0
	var entries []string
	for _, row := range rows {
		targets := ParseRotationTargets(h.decryptColumnOrLog(row.RotationTargets.String, "[]", "rotation_targets"))
		kept := make([]RotationTarget, 0, len(targets))
		removedHere := 0
		for _, t := range targets {
			if t.ConfiguredBy == userID {
				removedHere++
				continue
			}
			kept = append(kept, t)
		}
		if removedHere == 0 {
			continue
		}
		encoded, mErr := json.Marshal(kept)
		if mErr != nil {
			slog.Error("vault: could not encode purged targets", "entry", row.ID, "error", mErr)
			continue
		}
		enc, encErr := h.encryptColumn(string(encoded))
		if encErr != nil {
			slog.Error("vault: could not encrypt purged targets", "entry", row.ID, "error", encErr)
			continue
		}
		if uErr := h.queries.UpdateVaultEntryRotationTargets(ctx, db.UpdateVaultEntryRotationTargetsParams{
			RotationTargets: toNullString(enc),
			ID:              row.ID,
		}); uErr != nil {
			slog.Error("vault: could not persist purged targets", "entry", row.ID, "error", uErr)
			continue
		}
		dropped += removedHere
		entries = append(entries, row.Name)
	}

	if dropped == 0 {
		return ""
	}
	slog.Info("vault: purged rotation targets on account disable",
		"user", userID, "targets_removed", dropped)
	return fmt.Sprintf("removed %d rotation delivery target(s) they had configured on: %v", dropped, entries)
}

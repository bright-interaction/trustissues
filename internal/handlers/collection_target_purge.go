package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/brightinteraction/trustissues/internal/db"
)

// purgeTargetsConfiguredBy removes every rotation target in a collection that
// was configured by the given user, and returns a short human summary of what
// was dropped.
//
// This is the second half of the offboarding fix. The authoritative half is the
// check in DeliverRotatedKey, which refuses to send to a target whose configurer
// no longer has write access; that one also covers targets planted before this
// purge existed. Purging as well means the stale target does not sit in the UI
// looking active, does not keep producing "partial" rotations forever, and does
// not silently reactivate if the same person is ever re-added.
//
// Best-effort by design: it must never block or fail the removal itself. An
// offboarding that half-succeeds because a cleanup step errored is worse than
// one that completes and logs what it could not tidy.
func (h *CollectionHandler) purgeTargetsConfiguredBy(ctx context.Context, collectionID, userID string) string {
	if h.vault == nil || collectionID == "" || userID == "" {
		return ""
	}
	rows, err := h.queries.ListVaultEntryTargetsInCollection(ctx, toNullString(collectionID))
	if err != nil {
		slog.Error("collections: could not list entries for target purge", "collection", collectionID, "error", err)
		return ""
	}

	dropped := 0
	var entries []string
	for _, row := range rows {
		targets := ParseRotationTargets(h.vault.decryptColumnOrLog(row.RotationTargets.String, "[]", "rotation_targets"))
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
			slog.Error("collections: could not encode purged targets", "entry", row.ID, "error", mErr)
			continue
		}
		enc, encErr := h.vault.encryptColumn(string(encoded))
		if encErr != nil {
			slog.Error("collections: could not encrypt purged targets", "entry", row.ID, "error", encErr)
			continue
		}
		if uErr := h.queries.UpdateVaultEntryRotationTargets(ctx, db.UpdateVaultEntryRotationTargetsParams{
			RotationTargets: toNullString(enc),
			ID:              row.ID,
		}); uErr != nil {
			slog.Error("collections: could not persist purged targets", "entry", row.ID, "error", uErr)
			continue
		}
		dropped += removedHere
		entries = append(entries, row.Name)
	}

	if dropped == 0 {
		return ""
	}
	summary := fmt.Sprintf("removed %d rotation delivery target(s) they had configured on: %v", dropped, entries)
	slog.Info("collections: purged rotation targets on member removal",
		"collection", collectionID, "user", userID, "targets_removed", dropped)
	return summary
}

// logTargetPurge records the purge on the activity log so a manager can see that
// an offboarding actually detached a delivery endpoint, and which entries were
// touched. Silent cleanup would leave nobody able to answer "was that webhook
// still receiving our key?".
func (h *CollectionHandler) logTargetPurge(r *http.Request, collectionName, summary string) {
	if summary == "" {
		return
	}
	LogActivityFromRequest(h.queries, r, "collection.targets_purged",
		fmt.Sprintf("Offboarding cleanup in %s: %s", collectionName, summary))
}

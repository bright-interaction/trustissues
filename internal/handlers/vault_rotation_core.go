package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
)

// Shared rotation outcome logic: everything that happens AFTER the rotated value
// is durably committed.
//
// The two rotation paths (the manual HTTP handler and the scheduled sweep) were
// written separately and drifted on five distinct behaviours, four of which lost
// or falsified the record of a rotation. Each is fixed and pinned by a row in
// rotation_contract_test.go that asserts both paths agree. This file is where they
// now share the implementation, so a sixth divergence cannot be introduced by
// editing one path.
//
// It is deliberately TWO functions rather than one. The manual path has to send
// its HTTP response between the revoke and the delivery (the user needs the new
// value immediately, delivery can take minutes), so a single finish() would force
// the handler to either block the response or skip the shared code. The split is
// at the only point where the two paths genuinely need to differ.
//
// What stays with the callers, because it is genuinely per-path and must NOT be
// asserted identical:
//
//	method            "manual" vs "auto"
//	actor             a request user id vs nil
//	activity verb     vault.rotated via LogActivityFromRequest vs
//	                  vault.auto_rotate via LogActivity
//	delivery timing   a detached goroutine (so the HTTP response is immediate)
//	                  vs inline
//
// The matrix models that same discipline: wantManualStatus lives outside
// rotationOutcome precisely because the sweep has no HTTP surface.

// rotationDeps is the pair of handles both paths hold under different names.
type rotationDeps struct {
	queries *db.Queries
	vault   *VaultHandler
}

// revokeOldKeyAndPersistMeta destroys the predecessor key upstream and then writes
// provider_meta exactly ONCE. It returns the revoke warning, if any, for the
// caller to pass to recordRotationOutcome.
//
// Order matters and is the whole point of the function. performPendingRevoke
// strips the transient pending_revoke_* markers from the map, so writing meta
// afterwards is what keeps them out of the database. The manual path used to write
// meta first, with the markers still in the map, and clean up afterwards.
//
// Call only after the value is durably stored: revoking earlier means a failure in
// the encrypt/persist window leaves the old credential dead upstream and the new
// one discarded, with no copy of either anywhere.
func revokeOldKeyAndPersistMeta(ctx context.Context, deps rotationDeps, entryID, entryName string, providerMeta map[string]string, newValue string) string {
	if providerMeta == nil {
		return ""
	}
	performPendingRevoke(ctx, providerMeta, newValue)
	revokeWarn := providerMeta["last_revoke_error"]
	delete(providerMeta, "last_revoke_error")
	if revokeWarn != "" {
		slog.Error("vault rotation: old key revoke failed (predecessor still live)",
			"entry", entryName, "detail", revokeWarn)
	}

	// Persist the key id Rotate minted, so the NEXT rotation revokes the key we
	// just created instead of a stale predecessor. Errors are logged, never
	// discarded: losing this write means the next revoke targets a dead id and the
	// real predecessor leaks.
	if metaJSON, mErr := json.Marshal(providerMeta); mErr != nil {
		slog.Error("vault rotation: marshal provider_meta failed", "entry", entryName, "error", mErr)
	} else if encMeta, encErr := deps.vault.encryptColumn(string(metaJSON)); encErr != nil {
		slog.Error("vault rotation: encrypt provider_meta failed", "entry", entryName, "error", encErr)
	} else if pErr := deps.queries.UpdateVaultEntryProviderMeta(ctx, db.UpdateVaultEntryProviderMetaParams{
		ProviderMeta: toNullString(encMeta),
		ID:           entryID,
	}); pErr != nil {
		slog.Error("vault rotation: persist provider_meta failed", "entry", entryName, "error", pErr)
	}
	return revokeWarn
}

// rotationRecord is everything needed to finalise a rotation that has already
// committed its value.
type rotationRecord struct {
	EntryID   string
	EntryName string
	Provider  string
	Method    string // "manual" or "auto"
	UserID    string
	// RotationLog is the log column as it was READ. AppendRotationLog appends to
	// this, so a caller passing a stale copy loses entries.
	RotationLog string
	Targets     []RotationTarget
	OldValue    string
	NewValue    string
	// RevokeWarn is what revokeOldKeyAndPersistMeta returned.
	RevokeWarn string
}

// recordRotationOutcome delivers to configured targets, computes the true final
// status, alerts on anything short of clean, and writes last_rotation_error and
// rotation_log exactly once each.
//
// Delivery runs BEFORE the outcome is recorded so the status reflects delivery
// truth: a target that fails to apply makes the rotation partial and visible
// rather than being logged as a success.
//
// This is the single site that decides what a rotation's status IS. It used to be
// three sites (the sweep, the manual no-targets branch, and the manual delivery
// goroutine) and two of them were wrong: both overwrote a recorded revoke failure
// with a clean success and neither alerted.
func recordRotationOutcome(ctx context.Context, deps rotationDeps, rec rotationRecord) (string, string) {
	status, errSummary := "success", ""
	if len(rec.Targets) > 0 {
		results := DeliverRotatedKey(ctx, deps.queries, deps.vault,
			rec.EntryID, rec.EntryName, rec.OldValue, rec.NewValue, rec.Targets, rec.UserID)
		status, errSummary = summarizeDelivery(results)
		slog.Info("vault rotation: delivery complete",
			"entry", rec.EntryName, "status", status, "total_targets", len(rec.Targets))
		if status != "success" {
			slog.Error("vault rotation: delivery had failures", "entry", rec.EntryName, "detail", errSummary)
			dispatchRotationAlert(ctx, deps.queries, deps.vault, rec.EntryName, errSummary)
		}
	}

	status, errSummary, revokeAlert := foldRevokeOutcome(status, errSummary, rec.RevokeWarn)
	if revokeAlert {
		dispatchRotationAlert(ctx, deps.queries, deps.vault, rec.EntryName, revokeStillLiveMsg)
	}

	if err := deps.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString(errSummary),
		ID:                rec.EntryID,
	}); err != nil {
		slog.Error("vault rotation: persist last_rotation_error failed", "entry", rec.EntryName, "error", err)
	}
	updatedLog := AppendRotationLog(rec.RotationLog, RotationLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    status,
		Provider:  rec.Provider,
		Error:     errSummary,
		Method:    rec.Method,
	})
	if err := deps.queries.UpdateVaultEntryRotationLog(ctx, db.UpdateVaultEntryRotationLogParams{
		RotationLog: toNullString(updatedLog),
		ID:          rec.EntryID,
	}); err != nil {
		slog.Error("vault rotation: persist rotation_log failed", "entry", rec.EntryName, "error", err)
	}
	return status, errSummary
}

// revokeStillLiveMsg is the ONLY text either path may persist about a failed
// old-key revoke.
//
// Static on purpose. The raw revoke error can embed the provider URL, the key id
// and the upstream response body, and last_rotation_error is API-visible, so the
// detail belongs in the slog line and nowhere else.
const revokeStillLiveMsg = "old key not revoked (still live at provider); see server logs"

// foldRevokeOutcome merges "the predecessor key is still live upstream" into a
// rotation's final status, and reports whether an alert is owed.
//
// It exists because the manual handler wrote that fact to last_rotation_error
// immediately after the revoke failed, and then, a few lines later, unconditionally
// overwrote it: the no-targets branch with "" and Status "success", the delivery
// goroutine with a delivery-only summary. Either way the durable record said the
// rotation was clean while the key the operator believed they had just retired was
// still authenticating. No alert was dispatched either.
//
// That is not a rare path. resend, sendgrid and neon all defer a DELETE for the
// old key, so any 4xx, 5xx or transport error on it lands here, and the revoke
// uses the NEW key as its bearer, which providers routinely reject until the new
// key's permissions propagate. Worse, meta["key_id"] has already advanced to the
// successor by then, so the orphaned predecessor is never a revoke candidate
// again. Someone rotating a key precisely because they think it is compromised
// was told it worked.
//
// The scheduled sweep already computed this correctly. Both paths now call this,
// so the rule is stated once instead of being re-derived at the two sites that
// finalise a rotation.
func foldRevokeOutcome(status, errSummary, revokeWarn string) (outStatus, outSummary string, alert bool) {
	if revokeWarn == "" {
		return status, errSummary, false
	}
	// A delivery failure is already partial or error; do not promote it back up.
	if status == "success" {
		status = "partial"
	}
	if errSummary == "" {
		errSummary = revokeStillLiveMsg
	} else {
		errSummary = errSummary + "; " + revokeStillLiveMsg
	}
	return status, errSummary, true
}

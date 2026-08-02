package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
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
func revokeOldKeyAndPersistMeta(ctx context.Context, deps rotationDeps, entryID, entryName, provider string, providerMeta map[string]string, newValue string) string {
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
	// THE WRITE-BACK IS ALSO A HOST-CHOOSING WRITE, and nobody authorizes it.
	//
	// This map came back out of a provider adapter. Twilio writes key_sid,
	// backblaze writes key_id, and the whole map is then persisted with no
	// authorization check anywhere, because it is the server recording its own
	// work. An adapter that wrote a HOST-influencing key (grafana's instance,
	// datadog's site) would therefore move the entry's destination from inside
	// the rotation it was asked to perform, with nobody's permission.
	// TestProviderRequestsStayInsideTheirDeclaredHosts detects that in the suite;
	// this refuses it in production.
	//
	// The oracle is deliberately absent, which egressgate reads as deny: there is
	// no principal on this path. A rotation is triggered by the scheduler or by a
	// caller who has already been authorized to rotate, and neither of those is
	// "and may also repoint this secret". So the only write allowed here is one
	// that adds nothing.
	beforeMeta := map[string]string{}
	if row, rErr := deps.queries.GetVaultEntryMeta(ctx, entryID); rErr != nil {
		slog.Error("vault rotation: could not read the stored provider_meta to check the write-back",
			"entry", entryName, "error", rErr)
		return revokeWarn
	} else {
		beforeMeta = ParseProviderMeta(deps.vault.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"))
	}
	tk, tkErr := egressgate.Decide(egressgate.Request{
		EntryID: entryID,
		What:    egressFieldProviderMeta,
		Before:  providerDestinations(provider, beforeMeta),
		After:   providerDestinations(provider, providerMeta),
		Covers:  providerDestinationCovers,
	})
	if tkErr != nil {
		slog.Error("vault rotation: refusing to persist a provider_meta write-back that moves the "+
			"entry's reachable hosts", "entry", entryName, "provider", provider, "error", tkErr)
		return revokeWarn
	}

	if metaJSON, mErr := json.Marshal(providerMeta); mErr != nil {
		slog.Error("vault rotation: marshal provider_meta failed", "entry", entryName, "error", mErr)
	} else if encMeta, encErr := deps.vault.encryptColumn(string(metaJSON)); encErr != nil {
		slog.Error("vault rotation: encrypt provider_meta failed", "entry", entryName, "error", encErr)
	} else if pErr := setEntryProviderMeta(ctx, deps.queries, tk, db.UpdateVaultEntryProviderMetaParams{
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

	// Honour a "Notify only" target. It transmits nothing, so the delivery loop
	// rightly skips it, and its comment claimed the caller handled the notification.
	// No caller did, and there was no success event to fire even if one had wanted to,
	// so an operator who configured "tell me, I will update the consumer myself" was
	// told nothing while the credential rotated and the predecessor was revoked.
	//
	// Only on a clean success: a partial or failed rotation already alarms above, and
	// firing both would tell the operator it worked and did not work.
	if status == "success" && hasNotifyTarget(rec.Targets) {
		dispatchRotationSuccess(ctx, deps.queries, deps.vault, rec.EntryName,
			"rotated successfully; update any consumer you manage yourself")
	}

	if err := deps.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString(errSummary),
		ID:                rec.EntryID,
	}); err != nil {
		slog.Error("vault rotation: persist last_rotation_error failed", "entry", rec.EntryName, "error", err)
	}
	// Appended under a compare-and-swap, NOT from rec.RotationLog. That snapshot can
	// be 90s stale on the sweep, which used to erase a concurrent manual rotation's
	// history entry and stamp this pass's conflict error over a rotation that had
	// actually succeeded. See appendRotationLog.
	appendRotationLog(ctx, deps, rec.EntryID, rec.EntryName, RotationLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    status,
		Provider:  rec.Provider,
		Error:     errSummary,
		Method:    rec.Method,
	})
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

// ablationTakesPool exists only so the tx-scope ablation can pass the pool to a
// helper the way seedCapabilityDefaults did. Not called in production.
func ablationTakesPool(_ context.Context, _ *db.Queries) error { return nil }

// undeliverableMsg is what a rotation records when its delivery configuration
// could not be read. Static, like revokeStillLiveMsg, so nothing derived from a
// decrypt error reaches an API-visible column.
const undeliverableMsg = "rotated but NOT delivered: rotation_targets could not be read; see server logs"

// recordRotationOutcomeUndeliverable finalises a rotation whose target list was
// unreadable.
//
// The value is committed and the predecessor key is already destroyed upstream, so
// this is a PARTIAL rotation rather than a failure to rotate, and it must be loud:
// every configured consumer still holds a credential that no longer works, and the
// previous behaviour recorded it as a clean success with no alert because an
// undecryptable column degraded to "no targets configured".
//
// Deliberately not folded into recordRotationOutcome: that function's contract is
// "deliver, then record what delivery did", and here delivery cannot be attempted
// at all. Sharing it would mean passing a flag that means "skip the first half",
// which is how the two rotation paths drifted in the first place.
func recordRotationOutcomeUndeliverable(ctx context.Context, deps rotationDeps, rec rotationRecord) {
	slog.Error("vault rotation: target list unreadable, the new key was delivered to nobody",
		"entry", rec.EntryName)
	dispatchRotationAlert(ctx, deps.queries, deps.vault, rec.EntryName, undeliverableMsg)

	if err := deps.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString(undeliverableMsg),
		ID:                rec.EntryID,
	}); err != nil {
		slog.Error("vault rotation: persist last_rotation_error failed", "entry", rec.EntryName, "error", err)
	}
	appendRotationLog(ctx, deps, rec.EntryID, rec.EntryName, RotationLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "partial",
		Provider:  rec.Provider,
		Error:     undeliverableMsg,
		Method:    rec.Method,
	})
}

// rotationLogCASAttempts bounds the retry. Contention here is two rotations of ONE
// entry overlapping, so the loop converges immediately in practice; the bound exists
// so a pathological case degrades to a logged miss rather than spinning.
const rotationLogCASAttempts = 4

// appendRotationLog adds one entry to an entry's rotation_log without losing a
// concurrent append.
//
// It re-reads the column inside the loop rather than trusting a caller-supplied
// snapshot, which is the actual defect: the sweep snapshots at pass start and can be
// 90s behind by the time it writes, so a user clicking Rotate mid-pass had their
// successful rotation erased from history and replaced by the sweep's conflict error,
// with an alert fired about a rotation that had in fact succeeded. The user saw a red
// error on the entry they had just correctly rotated.
//
// A failure to converge is logged and dropped rather than propagated: this is the
// audit trail for a rotation that has ALREADY committed, so refusing the caller
// would be worse than a missing history line. The value, last_rotation_error and the
// alert are all written elsewhere.
func appendRotationLog(ctx context.Context, deps rotationDeps, entryID, entryName string, entry RotationLogEntry) {
	for attempt := 0; attempt < rotationLogCASAttempts; attempt++ {
		current, err := deps.queries.GetVaultEntryRotationLog(ctx, entryID)
		if err != nil {
			slog.Error("vault rotation: read rotation_log failed", "entry", entryName, "error", err)
			return
		}
		res, err := deps.queries.CASVaultEntryRotationLog(ctx, db.CASVaultEntryRotationLogParams{
			RotationLog:   toNullString(AppendRotationLog(current, entry)),
			ID:            entryID,
			RotationLog_2: toNullString(current),
		})
		if err != nil {
			slog.Error("vault rotation: persist rotation_log failed", "entry", entryName, "error", err)
			return
		}
		n, err := res.RowsAffected()
		if err != nil {
			slog.Error("vault rotation: rotation_log rows affected", "entry", entryName, "error", err)
			return
		}
		if n > 0 {
			return
		}
		// Someone else appended between the read and the write. Re-read and redo the
		// append on top of THEIR entry rather than over it.
		slog.Info("vault rotation: rotation_log changed under us, retrying the append",
			"entry", entryName, "attempt", attempt+1)
	}
	slog.Error("vault rotation: gave up appending to rotation_log after concurrent writes",
		"entry", entryName, "attempts", rotationLogCASAttempts)
}

// dispatchRotationSuccess fires the notification a "Notify only" target asks for.
//
// A var, like the other two dispatchers, so the rotation matrix can observe it.
var dispatchRotationSuccess = dispatchRotationSuccessReal

func dispatchRotationSuccessReal(ctx context.Context, queries *db.Queries, decrypter alerts.ConfigDecrypter, entryName, detail string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("vault rotation: success notification panicked", "recover", r)
		}
	}()
	alerts.NewChannelDispatcher(ctx, queries, decrypter).Dispatch(
		alerts.EventRotationSucceeded, "", "",
		map[string]string{"secret": entryName, "detail": detail},
	)
}

// hasNotifyTarget reports whether the entry asked to be told about a rotation.
//
// "notify" is skipped by the delivery loop (it transmits nothing, so there is nothing
// to deliver) and the loop's comment said notification "is handled separately by the
// caller". No caller handled it, and the alerts catalogue had no success event at all,
// so the one target type whose entire purpose is notification never notified anybody.
func hasNotifyTarget(targets []RotationTarget) bool {
	for _, t := range targets {
		if t.Type == "notify" {
			return true
		}
	}
	return false
}

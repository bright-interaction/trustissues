package handlers

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
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

// retryOutstandingRevoke consumes a pending revoke left by an EARLIER
// rotation, before this rotation's mint overwrites its coordinates.
//
// THIS IS THE CONSUMER THAT MAKES PRESERVING THE COORDINATES WORTH ANYTHING.
//
// Preserving them on a failed revoke is only useful if something later acts on
// them, and the only thing that reads them is performPendingRevoke, which runs
// AFTER the mint. deferRevokeOldProviderKey overwrites the marker set (four keys now, and pending_revoke_key_id is deleted rather than skipped when it cannot be recorded, so no stale half survives a re-defer)
// during that mint, so a stranded key's coordinates were destroyed one rotation
// later without ever being retried: the exact outcome the deferral exists to
// prevent, delayed by a cycle rather than avoided.
//
// Retrying first also removes the other half of it. A marker that survived
// because THIS rotation did not defer (every call site is guarded by
// oldID != "" && oldID != newID) would otherwise still be sitting in the map
// when performPendingRevoke runs post-mint, firing a previous rotation's
// coordinates with a freshly minted secret and, if the provider has changed
// since, sticking the entry in permanent partial-rotation behind an egress
// refusal.
//
// Authenticating with the entry's CURRENT value is correct: the pending revoke
// targets a key older than that value, and the current one is live by
// definition. It is the same claim performPendingRevoke already makes post-mint,
// made one step earlier.
//
// It never fails the rotation. A failed retry leaves the markers in place (see
// performPendingRevoke) and returns a warning, so the caller can tell the
// operator that an older key is still live upstream and is about to lose its
// retry record, instead of that record vanishing in silence.
//
// FORMERLY "KNOWN COVERAGE HOLE: THIS ONLY RUNS WHEN A ROTATION RUNS."
//
// That hole is now closed on the operator-visible side. There is a THIRD
// caller: VaultHandler.RetryPendingRevoke, behind POST
// /api/vault/{id}/pending-revoke/retry (vault_pending_revoke.go). It calls this
// function verbatim, with the entry's current value, exactly like the two
// rotation paths do, so the three callers share one behaviour rather than the
// endpoint re-deriving it. An operator looking at an on-demand entry
// (auto_rotate = 0) that the scheduled sweep will never touch again can now
// make it retry the stranded revoke without triggering a whole rotation, which
// is the affordance this comment used to say was the smaller, more honest fix.
//
// THE RESIDUAL, STATED HONESTLY: NOBODY IS NOTIFIED.
//
// Closing "never retried" is not the same as closing "never surfaced". The new
// endpoint is pull, not push: pendingRevokeStatusFrom puts outstanding: true on
// the entry's own GET/list response, so the fact is visible the moment an
// operator is already looking at that entry, but nothing scans the table, fires
// an alert, or badges a list view to tell them to go look. An on-demand entry
// with a stranded key that nobody happens to open still alerts no one, for as
// long as nobody opens it. Closing that residual needs the other half this
// comment originally named: a background reconciler (or a scheduled digest)
// over rows carrying pending_revoke_url, which remains unbuilt.
func retryOutstandingRevoke(ctx context.Context, meta map[string]string,
	entryName, provider string, current secretexit.Plaintext) string {

	if meta == nil || meta[pendingRevokeURL] == "" {
		return ""
	}
	// Cleared so the outcome read below is THIS attempt's and not a stale flag
	// from the rotation that recorded the markers.
	delete(meta, "last_revoke_error")

	performPendingRevoke(ctx, meta, provider, current)

	warn := meta["last_revoke_error"]
	delete(meta, "last_revoke_error")
	if warn != "" {
		slog.Error("vault rotation: an earlier failed revoke could not be retried; the predecessor "+
			"key is still live upstream and this rotation is about to overwrite its retry record",
			"entry", entryName, "provider", provider, "detail", warn)
		return "an earlier key could not be revoked on retry: " + warn
	}
	slog.Info("vault rotation: an earlier failed revoke succeeded on retry",
		"entry", entryName, "provider", provider)
	return ""
}

// revokeOldKeyAndPersistMeta destroys the predecessor key upstream and then writes
// provider_meta exactly ONCE. It returns TWO warnings, both for the caller to pass
// to recordRotationOutcome: the revoke warning, and the provider_meta write-back
// warning. They are independent -- either, neither or both can be set -- and they
// describe different damage, so neither may be collapsed into the other.
//
// Order matters and is the whole point of the function. The manual path used to
// write meta first and clean up afterwards, so the markers reached the column on
// the success path too.
//
// performPendingRevoke clears the pending_revoke_* markers ONLY on a confirmed
// success. On failure it deliberately leaves them, because they are the only
// record of what to revoke and how, so this function persists them; see
// reservedProviderMetaKeys for the surfaces that had to move when that stopped
// being impossible.
//
// Call only after the value is durably stored: revoking earlier means a failure in
// the encrypt/persist window leaves the old credential dead upstream and the new
// one discarded, with no copy of either anywhere.
func revokeOldKeyAndPersistMeta(ctx context.Context, deps rotationDeps, entryID, entryName, provider string, providerMeta map[string]string, newValue secretexit.Plaintext) (string, string) {
	if providerMeta == nil {
		return "", ""
	}
	performPendingRevoke(ctx, providerMeta, provider, newValue)
	revokeWarn := providerMeta["last_revoke_error"]
	delete(providerMeta, "last_revoke_error")
	if revokeWarn != "" {
		slog.Error("vault rotation: old key revoke failed (predecessor still live)",
			"entry", entryName, "detail", revokeWarn)
	}

	// The write-back half is shared with the pending-revoke retry endpoint; see
	// persistProviderMetaAfterRevoke.
	//
	// ITS ERROR IS A SECOND, INDEPENDENT OUTCOME, NOT A DETAIL OF THE REVOKE.
	//
	// This used to be a bare `_ =`, justified by "it already logs its own failure
	// cause, so there is nothing further to do with the error here". That is true
	// of OBSERVABILITY and false of CORRECTNESS, and the two were conflated. A
	// slog line is not a durable record: last_rotation_error, rotation_log and the
	// alert are, and all three said the rotation was clean.
	//
	// What is actually lost. providerMeta is the PASS-START map this rotation has
	// been mutating; by this point meta["key_id"] (or its per-provider twin) has
	// already advanced to the key the mint just created. If the write-back does
	// not land, the column keeps the PREDECESSOR's id while encrypted_value holds
	// the SUCCESSOR's secret. For any provider whose id is merely bookkeeping that
	// strands the predecessor: the next rotation revokes a dead id and the live
	// key is never named again. For backblaze and twilio it is worse, because the
	// id is half the credential -- backblazeAuthorize sends
	// base64(meta["key_id"] + ":" + value) -- so the stored pair is a mismatched
	// id/secret that authenticates as nobody. The entry is dead on arrival and,
	// before this, reported status success with last_rotation_error NULL.
	//
	// Deliberately a SEPARATE return value rather than folded into revokeWarn.
	// foldRevokeOutcome renders revokeWarn as revokeStillLiveMsgFor(), i.e. "old
	// key not revoked (still live at provider)", and on the common shape of this
	// failure the revoke SUCCEEDED -- the predecessor really is dead. Reusing that
	// channel would trade a silent falsehood for a loud one, which is the exact
	// class of defect the rest of this file exists to undo.
	//
	// The "provider changed under us" branch returns nil, not an error: writing
	// nothing is the CORRECT outcome there, and it must stay a clean success.
	metaWarn := ""
	if pErr := persistProviderMetaAfterRevoke(ctx, deps, entryID, entryName, provider, providerMeta); pErr != nil {
		metaWarn = metaWriteBackFailedMsg
		if errors.Is(pErr, errProviderChangedMidRotation) {
			metaWarn = providerChangedMidRotationMsg
		}
	}
	return revokeWarn, metaWarn
}

// persistProviderMetaAfterRevoke is the write-back half of
// revokeOldKeyAndPersistMeta, pulled out so the pending-revoke retry endpoint
// (VaultHandler.RetryPendingRevoke, and its terminal sibling
// ResolvePendingRevoke) can persist the SAME way a rotation does, rather than a
// second hand-rolled copy of a host-choosing write drifting from this one.
//
// Persists the key id a revoke or a rotation's mint just recorded, so the NEXT
// attempt targets the current predecessor instead of a stale one. Errors are
// logged, never silently discarded: losing this write means the next revoke
// targets a dead id and the real predecessor leaks.
//
// THE WRITE-BACK IS ALSO A HOST-CHOOSING WRITE, and nobody authorizes it.
//
// providerMeta came back out of a provider adapter, or out of the caller's own
// edits to it (a retry deleting the pending_revoke_* markers). Twilio writes
// key_sid, backblaze writes key_id, and the whole map is then persisted with no
// authorization check anywhere, because it is the server recording its own
// work. An adapter that wrote a HOST-influencing key (grafana's instance,
// datadog's site) would therefore move the entry's destination from inside an
// operation nobody asked to also repoint the secret.
// TestProviderRequestsStayInsideTheirDeclaredHosts detects that in the suite;
// this refuses it in production.
//
// The oracle is deliberately absent, which egressgate reads as deny: there is
// no principal on this path. A rotation is triggered by the scheduler or by a
// caller who has already been authorized to rotate; a retry is triggered by a
// caller already authorized to spend and write the entry (see
// VaultHandler.RetryPendingRevoke). Neither of those is "and may also repoint
// this secret". So the only write allowed here is one that adds nothing.
func persistProviderMetaAfterRevoke(ctx context.Context, deps rotationDeps, entryID, entryName, provider string, providerMeta map[string]string) error {
	beforeMeta := map[string]string{}
	row, rErr := deps.queries.GetVaultEntryMeta(ctx, entryID)
	if rErr != nil {
		slog.Error("vault rotation: could not read the stored provider_meta to check the write-back",
			"entry", entryName, "error", rErr)
		return rErr
	}
	// THE PROVIDER MOVED UNDER US: WRITE NOTHING.
	//
	// providerMeta describes the provider this pass started against. A
	// concurrent PUT can change the entry's provider during the mint-then-write
	// window -- which is a real window, it spans a network round trip to the
	// upstream -- and reconcileProviderMetaForStorage deliberately strips the
	// pending-revoke markers when that happens. Writing this map back then
	// resurrects markers naming a predecessor at a provider the entry no longer
	// targets, and pendingRevokeStatusFrom never cross-checks the provider
	// column, so they read back as a live stranded key and falsify the
	// vault.pending_revoke_discarded activity row the provider change wrote.
	// Nothing here is salvageable once the configuration it describes is gone.
	//
	// WRITING NOTHING IS CORRECT. REPORTING NOTHING IS NOT, AND IT USED TO DO BOTH.
	//
	// This branch returned a bare nil, which the caller could not distinguish from
	// "the write-back landed". The rotation therefore folded to status success with
	// last_rotation_error NULL and no alert -- while meta["key_id"] in the column
	// still named the PREDECESSOR and encrypted_value already held the SUCCESSOR's
	// secret. For backblaze and twilio the id is half the credential
	// (backblazeAuthorize sends base64(meta["key_id"] + ":" + value)), so the stored
	// pair authenticates as nobody: measured, the stored pair 401s where the correct
	// pair 200s. The predecessor is also already destroyed upstream by this point.
	//
	// The entry is incoherent either way -- it now names a provider the committed
	// value was never minted at -- and that is precisely why it cannot be recorded
	// as clean. The sentinel travels up so the caller can say so in the durable
	// record, without this function acquiring an opinion about rotation status.
	if row.Provider.String != provider {
		slog.Warn("vault rotation: the entry's provider changed during this rotation, so the "+
			"provider_meta write-back was skipped rather than restoring the previous provider's state",
			"entry", entryName, "rotated_as", provider, "now", row.Provider.String)
		return errProviderChangedMidRotation
	}

	beforeRaw := deps.vault.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)
	beforeMeta = ParseProviderMeta(beforeRaw)

	// MERGE ONTO WHAT IS STORED NOW; DO NOT REPLACE IT.
	//
	// providerMeta is a PASS-START snapshot that this rotation has been mutating
	// in memory, and the value CAS upstream guards only encrypted_value -- by
	// design, because comparing updated_at made unrelated writes fail a rotation
	// that had already minted. So a metadata-only edit by the operator neither
	// blocks this write nor appears in this map, and treating the map as the
	// target state deletes it: measured, an operator key added mid-rotation
	// vanished and the rotation still reported success.
	//
	// A rotation only ever ADDS or UPDATES ordinary keys (key_id and its
	// per-provider twins) and CLEARS its own server-owned ones. So take the
	// stored row as the base, let this pass's values win where it has an
	// opinion, and honour a deletion only for the reserved keys it owns.
	// Anything the operator wrote that this pass never knew about survives.
	next := make(map[string]string, len(beforeMeta)+len(providerMeta))
	for k, v := range beforeMeta {
		next[k] = v
	}
	for k, v := range providerMeta {
		next[k] = v
	}
	for _, k := range reservedProviderMetaKeys {
		if _, stillSet := providerMeta[k]; !stillSet {
			delete(next, k)
		}
	}

	// Decided on what is actually about to be written, not on the pass-start map.
	tk, tkErr := egressgate.Decide(egressgate.Request{
		EntryID: entryID,
		What:    egressFieldProviderMeta,
		Before:  providerDestinations(provider, beforeMeta),
		After:   providerDestinations(provider, next),
		Covers:  providerDestinationCovers,
	})
	if tkErr != nil {
		slog.Error("vault rotation: refusing to persist a provider_meta write-back that moves the "+
			"entry's reachable hosts", "entry", entryName, "provider", provider, "error", tkErr)
		return tkErr
	}

	// FROM THE RAW STORED COLUMN, NOT FROM THE map[string]string.
	//
	// provider_meta is operator-authored JSON and its values are not all
	// strings: a port is a number, a scope list is an array. json.Unmarshal
	// into a map[string]string does not DROP a non-string value, it records a
	// type error, discards it, and leaves the key present holding "" -- so
	// marshalling the map back writes {"port":""} over a stored {"port":8080},
	// with a 200 and no diagnostic, permanently.
	//
	// This is the third site in this column to need the fix and the second to
	// be found only after shipping the first: providerMetaBytesPreservingTypes
	// was extracted for casEditProviderMeta in the very change that left this
	// twin -- its own sibling, split out of revokeOldKeyAndPersistMeta in the
	// same pass -- still on the plain marshal. Whoever adds a fourth writer:
	// take the values from the stored bytes and only the KEY changes from your
	// map, the way this does.
	metaJSON, mErr := providerMetaBytesPreservingTypes(beforeRaw, beforeMeta, next)
	if mErr != nil {
		slog.Error("vault rotation: marshal provider_meta failed", "entry", entryName, "error", mErr)
		return mErr
	}
	encMeta, encErr := deps.vault.encryptColumn(string(metaJSON))
	if encErr != nil {
		slog.Error("vault rotation: encrypt provider_meta failed", "entry", entryName, "error", encErr)
		return encErr
	}
	if pErr := vaultegress.SetProviderMeta(ctx, deps.queries, tk, vaultegress.ProviderMetaParams{
		ProviderMeta: toNullString(encMeta),
		ID:           entryID,
	}); pErr != nil {
		slog.Error("vault rotation: persist provider_meta failed", "entry", entryName, "error", pErr)
		return pErr
	}
	return nil
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
	// OldValue and NewValue are the entry's secret, so they are opaque: neither
	// can be read, logged or transmitted except through secretexit.Exit.
	OldValue secretexit.Plaintext
	NewValue secretexit.Plaintext
	// RevokeWarn is the FIRST warning revokeOldKeyAndPersistMeta returned.
	RevokeWarn string
	// MetaWriteWarn is its SECOND: the provider_meta write-back did not land, so
	// the stored key id no longer describes the credential that is live at the
	// provider. Empty on the "provider changed under us" branch, which writes
	// nothing on purpose and is a clean outcome.
	MetaWriteWarn string
	// RevokeKeyIDs are the keys this row still says are live at the provider,
	// read off provider_meta AFTER the revoke attempt (outstandingRevokeKeyIDs):
	// the head marker's predecessor plus every entry on the stranded backlog.
	//
	// It is what gives the alarm a subject. Sourcing it from the MAP rather than
	// from the warning text is the point: the warnings are prose assembled by
	// combineRevokeWarnings out of two different failures, while the map is the
	// authoritative answer to "which keys did we fail to kill". An empty slice
	// degrades the alarm to the bare const, which is the pre-change behaviour.
	RevokeKeyIDs []string
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

	status, errSummary, revokeAlert := foldRevokeOutcome(status, errSummary, rec.RevokeWarn, rec.RevokeKeyIDs)
	if revokeAlert {
		// The alert body names the keys too, from the same bounded renderer, so
		// the email and the column agree. It was the bare const, which meant an
		// operator holding two alerts about two different stranded keys could not
		// tell them apart.
		dispatchRotationAlert(ctx, deps.queries, deps.vault, rec.EntryName, revokeStillLiveMsgFor(rec.RevokeKeyIDs))
	}

	// Folded AFTER the revoke and BEFORE the notify-target success dispatch, so a
	// rotation whose write-back failed can never reach the "rotated successfully"
	// notification below.
	status, errSummary, metaAlert := foldMetaWriteOutcome(status, errSummary, rec.MetaWriteWarn)
	if metaAlert {
		// The warning itself, not a const chosen here: MetaWriteWarn is already one
		// of the two static strings, and picking a fixed one would make the alert
		// contradict the column on the branch that did not choose it.
		dispatchRotationAlert(ctx, deps.queries, deps.vault, rec.EntryName, rec.MetaWriteWarn)
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
	appendRotationLog(ctx, deps.queries, rec.EntryID, rec.EntryName, RotationLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    status,
		Provider:  rec.Provider,
		Error:     errSummary,
		Method:    rec.Method,
	})
	return status, errSummary
}

// revokeStillLiveMsg is the STEM of the only text either path may persist about
// a failed old-key revoke. Nothing writes it directly any more: everything goes
// through revokeStillLiveMsgFor, which appends the bounded key identity.
//
// Static on purpose, and that has NOT been relaxed. The raw revoke error can
// embed the provider URL and the upstream response body, and last_rotation_error
// is API-visible, so all of that still belongs in the slog line and nowhere else.
// What changed is narrower: the KEY ID is appended, and only an id that passes
// conservativeKeyIDPattern, which is the identical filter
// pendingRevokeStatusFrom already applies to the predecessor_key_id field every
// entry GET and list response hands the same readers. So the alarm discloses
// nothing that surface did not already disclose.
//
// It had to change. A single identity-free const standing for N still-live keys
// is not clearable: settling one of them cleared the alarm for all of them, and
// a CAS over the value could not tell "nobody wrote" from "somebody re-armed the
// same sentence about a different key". Those are the audit's P0-1 and P1-1, and
// they are one defect: an alarm that carries no identity cannot be cleared
// safely, and a CAS cannot discriminate what the value does not encode.
const revokeStillLiveMsg = "old key not revoked (still live at provider); see server logs"

// metaWriteBackFailedMsg is the only text either path may persist about a
// provider_meta write-back that did not land.
//
// Static, for the same reason revokeStillLiveMsg is: the underlying error can be
// a driver message, an egressgate refusal naming hosts, or a cipher error, and
// last_rotation_error is API-visible. The cause belongs in the slog line
// persistProviderMetaAfterRevoke already writes at each of its four failure
// branches. Unlike the revoke alarm this carries no key id: the whole failure is
// that we do not know which id the row now holds, so naming one would assert
// precisely the fact that is in doubt.
const metaWriteBackFailedMsg = "provider_meta write-back failed; the stored key id may not match the live credential; see server logs"

// errProviderChangedMidRotation marks the one write-back branch that is a
// DELIBERATE no-write rather than a failure. It still ends the rotation's claim
// to be clean; see the branch itself for why writing nothing is right and
// reporting nothing was not.
var errProviderChangedMidRotation = errors.New("provider changed mid-rotation; provider_meta not written")

// providerChangedMidRotationMsg is what that branch records. Distinct from
// metaWriteBackFailedMsg because the operator's next step differs: nothing is
// retryable here, the entry needs a human to decide whether the value it now
// holds belongs to the provider it now names.
//
// Static, like its siblings, and it names no provider: the entry's current and
// previous provider are exactly what is in dispute, and last_rotation_error is
// API-visible. Both are in the slog line above.
const providerChangedMidRotationMsg = "the entry's provider changed during this rotation; the rotated value was minted at the previous provider and its key id was not recorded; see server logs"

// foldMetaWriteOutcome merges "the provider_meta write-back did not land" into a
// rotation's final status, and reports whether an alert is owed.
//
// Separate from foldRevokeOutcome because the two facts are independent and a
// rotation can carry both. Same shape deliberately: a delivery failure is
// already partial or error and must not be promoted back up, and the summary
// appends rather than replaces so no earlier fact is overwritten.
func foldMetaWriteOutcome(status, errSummary, metaWarn string) (outStatus, outSummary string, alert bool) {
	if metaWarn == "" {
		return status, errSummary, false
	}
	if status == "success" {
		status = "partial"
	}
	if errSummary == "" {
		errSummary = metaWarn
	} else {
		errSummary = errSummary + "; " + metaWarn
	}
	return status, errSummary, true
}

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
// keyIDs names the keys the row still says are live, and is what stops this
// function collapsing N facts into one. It used to write the bare const whatever
// happened, so two stranded keys produced one alarm and settling either one
// cleared it for both -- with the older key's coordinates already overwritten,
// nothing in the product named it again. Empty keyIDs still renders the bare
// const, which is what a row with no nameable predecessor id gets.
func foldRevokeOutcome(status, errSummary, revokeWarn string, keyIDs []string) (outStatus, outSummary string, alert bool) {
	if revokeWarn == "" {
		return status, errSummary, false
	}
	// A delivery failure is already partial or error; do not promote it back up.
	if status == "success" {
		status = "partial"
	}
	msg := revokeStillLiveMsgFor(keyIDs)
	if errSummary == "" {
		errSummary = msg
	} else {
		errSummary = errSummary + "; " + msg
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

	// A write-back failure survives this path too. Both facts are true at once and
	// this function is the only writer of the column on it, so folding here is the
	// only way the second one is durable: the caller sets rec.RevokeWarn = "" before
	// calling (the predecessor really is dead) but MetaWriteWarn stays set, and an
	// undeliverable rotation whose key id is also wrong is strictly worse than one
	// whose id is right. Same static text, appended the same way foldMetaWriteOutcome
	// appends it, so the two paths render one fact identically.
	summary := undeliverableMsg
	if rec.MetaWriteWarn != "" {
		summary = summary + "; " + rec.MetaWriteWarn
		dispatchRotationAlert(ctx, deps.queries, deps.vault, rec.EntryName, rec.MetaWriteWarn)
	}

	if err := deps.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString(summary),
		ID:                rec.EntryID,
	}); err != nil {
		slog.Error("vault rotation: persist last_rotation_error failed", "entry", rec.EntryName, "error", err)
	}
	appendRotationLog(ctx, deps.queries, rec.EntryID, rec.EntryName, RotationLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "partial",
		Provider:  rec.Provider,
		Error:     summary,
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
//
// It takes *db.Queries rather than rotationDeps because it is the ONLY writer of
// rotation_log left, and three of its callers sit outside the rotation-core deps
// struct: the reminder branch of the scheduled sweep, the reminder branch of the
// manual handler, and recordRotationFailure. Those three used to call a plain
// UpdateVaultEntryRotationLog with a caller-supplied snapshot, which is the exact
// read-modify-write this function exists to prevent; the plain query has been
// deleted so the mistake is no longer expressible.
func appendRotationLog(ctx context.Context, queries *db.Queries, entryID, entryName string, entry RotationLogEntry) {
	for attempt := 0; attempt < rotationLogCASAttempts; attempt++ {
		current, err := queries.GetVaultEntryRotationLog(ctx, entryID)
		if err != nil {
			slog.Error("vault rotation: read rotation_log failed", "entry", entryName, "error", err)
			return
		}
		res, err := queries.CASVaultEntryRotationLog(ctx, db.CASVaultEntryRotationLogParams{
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

// combineRevokeWarnings merges this rotation's revoke warning with one left by
// retryOutstandingRevoke, keeping both.
//
// The two name DIFFERENT keys and both are true. Choosing between them, which
// is what an `if revokeWarn == "" ` fallback does, silently drops one, and it
// drops the wrong one: the retry's warning is about a key whose coordinates
// this rotation's mint has already overwritten, so it is the fact that is about
// to become unrecoverable. The rotation's own warning names a key that still has
// its coordinates on the row and will be retried again next time.
func combineRevokeWarnings(thisRotation, staleRetry string) string {
	switch {
	case thisRotation == "":
		return staleRetry
	case staleRetry == "":
		return thisRotation
	}
	return thisRotation + "; also: " + staleRetry
}

package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
)

// Structural failure reasons. These strings are the ONLY thing an operator sees
// for a failed rotation: they are persisted to last_rotation_error, appended to
// rotation_log, written into the activity detail, and sent to notification
// channels off-box. So they must describe the failure CLASS and never carry a
// value, an upstream body, a URL, or an err.Error(). The cause always goes to
// slog at the call site.
const (
	rotFailUnknownProvider = "rotation skipped: the configured provider is not registered in this build"
	// rotFailInternal is recorded when a rotation panics. The panic is contained
	// to the one entry (it used to kill the process), so the operator needs the
	// row to say something happened rather than the rotation looking untried.
	rotFailInternal = "rotation failed with an internal error (see server logs)"
	rotFailDecrypt  = "decrypt failed (details in server logs)"
	rotFailProvider = "provider rotation failed (details in server logs)"
	rotFailEncrypt  = "new value could not be encrypted; the provider may have already issued a replacement key (details in server logs)"
	// rotFailConflict's "will be retried" promise is only true for providers
	// whose revoke is DEFERRED past the CAS (see deferRevokeOldProviderKey): for
	// those, a lost write leaves both keys live and the next pass can safely
	// try again. It is never used for a provider in predecessorDestroysInPlace,
	// which is refused before minting instead (see rotFailDestroysInPlace) for
	// exactly the reason that a retry promise would be false for them: the old
	// value is already dead and a lost write has no copy anywhere to retry from.
	rotFailConflict = "the secret was changed during the rotation pass, so the new value was not written; the provider may have issued a replacement key, and the entry will be retried on the next pass"
	rotFailPersist  = "new value could not be saved; the provider may have already issued a replacement key (details in server logs)"
	// rotFailDestroysInPlace is recorded when a provider in
	// predecessorDestroysInPlace is skipped BEFORE any upstream call is made.
	// Nothing was minted and nothing was lost; this is a refusal, not a partial
	// rotation.
	rotFailDestroysInPlace = "rotation skipped: this provider replaces the credential in place with no separable revoke step, so a write conflict here could destroy it with no copy anywhere; rotate it in the provider's own dashboard, then edit this entry and paste the new value"
)

// recordRotationFailure is the single exit for every hard failure in the
// auto-rotation sweep.
//
// It exists because the sweep had six failure paths that each did something
// different: four wrote nothing at all (unknown provider, encrypt failure,
// persist failure, and the sweep-level query error), one wrote only
// last_rotation_error, and one wrote last_rotation_error plus rotation_log.
// None of them wrote an activity row and none dispatched a notification, so the
// alerts.EventRotationFailed event was defined, documented and default-enabled
// while being fired from nowhere. A rotation could fail forever and the only
// evidence was a line in the container log.
//
// Every path that gives up on an entry calls this, so a failure cannot be
// half-recorded again. It writes, in order:
//
//  1. last_rotation_error, which the vault list and RotationManager read
//  2. a rotation_log entry with Status "error", so history keeps the attempt
//  3. an activity_log row, so it lands on the Activity page
//  4. alerts.EventRotationFailed, so configured channels actually get told
//
// Every step is best-effort and independent: a failure to record must never
// abort the sweep or skip the remaining steps, because the whole point is that
// the operator finds out.
// method is "auto" for the scheduled sweep and "manual" for a user-triggered
// rotation; actorID is the acting user for the manual path and nil for the
// scheduler, which has none.
func recordRotationFailure(
	ctx context.Context,
	queries *db.Queries,
	decrypter alerts.ConfigDecrypter,
	entryID, entryName, providerName, existingLog, reason string,
	method string,
	actorID *string,
) {
	if err := queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: sql.NullString{String: reason, Valid: true},
		ID:                entryID,
	}); err != nil {
		slog.Error("vault rotation: persisting last_rotation_error failed", "entry", entryName, "error", err)
	}

	// existingLog is the CALLER's snapshot and is deliberately not appended to.
	// On the sweep it is taken at pass start and can be 90 seconds behind, so
	// writing it back erased a concurrent manual rotation's success entry and
	// replaced it with this failure. appendRotationLog re-reads under CAS.
	appendRotationLog(ctx, queries, entryID, entryName, RotationLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "error",
		Provider:  providerName,
		Error:     reason,
		Method:    method,
	})

	// A nil actorID (the scheduler) shows as system in the activity list. Only
	// the secret NAME appears here, never its value.
	kind := "Auto-rotation"
	if method == "manual" {
		kind = "Rotation"
	}
	LogActivity(queries, actorID, "vault.rotation_failed",
		fmt.Sprintf("%s failed for vault secret: %s (provider: %s) - %s", kind, entryName, providerName, reason))

	dispatchRotationFailure(ctx, queries, decrypter, entryID, entryName, reason)
}

// dispatchRotationFailure fires alerts.EventRotationFailed. It mirrors
// dispatchRotationAlert (which fires EventRotationPartial for a rotation that
// stored a value but did not fully reach its consumers); this one is for a
// rotation that did not happen at all.
//
// Best-effort by design: a no-op when no channel subscribes, and it never
// panics the sweep.
// A var for the same reason as dispatchRotationAlert: the rotation matrix asserts
// that an operator was actually notified, and there are TWO dispatchers (this one
// fires EventRotationFailed, the other EventRotationPartial). A recorder that
// swaps only one of them reports "nobody was told" for a path that did tell them.
var dispatchRotationFailure = dispatchRotationFailureReal

func dispatchRotationFailureReal(ctx context.Context, queries *db.Queries, decrypter alerts.ConfigDecrypter,
	entryID, entryName, detail string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("vault rotation: failure alert dispatch panicked", "recover", r)
		}
	}()
	if !entryAllowsExternalNotificationMetadata(ctx, queries, entryID) {
		slog.Info("vault rotation: external failure notification suppressed by fully-private policy",
			"entry_id", entryID)
		return
	}
	alerts.NewChannelDispatcher(ctx, queries, decrypter).DispatchGuarded(
		alerts.EventRotationFailed, "", "",
		map[string]string{"secret": entryName, "detail": detail},
		entryExternalNotificationDeliveryGuard(queries, entryID),
	)
}

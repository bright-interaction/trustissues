package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

// rotationCheckInterval is how often the background worker looks for entries
// due for auto-rotation. Entries carry day-granularity intervals, so hourly
// checks keep worst-case lateness negligible.
const rotationCheckInterval = 1 * time.Hour

// rotationInitialDelay is the pause before the first check after boot, so a
// restart picks up overdue entries quickly without racing startup.
const rotationInitialDelay = 1 * time.Minute

// RunScheduledRotations is the background auto-rotation worker. Call it from
// main.go as a goroutine after the vault handler is constructed:
//
//	go handlers.RunScheduledRotations(ctx, dbConn, queries, vaultHandler)
//
// where ctx is the server's shutdown context (the worker returns when it is
// cancelled). It runs a first check shortly after boot, then every hour.
func RunScheduledRotations(ctx context.Context, dbConn *sql.DB, queries *db.Queries, vaultHandler *VaultHandler) {
	slog.Info("vault rotation: scheduler started",
		"initial_delay", rotationInitialDelay.String(),
		"interval", rotationCheckInterval.String())

	select {
	case <-ctx.Done():
		return
	case <-time.After(rotationInitialDelay):
	}
	RotateVaultKeys(dbConn, queries, vaultHandler)

	ticker := time.NewTicker(rotationCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("vault rotation: scheduler stopped")
			return
		case <-ticker.C:
			RotateVaultKeys(dbConn, queries, vaultHandler)
		}
	}
}

// RotateVaultKeys checks for vault entries that need auto-rotation and rotates
// them. Called by RunScheduledRotations; exported so main.go or tests can
// trigger a single pass directly.
func RotateVaultKeys(dbConn *sql.DB, queries *db.Queries, vaultHandler *VaultHandler) {
	// ONE registration for the whole pass, not one per entry.
	//
	// Add(1)/Done() around each entry let the counter fall to zero between
	// entries. sync.WaitGroup panics with "WaitGroup misuse: Add called
	// concurrently with Wait" if an Add that takes the counter off zero races a
	// Wait that is already blocked, which is exactly what a SIGTERM landing
	// mid-sweep produces: the shutdown drain crashed the process instead of
	// draining it.
	vaultHandler.delivery.Add(1)
	defer vaultHandler.delivery.Done()

	// The LIST gets the pass budget; each ENTRY gets its own below.
	//
	// One shared 5-minute deadline for the whole pass meant a slow head of the
	// queue starved the tail: entries that were never attempted got recorded as
	// provider failures, and because the context was already dead their own
	// last_rotation_error and rotation_log writes silently failed too, so the UI
	// showed them clean while the alert text said they had failed.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	entries, err := queries.ListVaultEntriesNeedingRotation(ctx)
	if err != nil {
		// The whole pass is skipped, so no per-entry record is possible and
		// nothing else would ever mention it. Log it as an activity row so a
		// repeatedly broken scheduler is visible in the product rather than
		// only in the container log.
		slog.Error("vault rotation: query failed", "error", err)
		LogActivity(queries, nil, "vault.rotation_failed",
			"Auto-rotation pass skipped: could not list entries due for rotation (details in server logs)")
		dispatchRotationFailure(ctx, queries, vaultHandler, "",
			"auto-rotation pass skipped: could not list entries due for rotation (details in server logs)")
		return
	}

	if len(entries) == 0 {
		return
	}

	slog.Info("vault rotation: found entries needing rotation", "count", len(entries))

	for _, entry := range entries {
		// Contain a panic to THIS entry. The sweep runs on a background
		// goroutine with no recover above it, so any panic here took the whole
		// process down rather than failing one rotation: a crash loop in which
		// an upstream key may already have been minted but never persisted.
		// One malformed row must not be able to stop the server.
		rotateOneEntry(ctx, queries, vaultHandler, entry)
	}
}

func rotateOneEntry(passCtx context.Context, queries *db.Queries, vaultHandler *VaultHandler, entry db.ListVaultEntriesNeedingRotationRow) {
	// Detached from the pass budget and re-bounded per entry. Detaching is the
	// point: an entry late in the queue must still get a full attempt AND must
	// still be able to write its own failure record, which a dead pass context
	// silently prevented.
	ctx, cancelEntry := context.WithTimeout(context.WithoutCancel(passCtx), 90*time.Second)
	defer cancelEntry()

	// Opened ONCE, into the local copy, so the 28 places below that use the name
	// are all correct without each having to remember. entry is a value, so this
	// changes nothing in the database.
	//
	// It is not cosmetic. This name reaches an operator's activity log, the
	// rotation alert email, and the delivery payload a consuming service
	// receives, so leaving it as stored since 00040 would have shipped enc:v1:
	// blobs to all three and made every rotation record unreadable at exactly the
	// moment somebody needs to read it.
	entry.Name = vaultHandler.EntryNamePlain(entry.Name)

	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("vault rotation: panic while rotating an entry; the sweep continues",
				"entry", entry.Name, "recover", rec)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, entry.Provider.String,
				entry.RotationLog.String, rotFailInternal, "auto", nil)
		}
	}()
	{
		providerName := entry.Provider.String
		// Same classifier the manual handler uses, so the four provider states are
		// enumerated once and a fifth cannot be handled here and forgotten there.
		role, provider := classifyProvider(providerName)
		if role == providerUnknown {
			// An entry configured for a provider this build does not know will
			// never rotate. Silently skipping it meant the secret quietly went
			// stale forever.
			slog.Warn("vault rotation: unknown provider", "provider", providerName, "entry", entry.Name)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
				entry.RotationLog.String, rotFailUnknownProvider, "auto", nil)
			return
		}

		if role == providerReminder {
			// For reminder-only providers, just log that rotation is due
			slog.Info("vault rotation: rotation due (reminder-only provider)", "provider", providerName, "entry", entry.Name)
			// entry.RotationLog is the pass-start snapshot and can be 90s stale by
			// the time this reminder is written, so it is NOT the base to append
			// to. appendRotationLog re-reads and compare-and-swaps.
			appendRotationLog(ctx, queries, entry.ID, entry.Name, RotationLogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Status:    "reminder",
				Provider:  providerName,
				Method:    "auto",
			})
			return
		}

		// A provider that destroys its predecessor IN PLACE (see
		// predecessorDestroysInPlace) has no recoverable CAS-conflict path yet: a
		// write lost to persistRotatedValue after such a mint is a credential that
		// exists nowhere, not the "both keys live, retry" case rotFailConflict
		// promises. Refuse BEFORE calling provider.Rotate, so nothing is ever
		// minted that this pass could then lose.
		if role == providerAuto && predecessorDestroysInPlace[providerName] {
			slog.Warn("vault rotation: refusing to auto-rotate a provider that destroys its "+
				"predecessor in place; no CAS-safe recovery exists yet",
				"provider", providerName, "entry", entry.Name)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
				entry.RotationLog.String, rotFailDestroysInPlace, "auto", nil)
			return
		}

		// Decrypt current value. It comes back opaque: the sweep runs with nobody
		// watching, so it is the path where a value held as a bare string is
		// hardest to notice going somewhere it should not.
		plaintext, err := vaultHandler.OpenEntrySecret(entry.EncryptedValue, entry.Nonce,
			int(entry.EncryptionVersion.Int64), entryOrigin(entry.ID, entry.Name))
		if err != nil {
			slog.Error("vault rotation: decrypt failed", "entry", entry.Name, "error", err)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
				entry.RotationLog.String, rotFailDecrypt, "auto", nil)
			return
		}

		meta := ParseProviderMeta(vaultHandler.decryptColumnOrLog(entry.ProviderMeta.String, "{}", vaultFieldProviderMeta))
		// The egress authority for this entry's rotation. This is the path the
		// round-4 report walked: an editor sets provider + provider_meta +
		// auto_rotate through PUT /api/vault/{id} with no password, and the
		// SCHEDULER, running with nobody watching, carries the operator's
		// decrypted key to the host they named. The write is refused now (see
		// VaultHandler.Update), and this refuses to deliver a row that got
		// written some other way. See egress_authority.go.
		rotateCtx, oldPlain, egressErr := spendProviderSecret(ctx, queries, plaintext,
			entry.ID, providerName, meta)
		if egressErr != nil {
			plaintext.Wipe()
			slog.Error("vault rotation: refusing to rotate through this provider configuration; "+
				"the secret was not sent anywhere",
				"entry", entry.Name, "provider", providerName, "error", egressErr)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
				entry.RotationLog.String, rotFailProvider, "auto", nil)
			return
		}
		oldValueCopy := plaintext // carried to delivery still opaque

		// Consume any revoke left outstanding by an earlier rotation BEFORE
		// Rotate overwrites its coordinates. See retryOutstandingRevokeBeforeMint.
		staleRevokeWarn := retryOutstandingRevokeBeforeMint(rotateCtx, meta, entry.Name, providerName, plaintext)

		rotated, err := provider.Rotate(rotateCtx, oldPlain, meta)
		newValue := vaultHandler.MintedEntrySecret([]byte(rotated), entry.ID, entry.Name)

		if err != nil {
			// Do NOT persist err.Error() here: a provider Rotate error can embed the
			// raw upstream HTTP response body (tokens/secrets/internal topology), so
			// only the structural reason is recorded; the full error is in the slog
			// line. upstreamHTTPError keeps the body slog-only for exactly this.
			slog.Error("vault rotation: provider rotation failed", "provider", providerName, "entry", entry.Name, "error", err)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
				entry.RotationLog.String, rotFailProvider, "auto", nil)
			return
		}

		// NOTE: the old key is NOT revoked yet. Rotate only recorded a pending
		// revoke; it runs after the new value is durably stored, below. Revoking
		// first meant a failure in the encrypt/persist window left the old
		// credential dead upstream and the new one discarded, with no copy of
		// either. See deferRevokeOldProviderKey.

		// Encrypt the new value
		encrypted, nonce, err := vaultHandler.encryptEntrySecret(newValue)
		if err != nil {
			// The provider has ALREADY issued a replacement key upstream and we
			// are about to throw it away. The old value stays in the vault, so
			// the two are now out of sync and an operator has to reconcile at
			// the provider. This must be loud.
			slog.Error("vault rotation: encrypt failed", "entry", entry.Name, "error", err)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
				entry.RotationLog.String, rotFailEncrypt, "auto", nil)
			return
		}

		// Update the entry with new encrypted value
		// Compare-and-swap on the snapshot's updated_at. The sweep read this row
		// at pass start and may be writing back minutes later, so without the
		// predicate a value the user saved in between is silently overwritten by
		// the stale one.
		applied, casErr := persistRotatedValue(ctx, queries,
			snapshotFromRotationRow(entry.ID, entry.UpdatedAtText, entry.EncryptedValue), encrypted, nonce)
		if casErr == nil {
			if !applied {
				// Someone changed or deleted the entry during the pass. The
				// provider has already minted a replacement, so say so plainly
				// rather than pretending the rotation succeeded; the next pass
				// picks the entry up again if it is still due.
				slog.Warn("vault rotation: entry changed during the pass, skipping the write-back",
					"entry", entry.Name)
				recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
					entry.RotationLog.String, rotFailConflict, "auto", nil)
				return
			}
		}
		err = casErr
		if err != nil {
			// Same hazard as the encrypt failure above: the replacement key
			// exists at the provider but the vault still holds the old value.
			slog.Error("vault rotation: update failed", "entry", entry.Name, "error", err)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
				entry.RotationLog.String, rotFailPersist, "auto", nil)
			return
		}

		// Everything from here is shared with the manual handler; see
		// vault_rotation_core.go. This path used to hold its own copy of it, which is
		// how the two drifted on five separate behaviours.
		deps := rotationDeps{queries: queries, vault: vaultHandler}
		revokeWarn := revokeOldKeyAndPersistMeta(rotateCtx, deps, entry.ID, entry.Name, providerName, meta, newValue)
		// A predecessor that could not be revoked on retry is still live
		// upstream, so it belongs in the rotation's own outcome rather than
		// only in a log line. This rotation's revoke warning wins when both
		// fired, because it names the key that was just replaced.
		if revokeWarn == "" {
			revokeWarn = staleRevokeWarn
		}

		// Same distinction the manual path makes: an undecryptable target list is
		// not "no targets". Degrading to "[]" recorded a clean success while every
		// configured consumer kept a credential that had just been revoked.
		targetsRaw := "[]"
		targetsUnreadable := false
		if stored := entry.RotationTargets.String; stored != "" {
			if plain, tErr := vaultHandler.decryptColumn(stored, vaultFieldRotationTargets); tErr != nil {
				targetsUnreadable = true
				slog.Error("vault rotation: rotation_targets did not decrypt; the new key cannot be delivered",
					"entry", entry.Name, "error", tErr)
			} else {
				targetsRaw = plain
			}
		}
		targets := ParseRotationTargets(targetsRaw)
		if targetsUnreadable {
			recordRotationOutcomeUndeliverable(ctx, deps, rotationRecord{
				EntryID: entry.ID, EntryName: entry.Name, Provider: providerName,
				Method: "auto", UserID: entry.UserID, RotationLog: entry.RotationLog.String,
			})
			LogActivity(queries, nil, "vault.auto_rotate", fmt.Sprintf(
				"Auto-rotated vault secret but NOT delivered: %s (provider: %s, rotation_targets unreadable)",
				vaultHandler.sealSecretName(ctx, entry.Name), providerName))
			return
		}
		status, _ := recordRotationOutcome(ctx, deps, rotationRecord{
			EntryID:     entry.ID,
			EntryName:   entry.Name,
			Provider:    providerName,
			Method:      "auto",
			UserID:      entry.UserID,
			RotationLog: entry.RotationLog.String,
			Targets:     targets,
			OldValue:    oldValueCopy,
			NewValue:    newValue,
			RevokeWarn:  revokeWarn,
		})

		// Per-path by design: the sweep has no request to attribute the activity to.
		LogActivity(queries, nil, "vault.auto_rotate", fmt.Sprintf("Auto-rotated vault secret: %s (provider: %s, targets: %d, status: %s)", vaultHandler.sealSecretName(ctx, entry.Name), providerName, len(targets), status))
		slog.Info("vault rotation: rotated", "provider", providerName, "entry", entry.Name, "status", status)
	}
}

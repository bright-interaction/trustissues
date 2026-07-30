package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
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
			logEntry := RotationLogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Status:    "reminder",
				Provider:  providerName,
				Method:    "auto",
			}
			updatedLog := AppendRotationLog(entry.RotationLog.String, logEntry)
			_ = queries.UpdateVaultEntryRotationLog(ctx, db.UpdateVaultEntryRotationLogParams{
				RotationLog: sql.NullString{String: updatedLog, Valid: true},
				ID:          entry.ID,
			})
			return
		}

		// Decrypt current value
		plaintext, err := vaultHandler.DecryptValue(entry.EncryptedValue, entry.Nonce, int(entry.EncryptionVersion.Int64))
		if err != nil {
			slog.Error("vault rotation: decrypt failed", "entry", entry.Name, "error", err)
			recordRotationFailure(ctx, queries, vaultHandler, entry.ID, entry.Name, providerName,
				entry.RotationLog.String, rotFailDecrypt, "auto", nil)
			return
		}

		meta := ParseProviderMeta(vaultHandler.decryptColumnOrLog(entry.ProviderMeta.String, "{}", "provider_meta"))
		oldValueCopy := string(plaintext) // captured for delivery, zeroed in plaintext below
		newValue, err := provider.Rotate(ctx, string(plaintext), meta)

		// Zero plaintext immediately
		for i := range plaintext {
			plaintext[i] = 0
		}

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
		encrypted, nonce, err := vaultHandler.EncryptValue([]byte(newValue))
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
			snapshotFromRotationRow(entry.ID, entry.UpdatedAtText), encrypted, nonce)
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

		// The new value is now durably stored, so it is finally safe to destroy the
		// old key upstream. A failure here leaves BOTH keys live, which is
		// recoverable and is reported as a partial rotation below.
		performPendingRevoke(ctx, meta, newValue)
		revokeWarn := meta["last_revoke_error"]
		delete(meta, "last_revoke_error")

		// Persist the meta Rotate mutated (new key id) so the NEXT rotation revokes
		// the key we just minted instead of a stale predecessor id. Meta-only update
		// preserves provider + auto_rotate. Best-effort: a failure here only means
		// the next rotation may leave one extra key live, not a broken rotation.
		if metaJSON, mErr := json.Marshal(meta); mErr == nil {
			encMeta, encErr := vaultHandler.encryptColumn(string(metaJSON))
			if encErr != nil {
				slog.Error("vault rotation: encrypt provider_meta failed", "entry", entry.Name, "error", encErr)
			} else if pErr := queries.UpdateVaultEntryProviderMeta(ctx, db.UpdateVaultEntryProviderMetaParams{
				ProviderMeta: sql.NullString{String: encMeta, Valid: true},
				ID:           entry.ID,
			}); pErr != nil {
				slog.Error("vault rotation: persist provider_meta failed", "entry", entry.Name, "error", pErr)
			}
		}

		// Deliver the new key to configured targets BEFORE recording the
		// outcome, so the rotation status reflects delivery truth. A target
		// that fails to apply makes the rotation "partial" (visible + alarmed)
		// instead of being silently logged as success.
		targets := ParseRotationTargets(vaultHandler.decryptColumnOrLog(entry.RotationTargets.String, "[]", "rotation_targets"))
		status := "success"
		errSummary := ""
		if len(targets) > 0 {
			results := DeliverRotatedKey(ctx, queries, vaultHandler, entry.ID, entry.Name, oldValueCopy, newValue, targets, entry.UserID)
			status, errSummary = summarizeDelivery(results)
			slog.Info("vault rotation: delivery complete",
				"entry", entry.Name,
				"status", status,
				"total_targets", len(targets))
			if status != "success" {
				slog.Error("vault rotation: delivery had failures", "entry", entry.Name, "detail", errSummary)
				dispatchRotationAlert(ctx, queries, vaultHandler, entry.Name, errSummary)
			}
		}

		// A failed old-key revoke means the predecessor is still live at the
		// provider: downgrade to partial and alarm it, but with a STATIC message
		// (the raw revoke error can embed the provider URL/id) so nothing sensitive
		// lands in last_rotation_error. Detail is in the logs.
		if revokeWarn != "" {
			slog.Error("vault rotation: old key revoke failed (predecessor still live)", "entry", entry.Name, "detail", revokeWarn)
		}
		// The sweep already got this right; it now shares the rule rather than
		// stating its own copy, so the manual path cannot drift away from it again.
		var revokeAlert bool
		status, errSummary, revokeAlert = foldRevokeOutcome(status, errSummary, revokeWarn)
		if revokeAlert {
			dispatchRotationAlert(ctx, queries, vaultHandler, entry.Name, revokeStillLiveMsg)
		}

		// Record outcome. last_rotation_error reflects delivery truth (empty on
		// full success), and the log status is success or partial accordingly.
		_ = queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
			LastRotationError: sql.NullString{String: errSummary, Valid: true},
			ID:                entry.ID,
		})
		logEntry := RotationLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Status:    status,
			Provider:  providerName,
			Error:     errSummary,
			Method:    "auto",
		}
		updatedLog := AppendRotationLog(entry.RotationLog.String, logEntry)
		_ = queries.UpdateVaultEntryRotationLog(ctx, db.UpdateVaultEntryRotationLogParams{
			RotationLog: sql.NullString{String: updatedLog, Valid: true},
			ID:          entry.ID,
		})

		LogActivity(queries, nil, "vault.auto_rotate", fmt.Sprintf("Auto-rotated vault secret: %s (provider: %s, targets: %d, status: %s)", entry.Name, providerName, len(targets), status))
		slog.Info("vault rotation: rotated", "provider", providerName, "entry", entry.Name, "status", status)
	}
}

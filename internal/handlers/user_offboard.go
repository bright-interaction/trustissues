package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// sealSecretNames seals the entry names this file reports, for the same reason
// the vault handler's own writers do: those names are the inventory the
// encrypted columns exist to withhold, and these two lines are the ones that
// list SEVERAL of them at once.
//
// It fails CLOSED when the vault handler is not wired. That is not a
// hypothetical branch worth being relaxed about: h.vault is optional by
// construction (SetVault runs after the handler is built), so "the offboard path
// ran before the wiring did" is a code change away, and the cost of guessing
// wrong is the names in the clear on the widest line in the product.
func (h *UserHandler) sealSecretNames(r *http.Request, names []string) []string {
	if h.vault == nil {
		slog.Error("offboard: no vault handler wired to seal the secret names in an activity line; " +
			"recording placeholders instead of cleartext")
		out := make([]string, len(names))
		for i := range out {
			out[i] = activityDetailUnavailable
		}
		return out
	}
	return h.vault.sealSecretNames(r.Context(), names)
}

// invalidateCredentials revokes every standing credential a user holds:
// sessions, API keys, and any service identities they created (plus the
// rotation delivery targets those identities and their entries reference).
// It records what it did on the activity log.
//
// It exists because this one property, "when someone's credentials are
// invalidated their reach actually ends", has now been fixed FIVE times in
// five separate places: collection removal, rotation-target delivery,
// capability minting, the shared entryAccessFor gate, and service identities.
// Each fix closed one door and the next audit round found another, because
// every caller re-implemented its own idea of what invalidation means. A
// docstring here once claimed this was "inherited by all three callers
// (disable, delete, password reset)" while the code had only two: password
// reset revoked sessions and API keys inline but never touched service
// identities, so a stolen service key kept reading the victim's vault straight
// through an admin's incident-response reset. Anything added here is now
// inherited by EVERY caller (disable, delete, admin password reset, and
// self-service password change) instead of by whichever one the author
// happened to be editing.
//
// Best-effort by design: an invalidation that half-completes because a
// cleanup step errored is worse than one that finishes and reports what it
// could not tidy. Every step logs its own failure and none of them abort the
// caller.
//
// The authoritative controls are still the runtime gates (FetchOwnSecrets
// refuses a disabled or deleted owner, targetStillAuthorized refuses delivery,
// entryAccessFor refuses access). This function is what makes the revocation
// VISIBLE in the product rather than surfacing as a mystery 401 at the next
// boot, and what stops dead endpoints and live service keys from sitting
// around looking active.
//
// reason is a short present-tense lead-in used to make each caller's activity
// log entries distinguishable ("Disabling", "Deleting", "Resetting password
// for", "Changing password for").
func invalidateCredentials(r *http.Request, queries *db.Queries, vault *VaultHandler, userID, email, reason string) {
	if userID == "" {
		return
	}
	ctx := r.Context()

	// 1. Sessions. The iat-based cutoff catches tokens that carry an iat claim;
	// revoking the server-side rows is what makes it unconditional.
	if err := queries.InvalidateUserSessions(ctx, db.InvalidateUserSessionsParams{
		SessionsValidAfter: time.Now().Unix(),
		ID:                 userID,
	}); err != nil {
		slog.Error("credentials: failed to invalidate sessions", "user", userID, "reason", reason, "error", err)
	}
	if err := queries.RevokeUserSessions(ctx, userID); err != nil {
		slog.Error("credentials: failed to revoke sessions", "user", userID, "reason", reason, "error", err)
	}

	// 2. API keys. A second standing credential that would otherwise survive
	// a session revocation untouched.
	if err := queries.RevokeAPIKeysByUser(ctx, userID); err != nil {
		slog.Error("credentials: failed to revoke api keys", "user", userID, "reason", reason, "error", err)
	}

	// 3. Service identities. FetchOwnSecrets resolves every secret as the
	// identity's created_by_user_id, so a live key outlives its owner and keeps
	// reading their personal vault, including values rotated after they left.
	names, listErr := queries.ListServiceIdentitiesByUser(ctx, sql.NullString{String: userID, Valid: true})
	if listErr != nil {
		slog.Error("credentials: could not list service identities", "user", userID, "reason", reason, "error", listErr)
	} else if len(names) > 0 {
		if _, revErr := queries.RevokeServiceIdentitiesByUser(ctx, sql.NullString{String: userID, Valid: true}); revErr != nil {
			slog.Error("credentials: could not revoke service identities", "user", userID, "reason", reason, "error", revErr)
		} else {
			labels := make([]string, 0, len(names))
			for _, n := range names {
				labels = append(labels, n.Name)
			}
			// Named explicitly: each one is a machine credential that will stop
			// working at its next boot, and the admin needs to know which
			// services to re-provision before that happens.
			LogActivityFromRequest(queries, r, "admin.service_identities_revoked",
				fmt.Sprintf("%s %s: revoked %d service key(s), these services must be re-provisioned: %v",
					reason, email, len(labels), labels))
			slog.Info("credentials: revoked service identities", "user", userID, "reason", reason, "count", len(labels))
		}
	}

	// 4. Rotation delivery targets they configured, across every entry
	// including their own personal ones (auto-rotation keeps running on those).
	if vault != nil {
		if summary := vault.PurgeTargetsConfiguredByUser(ctx, userID); summary != "" {
			LogActivityFromRequest(queries, r, "admin.user_targets_purged",
				fmt.Sprintf("%s %s: %s", reason, email, summary))
		}
	}
}

// disposeVaultEntriesOnDelete handles the departing user's secrets on a HARD
// delete, and is deliberately NOT part of invalidateCredentials: disabling an
// account is reversible and must leave the entries exactly where they are.
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

// verifyHardDeleteCleanup turns the older best-effort cleanup helpers into an
// atomic hard-delete contract. Disable and password reset deliberately keep
// their best-effort behaviour because refusing the incident-response action can
// be worse than leaving cosmetic cleanup behind. A hard delete is different:
// committing the user DELETE while a shared entry still names that user makes
// the ciphertext unreachable, and committing while one of their delivery
// targets survives leaves a dead principal's endpoint attached to future
// rotations.
//
// Delete calls this on the SAME write transaction as the policy check and user
// DELETE. Any residue therefore aborts and rolls back the entire offboarding,
// including personal-vault deletion and ownership transfers already attempted.
func (h *UserHandler) verifyHardDeleteCleanup(ctx context.Context, targetID string) error {
	if h.vault == nil {
		return fmt.Errorf("vault handler is not wired")
	}

	var heldEntries int64
	if err := h.queries.Handle().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vault_entries WHERE user_id = ?`, targetID).Scan(&heldEntries); err != nil {
		return fmt.Errorf("verify departing user's vault: %w", err)
	}
	if heldEntries != 0 {
		return fmt.Errorf("%d vault entries still name the departing user", heldEntries)
	}

	identities, err := h.queries.ListServiceIdentitiesByUser(ctx,
		sql.NullString{String: targetID, Valid: true})
	if err != nil {
		return fmt.Errorf("verify service identity revocation: %w", err)
	}
	if len(identities) != 0 {
		return fmt.Errorf("%d live service identities still name the departing user", len(identities))
	}

	rows, err := h.queries.ListAllVaultEntryTargets(ctx)
	if err != nil {
		return fmt.Errorf("verify rotation target purge: %w", err)
	}
	for _, row := range rows {
		raw, openErr := h.vault.decryptColumn(row.RotationTargets.String, vaultFieldRotationTargets)
		if openErr != nil {
			return fmt.Errorf("open rotation targets for entry %s: %w", row.ID, openErr)
		}
		var targets []RotationTarget
		if raw != "" {
			if decodeErr := json.Unmarshal([]byte(raw), &targets); decodeErr != nil {
				return fmt.Errorf("decode rotation targets for entry %s: %w", row.ID, decodeErr)
			}
		}
		for _, target := range targets {
			if target.ConfiguredBy == targetID {
				return fmt.Errorf("entry %s still has a rotation target configured by the departing user", row.ID)
			}
		}
	}
	return nil
}

type hardDeleteSummary struct {
	serviceNames  []string
	targetCount   int
	targetEntries []string
	sharedMoved   int
	sharedRenamed []string
	personalGone  int64
}

// hardDeleteCleanup is the fail-closed counterpart to invalidateCredentials
// and disposeVaultEntriesOnDelete. Those helpers remain intentionally
// best-effort for reversible incident-response actions. A hard delete has no
// such escape hatch: it runs this on the caller's transaction and any failed
// credential revocation, target purge, transfer or erasure aborts the delete.
func (h *UserHandler) hardDeleteCleanup(ctx context.Context, targetID, email, newOwnerID string) (hardDeleteSummary, error) {
	var out hardDeleteSummary
	if h.vault == nil {
		return out, fmt.Errorf("vault handler is not wired")
	}

	if err := h.queries.InvalidateUserSessions(ctx, db.InvalidateUserSessionsParams{
		SessionsValidAfter: time.Now().Unix(), ID: targetID,
	}); err != nil {
		return out, fmt.Errorf("invalidate user sessions: %w", err)
	}
	if err := h.queries.RevokeUserSessions(ctx, targetID); err != nil {
		return out, fmt.Errorf("revoke user sessions: %w", err)
	}
	if err := h.queries.RevokeAPIKeysByUser(ctx, targetID); err != nil {
		return out, fmt.Errorf("revoke user API keys: %w", err)
	}

	identities, err := h.queries.ListServiceIdentitiesByUser(ctx,
		sql.NullString{String: targetID, Valid: true})
	if err != nil {
		return out, fmt.Errorf("list service identities: %w", err)
	}
	if len(identities) > 0 {
		result, revokeErr := h.queries.RevokeServiceIdentitiesByUser(ctx,
			sql.NullString{String: targetID, Valid: true})
		if revokeErr != nil {
			return out, fmt.Errorf("revoke service identities: %w", revokeErr)
		}
		affected, affectedErr := result.RowsAffected()
		if affectedErr != nil || affected != int64(len(identities)) {
			return out, fmt.Errorf("service identity revocation affected %d of %d rows (count error: %v)",
				affected, len(identities), affectedErr)
		}
		out.serviceNames = make([]string, 0, len(identities))
		for _, identity := range identities {
			out.serviceNames = append(out.serviceNames, identity.Name)
		}
	}

	out.targetCount, out.targetEntries, err = h.purgeTargetsForHardDelete(ctx, targetID)
	if err != nil {
		return out, err
	}
	out.sharedMoved, out.sharedRenamed, err = h.reassignCollectionEntriesForHardDelete(
		ctx, targetID, email, newOwnerID)
	if err != nil {
		return out, err
	}
	deleted, err := h.queries.DeletePersonalVaultEntriesForUser(ctx, targetID)
	if err != nil {
		return out, fmt.Errorf("delete personal vault entries: %w", err)
	}
	out.personalGone, err = deleted.RowsAffected()
	if err != nil {
		return out, fmt.Errorf("count deleted personal vault entries: %w", err)
	}
	return out, nil
}

func (h *UserHandler) purgeTargetsForHardDelete(ctx context.Context, targetID string) (int, []string, error) {
	rows, err := h.queries.ListAllVaultEntryTargets(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("list rotation targets: %w", err)
	}
	dropped := 0
	entries := make([]string, 0)
	for _, row := range rows {
		raw, openErr := h.vault.decryptColumn(row.RotationTargets.String, vaultFieldRotationTargets)
		if openErr != nil {
			return 0, nil, fmt.Errorf("open rotation targets for entry %s: %w", row.ID, openErr)
		}
		targets := make([]RotationTarget, 0)
		if raw != "" {
			if decodeErr := json.Unmarshal([]byte(raw), &targets); decodeErr != nil {
				return 0, nil, fmt.Errorf("decode rotation targets for entry %s: %w", row.ID, decodeErr)
			}
		}
		kept := make([]RotationTarget, 0, len(targets))
		removed := 0
		for _, target := range targets {
			if target.ConfiguredBy == targetID {
				removed++
				continue
			}
			kept = append(kept, target)
		}
		if removed == 0 {
			continue
		}
		encoded, encodeErr := json.Marshal(kept)
		if encodeErr != nil {
			return 0, nil, fmt.Errorf("encode purged targets for entry %s: %w", row.ID, encodeErr)
		}
		sealed, sealErr := h.vault.encryptColumn(string(encoded))
		if sealErr != nil {
			return 0, nil, fmt.Errorf("seal purged targets for entry %s: %w", row.ID, sealErr)
		}
		ticket, ticketErr := egressgate.Decide(egressgate.Request{
			EntryID: row.ID,
			What:    egressFieldRotationTarget,
			Before:  deliveryDestinations(targets),
			After:   deliveryDestinations(kept),
		})
		if ticketErr != nil {
			return 0, nil, fmt.Errorf("prove target purge for entry %s is narrowing: %w", row.ID, ticketErr)
		}
		if writeErr := vaultegress.SetRotationTargets(ctx, h.queries, ticket,
			vaultegress.RotationTargetsParams{RotationTargets: toNullString(sealed), ID: row.ID}); writeErr != nil {
			return 0, nil, fmt.Errorf("persist target purge for entry %s: %w", row.ID, writeErr)
		}
		name, nameErr := h.vault.decryptColumn(row.Name, vaultFieldName)
		if nameErr != nil {
			return 0, nil, fmt.Errorf("open target-bearing entry name %s: %w", row.ID, nameErr)
		}
		dropped += removed
		entries = append(entries, name)
	}
	return dropped, entries, nil
}

func (h *UserHandler) reassignCollectionEntriesForHardDelete(ctx context.Context,
	targetID, email, newOwnerID string) (int, []string, error) {

	rows, err := h.queries.ListCollectionVaultEntriesForUser(ctx, targetID)
	if err != nil {
		return 0, nil, fmt.Errorf("list shared vault entries: %w", err)
	}
	actor, err := h.queries.GetUserByID(ctx, newOwnerID)
	if err != nil || actor.Disabled != 0 || actor.Role != middleware.RoleAdmin {
		return 0, nil, fmt.Errorf("the deleting principal is not a live instance admin")
	}
	moved := 0
	renamed := make([]string, 0)
	for _, row := range rows {
		plainName, openErr := h.vault.decryptColumn(row.Name, vaultFieldName)
		if openErr != nil {
			return 0, nil, fmt.Errorf("open shared entry name %s: %w", row.ID, openErr)
		}
		nameScope := bidxScope(newOwnerID, row.CollectionID)
		proof, proofErr := vaultegress.AuthorizeTransfer(vaultegress.TransferRequest{
			EntryID: row.ID, Actor: newOwnerID, ActorIsInstanceAdmin: true, To: newOwnerID,
			Why: "hard delete of " + email + ": the team keeps the shared entries they created",
		})
		if proofErr != nil {
			return 0, nil, fmt.Errorf("authorize shared entry transfer %s: %w", row.ID, proofErr)
		}
		_, transferErr := vaultegress.TransferSecretOwnership(ctx, h.queries, proof,
			vaultegress.TransferOwnershipParams{
				NewOwnerUserID: newOwnerID,
				ID:             row.ID,
				NameBidx:       h.vault.scopedNameBlindIndex(nameScope, plainName),
			})
		if transferErr == nil {
			moved++
			continue
		}
		if !strings.Contains(transferErr.Error(), "UNIQUE constraint") {
			return 0, nil, fmt.Errorf("transfer shared entry %s: %w", row.ID, transferErr)
		}

		dedup := plainName + " (from " + email + ")"
		sealedName, sealErr := h.vault.encryptColumn(dedup)
		if sealErr != nil {
			return 0, nil, fmt.Errorf("seal de-duplicated entry name %s: %w", row.ID, sealErr)
		}
		if renameErr := h.queries.UpdateVaultEntryName(ctx, db.UpdateVaultEntryNameParams{
			Name: sealedName, NameBidx: h.vault.scopedNameBlindIndex(nameScope, dedup), ID: row.ID,
		}); renameErr != nil {
			return 0, nil, fmt.Errorf("de-duplicate shared entry %s: %w", row.ID, renameErr)
		}
		retry, retryErr := vaultegress.AuthorizeTransfer(vaultegress.TransferRequest{
			EntryID: row.ID, Actor: newOwnerID, ActorIsInstanceAdmin: true, To: newOwnerID,
			Why: "hard delete of " + email + ": re-own after a name de-duplication",
		})
		if retryErr != nil {
			return 0, nil, fmt.Errorf("authorize de-duplicated shared entry transfer %s: %w", row.ID, retryErr)
		}
		if _, retryErr = vaultegress.TransferSecretOwnership(ctx, h.queries, retry,
			vaultegress.TransferOwnershipParams{
				NewOwnerUserID: newOwnerID,
				ID:             row.ID,
				NameBidx:       h.vault.scopedNameBlindIndex(nameScope, dedup),
			}); retryErr != nil {
			return 0, nil, fmt.Errorf("transfer de-duplicated shared entry %s: %w", row.ID, retryErr)
		}
		moved++
		renamed = append(renamed, plainName+" -> "+dedup)
	}
	return moved, renamed, nil
}

func (h *UserHandler) logHardDeleteSummary(r *http.Request, email string, summary hardDeleteSummary) {
	if len(summary.serviceNames) > 0 {
		LogActivityFromRequest(h.queries, r, "admin.service_identities_revoked",
			fmt.Sprintf("Deleting %s: revoked %d service key(s), these services must be re-provisioned: %v",
				email, len(summary.serviceNames), summary.serviceNames))
	}
	if summary.targetCount > 0 {
		LogActivityFromRequest(h.queries, r, "admin.user_targets_purged",
			fmt.Sprintf("Deleting %s: removed %d rotation delivery target(s) they had configured on: %v",
				email, summary.targetCount, h.sealSecretNames(r, summary.targetEntries)))
	}
	if summary.sharedMoved > 0 {
		detail := fmt.Sprintf("Deleting %s: re-owned %d shared collection secret(s) so the team keeps them",
			email, summary.sharedMoved)
		if len(summary.sharedRenamed) > 0 {
			detail += fmt.Sprintf("; renamed %d to avoid a name clash: %v", len(summary.sharedRenamed),
				h.sealSecretNames(r, summary.sharedRenamed))
		}
		LogActivityFromRequest(h.queries, r, "admin.entries_reassigned", detail)
	}
	if summary.personalGone > 0 {
		LogActivityFromRequest(h.queries, r, "admin.entries_deleted_with_user",
			fmt.Sprintf("Deleting %s: removed %d personal secret(s)", email, summary.personalGone))
	}
}

// reassignCollectionEntries re-owns the leaver's shared entries ONE AT A TIME.
//
// A single blanket UPDATE was all-or-nothing. Generic names ("GitHub", "AWS",
// "Stripe") collide constantly in a password manager, so one collection-scoped
// clash while converging a legacy token aborted the whole statement:
// every shared entry kept the deleted user's id, no activity row was written,
// and the confirmation dialog had just promised the team would keep them. The
// failure was invisible and the entries were left orphaned, which is exactly the
// state the change was meant to eliminate.
//
// Per row, a collision is resolved by suffixing the leaver's address rather than
// skipping, so the team keeps the secret either way and the rename says where it
// came from. Anything that still fails is NAMED on the activity log instead of
// being swallowed.
// THE PRODUCT'S ONE GENUINE OWNERSHIP TRANSFER, and the only post-creation
// writer of secret_owner_user_id.
//
// It is not a plain UPDATE any more. secret_owner_user_id is what the exit
// resolves "whose secret is this" from, and a column any route can write is not
// an authority, so the statement lives in internal/vaultegress and demands a
// vaultegress.TransferProof. AuthorizeTransfer grants one only to an instance
// admin taking ownership FOR THEMSELVES, resolved from the users row rather than
// from the session that got them into this handler.
//
// An instance admin already holds the widening right on every entry (grantFor
// row 3), so the transfer hands them nothing they did not have; what it does is
// make the new state attributable, which is the half the old blanket UPDATE was
// missing.
func (h *UserHandler) reassignCollectionEntries(r *http.Request, targetID, email, newOwnerID string) {
	rows, err := h.queries.ListCollectionVaultEntriesForUser(r.Context(), targetID)
	if err != nil {
		slog.Error("offboard: could not list collection entries", "user", targetID, "error", err)
		return
	}
	// Re-owning needs the vault handler for three things it cannot fake: opening
	// the stored name, sealing the de-duplicated one, and deriving the blind
	// index under the shared collection. Refusing here leaves the entries with the
	// departing user, which the caller reports and an admin can repair; guessing
	// would write a wrong-scope index and a name nobody can read.
	if h.vault == nil {
		slog.Error("offboard: no vault handler wired, refusing to re-own collection entries",
			"user", targetID, "entries", len(rows))
		return
	}
	if len(rows) == 0 {
		return
	}

	// Resolved from the users ROW. The route is AdminOnly, but "safe because of
	// an authorization rule somewhere else" is how a control survives until the
	// next refactor and not past it, and round 5 is what asking a session claim
	// on one side and the row on the other costs.
	actorIsAdmin := false
	if u, uErr := h.queries.GetUserByID(r.Context(), newOwnerID); uErr == nil {
		actorIsAdmin = u.Disabled == 0 && u.Role == middleware.RoleAdmin
	}

	moved := 0
	var renamed, failed []string
	for _, row := range rows {
		// Opened for the operator-facing lists below. ListCollectionVaultEntriesForUser
		// returns what is STORED, and 00040 made that ciphertext, so reporting
		// row.Name directly told the admin which entries were orphaned by naming
		// them "enc:v1:PT5r..." on the one surface that exists to tell them
		// exactly which entries need attention.
		//
		// EVERYTHING BELOW WORKS ON THE OPENED NAME.
		//
		// ListCollectionVaultEntriesForUser returns what is STORED, and 00040
		// made that ciphertext. Three separate things here need the plaintext:
		// the operator-facing lists, the de-duplicated name this builds, and the
		// blind index that carries collection uniqueness across the transfer.
		// Reading row.Name directly gave all three the wrong value.
		plainName := h.vault.EntryNamePlain(row.Name)
		// Shared names are keyed to c:<collection>, not to either custodian. We
		// still recompute here so a pre-00045 user-scoped token converges while the
		// row is already being touched.
		nameScope := bidxScope(newOwnerID, row.CollectionID)
		newBidx := h.vault.scopedNameBlindIndex(nameScope, plainName)
		proof, pErr := vaultegress.AuthorizeTransfer(vaultegress.TransferRequest{
			EntryID:              row.ID,
			Actor:                newOwnerID,
			ActorIsInstanceAdmin: actorIsAdmin,
			To:                   newOwnerID,
			Why:                  "hard delete of " + email + ": the team keeps the shared entries they created",
		})
		if pErr != nil {
			slog.Error("offboard: ownership transfer refused", "entry", row.ID, "error", pErr)
			failed = append(failed, plainName)
			continue
		}
		_, uErr := vaultegress.TransferSecretOwnership(r.Context(), h.queries, proof,
			vaultegress.TransferOwnershipParams{NewOwnerUserID: newOwnerID, ID: row.ID, NameBidx: newBidx})
		if uErr == nil {
			moved++
			continue
		}
		if !strings.Contains(uErr.Error(), "UNIQUE constraint") {
			slog.Error("offboard: could not re-own entry", "entry", row.ID, "error", uErr)
			failed = append(failed, plainName)
			continue
		}
		// The new owner already has an entry by this name. Keep both.
		//
		// Built from the OPENED name and written back sealed, with its index
		// beside it. The previous version concatenated onto the ciphertext and
		// stored the result, which produced a name column no key could ever open
		// again: enc:v1:<base64> with a suffix glued past the end of the base64
		// is not ciphertext, it is a corrupt row that still looks like one.
		dedup := plainName + " (from " + email + ")"
		sealedDedup, encErr := h.vault.encryptColumn(dedup)
		if encErr != nil {
			slog.Error("offboard: could not seal the de-duplicated entry name", "entry", row.ID, "error", encErr)
			failed = append(failed, plainName)
			continue
		}
		if rErr := h.queries.UpdateVaultEntryName(r.Context(), db.UpdateVaultEntryNameParams{
			Name:     sealedDedup,
			NameBidx: h.vault.scopedNameBlindIndex(nameScope, dedup),
			ID:       row.ID,
		}); rErr != nil {
			slog.Error("offboard: could not de-duplicate entry name", "entry", row.ID, "error", rErr)
			failed = append(failed, plainName)
			continue
		}
		retry, retryErr := vaultegress.AuthorizeTransfer(vaultegress.TransferRequest{
			EntryID:              row.ID,
			Actor:                newOwnerID,
			ActorIsInstanceAdmin: actorIsAdmin,
			To:                   newOwnerID,
			Why:                  "hard delete of " + email + ": re-own after a name de-duplication",
		})
		if retryErr != nil {
			slog.Error("offboard: ownership transfer refused after rename", "entry", row.ID, "error", retryErr)
			failed = append(failed, plainName)
			continue
		}
		if _, uErr2 := vaultegress.TransferSecretOwnership(r.Context(), h.queries, retry,
			vaultegress.TransferOwnershipParams{
				NewOwnerUserID: newOwnerID,
				ID:             row.ID,
				NameBidx:       h.vault.scopedNameBlindIndex(nameScope, dedup),
			}); uErr2 != nil {
			slog.Error("offboard: re-own failed after rename", "entry", row.ID, "error", uErr2)
			failed = append(failed, plainName)
			continue
		}
		moved++
		renamed = append(renamed, plainName+" -> "+dedup)
	}

	if moved > 0 {
		detail := fmt.Sprintf("Deleting %s: re-owned %d shared collection secret(s) so the team keeps them", email, moved)
		if len(renamed) > 0 {
			detail += fmt.Sprintf("; renamed %d to avoid a name clash: %v", len(renamed), h.sealSecretNames(r, renamed))
		}
		LogActivityFromRequest(h.queries, r, "admin.entries_reassigned", detail)
	}
	// Never silent. An entry left with a dangling owner is unreadable forever,
	// so the admin has to be told which ones by name.
	if len(failed) > 0 {
		LogActivityFromRequest(h.queries, r, "admin.entries_reassign_failed",
			fmt.Sprintf("Deleting %s: could NOT re-own %d shared secret(s), they are now orphaned and unreadable: %v",
				email, len(failed), h.sealSecretNames(r, failed)))
		slog.Error("offboard: some collection entries could not be re-owned",
			"user", targetID, "count", len(failed))
	}
}

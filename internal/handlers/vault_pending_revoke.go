package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
	"github.com/go-chi/chi/v5"
)

// THE OPERATOR-VISIBLE CLOSURE OF retryOutstandingRevoke's KNOWN COVERAGE HOLE.
//
// See the doc above retryOutstandingRevoke (vault_rotation_core.go) for the
// full history: the only consumer of a preserved pending-revoke marker used to
// be a rotation, so an on-demand entry (auto_rotate = 0) that nobody rotates
// again could carry a stranded predecessor key forever, correct and unread.
// These two handlers are the second consumer that doc names: an
// operator-visible affordance on the entry itself, reachable without
// triggering a whole rotation.
//
// pendingRevokeRetryResponse is the body of both. Its shape matches
// ValidateKey's: a boolean the caller can act on ("revoked") plus a detail
// string that is EITHER empty OR the exact static revokeStillLiveMsg, never
// the raw error -- see the rule at vault_rotation_core.go:288, restated here
// because this is the second place a caller-visible response could leak a
// provider URL, a key id or an upstream body if it forwarded the real error.
type pendingRevokeRetryResponse struct {
	Revoked       bool                 `json:"revoked"`
	Detail        string               `json:"detail"`
	PendingRevoke *pendingRevokeStatus `json:"pending_revoke"`
}

// pendingRevokeResolveResponse is ResolvePendingRevoke's success body.
type pendingRevokeResolveResponse struct {
	Resolved      bool                 `json:"resolved"`
	PendingRevoke *pendingRevokeStatus `json:"pending_revoke"`
}

// RetryPendingRevoke handles POST /api/vault/{id}/pending-revoke/retry.
//
// AUTHZ IS MODELLED ON ValidateKey, NOT Rotate, because this spends the LIVE
// credential upstream exactly like Validate does (performPendingRevoke
// authenticates the revoke request with the entry's current value) AND writes
// provider_meta afterwards. So it needs BOTH rights ValidateKey and Rotate
// separately require: entryCurrentlyUsableBy (the spend right; admin-bypassed
// the same way ValidateKey bypasses it, because entryCurrentlyUsableBy itself
// deliberately has no admin carve-out) for the spend, and entryAccess's
// canWrite for the persist. Gating a spend on read alone would hand a removed
// creator (who keeps a residual READ under grantFor row 7) an oracle: ask the
// server to spend a credential they no longer have any right to use.
//
// Refusals for missing/insufficient rights are 404, never 403 (vault_grant.go's
// rule: a probe must not be able to tell "gone" from "not yours" apart from any
// other single-entry endpoint). The entry id comes from the chi URL param only,
// never from the request body.
func (h *VaultHandler) RetryPendingRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeBadRequest(w, r, "password is required to retry a revoke")
		return
	}

	userID := middleware.GetUserID(r.Context())
	if !h.reauthOrRefuse(w, r, ctx, userID, req.Password) {
		return
	}

	// The spend right. entryCurrentlyUsableBy has no admin bypass by design (it
	// answers "may THIS user spend it"), so an instance admin gets an explicit
	// one here, exactly like ValidateKey.
	if !middleware.IsAdmin(ctx) && !h.entryCurrentlyUsableBy(ctx, userID, id) {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	// The write right, ADDITIONALLY: this persists provider_meta on both the
	// success and the failure path, which ValidateKey never does.
	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	meta, err := h.queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	// Opened ONCE, into the local copy. See vault.go:2914's comment on the same
	// line in Rotate: a manual path that re-reads the raw ciphertext at every
	// use site is exactly how enc:v1: blobs reached the activity log before.
	meta.Name = h.EntryNamePlain(meta.Name)
	provider := meta.Provider.String

	if role, _ := classifyProvider(provider); role == providerUnknown {
		logError(r, "vault.pending_revoke.retry: provider is not in this build's registry, refusing to retry",
			"entry", id, "provider", provider)
		writeError(w, r, http.StatusConflict, "unknown_provider",
			"this entry is configured for a provider this server does not support, so it was not rotated; "+
				"rotate the credential at the provider, then edit this entry and paste the new value. Nothing was changed.")
		return
	}

	entryRow, err := h.queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		writeNotFound(w, r, "entry not found")
		return
	}
	current, decErr := h.OpenEntrySecret(entryRow.EncryptedValue, entryRow.Nonce,
		int(entryRow.EncryptionVersion.Int64), entryOrigin(id, meta.Name))
	if decErr != nil {
		logError(r, "vault.pending_revoke.retry: decrypt failed, refusing to retry", "entry", id, "error", decErr)
		writeError(w, r, http.StatusConflict, "decrypt_failed",
			"this secret could not be decrypted, so the revoke was not retried; retrying would have "+
				"authenticated upstream with a value that is still recoverable")
		return
	}
	defer current.Wipe()

	// casToken is the exact ciphertext this attempt read, taken BEFORE the
	// network call below, per the CAS discipline in vaultegress.CASProviderMeta's
	// doc: provider_meta is sealed with a fresh nonce per write, so it is safe
	// to use as an opaque compare-and-swap token with no ABA problem.
	casToken := entryRow.ProviderMeta
	providerMetaRaw := h.decryptColumnOrLog(entryRow.ProviderMeta.String, "{}", vaultFieldProviderMeta)
	providerMeta := ParseProviderMeta(providerMetaRaw)
	targetURL := providerMeta[pendingRevokeURL]
	if targetURL == "" {
		writeError(w, r, http.StatusConflict, "no_pending_revoke",
			"there is no revoke outstanding on this entry")
		return
	}

	// THE SPEND, NOT OPTIONAL. performPendingRevoke (called inside
	// retryOutstandingRevoke below) mints its OWN secretexit receipt, so
	// providerDo would let the upstream request through without this call too --
	// silently skipping the AI-gateway pin check and the fail-closed read on a
	// provider-pin lookup error. See spendProviderSecret's doc: "the three paths
	// that SPEND"; this endpoint is the fourth.
	spendCtx, _, egressErr := spendProviderSecret(ctx, h.queries, current, id, provider, providerMeta)
	if egressErr != nil {
		logError(r, "vault.pending_revoke.retry: refusing to spend against this provider configuration",
			"entry", id, "user", userID, "error", egressErr)
		writeError(w, r, http.StatusForbidden, "destination_pinned", egressErr.Error())
		return
	}

	// THE ONE NETWORK CALL. Never branch on an HTTP status here or anywhere
	// downstream of it: the b2 trap (2026-08-17) was exactly that mistake.
	// retryOutstandingRevoke's only success signal is
	// meta["last_revoke_error"] == "" after performPendingRevoke returns, and it
	// ALREADY deletes the three pending_revoke_* markers from providerMeta
	// in-place on that confirmed-success branch (see performPendingRevoke) --
	// this handler never deletes them itself, on this path or any other. On
	// failure the markers are left exactly as performPendingRevoke found them.
	revokeWarn := retryOutstandingRevoke(spendCtx, providerMeta, meta.Name, provider, current)
	revoked := revokeWarn == ""

	// PERSIST, under a compare-and-swap. Both rotation paths still hold their
	// own in-memory provider_meta across their own mint-then-write window and
	// write it back unconditionally (persistProviderMetaAfterRevoke), so
	// without a CAS here a rotation racing this exact row could silently lose
	// this write, or -- worse -- resurrect the very markers a successful retry
	// just cleared with its own stale copy. See vaultegress.CASProviderMeta.
	work, applied, midFlight, persistErr := h.casEditProviderMeta(ctx, id, provider, targetURL,
		providerMetaRaw, providerMeta, casToken, func(m map[string]string) {
			if revoked {
				deletePendingRevokeMarkers(m)
			}
		})
	if persistErr != nil {
		logError(r, "vault.pending_revoke.retry: could not persist the outcome", "entry", id, "error", persistErr)
	}
	if midFlight {
		logError(r, "vault.pending_revoke.retry: the entry's provider_meta changed to different "+
			"coordinates mid-retry (very likely a rotation completed concurrently); this attempt's "+
			"marker deletion was NOT applied to the row that is live now", "entry", id)
	}

	// Clear the revoke half of last_rotation_error, and ONLY on a confirmed
	// success that actually landed. Nothing else clears it.
	// `applied` is checked EXPLICITLY rather than inferred from the other two.
	// Today every non-applied path out of casEditProviderMeta also returns an
	// error or midFlight, so !midFlight && persistErr == nil already implies it
	// -- but that is an invariant of a helper someone will extend, and the cost
	// of it silently ceasing to hold is that a revoke whose marker deletion
	// never reached the row still clears last_rotation_error, i.e. the entry
	// reports clean while an orphaned key is live upstream.
	if revoked && applied && !midFlight && persistErr == nil {
		// RE-READ, DO NOT REUSE THE VALUE FROM LINE ~94.
		//
		// That read happened BEFORE the provider round trip, which takes
		// seconds. The applied && !midFlight guard proves only that
		// provider_meta did not move; recordRotationFailure writes
		// last_rotation_error WITHOUT touching provider_meta, so a scheduled
		// rotation that failed while this revoke was in flight walks straight
		// through that guard. Writing back the stale value then erases a
		// rotation-failure alarm this endpoint knows nothing about -- and for a
		// MANUAL rotation nothing re-runs to re-record it, so the erasure is
		// durable. Re-read, and only clear if the column still says what it
		// said when we looked; anything else is newer and truer than we are.
		fresh, freshErr := h.queries.GetVaultEntryMeta(ctx, id)
		switch {
		case freshErr != nil:
			logError(r, "vault.pending_revoke.retry: could not re-read last_rotation_error, leaving it alone",
				"entry", id, "error", freshErr)
		case fresh.LastRotationError.String != meta.LastRotationError.String:
			logError(r, "vault.pending_revoke.retry: last_rotation_error changed while the revoke was in "+
				"flight (very likely a concurrent rotation recorded a failure); leaving it as found rather "+
				"than clearing a newer alarm this retry knows nothing about", "entry", id)
		default:
			h.clearRevokeHalfOfRotationError(ctx, r, id, meta.LastRotationError.String)
		}
	}

	detail := ""
	if !revoked {
		// The ONLY thing this field may ever hold on failure. The raw error
		// embeds the provider URL, the key id and the upstream body (see the
		// rule at vault_rotation_core.go:288); the real detail already went to
		// slog inside performPendingRevoke and retryOutstandingRevoke.
		detail = revokeStillLiveMsg
	}

	workJSON, _ := json.Marshal(work)
	LogActivityFromRequest(h.queries, r, "vault.pending_revoke_retried",
		fmt.Sprintf("Pending revoke retry for vault secret: %s (user: %s, revoked: %t)",
			h.sealSecretName(r.Context(), meta.Name), userID, revoked))

	// No appendRotationLog and no dispatchRotationAlert: a revoke retry is not
	// a rotation, and recording it as one would falsify the rotation history the
	// alert emails render.
	writeJSON(w, http.StatusOK, pendingRevokeRetryResponse{
		Revoked:       revoked,
		Detail:        detail,
		PendingRevoke: pendingRevokeStatusFrom(string(workJSON)),
	})
}

// ResolvePendingRevoke handles POST /api/vault/{id}/pending-revoke/resolve.
//
// The terminal escape hatch: an operator who has confirmed, OUTSIDE this
// product, that the predecessor key is no longer a concern (already dead,
// provider account gone, whatever) can discard the stranded markers without
// this server ever having verified that upstream. That is why it is gated on
// entryAccess's canWrite ALONE, no password: it is a metadata edit that
// resolves nothing at the provider, the same right and the same absence of a
// password prompt that deleting the whole entry already has. It must also
// name the key the caller is acknowledging, matched exactly against the
// derived predecessor_key_id, so a resolve typed against the wrong entry (or
// clicked without reading) fails loudly instead of silently discarding a
// marker for a different key than the operator thinks.
func (h *VaultHandler) ResolvePendingRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	var req struct {
		AcknowledgedKeyID string `json:"acknowledged_key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "acknowledged_key_id is required")
		return
	}

	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	entryRow, err := h.queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	casToken := entryRow.ProviderMeta
	raw := h.decryptColumnOrLog(entryRow.ProviderMeta.String, "{}", vaultFieldProviderMeta)

	// Refuse unless the caller names the exact predecessor this row currently
	// carries. A FRESHLY derived status, not a client-supplied one: the whole
	// point is that the caller cannot resolve a marker they have not been shown.
	status := pendingRevokeStatusFrom(raw)
	if req.AcknowledgedKeyID == "" || status == nil || status.PredecessorKeyID == "" ||
		req.AcknowledgedKeyID != status.PredecessorKeyID {
		writeBadRequest(w, r, "acknowledged_key_id does not match this entry's current predecessor key; nothing was changed")
		return
	}

	meta := ParseProviderMeta(raw)
	targetURL := meta[pendingRevokeURL]

	entryName := ""
	provider := ""
	lastRotationError := ""
	if metaRow, mErr := h.queries.GetVaultEntryMeta(ctx, id); mErr == nil {
		entryName = h.EntryNamePlain(metaRow.Name)
		provider = metaRow.Provider.String
		lastRotationError = metaRow.LastRotationError.String
	}

	// Delete the three markers from this FRESHLY read map, under the same
	// gated CAS write the retry endpoint uses. Provider and every other meta
	// key are untouched.
	_, applied, midFlight, persistErr := h.casEditProviderMeta(ctx, id, provider, targetURL, raw, meta, casToken,
		func(m map[string]string) {
			deletePendingRevokeMarkers(m)
		})
	if persistErr != nil {
		logError(r, "vault.pending_revoke.resolve: could not persist", "entry", id, "error", persistErr)
		writeInternalError(w, r, "failed to resolve the pending revoke")
		return
	}
	if midFlight || !applied {
		// The row moved under us (very likely a rotation), so what the caller
		// acknowledged is no longer what is live. Refuse rather than guess;
		// the caller can re-open the entry and try again against the fresh
		// state.
		writeBadRequest(w, r, "this entry changed while resolving; reload and try again")
		return
	}

	// Same re-read discipline as the retry path: lastRotationError was read
	// before the CAS, and a concurrent rotation can record a failure into that
	// column without ever touching provider_meta, so the CAS proves nothing
	// about it. Narrower window than retry (no network call in between) and the
	// same durable harm if it loses.
	if freshRow, fErr := h.queries.GetVaultEntryMeta(ctx, id); fErr != nil {
		logError(r, "vault.pending_revoke.resolve: could not re-read last_rotation_error, leaving it alone",
			"entry", id, "error", fErr)
	} else if freshRow.LastRotationError.String != lastRotationError {
		logError(r, "vault.pending_revoke.resolve: last_rotation_error changed while resolving; leaving "+
			"it as found rather than clearing a newer alarm", "entry", id)
	} else {
		h.clearRevokeHalfOfRotationError(ctx, r, id, lastRotationError)
	}

	userID := middleware.GetUserID(r.Context())
	LogActivityFromRequest(h.queries, r, "vault.pending_revoke_resolved",
		fmt.Sprintf("Pending revoke resolved for vault secret: %s (key: %s, user: %s)",
			h.sealSecretName(r.Context(), entryName), req.AcknowledgedKeyID, userID))

	writeJSON(w, http.StatusOK, pendingRevokeResolveResponse{
		Resolved:      true,
		PendingRevoke: nil,
	})
}

// casEditProviderMeta applies transform to a copy of the freshest provider_meta
// map available and persists it under vaultegress.CASProviderMeta, bounded by
// rotationLogCASAttempts.
//
// It exists because RetryPendingRevoke and ResolvePendingRevoke need the exact
// same shape of concurrency safety and differ only in WHAT they delete (retry
// only when the revoke actually succeeded; resolve unconditionally, once the
// operator has confirmed the key id): read a snapshot, apply an edit, CAS it
// in; on a miss, RE-READ rather than repeating any side effect the caller
// already had (a network revoke, in retry's case) and re-apply transform to
// the FRESH map, never to the stale one, so an unrelated concurrent edit to
// providerMeta is preserved rather than clobbered; if the fresh row's
// pending_revoke_url no longer matches targetURL, something else (almost
// certainly a rotation) already moved the coordinates this call was about, and
// the safe answer is to leave it alone and report that back rather than guess.
func (h *VaultHandler) casEditProviderMeta(ctx context.Context, entryID, provider, targetURL, rawJSON string,
	meta map[string]string, casToken sql.NullString, transform func(map[string]string)) (result map[string]string, applied, midFlight bool, err error) {

	work := meta
	workRaw := rawJSON
	tok := casToken
	for attempt := 0; attempt < rotationLogCASAttempts; attempt++ {
		next := make(map[string]string, len(work))
		for k, v := range work {
			next[k] = v
		}
		transform(next)

		// Compared against what is STORED, never against `work`.
		// performPendingRevoke MUTATES the caller's map in place -- it deletes
		// the three markers itself on a confirmed success -- so by the time the
		// retry path reaches here, `work` already lacks them and this
		// transform is a no-op against it while the ROW still carries them.
		// Comparing the two would skip the very write that clears them and
		// report applied=true. Measured: it made
		// TestStrandedKeyIsRevokedByTheRetryEndpointOnAnOnDemandEntry fail with
		// the coordinates still on the row after a revoke the endpoint
		// correctly reported as successful.
		stored := ParseProviderMeta(workRaw)

		// A NO-OP MUST NOT WRITE. The failing half of a retry deletes nothing,
		// and an unconditional CAS still reseals the column with a fresh nonce
		// and stamps updated_at = CURRENT_TIMESTAMP. A rotation in flight on this
		// row compares updated_at against a snapshot taken at the start of its
		// pass (RotateVaultEntryValueUnchecked), so that touch makes its value
		// CAS lose. The rotation has already MINTED the new credential upstream
		// by then, and the new key's id lives only in the map it is about to
		// discard -- RotationLogEntry has no field for it -- so the failure mode
		// is an orphaned live key with no record of its identity. See the
		// warning at vault_rotation_cas.go:110-116, which is the same defect
		// arriving through a different door.
		if sameProviderMetaMap(stored, next) {
			return work, true, false, nil
		}

		tk, tkErr := egressgate.Decide(egressgate.Request{
			EntryID: entryID,
			What:    egressFieldProviderMeta,
			Before:  providerDestinations(provider, work),
			After:   providerDestinations(provider, next),
			Covers:  providerDestinationCovers,
		})
		if tkErr != nil {
			return work, false, false, tkErr
		}
		// Marshal from the RAW column, applying only this transform's key
		// changes, so a value the operator stored as a non-string survives.
		// Marshalling `next` (a map[string]string) would write {"port":""} for
		// a stored {"port":8080}: json.Unmarshal into a string map RETAINS the
		// key with the zero value rather than dropping it, so the type loss is
		// invisible until the row is read back. This is the third appearance of
		// that class in this column; see reconcileProviderMetaForStorage.
		metaJSON, mErr := providerMetaBytesPreservingTypes(workRaw, stored, next)
		if mErr != nil {
			return work, false, false, mErr
		}
		encMeta, encErr := h.encryptColumn(string(metaJSON))
		if encErr != nil {
			return work, false, false, encErr
		}
		ok, casErr := vaultegress.CASProviderMeta(ctx, h.queries, tk, vaultegress.CASProviderMetaParams{
			ProviderMeta:     toNullString(encMeta),
			PrevProviderMeta: tok,
			ID:               entryID,
		})
		if casErr != nil {
			return work, false, false, casErr
		}
		if ok {
			return next, true, false, nil
		}

		// CAS missed: something else wrote provider_meta between our read and
		// this write. Re-read rather than repeating whatever side effect the
		// caller already performed.
		row, rErr := h.queries.GetVaultEntryMeta(ctx, entryID)
		if rErr != nil {
			return work, false, false, rErr
		}
		freshRaw := h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)
		fresh := ParseProviderMeta(freshRaw)
		if fresh[pendingRevokeURL] != targetURL {
			return fresh, false, true, nil
		}
		workRaw = freshRaw
		work = fresh
		tok = row.ProviderMeta
	}
	return work, false, false, fmt.Errorf("pending revoke: gave up persisting after %d concurrent writes to entry %s",
		rotationLogCASAttempts, entryID)
}

// sameProviderMetaMap reports whether a transform changed anything at all.
func sameProviderMetaMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || av != bv {
			return false
		}
	}
	return true
}

// providerMetaBytesPreservingTypes re-serialises the provider_meta column after
// a transform, taking the VALUES from the raw stored JSON and only the set of
// KEY changes from the transform.
//
// The column is operator-authored JSON and its values are not all strings: a
// port is a number, a scope list is an array. Every code path in this package
// reasons about it as map[string]string, which is fine for deciding, and
// destructive for writing. This is the seam where those two meet.
//
// Fails closed. If the stored column is not a JSON object, this refuses rather
// than substituting the string-map rendering, because that substitution IS the
// data loss: it would replace every non-string value with "" and report 200.
func providerMetaBytesPreservingTypes(rawJSON string, before, after map[string]string) ([]byte, error) {
	if strings.TrimSpace(rawJSON) == "" {
		rawJSON = "{}"
	}
	typed := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(rawJSON), &typed); err != nil {
		return nil, fmt.Errorf("provider_meta is not a JSON object, refusing to rewrite it: %w", err)
	}
	for k := range before {
		if _, still := after[k]; !still {
			delete(typed, k)
		}
	}
	for k, v := range after {
		prev, existed := before[k]
		if existed && prev == v {
			continue // untouched: keep the stored bytes, types and all
		}
		enc, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		typed[k] = enc
	}
	return json.Marshal(typed)
}

// clearRevokeHalfOfRotationError removes revokeStillLiveMsg from
// last_rotation_error and writes the result back, leaving any co-resident
// failure (a delivery error, say) in place.
//
// Both callers re-read and compare the column BEFORE calling this. That check
// lives at the call sites rather than in here on purpose: the value each one
// compares against is the value it made its own decision from, and folding the
// re-read in here would invite a future caller to skip the comparison and get a
// last-writer-wins update on a column that carries an alarm.
func (h *VaultHandler) clearRevokeHalfOfRotationError(ctx context.Context, r *http.Request, entryID, current string) {
	cleared := withoutRevokeStillLive(current)
	if cleared == current {
		return
	}
	if uErr := h.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString(cleared),
		ID:                entryID,
	}); uErr != nil {
		logError(r, "vault.pending_revoke: persist last_rotation_error failed", "entry", entryID, "error", uErr)
	}
}

package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE OTHER HALF OF A FAIL-CLOSED MIGRATION.
//
// Migration 00034 splits vault_entries.user_id into a CUSTODIAN and an OWNER,
// because a collection manager moves the custodian with two ordinary product
// calls and the exit was resolving "whose secret is this" from it. Backfilling
// the owner from user_id would have promoted an attacker who had already run
// those two calls into a permanent, correctly-authorised owner, so the backfill
// stamps only the class it can prove (an entry that has never been in a
// collection) and leaves every other row EMPTY.
//
// An empty owner denies. That is the right direction and it is not free: on a
// team instance every shared entry stops accepting NEW delivery destinations,
// and existing webhook or forgejo targets that a non-admin configured stop
// contributing hosts at delivery time, because ownerRecordedDestinations drops
// a target whose ConfiguredBy no longer holds the widening right.
//
// A fail-closed migration that strands secrets with no operator surface is its
// own outage, and an operator who cannot SEE what was closed will reach for
// sqlite3 and set the column by hand, which is the laundering step again with a
// human running it. So the repair is in the product:
//
//	GET  /api/admin/vault/ownership                  what was withheld, and why
//	POST /api/admin/vault/{id}/ownership/claim       an admin takes it, once
//
// Both are inside the AdminOnly group, and the claim goes through
// vaultegress.AuthorizeTransfer like every other ownership move in the module.
// It grants nothing new: an instance admin already holds the widening right on
// every entry (grantFor row 3). What it does is make the new state a recorded,
// attributable decision instead of a default.

// unownedEntry is one entry the backfill refused to stamp.
//
// It carries no ciphertext and no encrypted metadata. Repairing ownership is a
// decision about a row, not about a value, and a list that returned values
// would be a new way for an admin to sweep up every secret on the instance in
// one request.
type unownedEntry struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	CustodianUserID  string `json:"custodian_user_id"`
	CustodianEmail   string `json:"custodian_email"`
	CollectionID     string `json:"collection_id"`
	CollectionName   string `json:"collection_name"`
	AdoptionRecorded bool   `json:"adoption_recorded"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	// Why is the operator-facing reason this row has no owner, in the words the
	// migration would use. It is derived here rather than stored, because the
	// migration cannot write a per-row explanation into a column the exit reads.
	Why string `json:"why"`
}

// ownershipReport is what the admin page renders.
type ownershipReport struct {
	Entries []unownedEntry `json:"entries"`
	// Total is len(Entries), sent explicitly so a client rendering a badge does
	// not have to special-case an empty array.
	Total int `json:"total"`
}

// ListUnownedEntries handles GET /api/admin/vault/ownership.
func (h *VaultHandler) ListUnownedEntries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.queries.ListVaultEntriesWithNoRecordedOwner(ctx)
	if err != nil {
		logError(r, "vault.ownership: list failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	report := ownershipReport{Entries: make([]unownedEntry, 0, len(rows))}
	for _, row := range rows {
		e := unownedEntry{
			ID:              row.ID,
			Name:            row.Name,
			CustodianUserID: row.UserID,
			CustodianEmail:  row.CustodianEmail.String,
			CollectionID:    row.CollectionID.String,
			CollectionName:  row.CollectionName.String,
		}
		if row.CreatedAt.Valid {
			e.CreatedAt = row.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		if row.UpdatedAt.Valid {
			e.UpdatedAt = row.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		// Best effort. A count that cannot be read leaves the flag false, which
		// understates the evidence rather than inventing it.
		if n, cErr := h.queries.CountRecordedAdoptionsForEntry(ctx,
			sql.NullString{String: row.ID, Valid: true}); cErr == nil && n > 0 {
			e.AdoptionRecorded = true
		}
		e.Why = whyNoRecordedOwner(e)
		report.Entries = append(report.Entries, e)
	}
	report.Total = len(report.Entries)
	writeJSON(w, http.StatusOK, report)
}

// whyNoRecordedOwner says, per row, which branch of the backfill withheld it.
//
// The three cases are the three the migration distinguishes, and the wording is
// deliberately the same, so an operator reading the SQL and an operator reading
// the page are told the same thing.
func whyNoRecordedOwner(e unownedEntry) string {
	switch {
	case e.AdoptionRecorded:
		return "the audit trail records this entry being renamed and ADOPTED by a collection manager, " +
			"so its current custodian is not the principal who deposited the secret"
	case e.CollectionID != "":
		return "this entry lives in a shared collection, and nothing in the database separates " +
			"\"its creator still holds it\" from \"a manager adopted it\": both states are one row whose " +
			"custodian is a member of the collection"
	default:
		return "this entry has been in a collection at some point (the activity log records a move), so " +
			"adoption was reachable for it and its custodian may not be its creator"
	}
}

// ClaimSecretOwnership handles POST /api/admin/vault/{id}/ownership/claim.
//
// THE RULE IS vaultegress.AuthorizeTransfer'S, not a second one: an instance
// admin takes ownership FOR THEMSELVES, and nobody hands it to anybody else. A
// route that could name a recipient would be a route that can make a collection
// manager the owner, which is the attack with an administrative shape.
//
// It refuses an entry that ALREADY records an owner. Repair is for rows the
// migration left empty; letting it move an owner that exists would be a second
// post-creation transfer path with a friendlier name, and the point of the
// column is that there is one.
func (h *VaultHandler) ClaimSecretOwnership(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entryID := chi.URLParam(r, "id")
	if strings.TrimSpace(entryID) == "" {
		writeBadRequest(w, r, "no entry id")
		return
	}
	actor := middleware.GetUserID(ctx)
	if actor == "" {
		writeForbidden(w, r, "an ownership claim has to name the admin making it")
		return
	}

	access, err := h.queries.GetVaultEntryAccess(ctx, entryID)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	if err != nil {
		logError(r, "vault.ownership: access lookup failed", "entry", entryID, "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if access.SecretOwnerUserID != "" {
		writeConflict(w, r, "this entry already records a secret owner; ownership moves only when a "+
			"user is deleted or when a migration could not prove one")
		return
	}

	// From the users ROW, never from the session claim that got us here. The
	// route is AdminOnly, but round 5 is what asking a session on one side and
	// the row on the other costs.
	proof, pErr := vaultegress.AuthorizeTransfer(vaultegress.TransferRequest{
		EntryID:              entryID,
		Actor:                actor,
		ActorIsInstanceAdmin: h.instanceAdminByRecord(ctx, actor),
		To:                   actor,
		Why: "ownership repair after migration 00034: the backfill could not prove the custodian " +
			"deposited this secret, so an instance admin took it deliberately",
	})
	if pErr != nil {
		writeForbidden(w, r, pErr.Error())
		return
	}

	// ONE TRANSACTION, and the reason is in the next paragraph. Answering the
	// ownership question re-arms every recorded destination on the row, so the
	// answer and the disarming have to land together or the unattended sweep can
	// fire in between with the old evidence and the new authority.
	tx, txErr := h.db.BeginTx(ctx, nil)
	if txErr != nil {
		logError(r, "vault.ownership: begin failed", "entry", entryID, "error", txErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	defer func() { _ = tx.Rollback() }()
	qtx := h.queries.WithTx(tx)

	if _, tErr := vaultegress.TransferSecretOwnership(ctx, qtx, proof,
		vaultegress.TransferOwnershipParams{NewOwnerUserID: actor, ID: entryID}); tErr != nil {
		if strings.Contains(tErr.Error(), "UNIQUE constraint") {
			// The transfer moves the custodian as well as the owner, which is
			// what the one sanctioned statement does, so the entry's name lands
			// in the admin's UNIQUE(user_id, name) namespace. Say so; renaming
			// silently would edit an entry the admin is looking at.
			writeConflict(w, r, "you already have a vault entry with that name. Rename one of them and "+
				"claim again: taking ownership moves the entry into your namespace")
			return
		}
		logError(r, "vault.ownership: transfer failed", "entry", entryID, "error", tErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	withdrawn, wErr := h.disarmRecordedDestinations(ctx, qtx, entryID)
	if wErr != nil {
		logError(r, "vault.ownership: could not clear the recorded destinations", "entry", entryID,
			"error", wErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	if cErr := tx.Commit(); cErr != nil {
		logError(r, "vault.ownership: commit failed", "entry", entryID, "error", cErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	// The URL blind index is keyed to bidxScope(user_id, collection_id), so
	// moving the custodian of a PERSONAL entry invalidates it and autofill would
	// silently stop offering the entry. Same recompute MoveToCollection does,
	// for the same reason.
	h.reindexAfterCustodianChange(r, entryID, actor, access.CollectionID)

	LogActivityFromRequest(h.queries, r, "vault.ownership_claimed", fmt.Sprintf(
		"Entry %s: secret ownership claimed by admin %s (it had none; %s)%s",
		entryID, actor, proof.Why(), withdrawn.auditSuffix()))

	withdrawn.EntryID = entryID
	withdrawn.SecretOwnerUserID = actor
	writeJSON(w, http.StatusOK, withdrawn)
}

// withdrawnEvidence is what a claim took OUT of the row on its way in.
//
// It is returned to the admin rather than only logged, because these are values
// they may well want back and a repair surface that silently deletes an
// operator's configuration is a worse outage than the one it repairs.
type withdrawnEvidence struct {
	EntryID           string `json:"entry_id"`
	SecretOwnerUserID string `json:"secret_owner_user_id"`
	// DestinationPatterns is the capability ceiling as it stood, verbatim, so
	// re-entering it is a copy and not an archaeology exercise.
	DestinationPatterns []string `json:"cleared_destination_patterns"`
	// ProviderMetaKeys are the provider_meta keys that chose a host, with the
	// values they held.
	ProviderMetaKeys map[string]string `json:"cleared_provider_meta"`
	// Why is the operator-facing sentence. Present even when nothing was
	// cleared, so the page can always say what the claim did.
	Why string `json:"why"`
}

func (wd withdrawnEvidence) anything() bool {
	return len(wd.DestinationPatterns) > 0 || len(wd.ProviderMetaKeys) > 0
}

// auditSuffix renders the withdrawal for the activity row. Empty when there was
// nothing to withdraw, so an ordinary claim keeps its ordinary line.
func (wd withdrawnEvidence) auditSuffix() string {
	if !wd.anything() {
		return ""
	}
	var parts []string
	if len(wd.DestinationPatterns) > 0 {
		parts = append(parts, "destination_patterns "+strings.Join(wd.DestinationPatterns, " "))
	}
	for _, k := range sortedMetaKeys(wd.ProviderMetaKeys) {
		parts = append(parts, "provider_meta."+k+" = "+wd.ProviderMetaKeys[k])
	}
	return ". Recorded destinations chosen by the previous holder were WITHDRAWN and must be " +
		"re-entered deliberately: " + strings.Join(parts, "; ")
}

// disarmRecordedDestinations clears the two columns an attacker who held this
// row could have written, at the moment the row acquires an owner again.
//
// THIS IS THE HALF THAT MAKES THE REPAIR SAFE, and it is the answer to the
// question the read-time rule leaves open. ownerRecordedDestinations counts
// destination_patterns and the meta-derived provider hosts only while the
// entry's recorded owner may still direct its secret. On a row the migration
// withheld, nobody may, so the evidence is inert. Answering the question turns
// it back on, and the previous holder is exactly who wrote it: without this, an
// admin doing the right thing at Settings -> Ownership would silently adopt the
// attacker's collector as a place their secret may go.
//
// Clearing rather than keeping is deliberate, and it costs something real: an
// entry whose LEGITIMATE ceiling and provider host were withheld loses them too,
// and the admin has to put them back. They are returned in the response and
// written into the activity row for exactly that reason. Re-entering them is an
// ordinary PUT /api/vault/{id} which goes through egressgate.Decide with the new
// owner as the authority, so what comes back is attributable in a way what was
// there never was.
//
// It is not a permission check and does not need one: clearing a destination is
// a NARROWING, egressgate.Decide grants a ticket for it without consulting the
// authority oracle, and that is the same rule that keeps "clear the ceiling"
// available as the product's only per-secret agent revocation.
func (h *VaultHandler) disarmRecordedDestinations(ctx context.Context, q *db.Queries,
	entryID string) (withdrawnEvidence, error) {

	wd := withdrawnEvidence{
		Why: "nothing was recorded on this entry, so the claim withdrew nothing",
	}
	meta, err := q.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		return wd, fmt.Errorf("read entry %s: %w", entryID, err)
	}

	// destination_patterns.
	if stored := parseDestinationPatterns(meta.DestinationPatterns); len(stored) > 0 {
		wd.DestinationPatterns = stored
		tk, dErr := egressgate.Decide(egressgate.Request{
			EntryID: entryID,
			What:    vaultegress.FieldDestinations,
			Before:  ceilingDestinations(stored),
			After:   nil,
		})
		if dErr != nil {
			return wd, fmt.Errorf("decide the ceiling clear: %w", dErr)
		}
		if sErr := vaultegress.SetDestinationPatterns(ctx, q, tk,
			vaultegress.DestinationPatternsParams{DestinationPatterns: "", ID: entryID}); sErr != nil {
			return wd, fmt.Errorf("clear the ceiling: %w", sErr)
		}
	}

	// The provider_meta keys that CHOOSE A HOST, and only those. Clearing the
	// whole column would take out account ids and region-free settings that
	// name nowhere, which is destruction without a security argument.
	stored := ParseProviderMeta(h.decryptColumnOrLog(meta.ProviderMeta.String, "{}", vaultFieldProviderMeta))
	cleared := map[string]string{}
	next := map[string]string{}
	for k, v := range stored {
		next[k] = v
	}
	for _, k := range egressInfluencingMetaKeys() {
		if v, ok := next[k]; ok {
			cleared[k] = v
			delete(next, k)
		}
	}
	if len(cleared) > 0 {
		wd.ProviderMetaKeys = cleared
		tk, dErr := egressgate.Decide(egressgate.Request{
			EntryID: entryID,
			What:    vaultegress.FieldProviderMeta,
			Before:  providerDestinations(meta.Provider.String, stored),
			After:   providerDestinations(meta.Provider.String, next),
			Covers:  providerDestinationCovers,
		})
		if dErr != nil {
			return wd, fmt.Errorf("decide the provider_meta clear: %w", dErr)
		}
		encoded, mErr := json.Marshal(next)
		if mErr != nil {
			return wd, fmt.Errorf("encode provider_meta: %w", mErr)
		}
		enc, eErr := h.encryptColumn(string(encoded))
		if eErr != nil {
			return wd, fmt.Errorf("encrypt provider_meta: %w", eErr)
		}
		if sErr := vaultegress.SetProviderMeta(ctx, q, tk,
			vaultegress.ProviderMetaParams{ProviderMeta: toNullString(enc), ID: entryID}); sErr != nil {
			return wd, fmt.Errorf("clear the host-choosing provider_meta keys: %w", sErr)
		}
	}

	if wd.anything() {
		wd.Why = "the destinations recorded on this entry were chosen by whoever held it before the " +
			"migration withheld its owner. Claiming ownership answers the question those records were " +
			"waiting on, so they were withdrawn rather than adopted. Re-enter the ones you want; the " +
			"write goes through the same gate as any other, with you as the authority"
	}
	return wd, nil
}

// sortedMetaKeys is a stable rendering order for a message an operator reads.
func sortedMetaKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// reindexAfterCustodianChange recomputes the URL blind indexes under the entry's
// new scope. A failure is logged and not fatal: the ownership move already
// committed and is the point of the request, whereas a stale index degrades
// autofill and is repaired by any later save.
func (h *VaultHandler) reindexAfterCustodianChange(r *http.Request, entryID, newCustodian string,
	collectionID sql.NullString) {

	ctx := r.Context()
	meta, err := h.queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		logError(r, "vault.ownership: reindex lookup failed", "entry", entryID, "error", err)
		return
	}
	scope := bidxScope(newCustodian, collectionID)
	urlPlain := h.decryptColumnOrLog(meta.Url.String, "", vaultFieldURL)
	aliasPlain := h.decryptColumnOrLog(meta.AliasUrl.String, "", vaultFieldAliasURL)
	if err := h.queries.UpdateVaultEntryMetaAtRest(ctx, db.UpdateVaultEntryMetaAtRestParams{
		Url:          meta.Url,
		AliasUrl:     meta.AliasUrl,
		Username:     meta.Username,
		Category:     meta.Category,
		Notes:        meta.Notes,
		UrlBidx:      h.urlBlindIndex(scope, urlPlain),
		AliasUrlBidx: h.urlBlindIndex(scope, aliasPlain),
		ID:           entryID,
	}); err != nil {
		logError(r, "vault.ownership: reindex failed", "entry", entryID, "error", err)
	}
}

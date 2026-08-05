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
	// RecordedOwnerUserID is set only for the second class below: a row that HAS
	// an owner who may no longer direct it. Empty for the backfill's own rows,
	// which is what the page already knew how to render.
	RecordedOwnerUserID string `json:"recorded_owner_user_id"`
	RecordedOwnerEmail  string `json:"recorded_owner_email"`
	// Why is the operator-facing reason this row has no owner, in the words the
	// migration would use. It is derived here rather than stored, because the
	// migration cannot write a per-row explanation into a column the exit reads.
	Why string `json:"why"`
	// Cause is the machine-readable half of Why for the second class, so the page
	// can render a remedy without parsing prose. Empty for the backfill's own
	// rows, whose cause is the migration and is already in Why.
	Cause string `json:"cause"`
	// Remedy is the action that puts the row back the way it was WITHOUT moving
	// ownership, when one exists. It is the first thing an operator should try,
	// because taking ownership is the heavier of the two and until the restore
	// route existed it was also the irreversible one.
	Remedy string `json:"remedy"`
	// Reversible says whether Remedy undoes the cause through an ordinary product
	// route. It is the difference between "somebody's account is gone" and
	// "somebody's collection role changed", and the page must not present those
	// as the same situation: the second is routine, reversible, and any manager
	// of the collection can have caused it without touching the entry.
	Reversible bool `json:"reversible"`
}

// The causes a recorded owner can stop being able to direct their own entry.
//
// They are the branches of mayDirectSecretEgress read backwards. That function
// answers yes or no and an operator needs the reason, so this enumerates the
// ways the answer turns to no and each one's way back.
const (
	causeOwnerAccountDeleted  = "owner_account_deleted"
	causeOwnerAccountDisabled = "owner_account_disabled"
	// causeOwnerNotInCollection is deliberately NOT called "left the collection".
	//
	// "A manager removed them" and "they were never a member and were directing
	// this entry with an instance admin role that has since changed" leave the
	// database in the SAME state: no row in collection_members, and a users row
	// whose role is no longer admin. There is no column that distinguishes them,
	// so a page that picks one is guessing, and the guess it used to make sent
	// operators to ask a collection manager about a removal that never happened.
	causeOwnerNotInCollection     = "owner_not_in_collection"
	causeOwnerDemotedInCollection = "owner_demoted_in_collection"
	causeOwnerLostInstanceAdmin   = "owner_lost_instance_admin"
	causeOwnerUnknown             = "owner_unknown"
)

// ownerUnreachableDiagnosis is why one recorded owner can no longer direct one
// entry, and what puts it back.
type ownerUnreachableDiagnosis struct {
	Cause      string
	Why        string
	Remedy     string
	Reversible bool
}

// diagnoseUnreachableOwner asks WHICH of the ways to lose manage happened.
//
// THE PAGE USED TO ASSERT ONE CAUSE FOR ALL OF THEM. Every row in this class
// carried the sentence "the recorded owner was removed from the collection it
// lives in, which any manager of that collection can do", because that is the
// case the class was added for. It is one of at least five, and the sentence
// names a person: an operator reading it goes and asks a collection manager why
// they removed a colleague who was never removed, or who was never in that
// collection, or whose account was disabled by another admin an hour ago.
//
// Two of the observed cases had nothing to do with the collection at all. An
// instance admin who owns an entry in a collection they are not a member of
// holds manage through the admin flag alone, so demoting them from admin to user
// strands every such entry and the page blamed a manager. A member demoted from
// manager to viewer inside the collection is still an ACCEPTED member, and the
// page said they were removed.
//
// It reads only rows the caller may already read: this is an AdminOnly route and
// an instance admin can list the users table and every collection's members.
//
// A cause it cannot prove is causeOwnerUnknown with no remedy, which is the
// honest answer and is better than the confident wrong one it replaces.
func (h *VaultHandler) diagnoseUnreachableOwner(ctx context.Context, e unownedEntry) ownerUnreachableDiagnosis {
	owner := strings.TrimSpace(e.RecordedOwnerUserID)
	who := e.RecordedOwnerEmail
	if who == "" {
		who = owner
	}
	where := e.CollectionName
	if where == "" {
		where = e.CollectionID
	}

	// THE ACCOUNT FIRST, because instanceAdminByRecord refuses a missing or
	// disabled one before it looks at anything else, so an account answer makes
	// every collection answer below it moot.
	u, err := h.queries.GetUserByID(ctx, owner)
	switch {
	case err == sql.ErrNoRows:
		return ownerUnreachableDiagnosis{
			Cause: causeOwnerAccountDeleted,
			Why: "the account recorded as this entry's secret owner no longer exists, so nothing " +
				"can answer for where this secret may be sent and the entry contributes no delivery " +
				"destinations at all",
			Remedy: "take ownership here. There is no account to restore, so this is the repair",
		}
	case err != nil:
		// A read error is not a cause. Say nothing rather than guess.
		return ownerUnreachableDiagnosis{
			Cause: causeOwnerUnknown,
			Why: "this entry records a secret owner who can no longer reach it, so it contributes no " +
				"delivery destinations. The reason could not be read from the database",
		}
	case u.Disabled != 0:
		return ownerUnreachableDiagnosis{
			Cause: causeOwnerAccountDisabled,
			Why: "the account recorded as this entry's secret owner (" + who + ") is DISABLED, and a " +
				"disabled account may not direct a secret anywhere, so the entry contributes no " +
				"delivery destinations",
			Remedy:     "re-enable " + who + " if that was not deliberate. Nothing was written on the entry",
			Reversible: true,
		}
	}

	// A COLLECTION ENTRY. Manage comes from the collection role, so the question
	// is whether they are still a manager of it.
	if e.CollectionID != "" {
		role, rErr := h.queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
			CollectionID: e.CollectionID,
			UserID:       owner,
		})
		switch {
		case rErr != nil:
			// GetCollectionMemberRole returns no row for a pending or absent
			// membership. That covers a member who was removed AND a principal who
			// was never in the collection at all and held manage through the
			// instance admin flag, and those two are the same rows. Say what is
			// true of both and name both ways back.
			return ownerUnreachableDiagnosis{
				Cause: causeOwnerNotInCollection,
				Why: "this entry records a secret owner (" + who + ") who is not an accepted member of " +
					"the collection it lives in (" + where + ") and is not an instance admin, so nothing " +
					"gives them manage on it and the entry contributes no delivery destinations at all. " +
					"NOTHING WAS WRITTEN ON THE ENTRY. Either they were removed from " + where + ", which " +
					"any manager of that collection can do, or they were never a member of it and were " +
					"directing this entry with an instance admin role that has since changed. The " +
					"database records the state and not which of the two happened",
				Remedy: "add " + who + " to " + where + " as a manager, or restore their instance admin " +
					"role, whichever matches what changed. Nothing on the entry changed",
				Reversible: true,
			}
		case role != collRoleManager:
			return ownerUnreachableDiagnosis{
				Cause: causeOwnerDemotedInCollection,
				Why: "this entry records a secret owner (" + who + ") who is STILL an accepted member " +
					"of " + where + " but no longer manages it, so they may no longer choose where this " +
					"secret goes and the entry contributes no delivery destinations. Nothing was written " +
					"on the entry: any manager of that collection can change another member's role",
				Remedy:     "restore " + who + " to manager in " + where + ". Nothing on the entry changed",
				Reversible: true,
			}
		}
		return ownerUnreachableDiagnosis{
			Cause: causeOwnerUnknown,
			Why: "this entry records a secret owner (" + who + ") who manages the collection it lives " +
				"in and still cannot direct it. This is not one of the causes this page knows how to " +
				"explain",
		}
	}

	// A PERSONAL ENTRY. Manage comes from holding the row or from the instance
	// admin flag, so an owner who is neither has lost the flag.
	if owner != e.CustodianUserID && u.Role != middleware.RoleAdmin {
		return ownerUnreachableDiagnosis{
			Cause: causeOwnerLostInstanceAdmin,
			Why: "this entry records a secret owner (" + who + ") who does not hold the entry and is " +
				"no longer an instance admin, so the authority they were directing it with is gone and " +
				"the entry contributes no delivery destinations. NOBODY TOUCHED THIS ENTRY OR ANY " +
				"COLLECTION: an instance role changed from admin to user",
			Remedy: "restore " + who + " to the admin role if that was not deliberate. Nothing on the " +
				"entry changed",
			Reversible: true,
		}
	}
	return ownerUnreachableDiagnosis{
		Cause: causeOwnerUnknown,
		Why: "this entry records a secret owner (" + who + ") who can no longer reach it, so it " +
			"contributes no delivery destinations. This is not one of the causes this page knows how " +
			"to explain",
	}
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
	// THE SECOND CLASS: a row that HAS a recorded owner who can no longer direct
	// it.
	//
	// The list used to be exactly "secret_owner_user_id = ''", which is the set
	// the backfill withheld. That is not the set of entries that cannot accept a
	// delivery destination. ownerRecordedDestinations counts a recorded owner's
	// destinations only while that owner still holds manage, so a collection
	// manager runs DELETE /api/collections/{id}/members/{owner}, writes nothing
	// on the entry, and the entry silently stops contributing every destination
	// it has. Its owner column still names somebody, so it never appeared here.
	//
	// An admin who cannot SEE a stranded row cannot repair it, and the whole
	// reason this page exists is that an operator with no surface reaches for
	// sqlite3 instead. The claim route accepts these now; this is how they are
	// found.
	expired, xErr := h.expiredOwnerEntries(ctx)
	if xErr != nil {
		logError(r, "vault.ownership: expired-owner scan failed", "error", xErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	report.Entries = append(report.Entries, expired...)

	report.Total = len(report.Entries)
	writeJSON(w, http.StatusOK, report)
}

// expiredOwnerEntries lists entries whose recorded owner may no longer direct
// the secret.
//
// Raw SQL rather than a generated query because the authority question is not
// expressible in it: "may this principal still direct this secret" is
// mayConfigureDelivery, which resolves collection membership and the admin flag
// from rows this select does not join. So the SQL narrows to entries that have
// an owner at all, and the oracle decides, one row at a time. Admin-only route,
// bounded by the instance's own vault.
func (h *VaultHandler) expiredOwnerEntries(ctx context.Context) ([]unownedEntry, error) {
	rows, err := h.db.QueryContext(ctx, `
		SELECT e.id, e.name, e.user_id, e.collection_id, e.created_at, e.updated_at,
		       COALESCE(cu.email, ''), COALESCE(c.name, ''),
		       e.secret_owner_user_id, COALESCE(ou.email, '')
		FROM vault_entries e
		LEFT JOIN users cu ON cu.id = e.user_id
		LEFT JOIN users ou ON ou.id = e.secret_owner_user_id
		LEFT JOIN collections c ON c.id = e.collection_id
		WHERE e.secret_owner_user_id != ''
		ORDER BY e.created_at`)
	if err != nil {
		return nil, fmt.Errorf("list entries with a recorded owner: %w", err)
	}
	defer rows.Close()

	// DRAIN FIRST, THEN ASK. The authority question is a QUERY, and asking it
	// while this cursor is open holds two connections per request.
	//
	// database.Connect caps the pool at 10. At 9 concurrent requests this route
	// answered in about 400ms; at exactly 10 every connection was held by a
	// cursor waiting for a connection, no request completed, and an unrelated
	// SELECT on the same *sql.DB never returned. Nothing cancels those contexts,
	// so the outage lasted as long as the callers held their sockets: one admin
	// page took the whole process's database down. The same rows and the same
	// query count with the cursor closed first answer in about 120ms.
	type pending struct {
		e unownedEntry
	}
	var drained []pending
	for rows.Next() {
		var e unownedEntry
		var collectionID, createdAt, updatedAt sql.NullString
		if sErr := rows.Scan(&e.ID, &e.Name, &e.CustodianUserID, &collectionID, &createdAt,
			&updatedAt, &e.CustodianEmail, &e.CollectionName, &e.RecordedOwnerUserID,
			&e.RecordedOwnerEmail); sErr != nil {
			return nil, fmt.Errorf("scan entry with a recorded owner: %w", sErr)
		}
		e.CollectionID = collectionID.String
		e.CreatedAt = createdAt.String
		e.UpdatedAt = updatedAt.String
		drained = append(drained, pending{e: e})
	}
	if rErr := rows.Err(); rErr != nil {
		return nil, fmt.Errorf("iterate entries with a recorded owner: %w", rErr)
	}
	if cErr := rows.Close(); cErr != nil {
		return nil, fmt.Errorf("close the recorded-owner cursor: %w", cErr)
	}

	out := []unownedEntry{}
	for _, p := range drained {
		e := p.e
		live, lErr := h.recordedOwnerMayDirect(ctx, e.ID)
		if lErr != nil {
			// A read error is not "this row is fine". Skipping it would hide a
			// stranded entry behind a transient database problem, and the operator
			// would see a shorter list rather than an error.
			return nil, fmt.Errorf("read the recorded owner of %s: %w", e.ID, lErr)
		}
		if live {
			continue
		}
		d := h.diagnoseUnreachableOwner(ctx, e)
		e.Cause = d.Cause
		e.Why = d.Why
		e.Remedy = d.Remedy
		e.Reversible = d.Reversible
		out = append(out, e)
	}
	return out, nil
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
	// A RECORDED OWNER IS NOT THE SAME AS A LIVE ONE.
	//
	// This used to refuse every row whose owner column was non-empty, which is
	// right for an owner who can still direct the secret and wrong for one who
	// cannot. ownerRecordedDestinations counts a recorded owner's destinations
	// only while that owner still holds manage on the entry, so a collection
	// MANAGER removes a colleague from the collection with one ordinary call,
	//
	//	DELETE /api/collections/{id}/members/{owner}
	//
	// writes nothing on the entry at all, and the entry stops contributing every
	// destination it has. The owner column still names somebody, so the only
	// repair route in the product refused it and the row was stranded for good.
	// The migration's own operator notice sends people to this page.
	//
	// So the question is the one the exit asks: may the recorded owner still
	// direct this secret? If yes, this route stays closed, because moving a live
	// ownership would be a second transfer path with a friendlier name and the
	// whole point of the column is that there is one.
	if access.SecretOwnerUserID != "" {
		live, lErr := h.recordedOwnerMayDirect(ctx, entryID)
		if lErr != nil {
			logError(r, "vault.ownership: could not read the recorded owner", "entry", entryID,
				"error", lErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if live {
			// THE REFUSAL NAMES THE REMEDY, because the one it used to give was a
			// dead end and dead ends are what send an operator to sqlite3.
			//
			// The row this refusal is most often asked about is one whose owner
			// column names somebody the instance cannot account for: a database
			// that ran the first cut of 00034 had user_id copied into it, and an
			// operator who repaired a column by hand put somebody there too. Such
			// a row is neither of the two classes the page lists (its owner is
			// recorded, and that owner CAN direct it), so the page showed nothing
			// and this route said no, and the honest reading of that pair is
			// "the product has no remedy". It does.
			//
			// Disarming does not require ownership to move. Clearing a destination
			// is a NARROWING, egressgate.Decide grants a ticket for one without
			// consulting the authority oracle, and an instance admin can therefore
			// take every planted host off the row with an ordinary save. That is
			// the action to name here, along with what the row currently
			// authorises, so the admin can tell whether it needs taking.
			armed := ""
			if hosts, hErr := h.ownerRecordedDestinations(ctx, entryID); hErr == nil &&
				len(hosts.Hosts) > 0 {
				armed = " This entry currently authorises delivery to: " +
					strings.Join(hosts.Hosts, ", ") + "."
			}
			writeConflict(w, r, "this entry already records a secret owner who may still direct it; "+
				"ownership moves only when a user is deleted, when a migration could not prove one, or "+
				"when the recorded owner can no longer reach the entry."+armed+
				" If the recorded owner is not who should be directing this secret, you do not need "+
				"ownership to disarm it: clearing the agent destinations and the provider settings that "+
				"name a host with an ordinary save on the entry is a narrowing, which an instance admin "+
				"may always make. Ownership itself moves only after the recorded owner's account is "+
				"deleted or disabled")
			return
		}
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

	withdrawn, wErr := h.disarmRecordedDestinations(ctx, qtx, entryID, actor)
	if wErr != nil {
		logError(r, "vault.ownership: could not clear the recorded destinations", "entry", entryID,
			"error", wErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	// THE CLAIM IS RECORDED AS A ROW, in the same transaction as the ownership it
	// grants.
	//
	// Migrations 00035 and 00036 have to know which ownerships an admin took
	// deliberately, so they can spare those while withdrawing the ones nothing can
	// prove. They used to ask the activity log with an unanchored instr() over the
	// prose detail below, and that detail carried the withdrawn destination_patterns
	// and provider_meta VALUES, all written by the previous holder of this row. The
	// previous holder of entry A could therefore put "Entry <B>:" in a field of A
	// and spare a laundered ownership on entry B.
	//
	// The withdrawn values live here too, as JSON, because they are worth keeping
	// and the audit sentence is no longer allowed to carry them.
	// IT ALSO RECORDS WHO IT DISPLACED, which is what makes the claim undoable.
	//
	// access was read before the transfer, so these are the holder and custodian
	// as they stood when the admin pressed the button. Both are the ROW's values
	// and neither is reachable from the request: RestoreSecretOwnership will only
	// ever hand the entry back to previous_owner_user_id, so if a caller could
	// influence it, the restore would become the arbitrary-recipient transfer
	// vaultegress refuses.
	//
	// An empty previous owner is the honest value for the class the backfill
	// withheld: that claim displaced nobody, and restore refuses it rather than
	// inventing a holder.
	if _, iErr := tx.ExecContext(ctx,
		`INSERT INTO secret_ownership_claims
		   (entry_id, claimed_by, withdrawn_json, previous_owner_user_id, previous_custodian_user_id)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(entry_id) DO UPDATE SET
		   claimed_by = excluded.claimed_by,
		   claimed_at = CURRENT_TIMESTAMP,
		   withdrawn_json = excluded.withdrawn_json,
		   previous_owner_user_id = excluded.previous_owner_user_id,
		   previous_custodian_user_id = excluded.previous_custodian_user_id`,
		entryID, actor, withdrawn.json(), access.SecretOwnerUserID, access.UserID); iErr != nil {
		logError(r, "vault.ownership: could not record the claim", "entry", entryID, "error", iErr)
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

// restoredOwnership is what a restore put back, and what it deliberately did not.
type restoredOwnership struct {
	EntryID           string `json:"entry_id"`
	SecretOwnerUserID string `json:"secret_owner_user_id"`
	// PreviousCustodianUserID is reported only when it differs from the owner the
	// restore returned the entry to. See the note in RestoreSecretOwnership: the
	// one sanctioned statement moves both columns together, so a custodianship a
	// manager had taken is not re-created, and the operator is told rather than
	// left to discover it.
	PreviousCustodianUserID string `json:"previous_custodian_user_id,omitempty"`
	// WithdrawnNotRestored is the configuration the claim took off the row. It is
	// NOT put back automatically. See the note below.
	WithdrawnNotRestored json.RawMessage `json:"withdrawn_not_restored,omitempty"`
	Why                  string          `json:"why"`
}

// RestoreSecretOwnership handles POST /api/admin/vault/{id}/ownership/restore.
//
// THE UNDO FOR A CLAIM, and the reason the claim can stay available.
//
// Everything that makes an entry claimable is "its recorded owner cannot direct
// it right now", and almost every way to get there is reversible and is not an
// admin's doing. A collection manager removes the owner from the collection, or
// changes their role from manager to viewer; an admin demotes the owner's
// instance role. Nothing is written on the entry in any of those. The row then
// appears on the Ownership page, an admin does the helpful thing, and the
// reversible change has become permanent: ownership moved, the custodian moved
// with it, and the ceiling the owner configured was withdrawn. Putting the role
// back restored none of it, and there was no route that could.
//
// That is a non-admin escalation with an administrative shape. The manager never
// touched the entry and never needed to; they only had to wait for somebody with
// the right to act to look at a page that told them the row was stranded.
//
// WHAT IT PUTS BACK: the ownership, to the holder recorded on the claim, through
// vaultegress.AuthorizeRestore, which refuses every recipient except that one.
//
// WHAT IT DOES NOT PUT BACK, deliberately: the destinations the claim withdrew.
// Those are returned in the response and were returned by the claim, so
// re-entering them is a copy. Re-arming them here would write hosts back onto a
// row on the authority of a stored blob rather than of a principal, and the
// single rule this module rests on is that a destination is authorised by
// somebody who may direct the secret AT THE MOMENT IT IS WRITTEN. An ordinary
// PUT /api/vault/{id} by the restored owner goes through egressgate.Decide with
// them as the authority, which is attributable in a way a replay would not be.
func (h *VaultHandler) RestoreSecretOwnership(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entryID := chi.URLParam(r, "id")
	if strings.TrimSpace(entryID) == "" {
		writeBadRequest(w, r, "no entry id")
		return
	}
	actor := middleware.GetUserID(ctx)
	if actor == "" {
		writeForbidden(w, r, "an ownership restore has to name the admin making it")
		return
	}

	if _, err := h.queries.GetVaultEntryAccess(ctx, entryID); err == sql.ErrNoRows {
		writeNotFound(w, r, "vault entry not found")
		return
	} else if err != nil {
		logError(r, "vault.ownership: restore access lookup failed", "entry", entryID, "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	var prevOwner, prevCustodian, withdrawnJSON string
	rErr := h.db.QueryRowContext(ctx,
		`SELECT previous_owner_user_id, previous_custodian_user_id, withdrawn_json
		 FROM secret_ownership_claims WHERE entry_id = ?`, entryID).
		Scan(&prevOwner, &prevCustodian, &withdrawnJSON)
	if rErr == sql.ErrNoRows {
		writeConflict(w, r, "no ownership claim is recorded for this entry, so there is nothing to "+
			"undo. Ownership moves only through a claim, and a claim always records what it displaced")
		return
	}
	if rErr != nil {
		logError(r, "vault.ownership: could not read the claim record", "entry", entryID, "error", rErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	prevOwner = strings.TrimSpace(prevOwner)
	if prevOwner == "" {
		writeConflict(w, r, "the claim on this entry displaced nobody: the migration could not prove "+
			"an owner for it, so it had none to return. This entry is owned deliberately now, and the "+
			"way to move it again is another claim")
		return
	}

	// COULD THEY DIRECT IT AGAIN? Asked BEFORE the write, because a restore that
	// hands the row back to somebody who still cannot reach it puts it straight
	// back into the stranded class while reporting success, and the operator has
	// spent their undo. This is the same manage question mayDirectSecretEgress
	// asks; it cannot be mayConfigureDelivery because that one also requires the
	// principal to be the RECORDED owner, which is exactly what has not happened
	// yet.
	if !h.grantFor(ctx, prevOwner, h.instanceAdminByRecord(ctx, prevOwner), entryID).manage {
		writeConflict(w, r, "the holder recorded on this claim still cannot reach this entry, so "+
			"returning it would strand the row again. Put back whatever changed first (their "+
			"collection role, their instance role, or their account), then restore")
		return
	}

	proof, pErr := vaultegress.AuthorizeRestore(vaultegress.RestoreRequest{
		EntryID:               entryID,
		Actor:                 actor,
		ActorIsInstanceAdmin:  h.instanceAdminByRecord(ctx, actor),
		RecordedPreviousOwner: prevOwner,
		To:                    prevOwner,
		Why: "ownership restore: this entry was claimed while its recorded owner could not reach it, " +
			"and the condition that stranded it has been undone",
	})
	if pErr != nil {
		writeForbidden(w, r, pErr.Error())
		return
	}

	tx, txErr := h.db.BeginTx(ctx, nil)
	if txErr != nil {
		logError(r, "vault.ownership: restore begin failed", "entry", entryID, "error", txErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	defer func() { _ = tx.Rollback() }()
	qtx := h.queries.WithTx(tx)

	if _, tErr := vaultegress.TransferSecretOwnership(ctx, qtx, proof,
		vaultegress.TransferOwnershipParams{NewOwnerUserID: prevOwner, ID: entryID}); tErr != nil {
		if strings.Contains(tErr.Error(), "UNIQUE constraint") {
			writeConflict(w, r, "the holder this entry would go back to already has an entry with that "+
				"name. Rename one of them and restore again: ownership moves the entry into their namespace")
			return
		}
		logError(r, "vault.ownership: restore transfer failed", "entry", entryID, "error", tErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	// THE CLAIM RECORD GOES, because it has been undone. Leaving it would let the
	// same restore be replayed against a later, unrelated claim's state.
	if _, dErr := tx.ExecContext(ctx,
		`DELETE FROM secret_ownership_claims WHERE entry_id = ?`, entryID); dErr != nil {
		logError(r, "vault.ownership: could not clear the claim record", "entry", entryID, "error", dErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	if cErr := tx.Commit(); cErr != nil {
		logError(r, "vault.ownership: restore commit failed", "entry", entryID, "error", cErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	access, aErr := h.queries.GetVaultEntryAccess(ctx, entryID)
	if aErr == nil {
		h.reindexAfterCustodianChange(r, entryID, prevOwner, access.CollectionID)
	}

	LogActivityFromRequest(h.queries, r, "vault.ownership_restored", fmt.Sprintf(
		"Entry %s: secret ownership restored to the holder recorded on the claim, by admin %s (%s)",
		entryID, actor, proof.Why()))

	out := restoredOwnership{
		EntryID:           entryID,
		SecretOwnerUserID: prevOwner,
		Why: "this entry is owned and held by the principal recorded on the claim again. The " +
			"destinations the claim withdrew were NOT put back: re-enter the ones you want with an " +
			"ordinary save, so the write goes through the same gate as any other with a live " +
			"authority behind it",
	}
	if strings.TrimSpace(withdrawnJSON) != "" && strings.TrimSpace(withdrawnJSON) != "{}" {
		out.WithdrawnNotRestored = json.RawMessage(withdrawnJSON)
	}
	if pc := strings.TrimSpace(prevCustodian); pc != "" && pc != prevOwner {
		// Both columns move together through the one sanctioned statement, so the
		// entry goes back to its OWNER and not to whoever was holding it. When
		// those differed it is usually because a collection manager had adopted
		// the entry, and re-creating that is not something to do quietly.
		out.PreviousCustodianUserID = pc
		out.Why += ". Before the claim this entry was HELD by a different principal than it was owned " +
			"by, which is what an adoption by a collection manager looks like. It has gone back to its " +
			"owner and that custodianship was not re-created"
	}
	writeJSON(w, http.StatusOK, out)
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
// json is the withdrawal as stored on the claim row, which is where the VALUES
// live now.
func (wd withdrawnEvidence) json() string {
	b, err := json.Marshal(struct {
		DestinationPatterns []string          `json:"destination_patterns"`
		ProviderMetaKeys    map[string]string `json:"provider_meta"`
	}{wd.DestinationPatterns, wd.ProviderMetaKeys})
	if err != nil {
		// Never fail a repair over its own bookkeeping. The claim row is what the
		// migrations read; the values are a convenience on top of it.
		return "{}"
	}
	return string(b)
}

// auditSuffix renders the withdrawal for the activity row. Empty when there was
// nothing to withdraw, so an ordinary claim keeps its ordinary line.
//
// IT NAMES WHAT WAS WITHDRAWN AND NEVER THE VALUES. Those were written by the
// previous holder of this row, and this sentence used to interpolate them
// verbatim into an append-only log that two migrations then parsed with an
// unanchored instr() to decide who owns a secret. The values are on the claim
// row and in the response body; a caller's bytes do not belong in a sentence
// anything reads for authority, and the safe way to keep that true is for them
// never to be in it at all.
//
// The key NAMES are safe: egressInfluencingMetaKeys is a compile-time set.
func (wd withdrawnEvidence) auditSuffix() string {
	if !wd.anything() {
		return ""
	}
	var parts []string
	if n := len(wd.DestinationPatterns); n > 0 {
		parts = append(parts, fmt.Sprintf("destination_patterns (%d withdrawn)", n))
	}
	for _, k := range sortedMetaKeys(wd.ProviderMetaKeys) {
		parts = append(parts, "provider_meta."+k)
	}
	return ". Recorded destinations chosen by the previous holder were WITHDRAWN and must be " +
		"re-entered deliberately: " + strings.Join(parts, "; ") +
		". The withdrawn values are on the claim record and in this request's response"
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
	entryID, actor string) (withdrawnEvidence, error) {
	// THE ORACLE THIS DISARM ANSWERS TO.
	//
	// It used to pass none, which meant egressgate.Decide denied any request it
	// read as a widening, and a disarm CAN read as one: clearing datadog's "site"
	// does not remove a host, it swaps api.datadoghq.eu for the compile-time
	// default api.datadoghq.com. Added() sees a host that was not there before,
	// MayRedirect was nil, the disarm returned DeniedError, and the handler 500d.
	// Every datadog entry on a regional site was therefore permanently
	// unrepairable, and Settings -> Ownership is the page the migration notice
	// sends the operator to. datadoghq.eu is what an EU-sovereign product's
	// customers are on.
	//
	// The honest question is not "is this a narrowing" but "may this principal
	// direct this secret", and the answer is the same oracle every other egress
	// decision uses. instanceAdminByRecord reads the users row, so it is not
	// affected by the ownership transfer happening in this same transaction,
	// which a mayConfigureDelivery call here would not yet be able to see.
	mayRedirect := func() bool { return h.instanceAdminByRecord(ctx, actor) }

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
			EntryID:     entryID,
			What:        vaultegress.FieldDestinations,
			Before:      ceilingDestinations(stored),
			After:       nil,
			MayRedirect: mayRedirect,
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
			EntryID:     entryID,
			What:        vaultegress.FieldProviderMeta,
			Before:      providerDestinations(meta.Provider.String, stored),
			After:       providerDestinations(meta.Provider.String, next),
			Covers:      providerDestinationCovers,
			MayRedirect: mayRedirect,
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

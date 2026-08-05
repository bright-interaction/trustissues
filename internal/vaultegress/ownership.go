package vaultegress

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress/internal/egressq"
)

// WHO OWNS A SECRET, AND WHY THAT IS NOT A COLUMN A MEMBER MAY WRITE.
//
// Round 7 put every decrypted secret through one gate and asked one question:
// did the OWNER of the secret being sent authorise this destination. It resolved
// "owner" from vault_entries.user_id, and user_id is a column an ordinary
// product route lets a collection MANAGER write to their own id.
//
//	DELETE /api/collections/{id}/members/{creator}   manager-gated; now the
//	                                                 creator is not a member
//	PUT    /api/vault/{entry}  {"name": "..."}       managerMayAdoptOrphanedEntry
//	                                                 fires and AdoptAndRename-
//	                                                 VaultEntry writes user_id
//
// Two ordinary calls, and the manager was the owner. The exit then authorised
// the exact round-6 delivery it exists to refuse, because it was asking a
// question whose answer the attacker had just written.
//
// AN AUTHORITY DERIVED FROM DATA THE ATTACKER CAN WRITE IS NOT AN AUTHORITY.
//
// Taking adoption away was not the fix: adoption is what moves the
// UNIQUE(user_id, name) question into the renamer's own namespace, which is what
// stops a rename from being an existence oracle over a colleague's private
// vault. user_id was simply carrying two meanings, and the attack is exactly
// that conflation. So there are two columns, and this file owns the second one.
//
//	user_id               the CUSTODIAN. Adoption moves it, deliberately.
//	secret_owner_user_id  the OWNER. Only the exit asks about it, it is written
//	                      when the row is created, and the only statement in the
//	                      module that moves it afterwards is the one below.
//
// The enforcement is the same one the host-choosing columns already have and for
// the same reason: the statement is generated into
// internal/vaultegress/internal/egressq, which Go's `internal` rule puts out of
// reach of every package except this one, and the exported way in demands a
// value a handler cannot fabricate. What the compiler cannot see (a NEW query in
// internal/db, a hand-written statement) is covered by
// TestOnlyTheSanctionedStatementMovesTheSecretOwner, which hands every statement
// in the module to SQLite against a schema where secret_owner_user_id is
// GENERATED and lets the engine refuse the ones that assign it.

// TransferProof is proof that a deliberate ownership transfer was authorised,
// for ONE entry and ONE recipient.
//
// It is deliberately not a bool. A bool can be produced by forgetting to write
// the check; a TransferProof can only be produced by AuthorizeTransfer, and its
// zero value authorises nothing.
type TransferProof struct {
	entryID string
	to      string
	why     string
	granted bool
}

// TransferRequest is everything AuthorizeTransfer needs.
type TransferRequest struct {
	// EntryID is the entry whose ownership moves. The proof is bound to it, so a
	// decision made about one entry cannot be spent on another.
	EntryID string
	// Actor is the principal performing the transfer.
	Actor string
	// ActorIsInstanceAdmin must be resolved from the USERS ROW, never from a
	// session claim. Round 5 is what two sources for one fact costs: the write
	// gate read middleware.IsAdmin, the delivery gate hardcoded false, and an
	// admin's delivery target was accepted, reported as saved, and then silently
	// never delivered.
	ActorIsInstanceAdmin bool
	// To is the new owner. It must be Actor: see AuthorizeTransfer.
	To string
	// Why is the recorded reason, and it is required. A transfer with no stated
	// reason is not attributable, and attributability is half of what makes this
	// safe at all.
	Why string
}

// TransferDeniedError is what AuthorizeTransfer returns when it refuses.
type TransferDeniedError struct {
	EntryID, Actor, To, Reason string
}

func (e *TransferDeniedError) Error() string {
	return fmt.Sprintf("ownership transfer denied: %s may not make %s the owner of entry %s: %s",
		e.Actor, e.To, e.EntryID, e.Reason)
}

// AuthorizeTransfer is the ONLY constructor for a TransferProof.
//
// THE RULE, stated once: an instance admin may take ownership of an entry FOR
// THEMSELVES, and nobody may hand ownership to anybody else.
//
// Both halves matter.
//
//   - "an instance admin" because an instance admin already holds the widening
//     right on every entry (grantFor row 3), so the transfer hands them nothing
//     they did not already have. Every principal below that would be acquiring a
//     right by acting, which is the defect this whole file exists to close.
//   - "for themselves" because a route that can name an arbitrary recipient is a
//     route that can make a collection manager the owner. Then the attack is
//     back, one indirection further away, and it looks like an administrative
//     convenience rather than an escalation. The product's one genuine transfer
//     (an admin hard-deleting a user re-owns the shared entries that person
//     created, so the team keeps them) names the acting admin, so requiring it
//     costs nothing and closes the shape.
func AuthorizeTransfer(req TransferRequest) (TransferProof, error) {
	entry := strings.TrimSpace(req.EntryID)
	actor := strings.TrimSpace(req.Actor)
	to := strings.TrimSpace(req.To)
	why := strings.TrimSpace(req.Why)

	deny := func(reason string) (TransferProof, error) {
		return TransferProof{}, &TransferDeniedError{EntryID: entry, Actor: actor, To: to, Reason: reason}
	}
	switch {
	case entry == "":
		return deny("no entry was named, and a proof that names no entry would authorise every transfer")
	case actor == "":
		return deny("no acting principal was named")
	case to == "":
		return deny("no new owner was named")
	case why == "":
		return deny("no reason was recorded, so the transfer would not be attributable")
	case !req.ActorIsInstanceAdmin:
		return deny("that takes an instance admin, resolved from the users row")
	case to != actor:
		return deny("ownership may only be taken by the acting admin, never handed to a third party; " +
			"a route that can name an arbitrary recipient is a route that can make a collection " +
			"manager the owner")
	}
	return TransferProof{entryID: entry, to: to, why: why, granted: true}, nil
}

// RestoreRequest is everything AuthorizeRestore needs.
type RestoreRequest struct {
	// EntryID is the entry whose ownership goes back. The proof is bound to it.
	EntryID string
	// Actor is the admin undoing the claim.
	Actor string
	// ActorIsInstanceAdmin must be resolved from the USERS ROW, as above.
	ActorIsInstanceAdmin bool
	// RecordedPreviousOwner is what secret_ownership_claims stored when the claim
	// displaced somebody. IT MUST COME FROM THAT ROW AND NOT FROM THE REQUEST.
	// The whole safety argument below rests on this value being one the product
	// wrote about this entry, never one a caller chose.
	RecordedPreviousOwner string
	// To is who the caller intends to make the owner. AuthorizeRestore exists to
	// check that it equals RecordedPreviousOwner and nothing else.
	To string
	// Why is the recorded reason, and it is required, as above.
	Why string
}

// AuthorizeRestore is the second and last constructor for a TransferProof, and
// it is the ONLY way ownership reaches a principal who is not the acting admin.
//
// THE RULE: an instance admin may put an entry back with the exact holder the
// product recorded that a claim displaced, and may not name anybody else.
//
// WHY THIS IS NOT THE THIRD-PARTY TRANSFER AuthorizeTransfer REFUSES. That
// refusal is about a route whose recipient a CALLER chooses, because such a
// route can be driven to make a collection manager the owner and it looks like
// an administrative convenience while it does it. Here the recipient is read out
// of secret_ownership_claims.previous_owner_user_id, which ClaimSecretOwnership
// wrote from the entry's own row before it moved anything. There is no request
// field that reaches it. The most this route can do is return an entry to the
// state the product itself recorded one of its own actions displacing, which is
// strictly less than the claim that created the record was already allowed to do.
//
// WHY IT HAS TO EXIST. A claim is reachable exactly when the recorded owner
// cannot direct the entry, and almost every way to get there is reversible and
// is not an admin's doing: a collection manager removes the owner from the
// collection, or changes their role to viewer, and any admin who then does the
// helpful thing on the Ownership page makes it permanent. Without a way back,
// "somebody's collection role changed for an afternoon" and "somebody left the
// company" cost the same thing, and the cheaper one is available to a manager.
//
// The empty RecordedPreviousOwner is refused rather than defaulted. A claim on a
// row the backfill withheld displaced nobody, and defaulting to the custodian
// there would invent a holder the product never recorded.
func AuthorizeRestore(req RestoreRequest) (TransferProof, error) {
	entry := strings.TrimSpace(req.EntryID)
	actor := strings.TrimSpace(req.Actor)
	to := strings.TrimSpace(req.To)
	prev := strings.TrimSpace(req.RecordedPreviousOwner)
	why := strings.TrimSpace(req.Why)

	deny := func(reason string) (TransferProof, error) {
		return TransferProof{}, &TransferDeniedError{EntryID: entry, Actor: actor, To: to, Reason: reason}
	}
	switch {
	case entry == "":
		return deny("no entry was named, and a proof that names no entry would authorise every transfer")
	case actor == "":
		return deny("no acting principal was named")
	case why == "":
		return deny("no reason was recorded, so the restore would not be attributable")
	case !req.ActorIsInstanceAdmin:
		return deny("that takes an instance admin, resolved from the users row")
	case prev == "":
		return deny("nothing recorded a previous holder for this entry, so there is no state to " +
			"return it to; a restore that guessed one would be inventing an owner")
	case to != prev:
		return deny("a restore may only return the entry to the holder recorded on the claim it " +
			"undoes; naming any other recipient is the third-party transfer AuthorizeTransfer refuses")
	}
	return TransferProof{entryID: entry, to: to, why: why, granted: true}, nil
}

// Why is the recorded reason, so the caller can log what it just did.
func (p TransferProof) Why() string { return p.why }

// authorizes reports whether this proof covers a transfer of entryID to newOwner.
func (p TransferProof) authorizes(entryID, newOwner string) error {
	if !p.granted {
		return fmt.Errorf("vaultegress: refusing to move the owner of entry %s: the zero TransferProof "+
			"authorises nothing. Build one with AuthorizeTransfer", entryID)
	}
	if p.entryID != entryID {
		return fmt.Errorf("vaultegress: this TransferProof is for entry %s and was spent on entry %s",
			p.entryID, entryID)
	}
	if p.to != newOwner {
		return fmt.Errorf("vaultegress: this TransferProof makes %s the owner of entry %s and was spent "+
			"to make %s the owner", p.to, entryID, newOwner)
	}
	return nil
}

// TransferOwnershipParams names the entry and its new owner. Both columns move
// together; there is no way to spell moving one and not the other.
type TransferOwnershipParams struct {
	NewOwnerUserID string
	ID             string
}

// TransferSecretOwnership re-owns one entry: the custodian column and the
// secret-owner column together.
//
// The proof check is first, because a wrapper that performed the write and then
// complained would have already moved the authority.
func TransferSecretOwnership(ctx context.Context, q *db.Queries, p TransferProof,
	params TransferOwnershipParams) (sql.Result, error) {

	if err := p.authorizes(params.ID, params.NewOwnerUserID); err != nil {
		return nil, err
	}
	return writer(q).TransferVaultEntrySecretOwner(ctx, egressq.TransferVaultEntrySecretOwnerParams{
		UserID:            params.NewOwnerUserID,
		SecretOwnerUserID: params.NewOwnerUserID,
		ID:                params.ID,
	})
}

// OwnershipColumns is every vault_entries column that decides WHOSE AUTHORITY
// governs an entry's plaintext.
//
// Stated here, in the package that owns the write, for the same reason
// HostChoosingColumns is: so that reclassifying a column and forgetting to move
// its writer are not two independent edits. The guards read this.
//
// user_id is deliberately NOT in it. It is the custodian, adoption moves it on
// purpose, and putting it here would say the product has a bug where it has a
// feature.
func OwnershipColumns() []string { return []string{"secret_owner_user_id"} }

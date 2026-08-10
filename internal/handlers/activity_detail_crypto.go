package handlers

import (
	"context"
	"log/slog"
	"strings"

	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// THE THIRD MIRROR OF THE INVENTORY.
//
// 00040 encrypted vault_entries.name and audit_name_crypto.go encrypted the two
// audit tables that denormalise it, on the reasoning that a stolen database FILE
// should not hand a keyless reader the list of what this vault holds. Both were
// necessary and together they were still not sufficient, because a THIRD copy of
// those names was written on the same paths, in cleartext, into
// activity_log.detail:
//
//	"Vault secret created: Stripe live key (user: ...)"
//	"Vault secret deleted: GitHub production PAT (user: ...)"
//	"Auto-rotated vault secret: Neon prod connection string (provider: ...)"
//
// The name reaching those lines is PLAINTEXT by the time it does
// (vault_rotation.go calls EntryNamePlain at the top of its loop precisely so
// the operator-facing text reads), so this was not a theoretical mirror: on the
// instance this landed on, nine of twenty-eight activity rows named a secret,
// against a vault of five entries. The encrypted inventory was reconstructable
// in full from the log beside it. Same shape the estate keeps rediscovering, and
// the same one audit_name_crypto.go opens by naming: the fix lands on one of two
// twins. Here it was one of three.
//
// WHY THE NAME ONLY, AND NOT THE WHOLE LINE.
//
// Sealing the whole detail is simpler, cannot half-work, and is WRONG HERE, for
// a reason that is not obvious until the migrations are read:
//
//	00034/00035/00036 decide whose authority governs a stored secret partly from
//	this column, with instr(al.detail, vault_entries.id) > 0, in SQL.
//
// SQL cannot decrypt. A sealed detail is an opaque blob to instr(), so every
// entry that had passed through a collection would look to the backfill like one
// that never had, and a NON-CREATOR would be stamped as the owner of somebody
// else's secret. That is not a hypothetical: activity_entry_id_guard_test.go
// exists because a WORDING change already caused exactly that once, and five
// commits shipped before anyone noticed.
//
// So the constraint is that the entry id must stay matchable in cleartext. Given
// that, sealing the name alone is not the weaker option, it is the stronger one:
//
//   - it satisfies the migration constraint for every entry-scoped action that
//     exists AND every one added later, structurally, rather than by remembering
//     to exempt them. A future fourth action cannot silently break the backfill
//     the way whole-line sealing would.
//   - the action, actor, entry id, provider, collection labels and counts stay
//     readable and greppable without the key, which is most of what an operator
//     reads the log FOR. The inventory was never the part that had to be legible
//     to a keyless reader.
//
// The cost is the "which substring is the name" question, and that is answered
// by construction rather than by discipline: sealSecretName takes the NAME as
// its own argument and returns a self-delimiting token, so a call site cannot
// seal the wrong span. It can only forget entirely, and
// TestNoActivityWriterLeavesASecretNameInTheClear drives every writer with a
// distinctive name and fails if that name reaches the column.
//
// WHY THE SAME DEK AS THE AUDIT TABLES.
//
// Same class of data (an operator-facing record naming a secret) under the same
// constraint: activity_log has been append-only since 00003, so a master-key
// rotation can no more rewrite these rows than it can the audit tables. The
// audit DEK exists to answer exactly that and is already registered with the
// rekey sweep. A second key with an identical lifecycle would be two things to
// rotate and two things to lose.
//
// WHAT THIS DOES NOT DO: the rows already written. The append-only triggers mean
// the application cannot rewrite them, and that guarantee is worth more than
// those rows: an application that may rewrite audit history is indistinguishable
// from an attacker with application access covering their tracks, which is the
// path 00003 and 00039 exist to close.

// vaultFieldActivityDetail is the ledger handle for the sealed name inside an
// activity line.
//
// Declared separately from vaultFieldAuditName rather than borrowing it, even
// though both open under the same DEK: residual 1 in encrypted_field_ledger.go
// is that a door can borrow another column's Field and be recorded under the
// wrong name. Borrowing here would be doing that deliberately, in the ledger
// that exists to prevent it.
var vaultFieldActivityDetail = vaultfield.Declare(
	"activity_log.detail", vaultfield.NotACredential, "",
	"the vault entry name embedded in the activity line for the actions that name one: entry "+
		"created/updated/deleted/moved/rotated, the auto-rotation sweep, the offboard re-owning report "+
		"and the delivery-target authority report. Not a credential, and shown to any admin who can read "+
		"the activity page. Sealed at rest because this name is the same inventory vault_entries.name "+
		"and the audit tables were encrypted to withhold from a stolen file, and this was the third "+
		"copy. Only the NAME span is sealed, never the surrounding line, because migrations "+
		"00034/00035/00036 match the entry id in this column with SQL instr() and SQL cannot decrypt. "+
		"Sealed under the audit DEK rather than the master key because activity_log is append-only "+
		"since 00003, so a rekey sweep can never rewrite these rows.")

// The sealed name is wrapped in delimiters rather than left bare so the reader
// knows where it ends without depending on what the surrounding format string
// puts after it. Braces are outside the base64 alphabet and outside the enc:v1:
// prefix, so a token can never contain its own terminator.
const (
	sealedNameOpen  = "{{"
	sealedNameClose = "}}"
)

// sealSecretName seals ONE vault entry name for embedding in an activity line.
//
// It fails CLOSED: a name that cannot be sealed becomes a marker rather than the
// cleartext this function exists to prevent. The rest of the line is unaffected,
// so the row still answers who did what, to which entry id, when and from where
// even in the failure case.
func (h *VaultHandler) sealSecretName(ctx context.Context, name string) string {
	if name == "" {
		return ""
	}
	key, err := h.auditNameDEK(ctx)
	if err != nil {
		slog.Error("activity: could not seal a secret name for the activity log; recording a "+
			"placeholder instead of cleartext", "error", err)
		return activityDetailUnavailable
	}
	sealed, sErr := vaultfield.SealColumn(key, name)
	if sErr != nil {
		slog.Error("activity: sealing a secret name for the activity log failed", "error", sErr)
		return activityDetailUnavailable
	}
	return sealedNameOpen + sealed + sealedNameClose
}

// sealSecretNames seals a list of names for the two offboard lines that report
// several at once.
func (h *VaultHandler) sealSecretNames(ctx context.Context, names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, h.sealSecretName(ctx, n))
	}
	return out
}

// OpenActivityDetail replaces every sealed name span in a stored line with its
// plaintext, for display.
//
// Run over EVERY row of every read path rather than a known-sealed subset, on
// purpose: the log is a permanent mixture. Lines that name a secret carry sealed
// spans, every other action carries none, and the rows written before this
// existed never can, because activity_log has been append-only since 00003. A
// line with no span is returned unchanged, so one call covers all three cases
// and there is no per-action list to keep in sync with the writers.
//
// A span that does not open is left EXACTLY as it was found rather than replaced
// with a marker. The surrounding line carries user-chosen text (collection
// labels, provider names), so a user can put the literal "{{enc:v1:...}}" into
// one; leaving a non-opening span alone means the worst they achieve is seeing
// their own string rendered back, instead of making an audit line report that
// something was unavailable.
func (h *VaultHandler) OpenActivityDetail(ctx context.Context, stored string) string {
	if stored == "" || !strings.Contains(stored, sealedNameOpen+vaultfield.ColumnPrefix) {
		return stored
	}
	key, err := h.auditNameDEK(ctx)
	if err != nil {
		slog.Warn("activity: the audit key is unavailable, so sealed names cannot be shown", "error", err)
		return stored
	}

	var b strings.Builder
	rest := stored
	for {
		start := strings.Index(rest, sealedNameOpen+vaultfield.ColumnPrefix)
		if start < 0 {
			b.WriteString(rest)
			return b.String()
		}
		b.WriteString(rest[:start])
		body := rest[start+len(sealedNameOpen):]
		end := strings.Index(body, sealedNameClose)
		if end < 0 {
			// Unterminated: not something this module writes, so it is somebody
			// else's text. Emit it verbatim and stop scanning.
			b.WriteString(rest[start:])
			return b.String()
		}
		plain, oErr := vaultfield.OpenColumn(key, body[:end], vaultFieldActivityDetail)
		if oErr != nil {
			b.WriteString(rest[start : start+len(sealedNameOpen)+end+len(sealedNameClose)])
		} else {
			b.WriteString(plain)
		}
		rest = body[end+len(sealedNameClose):]
	}
}

// activityDetailUnavailable is what a failed seal records. It is deliberately
// distinct from the empty string, which reads as "this action recorded no name"
// rather than "a name was recorded and this process could not protect it".
const activityDetailUnavailable = "[unavailable]"

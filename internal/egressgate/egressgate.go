// Package egressgate holds the permission a write needs before it may change
// where a decrypted secret is sent.
//
// WHY THIS IS A PACKAGE AND NOT A FUNCTION.
//
// Five audit rounds reported the same defect with a different column name in
// it: the proxy path, then destination_patterns, then provider_meta, then
// rotation_targets.webhook_url. Round 4 answered it with a coverage table that
// forces every vault_entries column to be classified as host-choosing or not.
// The table was right and it still did not stop round 5, because a
// classification is a CLAIM about the code. rotation_targets was correctly
// labelled "chooses a host" and sat next to a handler that never asked anybody
// for permission. A table that says a field is dangerous, next to a write path
// that does not check, reads as coverage and is worse than no table.
//
// So the enforcement point is not a call a handler has to remember to make. It
// is a value a handler cannot fabricate:
//
//   - Ticket has no exported fields and no exported constructor other than
//     Decide. Package handlers can write egressgate.Ticket{}, but the zero value
//     authorizes nothing, so "I forgot to ask" and "I asked and was allowed"
//     cannot look the same to the code that performs the write.
//
//   - Every generated query that writes a host-choosing column lives in
//     internal/vaultegress/internal/egressq, which Go's own `internal` rule puts
//     out of reach of every package except internal/vaultegress, and the only
//     exported way in demands a Ticket for that entry and that field. Round 5
//     held that rule up with a test that read the source and matched it against
//     regular expressions, and four planted write paths walked through the gaps
//     while building clean. Now a handler that calls a host-choosing write does
//     not fail a test, it fails to compile:
//
//     h.queries.UpdateVaultEntryRotationTargets undefined
//     (type *db.Queries has no field or method UpdateVaultEntryRotationTargets)
//
//     What the compiler cannot see, a NEW query in internal/db or a hand-written
//     statement, is covered by
//     TestNoStatementOutsideTheEgressPackageWritesAHostChoosingColumn, which
//     asks SQLite rather than a pattern.
//
// Decide also decides WHEN to ask. Narrowing, clearing and re-saving an
// unchanged destination never consult the authority oracle, because clearing is
// the only per-secret revocation the product has and putting it behind a
// stricter right would take the revocation lever away. Only ADDING a
// destination asks.
package egressgate

import (
	"fmt"
	"sort"
	"strings"
)

// Ticket is proof that the authority question was asked, for one entry and one
// field, and answered yes.
//
// It is deliberately not comparable to a bool. A bool can be produced by
// forgetting to write the check; a Ticket can only be produced by Decide.
type Ticket struct {
	entryID string
	what    string
	added   []string
	granted bool
}

// Request is everything Decide needs to answer "may this write happen?".
type Request struct {
	// EntryID is the vault entry whose secret this write can redirect. A Ticket
	// is bound to it, so a decision made about one entry cannot be spent on
	// another.
	EntryID string
	// What names the field being written, for the refusal message and so a
	// Ticket for one column cannot be spent on a different column.
	What string
	// Before and After are the destination sets the write moves between. What a
	// "destination" is depends on the field (a capability pattern, a declared
	// provider host, a delivery target identity); this package only compares
	// them.
	Before []string
	After  []string
	// Covers reports whether an already-allowed destination `have` subsumes a
	// proposed destination `want`. nil means exact match after trimming and
	// lowercasing.
	//
	// It exists because the capability ceiling has a glob grammar: replacing
	// "api.openai.com/*" with "api.openai.com/v1/chat" is a NARROWING, and a
	// plain set difference would call it an addition and demand the widening
	// right for tightening a ceiling.
	Covers func(have, want string) bool
	// MayRedirect is the authority oracle, normally
	// VaultHandler.mayDirectSecretEgress. It is called ONLY when the write adds
	// a destination, and at most once.
	//
	// A nil oracle denies any addition. That is the fail-closed default: a call
	// site that has not decided who is allowed to redirect this secret has not
	// earned the right to redirect it.
	MayRedirect func() bool
}

// DeniedError is what Decide returns when a write would add a destination the
// caller may not add. Callers render Added in the 403 so the operator is told
// which destination did it.
type DeniedError struct {
	EntryID string
	What    string
	Added   []string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("egress widening denied: writing %s on entry %s would add %v to where this "+
		"secret may be sent, which takes the secret's owner or an instance admin",
		e.What, e.EntryID, e.Added)
}

// ErrNoSubject is returned when a decision is asked for with no entry or no
// field named. A Ticket with no subject would authorize every write, so this is
// an error rather than a permissive default.
type ErrNoSubject struct{ EntryID, What string }

func (e *ErrNoSubject) Error() string {
	return fmt.Sprintf("egress decision asked with entry=%q field=%q; both are required, because a "+
		"ticket that names neither would authorize any write", e.EntryID, e.What)
}

// Decide is the only constructor for a Ticket.
func Decide(req Request) (Ticket, error) {
	if strings.TrimSpace(req.EntryID) == "" || strings.TrimSpace(req.What) == "" {
		return Ticket{}, &ErrNoSubject{EntryID: req.EntryID, What: req.What}
	}

	added := Added(req.Before, req.After, req.Covers)
	if len(added) == 0 {
		// Narrowing, clearing, reordering, or re-saving what is already stored.
		// The oracle is deliberately NOT consulted: it would turn revocation
		// into a privileged operation.
		return Ticket{entryID: req.EntryID, what: req.What, granted: true}, nil
	}
	if req.MayRedirect == nil || !req.MayRedirect() {
		return Ticket{}, &DeniedError{EntryID: req.EntryID, What: req.What, Added: added}
	}
	return Ticket{entryID: req.EntryID, what: req.What, added: added, granted: true}, nil
}

// Added returns the destinations in after that before does not already cover.
//
// Exported because the same question is asked outside a decision (the refusal
// message on a pinned entry, tests that assert a write is a narrowing) and two
// implementations of "did this widen" is exactly the drift this package exists
// to prevent.
func Added(before, after []string, covers func(have, want string) bool) []string {
	if covers == nil {
		covers = exactMatch
	}
	var added []string
	seen := map[string]bool{}
	for _, want := range after {
		want = strings.TrimSpace(want)
		if want == "" || seen[want] {
			continue
		}
		covered := false
		for _, have := range before {
			if strings.TrimSpace(have) == "" {
				continue
			}
			if covers(have, want) {
				covered = true
				break
			}
		}
		if !covered {
			seen[want] = true
			added = append(added, want)
		}
	}
	sort.Strings(added)
	return added
}

func exactMatch(have, want string) bool {
	return strings.EqualFold(strings.TrimSpace(have), strings.TrimSpace(want))
}

// Authorizes reports whether this ticket permits writing field `what` on entry
// `entryID`. Every wrapper around a query that writes a host-choosing column
// calls it, and refuses the write on error.
//
// The zero Ticket fails here, which is the property the whole package rests on.
func (t Ticket) Authorizes(entryID, what string) error {
	if !t.granted {
		return fmt.Errorf("refusing to write %s on entry %q: no egress decision was made for it. "+
			"Call egressgate.Decide with the destination sets this write moves between; see "+
			"internal/handlers/vault_egress_writes.go", what, entryID)
	}
	if t.entryID != entryID {
		return fmt.Errorf("refusing to write %s on entry %q: the egress decision in hand was made for "+
			"entry %q. A decision about one secret cannot be spent on another", what, entryID, t.entryID)
	}
	if t.what != what {
		return fmt.Errorf("refusing to write %s on entry %q: the egress decision in hand was made for "+
			"%q. A decision about one field cannot be spent on another", what, entryID, t.what)
	}
	return nil
}

// Added reports the destinations this ticket authorized adding, for the audit
// line. Empty means the write was a narrowing or a no-op.
func (t Ticket) Added() []string { return append([]string(nil), t.added...) }

package handlers

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go/token"

	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE GUARD FOR THE COLUMN THE EXIT'S WHOLE ANSWER HANGS FROM.
//
// Round 7 asked one question at one point: did the OWNER of this secret
// authorise this destination. It resolved "owner" from vault_entries.user_id,
// and user_id is a column a collection MANAGER writes to their own id with two
// ordinary calls:
//
//	DELETE /api/collections/{id}/members/{creator}   manager-gated
//	PUT    /api/vault/{entry}  {"name":"..."}        adopt-and-rename
//
// so the gate was answering a question whose answer the attacker had just
// written. An authority derived from data the attacker can write is not an
// authority.
//
// secret_owner_user_id is the answer, and these are the guards that make it a
// fact about the code rather than a claim about it. They use the machinery
// egress_write_chokepoint_test.go already proved out: hand every statement in
// the module to a REAL SQLite engine against a schema where the column is
// GENERATED, and let the engine's own parser decide what writes it. Aliases,
// comments, casing and whitespace are not our problem.

// ownershipColumns is the classification, read as data from the package that
// owns the write.
func ownershipColumns(t *testing.T) []string {
	t.Helper()
	cols := append([]string(nil), vaultegress.OwnershipColumns()...)
	sort.Strings(cols)
	if len(cols) != 1 || cols[0] != "secret_owner_user_id" {
		t.Fatalf("ABORT: vaultegress.OwnershipColumns() is %v, want exactly [secret_owner_user_id]. "+
			"Either a second ownership column appeared and these guards have not been told about it, "+
			"or the one they exist for was renamed", cols)
	}
	return cols
}

// prepareRefusal asks SQLite what a statement does to the generated columns of
// the probe schema, and hands back the engine's own words ("cannot UPDATE
// generated column ...", "cannot INSERT into generated column ..."). "" means
// the statement does not assign one.
//
// The control database is what keeps a merely-broken statement from reading as a
// finding: anything the real schema cannot parse is not a statement this module
// executes against this schema.
func prepareRefusal(control, probe *sql.DB, stmt string) string {
	cs, err := control.Prepare(stmt)
	if err != nil {
		return ""
	}
	cs.Close()
	ps, err := probe.Prepare(stmt)
	if err == nil {
		ps.Close()
		return ""
	}
	if msg := err.Error(); strings.Contains(msg, "generated column") {
		return msg
	}
	return ""
}

// moduleSQLStatements is every compile-time-constant string in the module, which
// TestEverySQLStatementInTheModuleIsACompileTimeConstant proves is the same set
// as "every statement this module can execute".
func moduleSQLStatements(t *testing.T) []sqlCandidate {
	t.Helper()
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)
	consts := packageStringConstants(parsed)
	var candidates []sqlCandidate
	for path, f := range parsed {
		candidates = append(candidates,
			constantStrings(fset, f, path, consts[filepath.ToSlash(filepath.Dir(path))])...)
	}
	if len(candidates) < 200 {
		t.Fatalf("ABORT: only collected %d constant strings from the module; the AST walk is not "+
			"reaching the source", len(candidates))
	}
	return candidates
}

const ownershipWriterPkg = "internal/vaultegress/internal/egressq"

// TestOnlyTheSanctionedStatementMovesTheSecretOwner is the property in one
// sentence: after a row exists, exactly one statement in the module can change
// whose authority governs its plaintext, and it lives where the compiler keeps
// handlers out.
func TestOnlyTheSanctionedStatementMovesTheSecretOwner(t *testing.T) {
	cols := ownershipColumns(t)
	control, probe := probeSchema(t, cols)

	updaters := map[string]string{} // file -> statement
	for _, c := range moduleSQLStatements(t) {
		refusal := prepareRefusal(control, probe, c.text)
		if refusal == "" {
			continue
		}
		// An INSERT names the owner of a row that did not exist a moment ago,
		// which is the creator naming themselves; that is checked separately by
		// TestEveryRowCreatingStatementNamesTheSecretOwner. What must be rare is
		// changing the answer AFTERWARDS.
		if strings.Contains(refusal, "cannot INSERT") {
			continue
		}
		if strings.Contains(c.pkgPath, ownershipWriterPkg) {
			updaters[c.file] = collapseWhitespace(c.text)
			continue
		}
		t.Errorf("%s:%d executes a statement that MOVES vault_entries.%s.\n"+
			"  SQLite says: %s\n"+
			"  statement:   %s\n"+
			"That column is the one the exit resolves \"whose secret is this\" from. A second writer "+
			"of it is a second way to become the owner, which is the round-7 defect exactly: user_id "+
			"had two writers and a collection manager reached one of them. Move the query to "+
			"internal/vaultegress/queries and call it through vaultegress.TransferSecretOwnership, "+
			"which demands a TransferProof.\n"+
			"Note what did NOT decide this: the text of the SQL. SQLite refused to prepare it.",
			c.file, c.line, cols[0], strings.TrimSpace(refusal), collapseWhitespace(c.text))
	}

	if len(updaters) != 1 {
		t.Fatalf("expected exactly ONE statement in %s to move %s, found %d: %v.\n"+
			"Zero means the transfer path was deleted or this guard stopped recognising it, in which "+
			"case it would also stop recognising a planted one. More than one means the single "+
			"post-creation writer is no longer single.",
			ownershipWriterPkg, cols[0], len(updaters), updaters)
	}
	for file, stmt := range updaters {
		t.Logf("the one post-creation owner writer: %s\n  %s", file, stmt)
	}
}

// TestEveryRowCreatingStatementNamesTheSecretOwner closes the OTHER way a row
// ends up with an owner nobody chose: an INSERT that names user_id and leaves
// secret_owner_user_id at its ” default.
//
// mayDirectSecretEgress refuses an empty owner, so such a row is not a security
// hole; it is a silent product failure, which is the other bad direction. The
// person who just created or imported a secret could not configure delivery for
// it, with no error anywhere. Forgetting has to be a red test.
//
// The two sets are compared, not enumerated: every statement the engine says
// inserts a user_id must also be one the engine says inserts a
// secret_owner_user_id.
func TestEveryRowCreatingStatementNamesTheSecretOwner(t *testing.T) {
	cols := ownershipColumns(t)
	ownerControl, ownerProbe := probeSchema(t, cols)
	custodianControl, custodianProbe := probeSchema(t, []string{"user_id"})

	stmts := moduleSQLStatements(t)
	var namesCustodian, namesOwner []string
	for _, c := range stmts {
		key := fmt.Sprintf("%s:%d", c.file, c.line)
		if r := prepareRefusal(custodianControl, custodianProbe, c.text); strings.Contains(r, "cannot INSERT") {
			namesCustodian = append(namesCustodian, key)
		}
		if r := prepareRefusal(ownerControl, ownerProbe, c.text); strings.Contains(r, "cannot INSERT") {
			namesOwner = append(namesOwner, key)
		}
	}
	sort.Strings(namesCustodian)
	sort.Strings(namesOwner)

	if len(namesCustodian) < 2 {
		t.Fatalf("ABORT: only %d statements in the module insert a vault_entries.user_id (%v). Two are "+
			"known to (CreateVaultEntry, ImportVaultEntry), so this guard is not seeing the source",
			len(namesCustodian), namesCustodian)
	}

	have := map[string]bool{}
	for _, k := range namesOwner {
		have[k] = true
	}
	for _, k := range namesCustodian {
		if !have[k] {
			t.Errorf("%s inserts a vault_entries row and names user_id but NOT secret_owner_user_id.\n"+
				"The row lands with an empty owner, so mayDirectSecretEgress refuses everybody and "+
				"whoever created the entry silently cannot configure delivery for it. Name both "+
				"columns on every row-creating statement.", k)
		}
	}
	t.Logf("%d row-creating statements, all naming both owner columns: %v", len(namesCustodian), namesCustodian)
}

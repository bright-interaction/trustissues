package handlers

import (
	"database/sql"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/database"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE GUARD THAT STOPPED BEING A PATTERN.
//
// Round 4 forced every vault_entries column to be CLASSIFIED as host-choosing or
// not. Round 5 walked past it, because a classification is a CLAIM ABOUT THE
// CODE: rotation_targets was correctly labelled and its write path asked nobody.
//
// Round 5 answered that with a chokepoint file and four guards that read the
// source and matched it against regular expressions. A skeptic planted four
// write paths through the gaps. The sharpest:
//
//	UPDATE vault_entries AS ve SET rotation_targets = ?, updated_at = CURRENT_TIMESTAMP WHERE ve.id = ?
//
// which is the ordinary sqlc shape with a table alias, against a pattern of
// `update\s+vault_entries\s+set`. It built, vetted clean and passed all four
// guards.
//
// PROVING A PROPERTY BY RECOGNISING ITS TEXTUAL FORM ALWAYS LOSES.
//
// So there are now two enforcement mechanisms here and neither reads SQL text.
//
//  1. THE COMPILER. The statements that write a host-choosing column are
//     generated into internal/vaultegress/internal/egressq. Go's `internal` rule
//     makes that package importable only from inside internal/vaultegress, and
//     the methods are gone from *db.Queries, so there is nothing for a handler
//     to call. TestPlantedEgressBypassesDoNotCompile runs the real toolchain on
//     real planted bypasses and reads its refusals.
//
//  2. SQLITE. TestNoStatementOutsideTheEgressPackageWritesAHostChoosingColumn
//     takes every SQL statement in the module, hands it to a real SQLite engine
//     against a schema where the host-choosing columns are GENERATED, and lets
//     the engine refuse to prepare anything that assigns one. Aliases, casing,
//     comments and whitespace are the parser's problem. The statements come from
//     the Go AST rather than from a grep, and a companion check proves that
//     collection is COMPLETE by refusing any SQL argument in the module that is
//     not a compile-time constant.

// hostChoosingColumns is the classification, read as data from the package that
// owns the writes. Reclassifying a column immediately changes what these guards
// demand.
func hostChoosingColumns(t *testing.T) []string {
	t.Helper()
	fromWriter := append([]string(nil), vaultegress.HostChoosingColumns()...)
	sort.Strings(fromWriter)

	// Cross-checked against the round-4 classification table, which is a
	// different file maintained for a different reason. If the two ever disagree
	// somebody has classified a column in one place and not the other, and the
	// safe reading of that is "there is an unenforced host-choosing column".
	var fromTable []string
	for col, entry := range vaultEntryEgressClass {
		if entry.class == egressChoosesHost {
			fromTable = append(fromTable, col)
		}
	}
	sort.Strings(fromTable)
	if strings.Join(fromWriter, ",") != strings.Join(fromTable, ",") {
		t.Fatalf("the two statements of which columns choose a host disagree.\n"+
			"  vaultegress.HostChoosingColumns(): %v\n"+
			"  vaultEntryEgressClass:             %v\n"+
			"One of them has a column the other does not, which means either a column is enforced and "+
			"not classified, or classified and not enforced. The second one is round 5.",
			fromWriter, fromTable)
	}
	if len(fromWriter) < 4 {
		t.Fatalf("ABORT: only %d columns are classified as choosing a host (%v). Four are known to be "+
			"(destination_patterns, provider, provider_meta, rotation_targets)",
			len(fromWriter), fromWriter)
	}
	return fromWriter
}

// ── collecting the SQL the module can actually execute ──────────────────────

// sqlCandidate is one compile-time-constant string found in the module source.
type sqlCandidate struct {
	pkgPath string // repo-relative directory
	file    string
	line    int
	text    string
}

// moduleGoFiles walks the whole module and returns every non-generated,
// non-test source file, as path -> contents.
//
// The whole module, not just this package: a second writer of these columns in
// cmd/ or in a future internal/scheduler would be exactly the "one more door"
// this series keeps finding.
func moduleGoFiles(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "frontend", "docs", "scripts", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		out[filepath.ToSlash(path)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if len(out) < 30 {
		t.Fatalf("ABORT: only found %d non-test source files under the module; the walk is not reaching "+
			"the code and this guard is checking nothing", len(out))
	}
	return out
}

// foldConstantString folds a compile-time-constant string expression.
//
// go/ast, not a grep. A raw string literal, an interpreted one, and two of
// either joined with + are all the same thing to the compiler and are all the
// same thing here.
func foldConstantString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, okL := foldConstantString(v.X)
		r, okR := foldConstantString(v.Y)
		if !okL || !okR {
			return "", false
		}
		return l + r, true
	case *ast.ParenExpr:
		return foldConstantString(v.X)
	}
	return "", false
}

// constantStrings returns every compile-time-constant string in a file.
func constantStrings(fset *token.FileSet, f *ast.File, path string) []sqlCandidate {
	var out []sqlCandidate
	ast.Inspect(f, func(n ast.Node) bool {
		e, isExpr := n.(ast.Expr)
		if !isExpr {
			return true
		}
		switch e.(type) {
		case *ast.BasicLit, *ast.BinaryExpr, *ast.ParenExpr:
		default:
			return true
		}
		s, ok := foldConstantString(e)
		if !ok || strings.TrimSpace(s) == "" {
			return true
		}
		pos := fset.Position(e.Pos())
		out = append(out, sqlCandidate{
			pkgPath: filepath.ToSlash(filepath.Dir(path)),
			file:    filepath.ToSlash(path),
			line:    pos.Line,
			text:    s,
		})
		return false // the whole folded expression, not its pieces as well
	})
	return out
}

// sqlExecMethods are the database/sql entry points that take a statement.
var sqlExecMethods = map[string]bool{
	"Exec": true, "ExecContext": true,
	"Query": true, "QueryContext": true,
	"QueryRow": true, "QueryRowContext": true,
	"Prepare": true, "PrepareContext": true,
}

// TestEverySQLStatementInTheModuleIsACompileTimeConstant is what makes the
// prepare-based guard below COMPLETE rather than merely broad.
//
// That guard collects constant strings and asks SQLite what each one writes. It
// would miss `"UPDATE vault_entries SET " + col + " = ?"`, because there is no
// constant to hand over. This closes the gap by refusing the shape: every
// statement handed to Exec/Query/QueryRow/Prepare must be a constant or a named
// constant, module-wide. Then "every statement the module can execute" and
// "every constant string in the module" are the same set, by construction.
func TestEverySQLStatementInTheModuleIsACompileTimeConstant(t *testing.T) {
	fset := token.NewFileSet()
	checked, flagged := 0, 0
	for path := range moduleGoFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !sqlExecMethods[sel.Sel.Name] || len(call.Args) == 0 {
				return true
			}
			checked++
			// The statement is argument 0 (Exec) or argument 1 (ExecContext).
			// Accepting either keeps this free of type information: a constant
			// in one of the first two positions is the statement, and nothing
			// else in those positions is.
			limit := 2
			if len(call.Args) < limit {
				limit = len(call.Args)
			}
			for i := 0; i < limit; i++ {
				switch call.Args[i].(type) {
				case *ast.BasicLit, *ast.Ident, *ast.SelectorExpr:
					return true
				case *ast.BinaryExpr:
					if _, ok := foldConstantString(call.Args[i]); ok {
						return true
					}
				}
			}
			flagged++
			pos := fset.Position(call.Pos())
			t.Errorf("%s:%d builds a SQL statement dynamically (%s).\n"+
				"Every statement in this module has to be a compile-time constant, because the guard "+
				"that proves no statement writes a host-choosing column works by handing statements to "+
				"SQLite, and it can only hand over what exists at compile time. A statement assembled at "+
				"runtime is invisible to it, which is how a text-matching guard fails one level up.",
				pos.Filename, pos.Line, sel.Sel.Name)
			return true
		})
	}
	if checked < 20 {
		t.Fatalf("ABORT: only found %d SQL execution call sites in the module; this guard is not looking "+
			"at the code", checked)
	}
	t.Logf("checked %d SQL execution call sites, %d dynamic", checked, flagged)
}

// ── the probe database ──────────────────────────────────────────────────────

// probeSchema builds two real SQLite databases from the REAL migrations: a
// control, and a probe in which the named columns of vault_entries are GENERATED.
//
// SQLite refuses at PREPARE time to assign a generated column:
//
//	cannot UPDATE generated column "rotation_targets"
//	cannot INSERT into generated column "provider"
//
// That refusal is the engine's own answer to "does this statement write that
// column", derived from its parser rather than from ours. It does not care about
// table aliases, comments, casing, line breaks, or which package the SQL is in.
func probeSchema(t *testing.T, generated []string) (control, probe *sql.DB) {
	t.Helper()

	ctlConn, err := database.Connect(filepath.Join(t.TempDir(), "control"))
	if err != nil {
		t.Fatalf("connect control: %v", err)
	}
	t.Cleanup(func() { ctlConn.Close() })
	if err := database.RunMigrations(ctlConn); err != nil {
		t.Fatalf("migrate control: %v", err)
	}

	type object struct{ kind, name, sqlText string }
	var objects []object
	rows, err := ctlConn.Query(`SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL`)
	if err != nil {
		t.Fatalf("read sqlite_master: %v", err)
	}
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name, &o.sqlText); err != nil {
			t.Fatalf("scan sqlite_master: %v", err)
		}
		objects = append(objects, o)
	}
	rows.Close()
	if len(objects) < 10 {
		t.Fatalf("ABORT: the control database has %d schema objects; the migrations did not run", len(objects))
	}

	// vault_entries, rebuilt from the engine's own column metadata with the
	// host-choosing columns made unwritable. PRAGMA table_info, not a text edit
	// of the CREATE statement: the column list comes from SQLite.
	cols, err := ctlConn.Query(`PRAGMA table_info(vault_entries)`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	gen := map[string]bool{}
	for _, c := range generated {
		gen[c] = true
	}
	var defs []string
	seen := map[string]bool{}
	for cols.Next() {
		var cid, notNull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := cols.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		seen[name] = true
		if ctype == "" {
			ctype = "TEXT"
		}
		if gen[name] {
			// No NOT NULL and no DEFAULT: nothing is ever inserted into this
			// database, and a generated column may carry neither.
			defs = append(defs, fmt.Sprintf("%s %s GENERATED ALWAYS AS (NULL) VIRTUAL", name, ctype))
			continue
		}
		def := name + " " + ctype
		if pk == 1 {
			def += " PRIMARY KEY"
		}
		if notNull == 1 {
			def += " NOT NULL"
		}
		if dflt.Valid {
			// Parenthesised unconditionally. PRAGMA table_info hands back the
			// default EXPRESSION with its outer parentheses stripped, and
			// `DEFAULT lower(hex(randomblob(16)))` is not valid SQLite while
			// `DEFAULT (lower(hex(randomblob(16))))` is.
			def += " DEFAULT (" + dflt.String + ")"
		}
		defs = append(defs, def)
	}
	cols.Close()
	for _, c := range generated {
		if !seen[c] {
			t.Fatalf("ABORT: column %q is classified as choosing a host but vault_entries has no such "+
				"column. Either the classification names a column that was renamed or dropped, or this "+
				"guard is reading the wrong table", c)
		}
	}

	probeConn, err := database.Connect(filepath.Join(t.TempDir(), "probe"))
	if err != nil {
		t.Fatalf("connect probe: %v", err)
	}
	t.Cleanup(func() { probeConn.Close() })

	// Tables first, then views. Indexes and triggers are irrelevant to PREPARE,
	// and several are partial indexes on the columns being replaced.
	for _, o := range objects {
		if o.kind != "table" || o.name == "vault_entries" || strings.HasPrefix(o.name, "sqlite_") {
			continue
		}
		if _, err := probeConn.Exec(o.sqlText); err != nil {
			t.Fatalf("probe schema, table %s: %v", o.name, err)
		}
	}
	create := "CREATE TABLE vault_entries (\n  " + strings.Join(defs, ",\n  ") + "\n)"
	if _, err := probeConn.Exec(create); err != nil {
		t.Fatalf("probe schema, vault_entries: %v\n%s", err, create)
	}
	for _, o := range objects {
		if o.kind != "view" {
			continue
		}
		if _, err := probeConn.Exec(o.sqlText); err != nil {
			t.Fatalf("probe schema, view %s: %v", o.name, err)
		}
	}

	// SELF-CHECK. A probe that quietly failed to make the columns generated
	// would report that nothing writes them, which reads exactly like a clean
	// bill of health. Prove the mechanism on statements written here, including
	// the alias shape that beat the round-5 pattern.
	for _, col := range generated {
		for _, stmt := range []string{
			fmt.Sprintf("UPDATE vault_entries SET %s = ? WHERE id = ?", col),
			fmt.Sprintf("UPDATE vault_entries AS ve SET %s = ?, updated_at = CURRENT_TIMESTAMP WHERE ve.id = ?", col),
			fmt.Sprintf("/* comment */ update\n\tVAULT_ENTRIES\n\tas Ve\n\tset %s = ?\nwhere Ve.id = ?", col),
		} {
			if _, err := probeConn.Prepare(stmt); err == nil {
				t.Fatalf("ABORT: the probe database accepted %q, so %s is not actually a generated column "+
					"and this guard would pass on any write at all", stmt, col)
			}
			if _, err := ctlConn.Prepare(stmt); err != nil {
				t.Fatalf("ABORT: the control database rejected %q (%v), so the comparison below cannot "+
					"tell a host-choosing write from a broken statement", stmt, err)
			}
		}
	}
	return ctlConn, probeConn
}

// writesAHostChoosingColumn asks SQLite. It returns the engine's refusal, or "".
func writesAHostChoosingColumn(control, probe *sql.DB, stmt string) string {
	cs, err := control.Prepare(stmt)
	if err != nil {
		return "" // not a statement this schema can even parse; nothing to say
	}
	cs.Close()
	ps, err := probe.Prepare(stmt)
	if err == nil {
		ps.Close()
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "generated column") {
		return msg
	}
	return ""
}

// TestNoStatementOutsideTheEgressPackageWritesAHostChoosingColumn is the
// replacement for four regular expressions.
func TestNoStatementOutsideTheEgressPackageWritesAHostChoosingColumn(t *testing.T) {
	cols := hostChoosingColumns(t)
	control, probe := probeSchema(t, cols)

	fset := token.NewFileSet()
	var candidates []sqlCandidate
	for path := range moduleGoFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		candidates = append(candidates, constantStrings(fset, f, path)...)
	}
	if len(candidates) < 200 {
		t.Fatalf("ABORT: only collected %d constant strings from the module; the AST walk is not "+
			"reaching the source", len(candidates))
	}

	const egressPkg = "internal/vaultegress/internal/egressq"
	found := map[string]int{}
	for _, c := range candidates {
		refusal := writesAHostChoosingColumn(control, probe, c.text)
		if refusal == "" {
			continue
		}
		if strings.Contains(c.pkgPath, egressPkg) {
			found[c.file]++
			continue
		}
		t.Errorf("%s:%d executes a statement that writes a host-choosing column of vault_entries.\n"+
			"  SQLite says: %s\n"+
			"  statement:   %s\n"+
			"Move the query to internal/vaultegress/queries and call it through the ticket-taking "+
			"wrapper in internal/vaultegress. Nothing may write destination_patterns, provider, "+
			"provider_meta or rotation_targets without an egressgate.Ticket, and this check is what "+
			"covers the paths the compiler cannot: a NEW query generated into internal/db, or a "+
			"hand-written statement.\n"+
			"Note what did NOT decide this: the text of the SQL. SQLite refused to prepare it.",
			c.file, c.line, strings.TrimSpace(refusal), collapseWhitespace(c.text))
	}

	total := 0
	for _, n := range found {
		total += n
	}
	if total < 6 {
		t.Fatalf("ABORT: only %d statements in %s were found to write a host-choosing column (%v). Six "+
			"are known to (CreateVaultEntry, UpdateVaultEntryDestinationPatterns, "+
			"UpdateVaultEntryProvider, UpdateVaultEntryProviderMeta, UpdateVaultEntryRotationTargets, "+
			"SeedVaultEntryCapabilityDefaults), so either the generated package moved or this guard "+
			"stopped recognising the statements it is supposed to allow, in which case it would also "+
			"stop recognising the ones it is supposed to refuse", total, egressPkg, found)
	}
	t.Logf("SQLite reports %d host-choosing write statements, all inside %s", total, egressPkg)
}

func collapseWhitespace(s string) string { return strings.Join(strings.Fields(s), " ") }

// ── the compiler as the enforcement mechanism ───────────────────────────────

// TestPlantedEgressBypassesDoNotCompile runs the real toolchain on real planted
// bypasses and reads its refusals.
//
// The packages under testdata/ are invisible to ./... , so they never break the
// build; this test names them explicitly. Each is a bypass somebody could
// plausibly write, and each must FAIL to build. A test that greps for a pattern
// can be spelled around. A method that does not exist cannot be called.
func TestPlantedEgressBypassesDoNotCompile(t *testing.T) {
	cases := []struct {
		dir  string
		want string
		why  string
	}{
		{
			dir:  "importtheinternalpackage",
			want: "use of internal package",
			why: "importing the generated queries directly. Go's own `internal` rule refuses it, which " +
				"is why they were moved under internal/vaultegress/internal in the first place",
		},
		{
			dir:  "callremovedmethod",
			want: "UpdateVaultEntryRotationTargets",
			why:  "the round-5 defect written out literally: queries.UpdateVaultEntryRotationTargets(...)",
		},
		{
			dir:  "skiptheticket",
			want: "not enough arguments",
			why:  "calling the chokepoint wrapper without a Ticket. The Ticket is a parameter, so this is arity",
		},
		{
			dir:  "forgeaticket",
			want: "cannot refer to unexported field",
			why: "building an egressgate.Ticket by hand. It has no exported fields, so a forged one " +
				"cannot be spelled at all",
		},
		{
			dir:  "namethegeneratedparams",
			want: "use of internal package",
			why:  "naming the generated parameter struct, to route around the wrapper's own params type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			pkg := "./internal/handlers/testdata/egressbypass/" + tc.dir
			cmd := exec.Command("go", "build", pkg)
			cmd.Dir = filepath.Join("..", "..")
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("THE BYPASS COMPILES. %s\n%s built clean, so this is a thing the codebase can "+
					"still express and the enforcement is not by construction.", tc.why, pkg)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("%s failed to build, but not for the reason this is testing.\n"+
					"  want the compiler to say: %s\n  it said:\n%s", pkg, tc.want, out)
			}
			t.Logf("%s (%s)\n%s", tc.dir, tc.why, strings.TrimSpace(string(out)))
		})
	}
}

// TestEveryExportedEgressWriteDemandsATicket closes the way to satisfy the
// boundary without satisfying its point: add a function to internal/vaultegress
// that performs the write and asks for nothing.
//
// It reads the package's real exported signatures out of the AST, so a wrapper
// that merely mentions the word Ticket in a comment does not count.
func TestEveryExportedEgressWriteDemandsATicket(t *testing.T) {
	dir := filepath.Join("..", "vaultegress")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	pkg, ok := pkgs["vaultegress"]
	if !ok {
		t.Fatalf("ABORT: package vaultegress not found under %s; it was renamed and this guard is "+
			"checking nothing", dir)
	}

	checked, exempt := 0, 0
	for path, f := range pkg.Files {
		for _, decl := range f.Decls {
			fn, isFn := decl.(*ast.FuncDecl)
			if !isFn || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			// A function that reaches the generated querier must demand a
			// ticket. One that does not (HostChoosingColumns) is exempt, and it
			// declares that by not calling the writer.
			touchesWriter := false
			ast.Inspect(fn, func(n ast.Node) bool {
				if id, isID := n.(*ast.Ident); isID && id.Name == "writer" {
					touchesWriter = true
				}
				return true
			})
			if !touchesWriter {
				exempt++
				continue
			}
			checked++
			hasTicket := false
			for _, p := range fn.Type.Params.List {
				if sel, isSel := p.Type.(*ast.SelectorExpr); isSel && sel.Sel.Name == "Ticket" {
					hasTicket = true
				}
			}
			if !hasTicket {
				t.Errorf("%s: exported func %s reaches the generated egress querier but takes no "+
					"egressgate.Ticket.\nA wrapper that performs the write without a ticket is a "+
					"chokepoint with no lock on it: every caller looks correctly routed and none of "+
					"them is gated.", filepath.Base(path), fn.Name.Name)
			}
		}
	}
	if checked < 6 {
		t.Fatalf("ABORT: only %d exported functions in internal/vaultegress reach the writer; six are "+
			"known to (SetDestinationPatterns, SeedCapabilityDefaults, SetProvider, SetProviderMeta, "+
			"SetRotationTargets, CreateEntry), so the file layout changed and this guard is checking "+
			"almost nothing", checked)
	}
	t.Logf("checked %d exported egress writes, %d exported functions exempt", checked, exempt)
}

// TestTheChokepointHasADeriverForEveryHostChoosingColumn keeps the gate honest
// rather than merely present.
//
// egressgate.Decide compares two destination sets. If the sets are computed
// wrongly, the ticket is granted for a write that does move the secret, and
// every structural check above still passes. So the derivers are named, and a
// column classified host-choosing with no deriver behind it fails here.
func TestTheChokepointHasADeriverForEveryHostChoosingColumn(t *testing.T) {
	src := readPackageFile(t, "vault_egress_writes.go")
	derivers := map[string]string{
		"destination_patterns": "func ceilingDestinations(",
		"provider":             "func providerDestinations(",
		"provider_meta":        "func providerDestinations(",
		"rotation_targets":     "func deliveryDestinations(",
	}
	for _, col := range hostChoosingColumns(t) {
		deriver, ok := derivers[col]
		if !ok {
			t.Errorf("vault_entries.%s is classified as choosing a host but there is no named deriver "+
				"for it.\nA wrapper cannot decide whether a write ADDS a destination without a function "+
				"that turns that column's value into the set of places the secret can reach. Write one, "+
				"add it here, and use it at the decision site: without it the ticket is granted on an "+
				"empty comparison and the gate is decorative.", col)
			continue
		}
		if !strings.Contains(src, deriver) {
			t.Errorf("the deriver %q for vault_entries.%s is gone", deriver, col)
		}
	}
}

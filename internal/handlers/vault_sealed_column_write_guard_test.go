package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// THE GUARD FOR THE CLASS, not for the column that was just used.
//
// The enc:v1: decryption oracle was closed once, in encryptColumn, by making it
// ALWAYS seal: a client string that already carries the marker is stored as the
// attacker's own literal bytes rather than handed back opened. The regression
// test written at the time (TestEncryptColumnIsNotIdempotent in
// vault_column_crypto_test.go) pins that encryptColumn behaves. It cannot say
// anything at all about a write that never calls encryptColumn, and that is
// exactly how the oracle came back: VaultImportHandler.ImportConfirm sealed
// url, username, category and notes and passed Name straight through, into a
// column six read paths open, carrying bytes that are byte-interchangeable with
// a secret VALUE.
//
// A test that pins "does this function behave" cannot answer "can any path
// bypass it". This one asks the second question. It walks the AST of package
// handlers, finds every write to a column that is sealed at rest, and requires
// the value to have come through a sealer. A new endpoint that forgets is a red
// test on the day it is written, not a finding two audits later.
//
// NOTHING IN HERE IS A HAND-MAINTAINED LIST OF COLUMNS.
//
//   - the sealed columns come from rekeySurfaces (vault_rekey.go), which is
//     already the inventory a key rotation must cover, so a column that is
//     encrypted but missing there is a rotation bug too.
//   - the column-to-struct-field mapping comes from the sqlc json tags on the
//     generated params structs, so it cannot drift from the schema.
//   - which params structs WRITE (rather than read) a sealed table comes from
//     the generated SQL text of the query each struct belongs to.
//   - the hand-written internal/vaultegress wrappers are bridged to the
//     generated structs they forward into, by reading their bodies.
//
// THE RESIDUAL, stated rather than hidden. A local whose value is sealed on one
// branch and client-controlled on another counts as sealed here, because the
// reseal-in-place idiom (`x = enc` after `enc, _ := h.encryptColumn(x)`) is
// pervasive and rejecting it would make this guard unusable. Closing that hole
// properly means giving a sealed column value its own Go type so the compiler
// refuses a raw string, which is a bigger change than this fix and is written up
// in the report rather than smuggled in here.

// The sealers, anchored to the real symbols. Renaming one of these is a compile
// error in this file rather than a silently empty allowlist, which is the
// failure mode of every guard that matches names as strings.
var (
	_ = (*VaultHandler).encryptColumn
	_ = (*VaultHandler).encryptColumnIfNeeded
	_ = (*VaultHandler).encryptCustomFields
	_ = (*VaultHandler).encryptMetaColumns
	_ = (*VaultHandler).encryptMetaColumnsIfNeeded
	_ = (*UserHandler).sealInviteCode
	_ = vaultfield.SealColumn
)

var sealerNames = map[string]bool{
	"encryptColumn":              true,
	"encryptColumnIfNeeded":      true,
	"encryptCustomFields":        true,
	"encryptMetaColumns":         true,
	"encryptMetaColumnsIfNeeded": true,
	// sealInviteCode is a thin wrapper over encryptColumn that refuses rather
	// than storing an unrecoverable "". It is a sealer for the same reason the
	// others are: nothing reaches storage through it without being sealed.
	"sealInviteCode": true,
	"SealColumn":     true,
}

// unwrapperNames are calls that carry a value into a column without changing
// what it is, so classification passes through them to the argument.
var unwrapperNames = map[string]bool{
	"toNullString": true,
}

// storageSideWrite is one write site whose value legitimately does NOT come from
// a sealer, because it came out of the database already sealed.
//
// Every one of these has to be named. That is the entire discipline: the sites
// that skip encryptColumn are a set somebody signed for, not a set nobody
// counted. The test fails in both directions, so a stale entry is as loud as a
// missing one.
type storageSideWrite struct {
	File  string // file in internal/handlers
	Func  string // enclosing function
	Type  string // params type being built
	Field string // struct field
	Why   string
}

var storageSideWrites = []storageSideWrite{
	{"vault.go", "MoveToCollection", "db.UpdateVaultEntryMetaAtRestParams", "Name",
		"a move changes the collection, not the custodian, so the row's own stored ciphertext " +
			"is written back untouched; only the url indexes are recomputed. Re-sealing here " +
			"would double-wrap and permanently corrupt the name"},
	{"vault.go", "MoveToCollection", "db.UpdateVaultEntryMetaAtRestParams", "Url", "same row, written back untouched"},
	{"vault.go", "MoveToCollection", "db.UpdateVaultEntryMetaAtRestParams", "AliasUrl", "same row, written back untouched"},
	{"vault.go", "MoveToCollection", "db.UpdateVaultEntryMetaAtRestParams", "Username", "same row, written back untouched"},
	{"vault.go", "MoveToCollection", "db.UpdateVaultEntryMetaAtRestParams", "Category", "same row, written back untouched"},
	{"vault.go", "MoveToCollection", "db.UpdateVaultEntryMetaAtRestParams", "Notes", "same row, written back untouched"},

	{"vault.go", "UpdateSchedule", "vaultegress.ProviderParams", "ProviderMeta",
		"the entry's CURRENT stored provider_meta, re-sent because the statement writes provider, " +
			"provider_meta and auto_rotate together and only auto_rotate is changing here"},

	{"vault_pending_revoke.go", "clearRevokeHalfOfRotationError", "db.CASVaultEntryRotationErrorParams", "ProviderMeta",
		"NOT a write: provider_meta is the compare-and-swap PRE-IMAGE in this query's WHERE clause " +
			"(provider_meta IS ?), and the only SET target is last_rotation_error. It is the already-sealed " +
			"ciphertext read straight off GetVaultEntryMeta and used as an optimistic-lock token, exactly " +
			"like casToken in casEditProviderMeta; re-sealing it would change the bytes and make every CAS miss"},

	{"vault_ownership_repair.go", "reindexAfterCustodianChange", "db.UpdateVaultEntryMetaAtRestParams", "Name",
		"custodian transfer: the ciphertext is carried across untouched and only name_bidx is " +
			"recomputed, because the index is keyed by the custodian and the ciphertext is not"},
	{"vault_ownership_repair.go", "reindexAfterCustodianChange", "db.UpdateVaultEntryMetaAtRestParams", "Url",
		"same row, written back untouched"},
	{"vault_ownership_repair.go", "reindexAfterCustodianChange", "db.UpdateVaultEntryMetaAtRestParams", "AliasUrl",
		"same row, written back untouched"},
	{"vault_ownership_repair.go", "reindexAfterCustodianChange", "db.UpdateVaultEntryMetaAtRestParams", "Username",
		"same row, written back untouched"},
	{"vault_ownership_repair.go", "reindexAfterCustodianChange", "db.UpdateVaultEntryMetaAtRestParams", "Category",
		"same row, written back untouched"},
	{"vault_ownership_repair.go", "reindexAfterCustodianChange", "db.UpdateVaultEntryMetaAtRestParams", "Notes",
		"same row, written back untouched"},

	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "Name",
		"the rekey plan holds values ALREADY re-sealed under the new master key by the rekey " +
			"pass itself; they arrive here through the newCols map, not from a client"},
	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "Url", "same, re-sealed by the rekey pass"},
	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "AliasUrl", "same, re-sealed by the rekey pass"},
	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "Username", "same, re-sealed by the rekey pass"},
	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "Category", "same, re-sealed by the rekey pass"},
	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "Notes", "same, re-sealed by the rekey pass"},
	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "ProviderMeta", "same, re-sealed by the rekey pass"},
	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "RotationTargets", "same, re-sealed by the rekey pass"},
	{"vault_rekey.go", "scanVaultEntries", "vaultegress.RekeyEntryParams", "CustomFields", "same, re-sealed by the rekey pass"},
}

func (s storageSideWrite) key() string {
	return s.File + ":" + s.Func + ":" + s.Type + "." + s.Field
}

// sealedColumnsByTable reads the inventory out of rekeySurfaces, the same list a
// master-key rotation walks. familyVaultColumn IS the enc:v1: family: those are
// the columns SealColumn writes and OpenColumn opens.
func sealedColumnsByTable(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, s := range rekeySurfaces {
		if s.Family != familyVaultColumn {
			continue
		}
		if out[s.Table] == nil {
			out[s.Table] = map[string]bool{}
		}
		out[s.Table][s.Column] = true
	}
	if len(out) == 0 {
		t.Fatal("ABORT: rekeySurfaces yielded no enc:v1: columns, so this guard would pass " +
			"vacuously and prove nothing")
	}
	if !out["vault_entries"]["name"] {
		t.Fatal("ABORT: vault_entries.name is not classified as an enc:v1: column in " +
			"rekeySurfaces. That is the column the import oracle used, and without it this " +
			"guard cannot see the defect it exists for")
	}
	return out
}

var (
	queryNameRe = regexp.MustCompile(`--\s*name:\s*(\w+)\s*:`)
	writesRe    = regexp.MustCompile(`(?is)\b(?:insert\s+into|update)\s+([a-z_][a-z0-9_]*)`)
)

// sealedWriteFields maps "pkg.ParamsType" to the set of its fields that carry a
// sealed column into an INSERT or an UPDATE.
//
// It is derived, not written down. The generated SQL says which table a query
// writes; the generated struct's json tags say which field is which column.
func sealedWriteFields(t *testing.T, dir, pkgAlias string, sealed map[string]map[string]bool) map[string]map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}

	// query name -> the sealed tables that query writes. Binding the TABLE and
	// not just "writes something sealed" is what keeps invitations.name, which
	// is not sealed, from being confused with vault_entries.name, which is.
	writingQueries := map[string]map[string]bool{}
	structs := map[string]*ast.StructType{}

	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, spec := range gd.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for _, v := range s.Values {
							lit, ok := v.(*ast.BasicLit)
							if !ok || lit.Kind != token.STRING {
								continue
							}
							sql, err := strconv.Unquote(lit.Value)
							if err != nil {
								continue
							}
							m := queryNameRe.FindStringSubmatch(sql)
							if m == nil {
								continue
							}
							for _, w := range writesRe.FindAllStringSubmatch(sql, -1) {
								table := strings.ToLower(w[1])
								if sealed[table] == nil {
									continue
								}
								if writingQueries[m[1]] == nil {
									writingQueries[m[1]] = map[string]bool{}
								}
								writingQueries[m[1]][table] = true
							}
						}
					case *ast.TypeSpec:
						if st, ok := s.Type.(*ast.StructType); ok {
							structs[s.Name.Name] = st
						}
					}
				}
			}
		}
	}

	out := map[string]map[string]string{}
	for query, tables := range writingQueries {
		st, ok := structs[query+"Params"]
		if !ok {
			// A single-argument query has no params struct. Nothing to check.
			continue
		}
		fields := map[string]string{}
		for _, fld := range st.Fields.List {
			col := jsonTagName(fld.Tag)
			if col == "" {
				continue
			}
			for table := range tables {
				if !sealed[table][col] {
					continue
				}
				for _, n := range fld.Names {
					fields[n.Name] = table + "." + col
				}
			}
		}
		if len(fields) > 0 {
			out[pkgAlias+"."+query+"Params"] = fields
		}
	}
	return out
}

func jsonTagName(tag *ast.BasicLit) string {
	if tag == nil {
		return ""
	}
	raw, err := strconv.Unquote(tag.Value)
	if err != nil {
		return ""
	}
	st := reflect.StructTag(raw)
	name, _, _ := strings.Cut(st.Get("json"), ",")
	return name
}

// bridgeVaultegressWrappers maps the hand-written internal/vaultegress params
// types onto the generated ones they forward into, by reading the wrapper
// bodies. Without this the whole vaultegress door, which is where Create and
// Rekey write, would be invisible to the guard.
func bridgeVaultegressWrappers(t *testing.T, generated map[string]map[string]string) map[string]map[string]string {
	t.Helper()

	dir := filepath.Join("..", "vaultegress")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}

	out := map[string]map[string]string{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || fn.Type.Params == nil {
					continue
				}
				// The wrapper's own params type: the last parameter named with a
				// bare identifier type ending in Params.
				var wrapperType, wrapperVar string
				for _, p := range fn.Type.Params.List {
					id, ok := p.Type.(*ast.Ident)
					if !ok || !strings.HasSuffix(id.Name, "Params") || len(p.Names) != 1 {
						continue
					}
					wrapperType, wrapperVar = id.Name, p.Names[0].Name
				}
				if wrapperType == "" {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					cl, ok := n.(*ast.CompositeLit)
					if !ok {
						return true
					}
					sel, ok := cl.Type.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkgIdent, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}
					inner := generated[pkgIdent.Name+"."+sel.Sel.Name]
					if inner == nil {
						return true
					}
					for _, elt := range cl.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := kv.Key.(*ast.Ident)
						if !ok {
							continue
						}
						col, ok := inner[key.Name]
						if !ok {
							continue
						}
						// Only a straight p.Field forward is a bridge. Anything
						// else means the wrapper transforms the value and the
						// mapping would be a guess.
						fwd, ok := kv.Value.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						base, ok := fwd.X.(*ast.Ident)
						if !ok || base.Name != wrapperVar {
							continue
						}
						k := "vaultegress." + wrapperType
						if out[k] == nil {
							out[k] = map[string]string{}
						}
						out[k][fwd.Sel.Name] = col
					}
					return true
				})
			}
		}
	}
	return out
}

// TestEverySealedColumnWriteGoesThroughASealer is the guard.
func TestEverySealedColumnWriteGoesThroughASealer(t *testing.T) {
	sealed := sealedColumnsByTable(t)

	slots := map[string]map[string]string{}
	for k, v := range sealedWriteFields(t, filepath.Join("..", "db"), "db", sealed) {
		slots[k] = v
	}
	generatedEgress := sealedWriteFields(t,
		filepath.Join("..", "vaultegress", "internal", "egressq"), "egressq", sealed)
	for k, v := range bridgeVaultegressWrappers(t, generatedEgress) {
		slots[k] = v
	}

	// The derivation has to have found the two doors a vault entry is actually
	// created through, or an empty walk would report success.
	for _, must := range []string{"db.ImportVaultEntryParams", "vaultegress.CreateEntryParams"} {
		if slots[must]["Name"] != "vault_entries.name" {
			t.Fatalf("ABORT: %s.Name was not derived as a write of vault_entries.name (got %q). "+
				"The derivation is broken, so a pass here would mean nothing", must, slots[must]["Name"])
		}
	}

	seenLedger := map[string]bool{}
	var offenders []string
	checked := 0

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			assigns := collectAssignments(fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := cl.Type.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				fields := slots[pkgIdent.Name+"."+sel.Sel.Name]
				if fields == nil {
					return true
				}
				typeName := pkgIdent.Name + "." + sel.Sel.Name
				for _, elt := range cl.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					col, ok := fields[key.Name]
					if !ok {
						continue
					}
					checked++
					if isSealedExpr(kv.Value, assigns, map[string]bool{}) {
						continue
					}
					k := name + ":" + fn.Name.Name + ":" + typeName + "." + key.Name
					if ledgerHas(k) {
						seenLedger[k] = true
						continue
					}
					offenders = append(offenders, fmt.Sprintf(
						"%s:%d  %s writes %s.%s (column %s) with a value that never reaches a sealer",
						name, fset.Position(kv.Pos()).Line, fn.Name.Name, typeName, key.Name, col))
				}
				return true
			})
		}
	}

	if checked < 20 {
		t.Fatalf("ABORT: only %d sealed-column writes were examined. The tree has far more than "+
			"that, so the walk is not reaching them and a pass proves nothing", checked)
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf("A SEALED COLUMN IS WRITTEN WITHOUT SEALING, which is how the enc:v1: "+
			"decryption oracle came back through the import path:\n  %s\n\n"+
			"Client input into one of these columns must go through encryptColumn, which ALWAYS "+
			"seals, so a string that already looks like ciphertext is stored as the caller's own "+
			"literal bytes instead of being opened and handed back. A value that came out of the "+
			"database already sealed belongs in storageSideWrites with a reason.",
			strings.Join(offenders, "\n  "))
	}

	// The other direction: a signed-for exemption that no longer describes any
	// code is a claim about the tree that has stopped being true.
	for _, s := range storageSideWrites {
		if !seenLedger[s.key()] {
			t.Errorf("storageSideWrites still exempts %s, and no such write exists any more. "+
				"An exemption nobody can find is an exemption nobody is checking", s.key())
		}
	}
}

func ledgerHas(key string) bool {
	for _, s := range storageSideWrites {
		if s.key() == key {
			return true
		}
	}
	return false
}

// collectAssignments records every expression each local name is ever assigned
// in one function body, so an identifier can be traced back to a sealer.
func collectAssignments(body *ast.BlockStmt) map[string][]ast.Expr {
	out := map[string][]ast.Expr{}
	record := func(lhs []ast.Expr, rhs []ast.Expr) {
		for i, l := range lhs {
			id, ok := l.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			switch {
			case len(rhs) == len(lhs):
				out[id.Name] = append(out[id.Name], rhs[i])
			case len(rhs) == 1:
				// Multi-value call: encryptMetaColumns returns five sealed
				// columns and an error in one go.
				out[id.Name] = append(out[id.Name], rhs[0])
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			record(s.Lhs, s.Rhs)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, 0, len(s.Names))
			for _, nm := range s.Names {
				lhs = append(lhs, nm)
			}
			record(lhs, s.Values)
		}
		return true
	})
	return out
}

// isSealedExpr answers whether a value expression got where it is via a sealer.
func isSealedExpr(e ast.Expr, assigns map[string][]ast.Expr, seen map[string]bool) bool {
	switch v := e.(type) {
	case *ast.CallExpr:
		switch fn := v.Fun.(type) {
		case *ast.SelectorExpr:
			if sealerNames[fn.Sel.Name] {
				return true
			}
			if unwrapperNames[fn.Sel.Name] && len(v.Args) == 1 {
				return isSealedExpr(v.Args[0], assigns, seen)
			}
		case *ast.Ident:
			if sealerNames[fn.Name] {
				return true
			}
			if unwrapperNames[fn.Name] && len(v.Args) == 1 {
				return isSealedExpr(v.Args[0], assigns, seen)
			}
		}
		return false
	case *ast.CompositeLit:
		// sql.NullString{String: x, Valid: true} carries x unchanged.
		for _, elt := range v.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "String" {
				return isSealedExpr(kv.Value, assigns, seen)
			}
		}
		return false
	case *ast.Ident:
		if seen[v.Name] {
			return false
		}
		seen[v.Name] = true
		for _, rhs := range assigns[v.Name] {
			if isSealedExpr(rhs, assigns, seen) {
				return true
			}
		}
		return false
	}
	return false
}

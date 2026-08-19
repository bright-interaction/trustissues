package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// pendingRevokeHeadMarkerIdents are the constant IDENTIFIERS naming the four
// head markers.
var pendingRevokeHeadMarkerIdents = map[string]bool{
	"pendingRevokeMethod": true,
	"pendingRevokeURL":    true,
	"pendingRevokeAuth":   true,
	"pendingRevokeKeyID":  true,
}

// pendingRevokeHeadMarkerValues are the same four markers by VALUE, taken from
// the constants themselves so the two lists cannot drift apart.
//
// The first version of this guard matched identifiers only, on the reasoning
// that a site writing the literal "pending_revoke_url" was "a different and
// worse problem that reservedProviderMetaKeys already covers". THAT WAS FALSE
// and it is corrected here rather than left standing: rejectReservedProviderMetaKeys
// has exactly two call sites, vault.go:1503 and vault.go:2484, and both run on a
// CLIENT-SUPPLIED provider_meta body. Nothing in that list looks at a
// server-side write, so a handler assigning the bare literal was covered by
// nothing at all.
var pendingRevokeHeadMarkerValues = map[string]bool{
	pendingRevokeMethod: true,
	pendingRevokeURL:    true,
	pendingRevokeAuth:   true,
	pendingRevokeKeyID:  true,
}

// pendingRevokeMarkerSetIdents name package-level slices whose ELEMENTS are head
// markers. Ranging over one and assigning m[k] writes the head just as directly
// as naming a constant, and it is the shape a maintainer is most likely to
// reach for, because dischargePendingRevokeHead's own delete-loop looks exactly
// like it.
//
// THIS LIST IS NOW A CROSS-CHECK, NOT THE MECHANISM. Round 2 of the review
// showed that renaming pendingRevokeMarkerKeys silently reopened the range-loop
// shape, because nothing asserted the name still resolved to anything: a guard
// that cannot fail is not a guard. The mechanism is now the package-level taint
// pass in scanHeadMarkerWrites, which DERIVES the marker sets from the source
// instead of being told them, so a rename is covered on the day it happens. The
// list survives as a vacuity assertion: every name in it must still resolve to a
// package-level declaration that mentions a head marker, so the list cannot rot
// into decoration.
var pendingRevokeMarkerSetIdents = map[string]bool{
	"pendingRevokeMarkerKeys": true,
}

// pendingRevokeMarkerSetExemptIdents are package-level declarations that DO
// mention head markers but whose ranged writes are legitimate non-owner writes.
//
// This is the finite surface the guard owns. The taint pass would otherwise
// propagate through reservedProviderMetaKeys, which is a SUPERSET of the marker
// set and is ranged over by reconcileProviderMetaForStorage to RESTORE stored
// values on every Save. That is a deliberate non-owner write and always has
// been. Adding a name here sanctions every ranged write over it, so it is
// exactly the decision a reviewer should have to see.
var pendingRevokeMarkerSetExemptIdents = map[string]bool{
	"reservedProviderMetaKeys": true,
}

// pendingRevokeHeadWriters are the ONLY functions allowed to assign into the
// head marker slot, KEYED ON RECEIVER AND NAME.
//
// The key form is the bare name for a plain function and "(T).name" for a
// method. The first version keyed on fn.Name.Name alone and never looked at the
// receiver, so `func (x someType) dischargePendingRevokeHead(...)` on ANY type in
// this 58.7k-line package inherited the sanction of the real owner and could
// write the head freely.
//
//   - deferRevokeOldProviderKey records a new predecessor, and must call
//     pushDisplacedHeadOntoBacklog first so the head it is about to overwrite is
//     not evicted, and must honour its false return.
//   - dischargePendingRevokeHead retires the head and promotes the oldest
//     stranded predecessor into it.
//
// Anything else writing these four keys is claiming the slot without going
// through the queue, which is precisely how the CRITICAL was built: one slot,
// N stranded keys, last writer wins, and the loser is a credential still valid
// at a vendor with nothing in the product naming it.
var pendingRevokeHeadWriters = map[string]bool{
	"deferRevokeOldProviderKey":  true,
	"dischargePendingRevokeHead": true,
}

// headMarkerScan is the result of one detection run.
type headMarkerScan struct {
	// writers maps an enclosing declaration key to the position of each head
	// marker write found inside it.
	writers map[string][]string
	// pkgTainted are package-level identifiers that name, or hold, a head marker.
	pkgTainted map[string]bool
	// pkgNames is every package-level const/var name seen, so a stale entry in
	// one of the hand-written lists above can be told from a real one.
	pkgNames map[string]bool
	files    int
}

// scanHeadMarkerWrites is THE DETECTION MODEL, factored out of the guard so the
// self-test table at the bottom of this file can drive it with synthetic
// sources and pin both what it fires on and what it does not.
//
// WHAT IT SEES. A write into a map whose KEY mentions a head marker, in every
// shape Go offers for writing into a map:
//
//   - `m[pendingRevokeURL] = u`, the plain index assignment.
//   - `m["pending_revoke_url"] = u`, the bare string literal.
//   - `k := pendingRevokeURL; m[k] = u`, and any chain of aliases, because the
//     local taint pass runs to a fixpoint.
//   - `for _, k := range <any package-level slice holding a marker> { m[k] = u }`.
//   - `map[string]string{pendingRevokeURL: u}`, the composite literal. Round 2
//     reproduced the original CRITICAL byte for byte through this shape, which
//     the AssignStmt-plus-IndexExpr model walked straight past.
//   - `maps.Copy(dst, src)` and `maps.Insert`, which write N keys at once and
//     are not assignments at all.
//   - all of the above inside a package-level `var w = func(...){...}` or any
//     nested function literal, not only inside a func declaration.
//   - all of the above reached through a CROSS-FILE package-level alias, because
//     the taint pass runs over the whole package before any file is inspected.
//
// WHAT IT DOES NOT SEE, stated so the next reader is not misled the way the
// previous comment misled one:
//
//   - GENERIC WHOLE-MAP COPY LOOPS. `for k, v := range src { dst[k] = v }` moves
//     these keys with everything else and is outside the model entirely: the
//     index is a range variable over an untyped string map, and tainting that
//     would fire on every map copy in the package. FIVE such loops exist today
//     and all five carry head markers: vault_rotation_core.go:241 and :244
//     (persistProviderMetaAfterRevoke's merge), vault_pending_revoke.go:427
//     (the CAS retry's working copy) and :563 (providerMetaBytesPreservingTypes,
//     the persist path), and vault_ownership_repair.go:978. They are deliberate,
//     they are NOT covered here, and a new one is not covered either.
//   - RESERVED-KEY LOOPS. reservedProviderMetaKeys is a superset of the marker
//     set and is ranged over by reconcileProviderMetaForStorage to RESTORE
//     stored values (egress_authority.go:654 writes fields[k] from it, and
//     belongs in THIS bullet rather than the whole-map one above, where an
//     earlier revision of this comment filed it while also miscounting the
//     whole-map loops as four). Excluded on purpose, through
//     pendingRevokeMarkerSetExemptIdents.
//   - a key arriving as a function parameter or out of another package.
//
// So this is a guard against the targeted single-key write, which is the shape
// the CRITICAL had and the shape a maintainer reintroduces. It is not a complete
// mediation layer, and nothing downstream should be built as if it were.
func scanHeadMarkerWrites(fset *token.FileSet, files []*ast.File) headMarkerScan {
	sc := headMarkerScan{
		writers:    map[string][]string{},
		pkgTainted: map[string]bool{},
		pkgNames:   map[string]bool{},
		files:      len(files),
	}
	for name := range pendingRevokeMarkerSetIdents {
		sc.pkgTainted[name] = true
	}

	// PASS A, PACKAGE-WIDE AND CROSS-FILE. Any package-level const or var whose
	// value mentions a head marker names one too. Run to a fixpoint so an alias
	// of an alias is covered, and run over EVERY file before any file is
	// inspected, so a write in file B through a name declared in file A is not
	// laundered by parse order.
	for round := 0; round < 8; round++ {
		before := len(sc.pkgTainted)
		for _, f := range files {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						sc.pkgNames[name.Name] = true
						if name.Name == "_" || pendingRevokeMarkerSetExemptIdents[name.Name] {
							continue
						}
						if i < len(vs.Values) && mentionsHeadMarker(vs.Values[i], sc.pkgTainted) {
							sc.pkgTainted[name.Name] = true
						}
					}
				}
			}
		}
		if len(sc.pkgTainted) == before {
			break
		}
	}

	// PASS B. Attribute every write to the declaration that contains it.
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				sc.inspect(fset, headWriterKey(d), d.Body)
			case *ast.GenDecl:
				// PACKAGE-LEVEL VALUES. The first version walked *ast.FuncDecl
				// only, so `var w = func(m, u) { m[K] = u }` and a package-level
				// composite literal both evaded the guard entirely.
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, v := range vs.Values {
						key := "var _"
						if i < len(vs.Names) {
							key = "var " + vs.Names[i].Name
						}
						sc.inspect(fset, key, v)
					}
				}
			}
		}
	}
	return sc
}

// inspect walks one declaration and records every head marker write in it.
func (sc *headMarkerScan) inspect(fset *token.FileSet, key string, n ast.Node) {
	tainted := taintedMarkerAliases(n, sc.pkgTainted)
	record := func(pos token.Pos) {
		sc.writers[key] = append(sc.writers[key], fset.Position(pos).String())
	}
	ast.Inspect(n, func(nd ast.Node) bool {
		switch v := nd.(type) {
		case *ast.AssignStmt:
			for _, lhs := range v.Lhs {
				if idx, ok := lhs.(*ast.IndexExpr); ok && mentionsHeadMarker(idx.Index, tainted) {
					record(v.Pos())
				}
			}
		case *ast.CompositeLit:
			// A map literal keyed on a marker builds the head in one expression,
			// with no assignment for the old model to match on.
			if !isMapCompositeLit(v) {
				return true
			}
			for _, el := range v.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok && mentionsHeadMarker(kv.Key, tainted) {
					record(kv.Pos())
				}
			}
		case *ast.CallExpr:
			// maps.Copy and maps.Insert write N keys at once and are not
			// assignments, so neither the index model nor the literal model
			// above sees them.
			if !isBulkMapWrite(v.Fun) {
				return true
			}
			for _, a := range v.Args {
				if mentionsHeadMarker(a, tainted) {
					record(v.Pos())
					break
				}
			}
		}
		return true
	})
}

// isMapCompositeLit reports whether a composite literal builds a map. A literal
// with no explicit type is included: that is the elided form inside a slice or
// map of maps, and excluding it would reopen the shape one nesting level down.
func isMapCompositeLit(v *ast.CompositeLit) bool {
	if v.Type == nil {
		return true
	}
	_, ok := v.Type.(*ast.MapType)
	return ok
}

// isBulkMapWrite reports whether an expression names a stdlib bulk map write.
func isBulkMapWrite(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "maps" {
		return false
	}
	return sel.Sel.Name == "Copy" || sel.Sel.Name == "Insert"
}

// TestOnlyTheQueueOwnersWriteThePendingRevokeHeadMarkers pins the invariant that
// the four pending_revoke_* scalars are a QUEUE HEAD, not a free slot.
//
// The natural way to reintroduce the 2026-08-19 CRITICAL is to write the obvious
// thing: set the markers directly from a new adapter, a repair path or a future
// second defer site. That compiles, reads fine, passes review, and silently
// evicts a stranded predecessor whose coordinates are the only record of how to
// kill it. This walks the package AST (naming no file by hand, hardcoding no
// count) and fails when the head is assigned from anywhere but the two owners.
//
// The detection model, and everything it deliberately does not cover, is
// documented on scanHeadMarkerWrites. What it fires and does not fire on is
// PINNED EXECUTABLY by TestTheHeadWriterGuardFiresOnEveryWriteShape below,
// rather than described in prose that nothing checks.
func TestOnlyTheQueueOwnersWriteThePendingRevokeHeadMarkers(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files = append(files, f)
	}

	sc := scanHeadMarkerWrites(fset, files)

	// Fail closed. An empty glob, or a package that no longer assigns the head at
	// all, would make the assertion below vacuously pass.
	if sc.files < 5 {
		t.Fatalf("ABORT: only %d source files were parsed; this guard is not looking at the package", sc.files)
	}
	if len(sc.writers) == 0 {
		t.Fatalf("ABORT: no assignment to any of {%s} was found anywhere. Either the constants were "+
			"renamed (update pendingRevokeHeadMarkerIdents) or nothing records a deferred revoke any "+
			"more; neither is a change this guard should pass silently.", headMarkerIdentNames())
	}
	// The value list is what closes the string-literal shape. If the constants
	// ever collapse to fewer distinct values it stops covering what it claims to.
	if len(pendingRevokeHeadMarkerValues) != len(pendingRevokeHeadMarkerIdents) {
		t.Fatalf("ABORT: %d marker values for %d marker identifiers; the literal-shape half of this "+
			"guard is no longer covering every marker.",
			len(pendingRevokeHeadMarkerValues), len(pendingRevokeHeadMarkerIdents))
	}
	// THE VACUITY CHECK THE ROUND-2 REVIEW FOUND MISSING. Renaming
	// pendingRevokeMarkerKeys used to reopen the range-loop shape in silence.
	// The taint pass now derives marker sets from the source, so the rename is
	// covered either way, but a name in this list that resolves to nothing means
	// the list has rotted and someone is relying on a cross-check that is gone.
	if stale := staleIdents(pendingRevokeMarkerSetIdents, sc.pkgNames); len(stale) > 0 {
		t.Fatalf("ABORT: pendingRevokeMarkerSetIdents names %s, which is not declared at package "+
			"level any more. It was almost certainly renamed. Update this list so the cross-check "+
			"keeps meaning something.", strings.Join(stale, ", "))
	}
	// The same, for the exemptions. A stale exemption silently sanctions writes
	// through a name that no longer exists, and hides that it is doing so.
	if stale := staleIdents(pendingRevokeMarkerSetExemptIdents, sc.pkgNames); len(stale) > 0 {
		t.Fatalf("ABORT: pendingRevokeMarkerSetExemptIdents exempts %s, which is not declared at "+
			"package level any more. Remove the exemption or point it at the new name.",
			strings.Join(stale, ", "))
	}
	for _, owner := range sortedMapKeys(pendingRevokeHeadWriters) {
		if len(sc.writers[owner]) == 0 {
			t.Fatalf("ABORT: %s no longer assigns any head marker. It is declared an owner of the queue "+
				"head, so if it stopped writing one the ownership model has moved and this guard is "+
				"measuring nothing.", owner)
		}
	}

	for _, fn := range sortedMapKeys(sc.writers) {
		if pendingRevokeHeadWriters[fn] {
			continue
		}
		t.Errorf("%s assigns a pending-revoke head marker at %s.\n"+
			"The four pending_revoke_* scalars are the HEAD of a queue, not a free slot: only {%s} may "+
			"write them, because only they push the displaced head onto pending_revoke_stranded "+
			"(deferRevokeOldProviderKey) or promote the oldest stranded predecessor out of it "+
			"(dischargePendingRevokeHead). A site that claims the slot directly EVICTS a still-live "+
			"key whose coordinates are the only record of how to revoke it. That was the 2026-08-19 "+
			"CRITICAL.",
			fn, strings.Join(sc.writers[fn], ", "), ownerNamesOf(pendingRevokeHeadWriters))
	}
}

// TestTheHeadWriterGuardFiresOnEveryWriteShape IS THE GUARD'S OWN GUARD.
//
// It replaces a prose "ablation notes" comment that nothing executed. Round 1 of
// the review found four evading shapes, the fix widened the enumeration, and
// round 2 found four MORE walking past the widened version, one of which
// reproduced the original CRITICAL byte for byte. Prose cannot notice that. A
// table can: every row is a real source snippet run through the real detection
// model, and the not-fired rows pin the false-positive set just as hard as the
// fired rows pin the coverage, so the model cannot silently widen either.
//
// Add a row here whenever the model changes. A shape with no row is a shape
// nobody has checked.
func TestTheHeadWriterGuardFiresOnEveryWriteShape(t *testing.T) {
	const preamble = "package handlers\n\nimport \"maps\"\n"

	// wantWriters is the EXACT set of declarations the model must attribute a
	// head write to, not merely "something fired". Attribution is what the owner
	// allowlist keys on, so a shape detected under the wrong declaration is a
	// shape the ownership check cannot act on. It also stops a row passing on
	// the strength of a DIFFERENT shape in the same snippet, which is how the
	// first version of the maps.Copy row passed while the maps.Copy detection
	// itself was doing nothing.
	for _, tc := range []struct {
		name        string
		src         string
		wantWriters []string
	}{
		{
			name:        "the plain index assignment",
			src:         `func evader(m map[string]string, u string) { m[pendingRevokeURL] = u }`,
			wantWriters: []string{"evader"},
		},
		{
			name:        "the bare string literal",
			src:         `func evader(m map[string]string, u string) { m["pending_revoke_url"] = u }`,
			wantWriters: []string{"evader"},
		},
		{
			name:        "a local alias",
			src:         `func evader(m map[string]string, u string) { k := pendingRevokeURL; m[k] = u }`,
			wantWriters: []string{"evader"},
		},
		{
			name:        "a chain of local aliases",
			src:         `func evader(m map[string]string, u string) { a := pendingRevokeURL; b := a; m[b] = u }`,
			wantWriters: []string{"evader"},
		},
		{
			name: "a range over the declared marker set",
			src: `var pendingRevokeMarkerKeys = []string{pendingRevokeURL}
func evader(m map[string]string, u string) { for _, k := range pendingRevokeMarkerKeys { m[k] = u } }`,
			wantWriters: []string{"evader"},
		},
		{
			name: "a range over a RENAMED marker set, which the old model lost",
			src: `var freshlyRenamedMarkerKeys = []string{pendingRevokeURL, pendingRevokeKeyID}
func evader(m map[string]string, u string) { for _, k := range freshlyRenamedMarkerKeys { m[k] = u } }`,
			wantWriters: []string{"evader"},
		},
		{
			name:        "a map composite literal, which reproduced the CRITICAL",
			src:         `func evader(u string) map[string]string { return map[string]string{pendingRevokeURL: u} }`,
			wantWriters: []string{"evader"},
		},
		{
			name:        "a composite literal with the type elided one level down",
			src:         `func evader(u string) []map[string]string { return []map[string]string{{pendingRevokeURL: u}} }`,
			wantWriters: []string{"evader"},
		},
		{
			// The seed map fires where it is BUILT; the point of this row is that
			// "evader" fires too, which only the maps.Copy detection can produce.
			name: "maps.Copy of a marker-bearing map",
			src: `var headMarkerSeed = map[string]string{pendingRevokeURL: "u"}
func evader(m map[string]string) { maps.Copy(m, headMarkerSeed) }`,
			wantWriters: []string{"evader", "var headMarkerSeed"},
		},
		{
			name:        "a package-level function value",
			src:         `var evader = func(m map[string]string, u string) { m[pendingRevokeURL] = u }`,
			wantWriters: []string{"var evader"},
		},
		{
			name:        "a nested function literal inside an ordinary function",
			src:         `func benignLooking() func(map[string]string, string) { return func(m map[string]string, u string) { m[pendingRevokeURL] = u } }`,
			wantWriters: []string{"benignLooking"},
		},
		{
			name:        "a package-level alias of a marker constant",
			src:         `var aliasedKey = pendingRevokeURL` + "\n" + `func evader(m map[string]string, u string) { m[aliasedKey] = u }`,
			wantWriters: []string{"evader"},
		},
		{
			name:        "an unrelated single-key write",
			src:         `func benign(m map[string]string, u string) { m["some_other_key"] = u }`,
			wantWriters: nil,
		},
		{
			name:        "an unrelated map literal",
			src:         `func benign(u string) map[string]string { return map[string]string{"some_other_key": u} }`,
			wantWriters: nil,
		},
		{
			name:        "a generic whole-map copy loop",
			src:         `func benign(dst, src map[string]string) { for k, v := range src { dst[k] = v } }`,
			wantWriters: nil,
		},
		{
			name:        "maps.Copy of an untyped map",
			src:         `func benign(dst, src map[string]string) { maps.Copy(dst, src) }`,
			wantWriters: nil,
		},
		{
			name: "a reserved-keys loop, exempt on purpose",
			src: `var reservedProviderMetaKeys = []string{pendingRevokeURL, pendingRevokeKeyID}
func benign(m, stored map[string]string) { for _, k := range reservedProviderMetaKeys { m[k] = stored[k] } }`,
			wantWriters: nil,
		},
		{
			name:        "a struct literal whose field names are not markers",
			src:         `func benign() strandedRevoke { return strandedRevoke{KeyID: "K1", URL: "u"} }`,
			wantWriters: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "shape.go", preamble+tc.src+"\n", 0)
			if err != nil {
				t.Fatalf("parse the shape under test: %v", err)
			}
			sc := scanHeadMarkerWrites(fset, []*ast.File{f})
			got := sortedMapKeys(sc.writers)
			if strings.Join(got, "|") != strings.Join(tc.wantWriters, "|") {
				t.Errorf("the guard attributed head writes to %v, want %v, on:\n%s",
					got, tc.wantWriters, tc.src)
			}
		})
	}
}

// TestTheMarkerSetCrossCheckCannotGoVACUOUS pins the vacuity assertion itself.
//
// The round-2 review found that renaming pendingRevokeMarkerKeys silently
// reopened the range-loop shape, because the guard trusted a hand-written name
// list and never asked whether the name still resolved to anything. A guard
// that cannot fail is not a guard, so the check that catches that must itself
// be checked.
func TestTheMarkerSetCrossCheckCannotGoVACUOUS(t *testing.T) {
	declared := map[string]bool{"pendingRevokeMarkerKeys": true}

	present := map[string]bool{"pendingRevokeMarkerKeys": true, "somethingElse": true}
	if stale := staleIdents(declared, present); len(stale) != 0 {
		t.Errorf("a name that IS declared was reported stale: %v", stale)
	}

	renamed := map[string]bool{"pendingRevokeMarkerKeysRenamed": true}
	stale := staleIdents(declared, renamed)
	if len(stale) != 1 || stale[0] != "pendingRevokeMarkerKeys" {
		t.Errorf("a renamed marker set was not reported stale: got %v.\n"+
			"Without this the hand-written cross-check rots into decoration and nobody is told.", stale)
	}
}

// staleIdents returns the declared names that no name in the package matches.
func staleIdents(declared, present map[string]bool) []string {
	var out []string
	for _, name := range sortedMapKeys(declared) {
		if !present[name] {
			out = append(out, name)
		}
	}
	return out
}

// TestTheHeadWriterGuardSeesAcrossFiles pins the cross-file half separately,
// because it needs more than one file and a table row cannot express that.
//
// A package-level alias declared in one file and used in another walked past the
// old model entirely, since that model parsed and inspected each file on its own.
func TestTheHeadWriterGuardSeesAcrossFiles(t *testing.T) {
	fset := token.NewFileSet()
	declaring, err := parser.ParseFile(fset, "a.go",
		"package handlers\n\nvar aliasedKey = pendingRevokeURL\n", 0)
	if err != nil {
		t.Fatalf("parse a.go: %v", err)
	}
	using, err := parser.ParseFile(fset, "b.go",
		"package handlers\n\nfunc evader(m map[string]string, u string) { m[aliasedKey] = u }\n", 0)
	if err != nil {
		t.Fatalf("parse b.go: %v", err)
	}

	// The declaration second, so a model that depended on parse order fails here.
	sc := scanHeadMarkerWrites(fset, []*ast.File{using, declaring})
	if len(sc.writers) == 0 {
		t.Errorf("a package-level alias declared in one file and used in another was not detected; " +
			"the taint pass must run over the whole package before any file is inspected")
	}
}

// headWriterKey identifies a declaration the way pendingRevokeHeadWriters does:
// the bare name for a plain function, "(T).name" for a method. The receiver's
// pointer-ness is dropped because it is not part of the ownership question.
func headWriterKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	// receiverTypeName is the package's existing helper, in
	// secret_exit_registry_test.go. Shared rather than copied: two AST guards
	// disagreeing about what a receiver is called is exactly the drift this
	// estate keeps paying for.
	return "(" + receiverTypeName(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

// taintedMarkerAliases collects the identifiers inside one declaration that hold
// a head marker key, so `k := pendingRevokeURL; m[k] = u` and
// `for _, k := range pendingRevokeMarkerKeys { m[k] = v }` are not laundered.
//
// It is seeded with the package-level taint set, so a cross-file alias is
// already tainted before the walk starts.
//
// Run to a fixpoint so a chain (a := pendingRevokeURL; b := a; m[b] = u) is
// caught too, and so the pass does not depend on traversal order.
func taintedMarkerAliases(n ast.Node, seed map[string]bool) map[string]bool {
	tainted := map[string]bool{}
	for k, v := range seed {
		tainted[k] = v
	}
	for round := 0; round < 8; round++ {
		before := len(tainted)
		ast.Inspect(n, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				for i, rhs := range s.Rhs {
					if i >= len(s.Lhs) || !mentionsHeadMarker(rhs, tainted) {
						continue
					}
					if id, ok := s.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
						tainted[id.Name] = true
					}
				}
			case *ast.ValueSpec:
				for i, v := range s.Values {
					if i >= len(s.Names) || !mentionsHeadMarker(v, tainted) {
						continue
					}
					if s.Names[i].Name != "_" {
						tainted[s.Names[i].Name] = true
					}
				}
			case *ast.RangeStmt:
				// The ELEMENT of a marker-set slice is a marker key. The index is
				// deliberately not tainted: it is an int, and tainting it would
				// fire on any ordinary slice write in the same loop.
				if mentionsHeadMarker(s.X, tainted) {
					if id, ok := s.Value.(*ast.Ident); ok && id.Name != "_" {
						tainted[id.Name] = true
					}
				}
			}
			return true
		})
		if len(tainted) == before {
			break
		}
	}
	return tainted
}

// mentionsHeadMarker reports whether an expression names a head marker key in
// any of the recognised ways.
func mentionsHeadMarker(e ast.Expr, tainted map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.Ident:
			if pendingRevokeMarkerSetExemptIdents[v.Name] {
				return false
			}
			if pendingRevokeHeadMarkerIdents[v.Name] ||
				pendingRevokeMarkerSetIdents[v.Name] ||
				tainted[v.Name] {
				found = true
			}
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(v.Value)
			if err == nil && pendingRevokeHeadMarkerValues[s] {
				found = true
			}
		}
		return !found
	})
	return found
}

func headMarkerIdentNames() string {
	return strings.Join(sortedMapKeys(pendingRevokeHeadMarkerIdents), ", ")
}

func ownerNamesOf(m map[string]bool) string {
	return strings.Join(sortedMapKeys(m), ", ")
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

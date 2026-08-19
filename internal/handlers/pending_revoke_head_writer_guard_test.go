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
var pendingRevokeMarkerSetIdents = map[string]bool{
	"pendingRevokeMarkerKeys": true,
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
// WHAT THIS GUARD SEES. A map index assignment whose INDEX EXPRESSION mentions a
// head marker in any of four ways: the constant identifier, the bare string
// literal, an element of a marker-set slice (including a range variable bound to
// one), or a local variable that was assigned from any of those. The taint pass
// runs to a fixpoint, so a chain of aliases does not launder a write.
//
// WHAT THIS GUARD DOES NOT SEE, stated so the next reader is not misled the way
// the previous comment misled one:
//
//   - GENERIC WHOLE-MAP COPY LOOPS. `for k, v := range src { dst[k] = v }` moves
//     these keys with everything else and is outside the model entirely: the
//     index is a range variable over an untyped string map, and tainting that
//     would fire on every map copy in the package. Four such loops exist today
//     and all four carry head markers: vault_rotation_core.go:241 and :244
//     (persistProviderMetaAfterRevoke's merge), vault_pending_revoke.go:427,
//     vault_ownership_repair.go:978 and egress_authority.go:654. They are
//     deliberate, they are NOT covered here, and a new one is not covered either.
//   - reservedProviderMetaKeys loops. That slice is a superset of the marker set
//     and is ranged over by reconcileProviderMetaForStorage to RESTORE stored
//     values, which is a legitimate non-owner write. It is excluded on purpose.
//   - a key arriving as a function parameter or out of another package.
//
// So this is a guard against the targeted single-key write, which is the shape
// the CRITICAL had and the shape a maintainer reintroduces. It is not a complete
// mediation layer, and nothing downstream should be built as if it were.
//
// Ablation notes, recorded per the audit's guard rules:
//   - deleting the pushDisplacedHeadOntoBacklog call from
//     deferRevokeOldProviderKey does NOT fire this guard (it is a call, not an
//     assignment); that regression is caught behaviourally by
//     TestTwoStillLiveKeysKeepSeparateIdentitiesAndOneRetryClearsOnlyItsOwn and
//     by TestOldShapeProviderMetaRowsStillReadAndDischargeCorrectly. The two are
//     complementary and neither replaces the other.
//   - adding any of these to another function fires the non-owner assertion:
//     `m[pendingRevokeURL] = u`, `k := pendingRevokeURL; m[k] = u`,
//     `m["pending_revoke_url"] = u`, or
//     `for i, k := range pendingRevokeMarkerKeys { m[k] = vals[i] }`.
//   - moving an owner onto a receiver, or renaming either owner, without
//     updating pendingRevokeHeadWriters fires it too, which is correct: that is
//     exactly when the ownership question should be re-asked.
//   - emptying the glob, or removing the last assignment, fires the vacuity
//     checks rather than passing silently.
func TestOnlyTheQueueOwnersWriteThePendingRevokeHeadMarkers(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	checked := 0
	writers := map[string][]string{} // enclosing func key -> file:pos of each assignment
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		checked++

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := headWriterKey(fn)
			tainted := taintedMarkerAliases(fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assign.Lhs {
					idx, ok := lhs.(*ast.IndexExpr)
					if !ok {
						continue
					}
					if !mentionsHeadMarker(idx.Index, tainted) {
						continue
					}
					writers[name] = append(writers[name], fset.Position(assign.Pos()).String())
				}
				return true
			})
		}
	}

	// Fail closed. An empty glob, or a package that no longer assigns the head at
	// all, would make the assertion below vacuously pass.
	if checked < 5 {
		t.Fatalf("ABORT: only %d source files were parsed; this guard is not looking at the package", checked)
	}
	if len(writers) == 0 {
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
	for _, owner := range sortedMapKeys(pendingRevokeHeadWriters) {
		if len(writers[owner]) == 0 {
			t.Fatalf("ABORT: %s no longer assigns any head marker. It is declared an owner of the queue "+
				"head, so if it stopped writing one the ownership model has moved and this guard is "+
				"measuring nothing.", owner)
		}
	}

	for _, fn := range sortedMapKeys(writers) {
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
			fn, strings.Join(writers[fn], ", "), ownerNamesOf(pendingRevokeHeadWriters))
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

// taintedMarkerAliases collects the local identifiers inside one function body
// that hold a head marker key, so `k := pendingRevokeURL; m[k] = u` and
// `for _, k := range pendingRevokeMarkerKeys { m[k] = v }` are not laundered.
//
// Run to a fixpoint so a chain (a := pendingRevokeURL; b := a; m[b] = u) is
// caught too, and so the pass does not depend on traversal order.
func taintedMarkerAliases(body *ast.BlockStmt) map[string]bool {
	tainted := map[string]bool{}
	for round := 0; round < 8; round++ {
		before := len(tainted)
		ast.Inspect(body, func(n ast.Node) bool {
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
// any of the four recognised ways.
func mentionsHeadMarker(e ast.Expr, tainted map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.Ident:
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

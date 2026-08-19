package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// pendingRevokeHeadMarkerIdents are the constant IDENTIFIERS naming the four
// head markers. Matched as identifiers, not as their string values, because a
// site that writes the literal "pending_revoke_url" instead of the const is a
// different (and worse) problem that reservedProviderMetaKeys already covers.
var pendingRevokeHeadMarkerIdents = map[string]bool{
	"pendingRevokeMethod": true,
	"pendingRevokeURL":    true,
	"pendingRevokeAuth":   true,
	"pendingRevokeKeyID":  true,
}

// pendingRevokeHeadWriters are the ONLY functions allowed to assign into the
// head marker slot.
//
//   - deferRevokeOldProviderKey records a new predecessor, and must call
//     pushDisplacedHeadOntoBacklog first so the head it is about to overwrite is
//     not evicted.
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
// Ablation notes, recorded per the audit's guard rules:
//   - deleting the pushDisplacedHeadOntoBacklog call from
//     deferRevokeOldProviderKey does NOT fire this guard (it is a call, not an
//     assignment); that regression is caught behaviourally by
//     TestTwoStillLiveKeysKeepSeparateIdentitiesAndOneRetryClearsOnlyItsOwn and
//     by TestOldShapeProviderMetaRowsStillReadAndDischargeCorrectly. The two are
//     complementary and neither replaces the other.
//   - adding `m[pendingRevokeURL] = ...` to any other function fires the
//     non-owner assertion.
//   - renaming either owner without updating pendingRevokeHeadWriters fires it
//     too, which is correct: a rename is exactly when the ownership question
//     should be re-asked.
//   - emptying the glob, or removing the last assignment, fires the vacuity
//     checks rather than passing silently.
func TestOnlyTheQueueOwnersWriteThePendingRevokeHeadMarkers(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	checked := 0
	writers := map[string][]string{} // enclosing func name -> file:pos of each assignment
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
			name := fn.Name.Name
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
					key, ok := idx.Index.(*ast.Ident)
					if !ok || !pendingRevokeHeadMarkerIdents[key.Name] {
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

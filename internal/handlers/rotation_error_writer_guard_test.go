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

// The two writers of last_rotation_error, matched by the selector name a caller
// types (queries.<name>). One SETs the column unconditionally; the other
// compare-and-swaps on its prior value.
const (
	unconditionalRotationErrorWriter = "UpdateVaultEntryRotationError"
	casRotationErrorWriter           = "CASVaultEntryRotationError"
	// The single clearer that must route through the CAS writer. If it reverts to
	// the unconditional writer the durable-alarm-erasure bug is back, and the
	// vacuity check below turns that revert into a failure rather than a pass.
	rotationErrorClearer = "clearRevokeHalfOfRotationError"
)

// rotationErrorOwners are the only functions allowed to write last_rotation_error
// UNCONDITIONALLY. Each records an absolute verdict about the rotation attempt it
// just made and legitimately owns the column's new value, so a compare-and-swap
// there would DROP a real alarm on a spurious mismatch. The CLEARERS, which strip
// only the revoke half and write the rest back, must use the CAS writer instead.
var rotationErrorOwners = map[string]bool{
	"recordRotationOutcome":              true,
	"recordRotationOutcomeUndeliverable": true,
	"recordRotationFailure":              true,
}

// TestOnlyTheOutcomeRecordersWriteRotationErrorUnconditionally pins the split
// that closed the last pending-revoke audit item (the last_rotation_error CAS).
//
// last_rotation_error has two kinds of writer with opposite concurrency needs:
//
//   - The OUTCOME recorders SET the whole column to a verdict they just produced.
//     They own it and must write unconditionally, because a CAS that lost to a
//     neighbour would drop the alarm they were told to raise.
//   - The CLEARERS (the pending-revoke retry and resolve endpoints, and the
//     provider-change discard in Update) strip only the revoke half and write the
//     rest back. If a rotation records a failure between their re-read and their
//     write, an unconditional UPDATE erases it -- durably, because a manual
//     rotation does not re-run to re-record it, so the entry reports clean while a
//     key is live upstream. They must go through CASVaultEntryRotationError.
//
// The natural way to reintroduce the bug is to write the clear the obvious way --
// call UpdateVaultEntryRotationError from a new clearer -- which compiles, reads
// fine and passes review. This walks the package AST (naming no file by hand) and
// fails if the unconditional writer is called from anywhere but an owner, or if
// the CAS writer stops being called at all.
//
// Ablation notes: restoring the pre-fix unconditional write in
// clearRevokeHalfOfRotationError makes both the "non-owner caller" assertion and
// the "CAS writer vanished" vacuity check fire. Renaming an owner without updating
// rotationErrorOwners fires the non-owner assertion (the rename is exactly the
// event that must be re-reasoned). Adding a fourth genuine owner is a deliberate
// edit to rotationErrorOwners, which is the point at which someone re-reads this
// doc and decides whether the new writer really owns its value.
func TestOnlyTheOutcomeRecordersWriteRotationErrorUnconditionally(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	checked := 0
	unconditionalCallers := map[string]string{} // enclosing func name -> file:pos of the call
	casCallers := map[string]bool{}             // enclosing func names that CAS
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
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case unconditionalRotationErrorWriter:
					unconditionalCallers[name] = fset.Position(sel.Pos()).String()
				case casRotationErrorWriter:
					casCallers[name] = true
				}
				return true
			})
		}
	}

	// Fail closed. An empty glob, or a package that no longer names either writer,
	// would make every assertion below vacuously pass.
	if checked < 5 {
		t.Fatalf("ABORT: only %d source files were parsed; this guard is not looking at the package", checked)
	}
	if len(unconditionalCallers) == 0 {
		t.Fatalf("ABORT: no call to %s found anywhere. Either it was renamed (update this guard) or the "+
			"owners stopped recording rotation outcomes -- neither is a change this guard should pass silently.",
			unconditionalRotationErrorWriter)
	}
	if !casCallers[rotationErrorClearer] {
		t.Fatalf("ABORT: %s no longer calls %s. The CAS writer exists precisely so the clear path cannot "+
			"clobber a rotation-failure alarm; if the clearer reverted to the unconditional writer, the "+
			"durable-erasure bug this guard was written for is live again.",
			rotationErrorClearer, casRotationErrorWriter)
	}

	for fn, where := range unconditionalCallers {
		if !rotationErrorOwners[fn] {
			t.Errorf("%s: %s is called from %q, which is not one of the rotation-outcome owners {%s}.\n"+
				"Only a function that OWNS the verdict it writes may set last_rotation_error unconditionally. "+
				"A CLEARER that strips just the revoke half must use %s, or it will erase a rotation-failure "+
				"alarm that landed between its re-read and its write.",
				where, unconditionalRotationErrorWriter, fn, ownerNames(), casRotationErrorWriter)
		}
	}
}

// ownerNames renders the allowed owner set deterministically for failure output.
func ownerNames() string {
	names := make([]string, 0, len(rotationErrorOwners))
	for n := range rotationErrorOwners {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

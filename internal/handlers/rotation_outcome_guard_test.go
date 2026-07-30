package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// outcomeCoreFile is the only place allowed to declare a rotation successful.
const outcomeCoreFile = "vault_rotation_core.go"

// TestOnlyTheCoreDeclaresARotationSuccessful keeps the merge from unwinding.
//
// The two rotation paths drifted on five behaviours, and four of them were the
// same shape: a path decided for itself what a rotation's final status was. There
// were three sites computing it (the sweep, the manual no-targets branch, and the
// manual delivery goroutine) and two were wrong, both overwriting a recorded
// revoke failure with a clean "success" and neither alerting.
//
// recordRotationOutcome is now the single site that decides. Nothing enforces that
// except this test: the natural way to reintroduce the bug is to add a
// RotationLogEntry{Status: "success"} somewhere convenient, which compiles, passes
// review, and silently takes a path back off the shared core.
//
// PRE-COMMIT branches are still allowed to write a log entry, because they run
// when nothing was rotated at all: a provider that refused, a reminder-only
// provider, an unregistered one. Those may only ever say "error" or "reminder".
// Claiming success or partial is what is reserved, because those two are the
// statuses that assert something about a credential that actually changed.
func TestOnlyTheCoreDeclaresARotationSuccessful(t *testing.T) {
	reserved := map[string]bool{"success": true, "partial": true}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	checked, coreDynamic := 0, false
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

		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			name, ok := lit.Type.(*ast.Ident)
			if !ok || name.Name != "RotationLogEntry" {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Status" {
					continue
				}
				switch v := kv.Value.(type) {
				case *ast.BasicLit:
					if v.Kind != token.STRING {
						continue
					}
					s, err := strconv.Unquote(v.Value)
					if err != nil {
						continue
					}
					if reserved[s] && path != outcomeCoreFile {
						t.Errorf("%s: writes a rotation_log entry with Status %q\n"+
							"Only %s may declare a rotation successful or partial. Three sites used to "+
							"compute the final status and two of them reported success over a still-live "+
							"predecessor key. Route this through recordRotationOutcome, or, if nothing was "+
							"actually rotated here, use \"error\" or \"reminder\".",
							fset.Position(v.Pos()), s, outcomeCoreFile)
					}
				default:
					// A non-literal status (a variable) is the computed outcome. Only
					// the core is entitled to compute one.
					if path == outcomeCoreFile {
						coreDynamic = true
					} else {
						t.Errorf("%s: computes a rotation_log Status dynamically\n"+
							"That is the shared core's job. A second site computing the outcome is exactly "+
							"the drift this file exists to prevent.", fset.Position(kv.Value.Pos()))
					}
				}
			}
			return true
		})

		// A composite literal is not the only way to set a status.
		//
		// `logEntry.Status = x` after construction sets it just as durably and is
		// invisible to the walk above, which only inspects RotationLogEntry literals.
		// I found this by ablating the guard: the mutation form passed clean. It is
		// the same hole the tx-scope guard had, where a pool passed as an ARGUMENT
		// slipped past a check that only looked at receiver calls. Assume every
		// structural guard has this shape of gap until an ablation says otherwise.
		ast.Inspect(f, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Status" {
					continue
				}
				if path == outcomeCoreFile {
					continue
				}
				// Only complain when the value is not a safe literal.
				if i < len(assign.Rhs) {
					if bl, ok := assign.Rhs[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						if v, err := strconv.Unquote(bl.Value); err == nil && !reserved[v] {
							continue
						}
					}
				}
				t.Errorf("%s: assigns a rotation Status outside %s\n"+
					"Setting .Status after the struct is built is the same act as setting it inside "+
					"the literal. Route the outcome through recordRotationOutcome.",
					fset.Position(sel.Pos()), outcomeCoreFile)
			}
			return true
		})
	}

	// Fail closed twice over: an empty glob, a renamed core, or a core that
	// stopped computing the status would all make this gate vacuous.
	if checked < 5 {
		t.Fatalf("ABORT: only %d source files were parsed; this guard is not looking at the package", checked)
	}
	if !coreDynamic {
		t.Fatalf("ABORT: %s does not compute a rotation_log Status. Either the shared core was "+
			"renamed (update outcomeCoreFile) or the outcome logic moved back out of it, which "+
			"is the regression this guard exists to catch.", outcomeCoreFile)
	}
}

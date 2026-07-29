package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNothingReachesThePoolInsideATransaction is a scope rule the compiler
// cannot express.
//
// SQLite allows one writer. A helper called between BeginTx and Commit that
// reaches for h.queries (the pool) opens a SECOND connection and contends with
// the write lock its own caller is holding. It does not deadlock, it burns the
// full _busy_timeout and then fails, which reads as a mysterious stall rather
// than a lock bug. This happened twice, both times in the same handler:
//
//	LogActivityFromRequest inside the tx -> 5.1s stall, activity row LOST
//	seedCapabilityDefaults inside the tx -> 5.3s stall, capability seed DROPPED
//
// Both were introduced by a fix (the round-8 transaction) and both survived
// review, because the call sites look completely ordinary. The rule is
// positional, so a positional check is the honest way to enforce it.
//
// This is deliberately cheaper than retyping every querier into pool and tx
// variants: that is 65 signature changes on a live product and it catches only
// one direction (passing the wrong querier down), not this one (reaching for the
// package-level pool from inside the window).
func TestNothingReachesThePoolInsideATransaction(t *testing.T) {
	// Calls that open their own connection. LogActivityFromRequest and
	// LogActivity build their own background context by design, so they are
	// always a second connection.
	banned := map[string]string{
		"LogActivityFromRequest": "writes on its own background context, so its own connection",
		"LogActivity":            "writes on its own background context, so its own connection",
	}
	// h.queries is the pool. Inside a transaction the tx-bound querier (qtx)
	// must be used instead.
	const poolSelector = "queries"

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	checkedFuncs := 0

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		file, err := parser.ParseFile(fset, f, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			beginPos, commitPos := token.NoPos, token.NoPos
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				sel, ok := m.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "BeginTx":
					if !beginPos.IsValid() {
						beginPos = sel.Pos()
					}
				case "Commit":
					if !commitPos.IsValid() {
						commitPos = sel.Pos()
					}
				}
				return true
			})
			if !beginPos.IsValid() {
				return true
			}
			checkedFuncs++
			// No Commit found: treat the whole rest of the function as the window.
			end := fn.Body.End()
			if commitPos.IsValid() {
				end = commitPos
			}

			// Any mention of the pool inside the window, including as an ARGUMENT.
			// The receiver-call check below misses seedCapabilityDefaults(ctx,
			// h.queries, ...), which is one of the two bugs this guard exists for:
			// handing the pool to a helper is the same second connection as
			// calling it directly.
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok || call.Pos() < beginPos || call.Pos() > end {
					return true
				}
				for _, arg := range call.Args {
					sel, ok := arg.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != poolSelector {
						continue
					}
					// LogActivity* legitimately take the pool: they run on their
					// own context by design and are flagged by name below.
					if id, ok := call.Fun.(*ast.Ident); ok {
						if _, isBanned := banned[id.Name]; isBanned {
							continue
						}
					}
					t.Errorf("%s: passes the pool querier (h.%s) into a call inside the transaction "+
						"opened at %s.\nThe callee will open a second connection and contend with the "+
						"write lock this function holds. Pass the transaction-bound querier instead.",
						fset.Position(arg.Pos()), poolSelector, fset.Position(beginPos))
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					if why, bad := banned[fun.Name]; bad {
						t.Errorf("%s: %s is called inside the transaction opened at %s.\n"+
							"It %s, so it contends with the write lock this function holds: "+
							"the full busy timeout burns and the write is then lost. "+
							"Queue it and run it after Commit.",
							fset.Position(call.Pos()), fun.Name, fset.Position(beginPos), why)
					}
				case *ast.SelectorExpr:
					// h.queries.Something(...) inside the window.
					// WithTx is how the tx-bound querier is DERIVED from the pool
					// (qtx := h.queries.WithTx(tx)), so it is the one legitimate
					// reference to h.queries inside the window.
					if fun.Sel.Name == "WithTx" {
						return true
					}
					if inner, ok := fun.X.(*ast.SelectorExpr); ok && inner.Sel.Name == poolSelector {
						t.Errorf("%s: reaches for the pool querier (h.%s.%s) inside the transaction "+
							"opened at %s.\nUse the transaction-bound querier instead; the pool is a "+
							"second connection and will contend with the write lock this function holds.",
							fset.Position(call.Pos()), poolSelector, fun.Sel.Name, fset.Position(beginPos))
					}
				}
				return true
			})
			return true
		})
	}

	// Fail closed. If no transaction is found, the rule is asserting nothing and
	// the guard has quietly stopped guarding, which is the failure class it
	// exists to prevent.
	if checkedFuncs == 0 {
		t.Fatal("ABORT: found no function containing BeginTx; this guard is vacuous " +
			"(did the transactions move to another package?)")
	}
	t.Logf("checked %d function(s) containing a transaction", checkedFuncs)
}

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

			// Taint pass, over the WHOLE body rather than just the window.
			//
			// Matching the spelling `h.queries` catches only one of several ways to
			// reach the pool. An ablation sweep found three this check used to miss
			// entirely, all of which open the same second connection:
			//
			//	pool := h.queries          then pool.Foo(ctx)      receiver is an Ident
			//	poolEarly := h.queries     BEFORE BeginTx          not positionally inside
			//	fn := h.queries.Foo        then fn(ctx)            a method value is not a call
			//
			// So any local bound from the pool, or from a method ON the pool, is
			// tainted, and a tainted name behaves exactly like h.queries below. The
			// scan covers the whole body because an alias created before the window
			// is still the pool when used inside it.
			//
			// qtx := h.queries.WithTx(tx) is deliberately NOT tainted: its RHS is a
			// CallExpr, not a selector, and qtx is the transaction-bound querier that
			// callers are supposed to use.
			tainted := map[string]bool{}
			for changed := true; changed; {
				changed = false
				ast.Inspect(fn.Body, func(m ast.Node) bool {
					assign, ok := m.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for i, rhs := range assign.Rhs {
						if i >= len(assign.Lhs) {
							break
						}
						lhs, ok := assign.Lhs[i].(*ast.Ident)
						if !ok || lhs.Name == "_" || tainted[lhs.Name] {
							continue
						}
						// A chained alias (b := a where a is already tainted) needs the
						// loop above; one pass would miss it.
						if aliasesPool(rhs, poolSelector, tainted) {
							tainted[lhs.Name] = true
							changed = true
						}
					}
					return true
				})
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
					// A tainted local passed along is the pool passed along.
					if id, ok := arg.(*ast.Ident); ok && tainted[id.Name] {
						t.Errorf("%s: passes %s, which aliases the pool querier, into a call inside "+
							"the transaction opened at %s.\nThe callee will open a second connection "+
							"and contend with the write lock this function holds.",
							fset.Position(arg.Pos()), id.Name, fset.Position(beginPos))
						continue
					}
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
					if tainted[fun.Name] {
						t.Errorf("%s: calls %s, which was bound from the pool querier, inside the "+
							"transaction opened at %s.\nA method value taken off the pool is still the "+
							"pool: it opens a second connection and contends with this function's write lock.",
							fset.Position(call.Pos()), fun.Name, fset.Position(beginPos))
					}
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
					// pool.Foo(...) where pool aliases h.queries.
					if x, ok := fun.X.(*ast.Ident); ok && tainted[x.Name] {
						t.Errorf("%s: calls %s.%s inside the transaction opened at %s, and %s aliases "+
							"the pool querier.\nUse the transaction-bound querier; the pool is a second "+
							"connection and will contend with the write lock this function holds.",
							fset.Position(call.Pos()), x.Name, fun.Sel.Name, fset.Position(beginPos), x.Name)
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

// aliasesPool reports whether e binds the pool querier or something taken off it.
//
//	h.queries        -> the pool itself
//	h.queries.Foo    -> a method VALUE on the pool, which is still the pool
//	someAlias        -> already-tainted local, for chained aliases
//
// A CallExpr is deliberately not an alias, which is what keeps
// qtx := h.queries.WithTx(tx) legitimate.
func aliasesPool(e ast.Expr, poolSelector string, tainted map[string]bool) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return tainted[v.Name]
	case *ast.SelectorExpr:
		if v.Sel.Name == poolSelector {
			return true
		}
		if inner, ok := v.X.(*ast.SelectorExpr); ok && inner.Sel.Name == poolSelector {
			return true
		}
		if id, ok := v.X.(*ast.Ident); ok && tainted[id.Name] {
			return true
		}
	}
	return false
}

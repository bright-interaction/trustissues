package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Why this test reads the router's SYNTAX instead of driving the router.
//
// The gate it guards is middleware, and internal/middleware/totp_enrollment_test.go
// already proves the middleware itself: refuses an un-enrolled session, passes an
// enrolled one, exempts only API keys, fails closed on a database error. All of
// that stayed green when the mount was deleted from this file. A gate that is
// fully tested and not installed enforces nothing, and this codebase loses things
// exactly that way -- "adding a file to the list that ENFORCES a property and not
// the list that CHECKS it leaves the property true today and unguarded tomorrow".
//
// Driving the real router would be the stronger test. It is not available: the
// router is built inline inside main() across roughly 370 lines with every handler
// constructed in place, so there is nothing to call from a test. Extracting a
// newRouter() seam is the right fix and is deliberately NOT bundled into a security
// change -- it is a refactor of the process entrypoint and wants its own review.
// Until it exists, this asserts the two structural facts that the mount depends on,
// over the AST rather than over a regexp, because round 5 of this product's audit
// history already showed a source-matching guard being walked through by four
// planted paths.
//
// If you extract newRouter(), DELETE this file and replace it with a test that
// issues real requests. It is a stand-in, not the intended end state.

const gateMiddleware = "RequireTOTPEnrollment"

// findGatedGroups returns the body of EVERY r.Group(func(r chi.Router){...})
// call that mounts the enrolment gate.
//
// It returns all of them, not the first one, and that is not defensiveness --
// the single-result version of this function was written first and was blind to
// its own ablation. ast.Inspect's `return false` only stops the walk
// DESCENDING into that node; it keeps visiting siblings. So with the gate
// mounted on two groups, the match was silently overwritten by whichever came
// last, and planting the gate on /auth (the lockout this file exists to
// prevent) left the later, innocent group as the one under test and the suite
// stayed green. The same shape as the guard that "restates the same hardcoded
// list as the production mechanism it guards", one level down: a checker that
// examines one of N sites cannot see a defect introduced at any of the others.
func findGatedGroups(file *ast.File) []*ast.BlockStmt {
	var found []*ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSelector(call.Fun, "Group") || len(call.Args) != 1 {
			return true
		}
		lit, ok := call.Args[0].(*ast.FuncLit)
		if !ok {
			return true
		}
		// Does this group's body mount the gate directly (r.Use(timw.RequireTOTPEnrollment(...)))?
		for _, stmt := range lit.Body.List {
			es, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			use, ok := es.X.(*ast.CallExpr)
			if !ok || !isSelector(use.Fun, "Use") || len(use.Args) != 1 {
				continue
			}
			inner, ok := use.Args[0].(*ast.CallExpr)
			if ok && isSelector(inner.Fun, gateMiddleware) {
				found = append(found, lit.Body)
				break
			}
		}
		// Keep descending: groups nest, and a gated group inside a gated group
		// is still a site this file has to inspect.
		return true
	})
	return found
}

func isSelector(e ast.Expr, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == name
}

// routePrefixesIn collects the string literal of every r.Route("...") and
// r.Mount("...") registered anywhere inside the given block.
func routePrefixesIn(block ast.Node) []string {
	var out []string
	ast.Inspect(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		if !isSelector(call.Fun, "Route") && !isSelector(call.Fun, "Mount") {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if s, err := strconv.Unquote(lit.Value); err == nil {
			out = append(out, s)
		}
		return true
	})
	return out
}

func parseMain(t *testing.T) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	return f
}

// The mount exists. Deleting the r.Use line fails here and nowhere else.
func TestEnrollmentGateIsActuallyMountedOnTheRouter(t *testing.T) {
	if len(findGatedGroups(parseMain(t))) == 0 {
		t.Fatalf("no r.Group in main.go mounts %s.\n"+
			"The middleware and its tests can be fully green while the router never installs it, "+
			"which is a 2FA policy that silently enforces nothing.", gateMiddleware)
	}
}

// The escape hatch is real: /auth must be registered OUTSIDE every gated group,
// or switching require_totp on locks out every un-enrolled account, including
// the only administrator on a fresh instance, with no route to enrol.
func TestAuthRoutesStayOutsideTheGatedGroup(t *testing.T) {
	groups := findGatedGroups(parseMain(t))
	if len(groups) == 0 {
		t.Skip("gate not mounted; TestEnrollmentGateIsActuallyMountedOnTheRouter reports that")
	}
	// EVERY gated group, not just one: gating /auth anywhere is the lockout,
	// regardless of how many other groups are innocent.
	for i, group := range groups {
		for _, p := range routePrefixesIn(group) {
			if p == "/auth" || strings.HasPrefix(p, "/auth/") {
				t.Fatalf("%q is registered INSIDE enrolment-gated group #%d of %d.\n"+
					"Enrolling is the only way past the gate, so gating it locks out every "+
					"un-enrolled user the moment the policy is switched on.", p, i+1, len(groups))
			}
		}
	}
}

// The protected surface actually lives behind the gate. If someone moves the
// vault routes out, the gate keeps passing its own tests while guarding
// nothing.
func TestTheGatedGroupStillContainsTheProtectedSurface(t *testing.T) {
	groups := findGatedGroups(parseMain(t))
	if len(groups) == 0 {
		t.Skip("gate not mounted; TestEnrollmentGateIsActuallyMountedOnTheRouter reports that")
	}
	var got []string
	for _, g := range groups {
		got = append(got, routePrefixesIn(g)...)
	}
	inside := make(map[string]bool, len(got))
	for _, p := range got {
		inside[p] = true
	}
	// Deliberately a small, high-value set rather than an exhaustive mirror of
	// the route table: a list that restates the whole router would have to be
	// edited on every routing change and would be maintained by deletion.
	for _, want := range []string{"/vault", "/settings", "/collections", "/admin"} {
		if !inside[want] {
			t.Errorf("%q is no longer inside the enrolment-gated group (found: %v)", want, got)
		}
	}
}

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
// already proves the middleware itself. All of that stayed green when the mount was
// deleted from this file. A gate that is fully tested and not installed enforces
// nothing, and this codebase loses things exactly that way.
//
// Driving the real router would be stronger and is not available: the router is
// built inline inside main() across ~370 lines with every handler constructed in
// place, so there is nothing to call from a test. Extracting a newRouter() seam is
// the right fix and is deliberately not bundled into a security change. If you
// extract it, DELETE this file and replace it with a test that issues real requests.
//
// WHAT THE FIRST VERSION GOT WRONG, because it is the whole reason this one is
// shaped the way it is. It asserted the EXISTENCE of a gated group: somewhere in
// main.go there is an r.Group that calls RequireTOTPEnrollment and mentions four
// route prefixes. Review broke it with four mutations:
//
//	A7  delete the real r.Use, add a dead decoy group with four empty
//	    r.Route stubs                                    -> GREEN, whole surface ungated
//	A2b move /api/api-keys out of the gate               -> GREEN, not in the hardcoded four
//	A3  register a new r.Route("/reports") outside       -> GREEN, never looked
//	A4b replace the gate with a same-named no-op         -> GREEN, receiver ignored
//
// Every one of those is the same mistake: asserting that something good exists
// somewhere, rather than that nothing bad exists anywhere. An existence claim is
// satisfied by a decoy. So this version asserts the COMPLEMENT -- it enumerates
// every route registered under the authenticated group and requires each one to be
// either under /auth or inside a gated scope. That single assertion subsumes A7,
// A2b, A3 and A5b, and needs no hardcoded list of route names to stay current.

const (
	gateMiddleware = "RequireTOTPEnrollment"
	authMiddleware = "JWTOrAPIKeyAuth"
	// middlewarePkg is the import alias main.go uses for internal/middleware.
	// The receiver is checked, not just the method name: mutation A4b replaced
	// the gate with a locally defined function of the same name and the first
	// version could not tell the difference.
	middlewarePkg = "timw"
)

// routeSite is one registration and whether the scope enclosing it is gated.
type routeSite struct {
	pattern string
	gated   bool
	line    int
}

// verbs are the chi registration methods that bind a pattern to a handler.
var verbs = map[string]bool{
	"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true,
	"Head": true, "Options": true, "Handle": true, "HandleFunc": true,
	"Method": true, "Mount": true,
}

// callsPkgFunc reports whether e is a call of <middlewarePkg>.<name>(...).
// Both halves are checked, so a same-named local function is not mistaken for
// the real middleware.
func callsPkgFunc(e ast.Expr, name string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == middlewarePkg
}

// bodyUses reports whether this block's own statements include
// r.Use(<middlewarePkg>.<name>(...)).
func bodyUses(block *ast.BlockStmt, name string) bool {
	for _, stmt := range block.List {
		es, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := es.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Use" || len(call.Args) != 1 {
			continue
		}
		if callsPkgFunc(call.Args[0], name) {
			return true
		}
	}
	return false
}

// joinPath composes a chi mount prefix with a child pattern.
func joinPath(prefix, pat string) string {
	switch {
	case prefix == "":
		return pat
	case pat == "" || pat == "/":
		return prefix
	}
	return strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(pat, "/")
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// collectRoutes walks a chi router body, carrying whether the enclosing scope is
// gated, and records every pattern registered at any depth.
// prefix is the accumulated mount path, so a Get("/me") nested inside
// Route("/auth", ...) is recorded as "/auth/me". Recording the leaf alone made
// the escape-hatch check compare "/me" against "/auth" and flag every
// self-service route as ungated.
func collectRoutes(block *ast.BlockStmt, prefix string, gated bool, fset *token.FileSet, out *[]routeSite) {
	for _, stmt := range block.List {
		es, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := es.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		// r.With(...).Get("/x", h) -- the outer call is the verb, so the switch
		// below sees it. Mutation A5b used this shape.
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			continue
		}
		line := fset.Position(call.Pos()).Line

		switch {
		case sel.Sel.Name == "Group" && len(call.Args) == 1:
			lit, ok := call.Args[0].(*ast.FuncLit)
			if !ok {
				continue
			}
			// A Group does not change the path, only the middleware scope.
			collectRoutes(lit.Body, prefix, gated || bodyUses(lit.Body, gateMiddleware), fset, out)

		case sel.Sel.Name == "Route" && len(call.Args) == 2:
			pat, ok := stringLit(call.Args[0])
			if !ok {
				continue
			}
			full := joinPath(prefix, pat)
			*out = append(*out, routeSite{full, gated, line})
			if lit, ok := call.Args[1].(*ast.FuncLit); ok {
				// A nested Route inherits its parent's gated state, and may add
				// the gate itself.
				collectRoutes(lit.Body, full, gated || bodyUses(lit.Body, gateMiddleware), fset, out)
			}

		case verbs[sel.Sel.Name] && len(call.Args) >= 1:
			if pat, ok := stringLit(call.Args[0]); ok {
				*out = append(*out, routeSite{joinPath(prefix, pat), gated, line})
			}
		}
	}
}

// findAuthGroup returns the body of the r.Group that mounts JWTOrAPIKeyAuth --
// every authenticated route in the product lives inside it.
func findAuthGroup(file *ast.File) *ast.BlockStmt {
	var found *ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Group" || len(call.Args) != 1 {
			return true
		}
		lit, ok := call.Args[0].(*ast.FuncLit)
		if !ok {
			return true
		}
		if bodyUses(lit.Body, authMiddleware) {
			found = lit.Body
			return false
		}
		return true
	})
	return found
}

func parseMain(t *testing.T) (*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	return f, fset
}

// THE assertion. Every authenticated route is either the enrolment escape hatch
// or behind the gate. Nothing else is permitted, so a route added anywhere new
// fails here by default rather than needing to be predicted by a list.
func TestEveryAuthenticatedRouteIsGatedOrIsTheEscapeHatch(t *testing.T) {
	file, fset := parseMain(t)
	authGroup := findAuthGroup(file)
	if authGroup == nil {
		t.Fatalf("no r.Group in main.go mounts %s.%s. Either the router was restructured or this "+
			"guard stopped matching it; a guard that inspects nothing must fail rather than pass.",
			middlewarePkg, authMiddleware)
	}

	var sites []routeSite
	collectRoutes(authGroup, "", false, fset, &sites)
	if len(sites) == 0 {
		t.Fatal("found no routes inside the authenticated group; the walker is broken and this " +
			"guard would pass no matter what the router did")
	}

	var ungated []routeSite
	for _, s := range sites {
		if s.pattern == "/auth" || strings.HasPrefix(s.pattern, "/auth/") {
			continue // the escape hatch, deliberately outside the gate
		}
		if !s.gated {
			ungated = append(ungated, s)
		}
	}
	if len(ungated) > 0 {
		for _, s := range ungated {
			t.Errorf("main.go:%d  route %q is registered inside the authenticated group but NOT "+
				"behind %s", s.line, s.pattern, gateMiddleware)
		}
		t.Fatalf("%d authenticated route(s) escape the enrolment gate. Every route under /api "+
			"except /auth must sit inside the group that mounts %s -- /auth is the only exemption, "+
			"because enrolling is the sole way past the gate.", len(ungated), gateMiddleware)
	}
}

// The escape hatch is real: /auth must NOT be gated, or switching require_totp on
// locks out every un-enrolled account, including the only administrator on a
// fresh instance, with no route to enrol.
func TestAuthRoutesAreNotGated(t *testing.T) {
	file, fset := parseMain(t)
	authGroup := findAuthGroup(file)
	if authGroup == nil {
		t.Skip("auth group not found; TestEveryAuthenticatedRouteIsGatedOrIsTheEscapeHatch reports that")
	}
	var sites []routeSite
	collectRoutes(authGroup, "", false, fset, &sites)
	for _, s := range sites {
		if (s.pattern == "/auth" || strings.HasPrefix(s.pattern, "/auth/")) && s.gated {
			t.Fatalf("main.go:%d  %q is INSIDE the enrolment gate. Enrolling is the only way past "+
				"the gate, so gating it locks out every un-enrolled user the moment the policy is "+
				"switched on.", s.line, s.pattern)
		}
	}
}

// The gate is mounted with the real middleware, not something that merely shares
// its name. Mutation A4b replaced it with a local no-op and the receiver-blind
// first version could not tell.
func TestGateMountIsTheRealMiddleware(t *testing.T) {
	file, _ := parseMain(t)
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Use" {
			return true
		}
		if callsPkgFunc(call.Args[0], gateMiddleware) {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Fatalf("no r.Use(%s.%s(...)) in main.go. A local function of the same name does not "+
			"count: the receiver is part of the assertion.", middlewarePkg, gateMiddleware)
	}
}

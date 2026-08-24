package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/go-chi/chi/v5"
)

// Why this file is two DIFFERENT kinds of test, on purpose.
//
// The gate it guards is middleware, and internal/middleware/totp_enrollment_test.go
// already proves the middleware itself. All of that stayed green when the mount was
// deleted from this file. A gate that is fully tested and not installed enforces
// nothing, and this codebase loses things exactly that way.
//
// WHAT THE FIRST VERSION GOT WRONG (existence, not complement). It asserted the
// EXISTENCE of a gated group: somewhere in main.go there is an r.Group that calls
// RequireTOTPEnrollment and mentions four route prefixes. Review broke it with four
// mutations (decoy group, a route moved out of the hardcoded four, a new route the
// walker never looked at, a same-named no-op gate) because an existence claim is
// satisfied by a decoy.
//
// THE SECOND VERSION (asserted the complement, over the wrong set). It rewrote the
// assertion as "every route registered inside the r.Group that mounts
// JWTOrAPIKeyAuth is either under /auth or inside a gated scope" and walked main.go's
// AST to enumerate them. That subsumed all four mutations above. But its universe was
// "routes inside the authenticated group" -- so a route registered OUTSIDE that group
// entirely was never in its domain and the guard reported nothing about it. That is
// exactly what POST /api/service-identities/me/secrets was (main.go, registered on
// r.Route("/api", ...) directly, never wrapped in any r.Group at all): a live P0, and
// the guard stayed green through it. See ops/audits/trustissues-AUDIT-2026-08-24.md,
// P0-1 and P1-1.
//
// THIS VERSION fixes the quantifier by dropping source re-parsing for the coverage
// question entirely. newRouter() (see main.go) is a real, callable seam extracted
// from main() for exactly this reason: TestEveryRegisteredRouteIsGatedAuthEscapeHatchOrExempt
// below builds the ACTUAL chi.Mux this binary serves and calls chi.Walk() on it, which
// enumerates every route the server will ever answer for -- gated group, escape
// hatch, or registered nowhere near either -- with no hardcoded list of prefixes and
// nothing for a route to hide behind by being declared in an unexpected place.
//
// WHY THE OLDER, NARROWER AST TESTS BELOW ARE KEPT, NOT REPLACED.
//
// chi.Walk reports each route's accumulated middleware stack as compiled closures,
// identified here by their runtime symbol name. That identity check is NOT reliable
// against the exact attack TestGateMountIsTheRealMiddleware exists to catch: a local
// function in this package, named RequireTOTPEnrollment, with the identical
// func(*sql.DB) func(http.Handler) http.Handler shape, mounted with no "timw."
// qualifier. Verified empirically while building this fix -- with the compiler's
// default inlining (the flags `go test ./...` actually uses, not a special-cased
// invocation), such a decoy's runtime symbol name and even its reflect.Value.Pointer()
// are INDISTINGUISHABLE from the real timw.RequireTOTPEnrollment's, because the
// closure literal gets renamed into the caller's (newRouter's) naming scope during
// inlining regardless of which package originally defined it. Source-level receiver
// checking (callsPkgFunc, below) does not have this problem: it reads the actual
// selector expression, `timw.RequireTOTPEnrollment`, which cannot be spoofed by a
// same-named local function no matter how the compiler inlines the result. So:
// chi.Walk owns the QUANTIFIER (which routes exist and are they covered by anything),
// the retained AST tests own IDENTITY (is the thing covering them actually the real
// middleware). Neither alone is sufficient; dropping either regresses a property the
// suite already had.

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

// The escape hatch is real: /auth must NOT be gated, or switching require_totp on
// locks out every un-enrolled account, including the only administrator on a
// fresh instance, with no route to enrol.
func TestAuthRoutesAreNotGated(t *testing.T) {
	file, fset := parseMain(t)
	authGroup := findAuthGroup(file)
	if authGroup == nil {
		t.Skip("auth group not found; TestEveryRegisteredRouteIsGatedAuthEscapeHatchOrExempt reports that")
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
// its name. Mutation A4b replaced it with a local no-op and a name/pointer-based
// runtime check cannot tell the difference under normal inlining (see the file
// doc comment) -- this receiver check is what actually catches it.
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

// ---------------------------------------------------------------------------
// Below: the quantifier fix. Real router, real chi.Walk, every route.
// ---------------------------------------------------------------------------

// funcSymbolContains reports whether mw's compiled runtime symbol name contains
// substr. This is a COVERAGE signal (does something resembling the gate sit on
// this route's stack at all), not an identity proof -- see the file doc comment
// for why identity is TestGateMountIsTheRealMiddleware's job, not this one's.
func funcSymbolContains(mw func(http.Handler) http.Handler, substr string) bool {
	name := runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name()
	return strings.Contains(name, substr)
}

func stackContains(mws []func(http.Handler) http.Handler, substr string) bool {
	for _, mw := range mws {
		if funcSymbolContains(mw, substr) {
			return true
		}
	}
	return false
}

// walkedRoute is one (method, pattern) chi actually registered on the real
// router, and what its accumulated middleware stack looks like.
type walkedRoute struct {
	method  string
	pattern string
	gated   bool // RequireTOTPEnrollment appears somewhere in its stack
	hasAuth bool // JWTOrAPIKeyAuth appears somewhere in its stack
}

// buildRealRouterRoutes calls the SAME newRouter() main() calls, with a deps
// struct that is nil everywhere except cfg (needed because csrfOriginCheck and
// JWTOrAPIKeyAuth read cfg.BaseURL / cfg.JWTSecret directly at registration
// time, not inside a deferred closure, so a nil *config.Config would panic
// before chi.Walk ever runs). Every other field stays nil: route registration
// only takes method VALUES off the handlers and closes over the limiters, it
// never calls or dereferences them, so this never touches a database or does
// real work.
func buildRealRouterRoutes(t *testing.T) []walkedRoute {
	t.Helper()
	r := newRouter(routerDeps{cfg: &config.Config{}})

	var routes []walkedRoute
	err := chi.Walk(r, func(method, route string, handler http.Handler, mws ...func(http.Handler) http.Handler) error {
		routes = append(routes, walkedRoute{
			method:  method,
			pattern: route,
			gated:   stackContains(mws, gateMiddleware),
			hasAuth: stackContains(mws, authMiddleware),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk(newRouter(...)): %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("newRouter() registered no routes at all; the router seam is broken and this " +
			"guard would pass no matter what the server does")
	}
	return routes
}

// serviceSecretsInHandlerCheckExists reports whether
// ServiceSecretsHandler.FetchOwnSecrets contains a call site that refuses with
// middleware.TOTPEnrollmentRequiredCode. POST /api/service-identities/me/secrets
// sits outside the session-auth group by necessity -- service containers call
// it with no cookie and no session, so RequireTOTPEnrollment can never be
// mounted on it (see the route's comment in newRouter). The ONLY enforcement
// left for it is inside the handler itself, which is a DIFFERENT mechanism than
// everything else this file checks, so the exemption below is granted ONLY
// while this is actually true in source -- not trusted from a comment that can
// go stale. Before the fix (branch agent/ti-p0-1-service-key-fix-2026-08-24,
// commit 1e6bc81aa) this returns false and the exemption is withdrawn, which is
// exactly what proves this guard would have caught P0-1: see
// TestServiceIdentitiesMeSecretsExemptionReflectsRealCoverage below.
func serviceSecretsInHandlerCheckExists() (ok bool, detail string) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "../../internal/handlers/service_secrets.go", nil, 0)
	if err != nil {
		return false, "could not parse internal/handlers/service_secrets.go: " + err.Error()
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "FetchOwnSecrets" || fn.Body == nil {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "TOTPEnrollmentRequiredCode" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "middleware" {
				found = true
			}
			return true
		})
		return false
	})
	if !found {
		return false, "ServiceSecretsHandler.FetchOwnSecrets has no call site referencing " +
			"middleware.TOTPEnrollmentRequiredCode; the owner-enrolment check is not present " +
			"in internal/handlers/service_secrets.go"
	}
	return true, "found middleware.TOTPEnrollmentRequiredCode inside FetchOwnSecrets"
}

// exemption is one route explicitly carved out of "must be gated or the escape
// hatch", with a reviewer-visible reason. verify, when non-nil, must return
// true for the exemption to be honored: an exemption that depends on a fact
// this test can check is granted ONLY while that fact holds, so a regression
// withdraws it automatically instead of leaving a stale comment nobody re-reads.
type routeExemption struct {
	pattern string
	why     string
	verify  func() (ok bool, detail string)
}

var routeExemptions = []routeExemption{
	{
		pattern: "/health",
		why:     "liveness probe. Must answer with no credential of any kind so an orchestrator can tell a broken instance apart from a healthy one and restart it; carries no data.",
	},
	{
		pattern: "/proxy/{host}",
		why: "capability bridge proxy (internal/handlers/capability.go). Authenticates via its own " +
			"signed capability token (Authorization: Capability <token>), not a session: 600s TTL, " +
			"single-use nonce, and mintable ONLY by a principal that already passed JWTOrAPIKeyAuth " +
			"and RequireTOTPEnrollment to reach POST /api/secrets/issue or the MCP use_secret tool in " +
			"the first place. A prior investigation concluded this is architecturally safe rather than " +
			"a bypass of the gate, precisely because nothing reaches it without the gate having already " +
			"run once, upstream, to mint the token.",
	},
	{
		pattern: "/proxy/{host}/*",
		why:     "same route, the wildcard sub-path form; see /proxy/{host} above.",
	},
	{
		pattern: "/api/auth/status",
		why:     "the SPA's first-run / login-page probe. Must be reachable with no session at all, or the login screen itself could never render.",
	},
	{
		pattern: "/api/auth/login",
		why:     "the login route. Gating it behind a login-only gate is a contradiction: nothing could ever pass it.",
	},
	{
		pattern: "/api/auth/register",
		why:     "first-run admin registration on a fresh instance with no users and no policy yet. Gating it would make a new deployment impossible to set up.",
	},
	{
		pattern: "/api/invitations/redeem",
		why:     "invitation acceptance for a brand-new account that by definition has no session yet.",
	},
	{
		pattern: "/api/service-identities/me/secrets",
		why: "service fetch-on-boot (X-Service-Key). Registered outside the session-auth group by " +
			"necessity: service containers call it with no cookie and no session, so " +
			"RequireTOTPEnrollment can never be mounted on it. This WAS P0-1 (crew audit " +
			"trustissues-AUDIT-2026-08-24.md): a pre-existing service key for an un-enrolled owner " +
			"returned plaintext secrets while that same owner's session got 403. The fix (branch " +
			"agent/ti-p0-1-service-key-fix-2026-08-24, commit 1e6bc81aa) is a DIFFERENT mechanism " +
			"from every other row in this table -- an in-handler check, not middleware -- pinned by " +
			"internal/handlers/service_secrets_totp_gate_test.go " +
			"TestFetchOwnSecrets_RefusesUnenrolledOwnerUnderRequireTOTP. Because it is a different " +
			"mechanism this guard cannot see via chi.Walk, the exemption is granted only while " +
			"serviceSecretsInHandlerCheckExists() confirms the check is actually present in source, " +
			"not because this comment says so.",
		verify: serviceSecretsInHandlerCheckExists,
	},
}

func findExemption(pattern string) *routeExemption {
	for i := range routeExemptions {
		if routeExemptions[i].pattern == pattern {
			return &routeExemptions[i]
		}
	}
	return nil
}

// THE assertion. Every route the real router answers for is either behind the
// TOTP gate, inside the deliberate /api/auth escape hatch (reached via a
// session but not the gate -- enrolling is how a user gets past the gate, so
// gating enrolment would lock out every un-enrolled account the moment the
// policy switches on), or named on routeExemptions with a reviewer-visible
// reason. A route matching none of those fails BY DEFAULT: the author has to
// gate it or justify it above, where a reviewer sees it, rather than the guard
// silently saying nothing because the route was declared somewhere it wasn't
// looking. This is what P1-1 found missing and what let P0-1 through.
func TestEveryRegisteredRouteIsGatedAuthEscapeHatchOrExempt(t *testing.T) {
	routes := buildRealRouterRoutes(t)

	seenExemptions := map[string]bool{}
	var failures []string
	for _, r := range routes {
		if r.gated {
			continue // (a) behind the gate
		}
		if strings.HasPrefix(r.pattern, "/api/auth") && r.hasAuth {
			continue // (b) the deliberate escape hatch: session required, gate not
		}
		if ex := findExemption(r.pattern); ex != nil {
			seenExemptions[r.pattern] = true
			if ex.verify != nil {
				if ok, detail := ex.verify(); !ok {
					failures = append(failures, fmt.Sprintf(
						"%-7s %-45s exemption %q is NOT currently valid: %s (reason on file: %s)",
						r.method, r.pattern, ex.pattern, detail, ex.why))
					continue
				}
			}
			continue // (c) explicitly exempted, and any conditional proof held
		}
		failures = append(failures, fmt.Sprintf(
			"%-7s %-45s registered but not gated, not the /api/auth escape hatch, and not on "+
				"routeExemptions", r.method, r.pattern))
	}

	if len(failures) > 0 {
		for _, f := range failures {
			t.Errorf("%s", f)
		}
		t.Fatalf("%d route(s) escape both the enrolment gate and the exemption list. Every route "+
			"this server registers must be inside the group that mounts %s, under /api/auth, or "+
			"named on routeExemptions with a reason -- there is no fourth way past this guard.",
			len(failures), gateMiddleware)
	}

	for _, ex := range routeExemptions {
		if !seenExemptions[ex.pattern] {
			t.Errorf("routeExemptions lists %q but newRouter() never registers that pattern; "+
				"remove the stale entry or the router changed shape underneath it", ex.pattern)
		}
	}
}

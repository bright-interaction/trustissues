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

// routeGuardRequirement is one route and the middleware that must still be
// wrapped around it in cmd/server/main.go.
//
// This guard exists because two of the round-3 findings are properties of the
// ROUTER, not of any handler: the handlers behind /api/secrets/issue and
// /api/mcp have no role check of their own, and the AI gateway's per-caller
// budget is a middleware. A package test cannot reach main(), so without this
// the wiring is the one part of the fix nothing would notice losing.
//
// It also pins the premise the whole provider pin rests on: ai_key_openai /
// ai_key_anthropic name the vault entry holding the operator's key, and the pin
// is only unforgeable while writing them stays AdminOnly. If that route ever
// loses AdminOnly, an editor picks the pin's contents and secret_egress.go's
// central claim quietly becomes false.
type routeGuardRequirement struct {
	path string
	// verb is the chi method the route is declared with ("Post", "Delete",
	// "Route", "HandleFunc", ...). Empty matches any. It matters because two
	// different routes can share a path literal: /admin/invitations and the
	// collection's DELETE /invitations are both "/invitations", and an
	// exists-anywhere match would let one satisfy the other's requirement.
	verb       string
	middleware string
	why        string
}

var routeGuardRequirements = []routeGuardRequirement{
	{"/members", "Post", "membershipLimiter",
		"its timing answers the account-enumeration question its body refuses to answer; the sample count is the part that can be taken away"},
	{"/invitations", "Delete", "membershipLimiter",
		"same oracle on the withdraw path"},
	{"/ai/{provider}/*", "", "VaultOnlyBlock", "vault_only is what the PUBLIC invite endpoint hands out; it must not spend the team's LLM budget"},
	// The LIMITER, not just the word RateLimit: /api already carries the shared
	// 500/min apiLimiter, so requiring "a rate limit" here would be satisfied by
	// the one that was already there and this row would prove nothing.
	{"/ai/{provider}/*", "", "aiGatewayLimiter", "every allowed call spends the operator's provider budget and every refused one writes an activity_log row; the shared apiLimiter is not a per-feature bound"},
	{"/mcp", "", "VaultOnlyBlock", "use_secret mints capability tokens through the same Issue handler; blocking the gateway and not this is the same door twice"},
	{"/secrets", "", "VaultOnlyBlock", "POST /secrets/issue mints a token /proxy spends by injecting a decrypted secret upstream"},
	{"/issue", "", "capabilityLimiter", "single-use tokens: minting is the real budget"},
	{"/proxy/{host}/*", "", "proxyLimiter", "mounted outside /api and its apiLimiter, so this is its only bound"},
	{"/settings/ai", "Put", "AdminOnly", "the write that decides which entry is the instance's provider key, and therefore what the egress pin pins"},
	// The credential access trail. Its rows name WHICH SECRET an agent spent,
	// which is the inventory that vault_entries.name, the audit tables and
	// activity_log.detail are all encrypted at rest to withhold. A reader without
	// this gate would hand any authenticated account, including the vault_only
	// role a public invite hands out, the list those four passes exist to
	// protect, in cleartext, over HTTP.
	{"/capability-log", "Get", "AdminOnly", "the rows name which secret each agent spent, which is the inventory every at-rest encryption pass exists to withhold"},
}

// routeGuardForbidden is the other direction, and it is what keeps the check
// above honest. chi middleware is inherited by nested groups, so a test that
// only ever asks "is X somewhere above this route" would also answer yes for a
// SIBLING group's middleware if the scope comparison were wrong. /vault must
// stay reachable by vault_only (that role exists to use the vault), so this row
// fails loudly if the scoping ever goes fuzzy.
var routeGuardForbidden = []routeGuardRequirement{
	{"/vault", "", "VaultOnlyBlock", "vault_only accounts exist to use the vault through the browser extension"},
}

// TestServerRoutesKeepTheirGuards parses the real router and fails when a route
// loses the middleware it is mounted behind.
func TestServerRoutesKeepTheirGuards(t *testing.T) {
	path := filepath.Join("..", "..", "cmd", "server", "main.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	// Two collections, both keyed by the stack of enclosing function literals,
	// because a chi group's middleware applies to the routes declared INSIDE it
	// and to nothing else. Comparing stacks by prefix is what stops a sibling
	// group's r.Use from counting for this route: "/vault" must not inherit the
	// VaultOnlyBlock that sits in the AI gateway's group next to it.
	type scoped struct {
		stack []*ast.FuncLit
		verb  string
		names []string // middleware idents (r.Use) or the route path (literals)
		line  int
	}
	var uses []scoped
	var routes []scoped

	var stack []*ast.FuncLit

	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			stack = append(stack, node)
			for _, s := range node.Body.List {
				ast.Inspect(s, visit)
			}
			stack = stack[:len(stack)-1]
			return false
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Use":
				uses = append(uses, scoped{stack: append([]*ast.FuncLit{}, stack...),
					verb: "Use", names: identsIn(node.Args), line: fset.Position(node.Pos()).Line})
			case "Route", "Group", "Get", "Post", "Put", "Delete", "Patch", "HandleFunc", "Mount":
				for _, arg := range node.Args {
					lit, ok := arg.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					p, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					// Inline middleware: r.With(RateLimit(x)).Post("/issue", h).
					// It applies to this route only, so it is attached to the
					// route record rather than to a scope.
					inline := identsIn([]ast.Expr{node.Fun})
					routes = append(routes, scoped{stack: append([]*ast.FuncLit{}, stack...),
						verb:  sel.Sel.Name,
						names: append([]string{p}, inline...), line: fset.Position(node.Pos()).Line})
				}
			}
			return true
		}
		return true
	}
	ast.Inspect(file, visit)

	isAncestor := func(outer, inner []*ast.FuncLit) bool {
		if len(outer) > len(inner) {
			return false
		}
		for i := range outer {
			if outer[i] != inner[i] {
				return false
			}
		}
		return true
	}

	for _, req := range routeGuardRequirements {
		found := false
		mounted := false
		for _, rt := range routes {
			if rt.names[0] != req.path || (req.verb != "" && rt.verb != req.verb) {
				continue
			}
			mounted = true
			for _, inline := range rt.names[1:] {
				if inline == req.middleware {
					found = true
				}
			}
			for _, u := range uses {
				if !isAncestor(u.stack, rt.stack) {
					continue
				}
				for _, name := range u.names {
					if name == req.middleware {
						found = true
					}
				}
			}
		}
		if !mounted {
			t.Errorf("route %q is no longer mounted in cmd/server/main.go; if it moved, move this requirement with it (%s)",
				req.path, req.why)
			continue
		}
		if !found {
			t.Errorf("route %q is no longer behind %s in cmd/server/main.go: %s",
				req.path, req.middleware, req.why)
		}
	}

	for _, req := range routeGuardForbidden {
		for _, rt := range routes {
			if rt.names[0] != req.path || (req.verb != "" && rt.verb != req.verb) {
				continue
			}
			for _, u := range uses {
				if !isAncestor(u.stack, rt.stack) {
					continue
				}
				for _, name := range u.names {
					if name == req.middleware {
						t.Errorf("route %q is behind %s: %s. If that is deliberate, this guard's scope "+
							"comparison is what has to change, not this row", req.path, req.middleware, req.why)
					}
				}
			}
		}
	}
}

// readPackageFile reads one source file of this package.
func readPackageFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// functionBody returns the source text of the function whose declaration starts
// with decl, up to the closing brace in column 0.
func functionBody(t *testing.T, src, decl string) string {
	t.Helper()
	start := strings.Index(src, decl)
	if start < 0 {
		t.Fatalf("declaration %q not found; if it was renamed, rename it here too", decl)
	}
	rest := src[start:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// identsIn returns every identifier name appearing anywhere in the expressions,
// so RateLimit is found inside timw.RateLimit(aiGatewayLimiter).
func identsIn(exprs []ast.Expr) []string {
	var out []string
	for _, e := range exprs {
		ast.Inspect(e, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				out = append(out, v.Name)
			case *ast.SelectorExpr:
				out = append(out, v.Sel.Name)
			}
			return true
		})
	}
	return out
}

// TestProviderPinReadsOnlyAdminWritableState is the other half of the same
// premise, on this side of the boundary: the pin must be derived from the
// settings table and the compile-time provider list, never from the entry.
//
// A pin sourced from anything an entry editor can write (the provider column,
// provider_meta, destination_patterns itself) would be exactly the bug it exists
// to close, and that would be invisible at review time because the function
// would still be called from the right places.
func TestProviderPinReadsOnlyAdminWritableState(t *testing.T) {
	src := readPackageFile(t, "secret_egress.go")
	body := functionBody(t, src, "func providerPinFor(")
	for _, forbidden := range []string{"vault_entries", "destination_patterns", "provider_meta", "collection_members"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("providerPinFor reads %q; the pin must come from admin-only state, "+
				"otherwise the principal it constrains chooses its contents", forbidden)
		}
	}
	if !strings.Contains(body, "GetSetting") || !strings.Contains(body, "settingKey") {
		t.Error("providerPinFor no longer resolves the ai_key_* settings; the pin has lost its source of truth")
	}
	if !strings.Contains(body, "apiHost") {
		t.Error("providerPinFor no longer pins to aiProviders[...].apiHost, the compile-time host table")
	}
}

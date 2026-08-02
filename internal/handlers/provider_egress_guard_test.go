package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// gatedNote marks a call site that MUST route through allowedProviderRoute,
// because the caller chooses the method and the path and the request carries a
// secret this server holds.
const gatedNote = "GATED: caller-supplied method and path, secret injected server-side"

// providerEgressRegistry is every place in this package that builds an outbound
// HTTP request, with the reason each one is safe.
//
// It exists because the AI gateway fix was reported as closed while the
// capability bridge carried the same provider key to the same host with no
// allowlist at all. The gateway was scoped, its sibling was not, and nothing in
// the tree said the second door existed. A registry is the cheapest thing that
// fails when the third one is added: a new call site is an unrecognised key here
// and this test names it, so the author has to say why it is safe (or gate it)
// in the same commit.
//
// Adding an entry is not a rubber stamp. If the new site can reach an LLM
// provider with a method or path the caller influences, it must call
// allowedProviderRoute and carry gatedNote, which is asserted below.
var providerEgressRegistry = map[string]string{
	"ai_gateway.go:AIGatewayHandler.Proxy":  gatedNote,
	"capability.go:CapabilityHandler.Proxy": gatedNote,

	"mcp.go:MCPHandler.toolUseSecret": "in-process: builds a request for the local Issue handler and calls it " +
		"directly (no client, no socket), so it egresses nothing on its own. What it mints IS spendable at " +
		"capability.Proxy, which is gated.",

	"vault_targets.go:deliverToWebhook": "operator-configured delivery endpoint for a ROTATED secret, not an LLM " +
		"provider key. Its own authorization lives in DeliverRotatedKey (a target configured by a departed member " +
		"is refused); the URL is validated and SSRF-guarded, and no caller picks the method.",
	"vault_targets.go:deliverToForgejoSecret": "same delivery path, Forgejo repo-secret variant. Host comes from " +
		"the operator's target config, path is built here, method is fixed.",
}

// providerEgressExemptFiles are whole files of first-party outbound calls where
// no caller influences the method or the path.
var providerEgressExemptFiles = map[string]string{
	"vault_providers.go": "key rotation and validation. Every endpoint is a compile-time literal for one provider " +
		"and the method is fixed in the source; nothing here forwards a caller's request. Literal provider URLs are " +
		"still checked against the inference allowlist below.",
}

// TestProviderEgressCallSitesAreRegistered is the guard the review asked for:
// it fails when a future call site forwards to a provider without going through
// the allowlist.
//
// It checks two shapes, because a bypass can arrive as either:
//
//  1. an unregistered outbound-request site anywhere in the package, and
//  2. a hardcoded provider URL whose (method, path) is not on the inference
//     allowlist, which is the same egress with the caller removed.
//
// It is deliberately paired with behavioural tests
// (TestAIGatewayRefusesNonInferenceRoutes,
// TestCapabilityBridgeAppliesTheInferenceAllowlist). A structural guard cannot
// tell whether the helper it points at actually refuses anything, so it is never
// the only thing standing here.
func TestProviderEgressCallSitesAreRegistered(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			site := name + ":" + funcIdentity(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isOutboundRequestBuilder(call) {
					return true
				}
				// (2) A literal provider URL is held to the allowlist directly.
				urlIdx, method, methodStatic, hasURL := requestURLArg(call)
				rawURL, urlStatic := "", false
				if hasURL && len(call.Args) > urlIdx {
					rawURL, urlStatic = staticString(call.Args[urlIdx])
				}
				if urlStatic && isProviderURL(rawURL) {
					if !methodStatic {
						t.Errorf("%s builds a request to %s with a non-literal method; route it through "+
							"allowedProviderRoute so the inference allowlist decides", site, rawURL)
					} else if u, perr := url.Parse(rawURL); perr == nil {
						if _, isProvider, allowed := allowedProviderRoute(u.Host, method, u.EscapedPath()); isProvider && !allowed {
							t.Errorf("%s hardcodes %s %s, which is NOT on the inference allowlist for %s. "+
								"Add the route to providerInferenceRoutes deliberately, or do not call it.",
								site, method, u.EscapedPath(), u.Host)
						}
					}
				}

				// (1) The site itself must be known.
				if seen[site] {
					return true
				}
				seen[site] = true
				if _, exempt := providerEgressExemptFiles[name]; exempt {
					return true
				}
				note, registered := providerEgressRegistry[site]
				if !registered {
					t.Errorf("NEW outbound HTTP call site %s is not in providerEgressRegistry.\n"+
						"If it can reach an LLM provider with a method or path a caller influences, it must call "+
						"allowedProviderRoute (see capability.Proxy) and be registered with gatedNote. If it cannot, "+
						"register it with the reason. The AI gateway allowlist was reported closed while the "+
						"capability bridge carried the same key to the same host through a second, unscoped door.", site)
					return true
				}
				if note == gatedNote && !callsProviderGate(fn) {
					t.Errorf("%s is registered as GATED but its body never calls allowedProviderRoute, so the "+
						"inference allowlist does not apply to it", site)
				}
				return true
			})
		}
	}

	for site := range providerEgressRegistry {
		if !seen[site] {
			t.Errorf("providerEgressRegistry lists %s, which no longer builds an outbound request. "+
				"Remove the entry so the registry keeps meaning what it says.", site)
		}
	}
	// The two doors this work is about must both be present. Without this, a
	// deleted call site would silently empty the guard.
	for _, must := range []string{"ai_gateway.go:AIGatewayHandler.Proxy", "capability.go:CapabilityHandler.Proxy"} {
		if !seen[must] {
			t.Errorf("%s no longer builds an outbound request; if the egress moved, move the gate with it", must)
		}
	}
}

// TestProviderURLLiteralsAreOnTheInferenceAllowlist closes the blind spot the
// re-review found by ablation.
//
// The check inside TestProviderEgressCallSitesAreRegistered only inspects URLs
// passed DIRECTLY to http.NewRequest*, so a literal routed through a wrapper is
// invisible to it. The reviewer changed
// OpenAIProvider.Validate's providerGet(ctx, "https://api.openai.com/v1/models")
// to "/v1/organization/admin_api_keys" and the guard stayed green: a first-party
// call to a non-inference endpoint on the operator's account, with the operator's
// key, past every gate.
//
// So this asks the question of the LITERAL, wherever it appears, and however it
// is passed on. The method is not knowable from a bare string, so the rule is the
// weaker but still decisive one: the path must be reachable by at least ONE
// method on that provider's inference allowlist. Anything on the files, batch,
// fine-tuning, assistants or admin surfaces is reachable by none.
func TestProviderURLLiteralsAreOnTheInferenceAllowlist(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		check := func(raw string, pos token.Pos) {
			if !isProviderURL(raw) {
				return
			}
			u, perr := url.Parse(raw)
			if perr != nil || u.Host == "" {
				return
			}
			path := u.EscapedPath()
			if path == "" || path == "/" {
				return // a base URL, not an endpoint
			}
			checked++
			if !pathReachableOnAllowlist(u.Host, path) {
				t.Errorf("%s hardcodes %s%s, which no method on the inference allowlist reaches. "+
					"This is first-party egress with the operator's provider key on it: add the route to "+
					"providerInferenceRoutes deliberately, or do not call it.",
					fset.Position(pos), u.Host, path)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BinaryExpr:
				// "https://api.openai.com" + path, assembled in source.
				if joined, ok := staticString(v); ok {
					check(joined, v.Pos())
					return false
				}
			case *ast.BasicLit:
				if v.Kind == token.STRING {
					if lit, ok := staticString(v); ok {
						check(lit, v.Pos())
					}
				}
			}
			return true
		})
	}
	// A scan that finds nothing to check is a scan that has stopped working: the
	// package holds provider URLs today (the gateway base URLs and the two
	// key-validation calls), so zero means the walk broke, not that the tree got
	// safer.
	if checked == 0 {
		t.Error("no provider URL literals were inspected at all; this guard is no longer looking at anything")
	}
}

// pathReachableOnAllowlist reports whether ANY HTTP method reaches path on that
// provider's inference allowlist.
func pathReachableOnAllowlist(host, path string) bool {
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"} {
		if _, isProvider, allowed := allowedProviderRoute(host, m, path); isProvider && allowed {
			return true
		}
	}
	return false
}

// funcIdentity renders "Receiver.Name" (or "Name" for a plain function).
func funcIdentity(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// isOutboundRequestBuilder recognises every shape in this package that puts a
// request on the wire, not just http.NewRequest*.
//
// The re-review found the narrow version blind twice over: it saw neither
// http.Get / http.Post / client.Do, so a future call site could egress without
// ever appearing in the registry. Registration is the part that forces an author
// to say why a new site is safe, so a shape it cannot see is a shape that skips
// the argument.
func isOutboundRequestBuilder(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" {
		switch sel.Sel.Name {
		case "NewRequest", "NewRequestWithContext", "Get", "Post", "PostForm", "Head":
			return true
		}
	}
	// client.Do(req) / h.httpClient.Do(req). The receiver is not inspected: this
	// package has no other Do method, and a false positive costs one registry
	// line with a reason, while a false negative costs an unregistered egress.
	return sel.Sel.Name == "Do"
}

// requestURLArg reports the index of the URL argument for the shapes that carry
// one, and the method that shape implies. ok is false for client.Do, which has
// no literal URL to check (the request was built elsewhere, at a site this guard
// sees separately).
func requestURLArg(call *ast.CallExpr) (idx int, method string, methodStatic bool, ok bool) {
	sel := call.Fun.(*ast.SelectorExpr)
	switch sel.Sel.Name {
	case "NewRequest":
		m, static := staticString(call.Args[0])
		return 1, m, static, true
	case "NewRequestWithContext":
		m, static := staticString(call.Args[1])
		return 2, m, static, true
	case "Get":
		return 0, "GET", true, true
	case "Head":
		return 0, "HEAD", true, true
	case "Post", "PostForm":
		return 0, "POST", true, true
	}
	return 0, "", false, false
}

// staticString renders a compile-time string expression, following "a" + "b"
// concatenation. It reports false when any part is computed at run time.
func staticString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, lok := staticString(v.X)
		r, rok := staticString(v.Y)
		return l + r, lok && rok
	case *ast.SelectorExpr:
		// http.MethodPost and friends.
		if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "http" {
			if m, found := httpMethodConstants[v.Sel.Name]; found {
				return m, true
			}
		}
		return "", false
	}
	return "", false
}

var httpMethodConstants = map[string]string{
	"MethodGet": "GET", "MethodPost": "POST", "MethodPut": "PUT",
	"MethodPatch": "PATCH", "MethodDelete": "DELETE", "MethodHead": "HEAD",
}

func isProviderURL(raw string) bool {
	for host := range providerInferenceRoutes {
		if strings.Contains(raw, host) {
			return true
		}
	}
	return false
}

// callsProviderGate reports whether the function body calls allowedProviderRoute.
func callsProviderGate(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "allowedProviderRoute" {
			found = true
		}
		return true
	})
	return found
}

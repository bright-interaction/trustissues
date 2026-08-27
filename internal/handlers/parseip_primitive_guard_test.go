package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// net.ParseIP is a fail-open primitive in this module and it has now produced
// the same bug twice.
//
// It does not accept an IPv6 zone id, so it returns nil for "::1%1",
// "::ffff:169.254.169.254%1" and every other zoned spelling of an address that
// the kernel dials perfectly happily. Both defects had the identical shape: the
// nil result was read as "not an IP, nothing to check here" and the security
// test was SKIPPED rather than failed.
//
//	P0-4        internal/alerts, the dial Control hook. Fixed 2026-08-13.
//	P0-4 twin   internal/handlers ValidateDestinationPatterns, the capability
//	            proxy's stored destination ceiling. Fixed here.
//
// The first fix shipped with a structural test, TestEveryDialControlFailsClosed
// in internal/alerts, which forbids net.ParseIP inside a net.Dialer Control
// hook. It passed clean while the twin was live, because it is scoped to CALL
// SITES OF ONE SHAPE and the twin is a different shape in a different package.
// That is the blind spot this test closes: the invariant is the PRIMITIVE, and
// the call sites are only its instances.
//
// So the rule is flat and has no syntactic escape hatch: net.ParseIP must not
// appear anywhere in the module except on the allowlist below, with a stated
// reason. Use netip.ParseAddr, which parses zones, and reject a non-empty
// Zone() explicitly:
//
//	a, err := netip.ParseAddr(host)
//	if err != nil || a.Zone() != "" || alerts.IsNonPublicAddr(a.Unmap()) { reject }
//
// Keying on the identifier rather than on the surrounding "if x != nil &&"
// shape is deliberate. Go spells that shape at least four ways (init statement
// with &&, init statement with a nested if, assignment then a separate if,
// inlined into a call) and a guard that enumerates shapes only ever catches the
// one its author had in mind; see the estate note "a structural guard sees ONE
// syntactic form and misses the equivalent one". There is no way to write
// net.ParseIP without naming net.ParseIP.

// parseIPAllowlist maps "<path from module root>#<enclosing func>" to the reason
// that site is safe. A site qualifies only when a nil result makes the code
// STRICTER, never more permissive.
//
// Adding a row here is a security decision. State what nil does, not that it is
// fine.
var parseIPAllowlist = map[string]string{
	"internal/middleware/rate_limit.go#clientIP": "" +
		"Fail-CLOSED. This is the VALUE check, not the peer check: the element " +
		"selected from the forwarding chain must parse as an IP or clientIP falls back " +
		"to the socket peer. nil therefore costs a caller the ability to put arbitrary " +
		"text, \"unknown\", a hostname, a host:port, or a newline that forges a log " +
		"line, into login_attempts.ip_address, activity_log.ip_address and " +
		"service_secret_audit.remote_ip, all of which sit behind no-update/no-delete " +
		"triggers so a forged row is permanent. A zone id parsing as nil here only " +
		"loses an attacker their forged value. Verified by " +
		"TestClientIPRejectsAValueThatIsNotAnIP.",

	"internal/handlers/smtp.go#isLoopbackSMTPHost": "" +
		"Fail-CLOSED. The function is permissive-on-TRUE: true is the ONLY thing that " +
		"waives the TLS requirement for a local mail catcher. nil returns false, so a " +
		"zoned host such as \"::1%1\" is treated as remote and TLS stays mandatory. " +
		"Verified by TestIsLoopbackSMTPHostFailsClosed.",
}

// parseIPRef is one syntactic reference to the primitive.
type parseIPRef struct {
	key   string // "<relpath>#<enclosing func>"
	where string // file:line:col, for the failure message
}

// netPackageNames returns the identifiers that refer to the standard "net"
// package in this file, plus whether it is dot-imported. An alias
// (import stdnet "net") is a spelling of the same call and must not slip past.
func netPackageNames(f *ast.File) (names map[string]bool, dotImported bool) {
	names = map[string]bool{}
	for _, imp := range f.Imports {
		if imp.Path == nil || imp.Path.Value != `"net"` {
			continue
		}
		if imp.Name == nil {
			names["net"] = true
			continue
		}
		switch imp.Name.Name {
		case ".":
			dotImported = true
		case "_":
			// blank import cannot be referenced
		default:
			names[imp.Name.Name] = true
		}
	}
	return names, dotImported
}

// enclosingFuncName finds the top-level declaration a position falls inside.
// A FuncLit nested in a function is attributed to that function, so hoisting the
// call into a closure does not create a new, unlisted key.
func enclosingFuncName(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		if d.Pos() <= pos && pos <= d.End() {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if decl.Recv != nil && len(decl.Recv.List) > 0 {
					return "(recv)." + decl.Name.Name
				}
				return decl.Name.Name
			case *ast.GenDecl:
				return "<package-level declaration>"
			}
		}
	}
	return "<file scope>"
}

// findParseIPRefs walks the module and returns every reference to net.ParseIP.
// It matches the identifier, not a call shape, so passing net.ParseIP as a
// function value is caught too.
func findParseIPRefs(t *testing.T, root string) (refs []parseIPRef, files int) {
	t.Helper()
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", "node_modules", ".git":
				return filepath.SkipDir
			}
			if strings.HasPrefix(d.Name(), "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		files++
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		netNames, dot := netPackageNames(f)
		if len(netNames) == 0 && !dot {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		record := func(pos token.Pos) {
			refs = append(refs, parseIPRef{
				key:   rel + "#" + enclosingFuncName(f, pos),
				where: fset.Position(pos).String(),
			})
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.SelectorExpr:
				if e.Sel.Name != "ParseIP" {
					return true
				}
				if id, ok := e.X.(*ast.Ident); ok && netNames[id.Name] {
					record(e.Pos())
				}
			case *ast.Ident:
				// Only reachable when "net" is dot-imported, where the call is
				// spelled as a bare ParseIP(...).
				if dot && e.Name == "ParseIP" {
					record(e.Pos())
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	return refs, files
}

// TestNoFailOpenParseIPOutsideAllowlist is the invariant. Every individual
// SSRF-guard fix in this module is an instance of it.
func TestNoFailOpenParseIPOutsideAllowlist(t *testing.T) {
	root := filepath.Join("..", "..")

	refs, files := findParseIPRefs(t, root)

	// Anti-vacuity. A walk that reads the wrong tree, or a parser change that
	// stops matching, would report zero offenders and read as a clean bill of
	// health. Both self-checks below have to hold before any verdict counts.
	if files < 50 {
		t.Fatalf("only %d .go files scanned from %s: this is reading the wrong tree, so a green "+
			"result here means nothing", files, root)
	}

	seen := map[string]bool{}
	var offenders []parseIPRef
	for _, r := range refs {
		if _, ok := parseIPAllowlist[r.key]; ok {
			seen[r.key] = true
			continue
		}
		offenders = append(offenders, r)
	}

	for _, r := range offenders {
		t.Errorf("%s: net.ParseIP is called here (%s), and that call is not on the allowlist.\n\n"+
			"net.ParseIP does not parse an IPv6 zone id. It returns nil for \"::1%%1\" and for "+
			"\"::ffff:169.254.169.254%%1\", so any check written as\n"+
			"    if ip := net.ParseIP(h); ip != nil { ...reject if private... }\n"+
			"SKIPS the rejection for exactly the inputs an attacker controls. That is the P0-4 "+
			"defect and it shipped twice, once in the dial guard and once in the capability "+
			"destination ceiling.\n\n"+
			"Use netip.ParseAddr, which parses zones, and refuse a non-empty Zone():\n"+
			"    a, err := netip.ParseAddr(h)\n"+
			"    if err != nil || a.Zone() != \"\" || alerts.IsNonPublicAddr(a.Unmap()) { reject }\n\n"+
			"If nil genuinely makes this site STRICTER, add %q to parseIPAllowlist with a reason "+
			"that says what nil does, and a test that proves it.",
			r.where, r.key, r.key)
	}

	// A stale allowlist row is a live hole waiting for a file to be recreated at
	// the same path, and it is also proof the walk is no longer finding what the
	// row was written about. Either way the row must not survive its site.
	var stale []string
	for key := range parseIPAllowlist {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("parseIPAllowlist has a row for %q but no net.ParseIP call was found there.\n"+
			"Either the call is gone (delete the row) or this scanner stopped recognising it "+
			"(fix the scanner, because everything else it reports is then also worthless).", key)
	}
}

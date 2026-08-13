package alerts

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The dial-time private-IP guard had no test at all. The SSRF suite tested a
// COPY of it in internal/handlers/vault_ssrf.go that no production code called,
// so the shipping guard was free to be wrong, and it was: it read
//
//	if ip := net.ParseIP(host); ip != nil && isPrivateAlertIP(ip) { block }
//
// net.ParseIP does not accept an IPv6 zone id, so it returned nil for "::1%1",
// the "ip != nil &&" short-circuited to ALLOW, and the kernel dialled the
// loopback. These tests pin the INVARIANT (nothing reaches a non-routable
// address, in any encoding, and no dial guard in the module may fail open)
// rather than the behaviour of one function.

// startLoopback starts an httptest server bound to a specific loopback address
// and returns the port it listens on. It is a REAL listener: if the guard lets
// a request through, the request is genuinely served, so a passing test cannot
// be an artefact of the destination being unreachable.
func startLoopback(t *testing.T, network, addr string) int {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().(*net.TCPAddr).Port
}

// TestGuardedClientBlocksEveryLoopbackEncoding is the P0 repro. Each URL below
// names the SAME loopback listener in a different encoding; every one of them
// must be refused at dial time. Before the fix the two zoned forms returned 418
// from the real server.
func TestGuardedClientBlocksEveryLoopbackEncoding(t *testing.T) {
	v4Port := startLoopback(t, "tcp4", "127.0.0.1:0")
	v6Port := startLoopback(t, "tcp6", "[::1]:0")

	client := GuardedWebhookClient(5 * time.Second)

	cases := []struct {
		name string
		url  string
	}{
		{"plain ipv4 loopback", fmt.Sprintf("http://127.0.0.1:%d/", v4Port)},
		{"ipv4-mapped ipv6", fmt.Sprintf("http://[::ffff:127.0.0.1]:%d/", v4Port)},
		{"ipv4-mapped ipv6, hex form", fmt.Sprintf("http://[::ffff:7f00:1]:%d/", v4Port)},
		{"plain ipv6 loopback", fmt.Sprintf("http://[::1]:%d/", v6Port)},
		// The P0. %25 is the percent-encoding of "%" in a URL host.
		{"ipv6 loopback with numeric zone", fmt.Sprintf("http://[::1%%251]:%d/", v6Port)},
		{"ipv6 loopback with named zone", fmt.Sprintf("http://[::1%%25lo0]:%d/", v6Port)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Get(tc.url)
			if err == nil {
				defer resp.Body.Close()
				t.Fatalf("REACHED the loopback server (status %d) via %s: the dial guard was bypassed",
					resp.StatusCode, tc.url)
			}
			if !strings.Contains(err.Error(), "blocked outbound to") {
				t.Fatalf("%s failed for the wrong reason, wanted the dial guard's refusal: %v", tc.url, err)
			}
		})
	}
}

// TestGuardDialAddressFailsClosed covers the shapes a listener test cannot
// reach, and the positive control: a public unicast address must still be
// allowed, or the guard is just an outage.
func TestGuardDialAddressFailsClosed(t *testing.T) {
	blocked := []string{
		"127.0.0.1:80", "10.0.0.5:80", "172.16.0.1:80", "172.31.255.255:80",
		"192.168.1.1:80", "169.254.169.254:80", "0.0.0.1:80", "100.64.0.1:80",
		"[::1]:80", "[fc00::1]:80", "[fe80::1]:80",
		"[::1%1]:80", "[::1%lo0]:80", "[fe80::42:acff:fe11:2%2]:8080",
		"[::ffff:127.0.0.1]:80", "[::ffff:169.254.169.254]:80", "[::ffff:7f00:1]:80",
		"[::]:80", "0.0.0.0:80", "[ff01::1]:80", "[ff02::1]:80",
		// Not an IP literal at all. A Control hook is always handed a resolved
		// address, so anything else means something unexpected happened.
		"metadata.google.internal:80", "localhost:80", "not-an-address",
		"2130706433:80", "0x7f.0.0.1:80", "[2606:4700::1111%eth0]:443",
	}
	for _, addr := range blocked {
		if err := guardDialAddress(addr); err == nil {
			t.Errorf("guardDialAddress(%q) = nil, want a refusal", addr)
		}
	}

	allowed := []string{
		"1.1.1.1:443", "8.8.8.8:443", "93.184.216.34:80",
		"[2606:4700::1111]:443", "[2001:db8::1]:443",
	}
	for _, addr := range allowed {
		if err := guardDialAddress(addr); err != nil {
			t.Errorf("guardDialAddress(%q) = %v, want nil (public unicast must still be reachable)", addr, err)
		}
	}
}

// controlHookShape is the signature of a net.Dialer Control hook:
// func(network, address string, c syscall.RawConn) error.
func controlHookShape(fn *ast.FuncLit) bool {
	params := fn.Type.Params
	results := fn.Type.Results
	if params == nil || results == nil || results.NumFields() != 1 {
		return false
	}
	var types []string
	for _, f := range params.List {
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			types = append(types, typeString(f.Type))
		}
	}
	if len(types) != 3 {
		return false
	}
	return types[0] == "string" && types[1] == "string" &&
		strings.HasSuffix(types[2], "RawConn") && typeString(results.List[0].Type) == "error"
}

func typeString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return typeString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	default:
		return ""
	}
}

// TestEveryDialControlFailsClosed is the structural half, and it is the half
// that would have caught this finding.
//
// The bug was not that one function was wrong; it was that a second copy of the
// guard existed, the tests aimed at the copy with no callers, and the copy that
// shipped drifted. A unit test of the fixed function cannot see that happen
// again. So this walks the MODULE'S FILES, finds every net.Dialer Control hook
// wherever it lives, and requires each one to route through the single
// guardDialAddress and to contain no call to net.ParseIP, the fail-open
// primitive that caused this. Adding a second egress client anywhere in
// Trustissues is fine; adding a second egress POLICY is what fails here.
func TestEveryDialControlFailsClosed(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()

	type hook struct {
		where string
		body  string
	}
	var hooks []hook
	var files int

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
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncLit)
			if !ok || !controlHookShape(fn) {
				return true
			}
			var sb strings.Builder
			if perr := printer.Fprint(&sb, fset, fn.Body); perr != nil {
				sb.WriteString("<unprintable>")
			}
			hooks = append(hooks, hook{where: fset.Position(fn.Pos()).String(), body: sb.String()})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	if files < 50 {
		t.Fatalf("only %d .go files scanned from %s: the scan is reading the wrong tree, so its green means nothing", files, root)
	}
	if len(hooks) == 0 {
		t.Fatal("no net.Dialer Control hook found in the module. Either the egress guard was deleted " +
			"or this scanner stopped recognising it; both make every other assertion here vacuous.")
	}

	for _, h := range hooks {
		if strings.Contains(h.body, "ParseIP") {
			t.Errorf("%s: dial Control hook calls net.ParseIP.\n"+
				"That is the fail-open primitive this test exists to refuse: it does not parse an IPv6 "+
				"zone id, so it returns nil for \"::1%%1\" and an \"ip != nil &&\" guard short-circuits to "+
				"ALLOW while the kernel dials the loopback. Use alerts.guardDialAddress.\nhook body:\n%s",
				h.where, h.body)
		}
		if !strings.Contains(h.body, "guardDialAddress") {
			t.Errorf("%s: dial Control hook does not route through guardDialAddress.\n"+
				"Trustissues has ONE egress policy on purpose. A second copy is how the shipped guard "+
				"drifted from the tested one and let a zoned IPv6 literal through.\nhook body:\n%s",
				h.where, h.body)
		}
	}
}

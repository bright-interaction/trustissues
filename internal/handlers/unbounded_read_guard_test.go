package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// NO PRODUCT CODE MAY READ A RESPONSE BODY WITHOUT A CEILING, ANYWHERE.
//
// The property is "no site does X", which no single request can demonstrate, so
// it is checked in source. The previous version of this guard checked it in the
// source of ONE FILE, named as a string literal:
//
//	src := mustReadSource(t, "vault_providers.go")
//
// which is how two unbounded reads sat in vault_targets.go, in the same package,
// for the entire life of the guard that existed to forbid them. A guard that
// enumerates its subjects by name only ever covers the file whose bug prompted
// it, and the next copy of the bug is written in a different file by definition.
// So this one enumerates: every non-test Go file in the module, found by walking
// the tree, parsed rather than pattern-matched.
//
// Why it matters here rather than in a typical client: several providers
// (grafana, zitadel, forgejo, datadog, supabase) and both rotation delivery
// targets talk to an OPERATOR-SUPPLIED URL, so the host on the other end is not
// a vendor and is not trusted. This is a single-process secrets manager, and an
// OOM kill landing AFTER a successful mint leaves the credential created
// upstream with nothing stored and nothing recorded: the same stranded-secret
// state the rotation work keeps closing, reached by exhaustion instead of by
// logic.
//
// Test files are deliberately out of scope. Their io.ReadAll(r.Body) calls read a
// request their own fixture just sent to their own in-process server, which is
// neither attacker-influenced nor a production allocation.
func TestNoUnboundedResponseReadAnywhereInTheProduct(t *testing.T) {
	root := goModuleRoot(t)

	var scanned []string
	var findings []string
	bounded := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// frontend is TypeScript; testdata holds deliberately broken fixtures
			// other guards compile on purpose.
			switch d.Name() {
			case ".git", "node_modules", "vendor", "frontend", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		scanned = append(scanned, rel)

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		reads, ok, scanErr := scanUnboundedReads(rel, src)
		if scanErr != nil {
			return scanErr
		}
		bounded += ok
		for _, r := range reads {
			findings = append(findings, r.describe())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ABORT: walking %s failed (%v); the guard checked nothing", root, err)
	}

	// ZERO MATCHES IS SILENCE, NOT PROOF. Every one of these aborts exists
	// because the failure mode of a structural guard is passing while looking at
	// nothing: the wrong directory, a walk that returned early, a rename that
	// emptied the set. A guard cannot report "clean" from an empty scan.
	if len(scanned) == 0 {
		t.Fatalf("ABORT: no product Go files found under %s; the guard scanned nothing", root)
	}
	if len(scanned) < 60 {
		t.Fatalf("ABORT: only %d product Go files scanned under %s; this module has ~100, so the "+
			"walk is not reaching the tree and a violation could hide in the part it missed",
			len(scanned), root)
	}
	if bounded == 0 {
		t.Fatal("ABORT: not a single BOUNDED io.ReadAll was found in the whole module. Either the " +
			"reads were all rewritten into a shape this guard does not recognise, or it is parsing " +
			"the wrong thing. Both mean it is no longer checking what it claims to check")
	}

	// The specific regression, pinned. The old guard could see vault_providers.go
	// and could not see vault_targets.go; both must now be in the scanned set, and
	// a rename must fail here loudly rather than quietly shrink the coverage.
	for _, must := range []string{
		"internal/handlers/vault_providers.go",
		"internal/handlers/vault_targets.go",
		"internal/handlers/ai_gateway.go",
		"internal/handlers/upstream_error.go",
	} {
		if !containsPath(scanned, must) {
			t.Fatalf("ABORT: %s was not scanned. It either moved or was renamed; until this list "+
				"is updated the guard's coverage of it is unproven", must)
		}
	}

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf("%d unbounded read(s) of a response body in product code:\n  %s\n\n"+
			"An upstream must never choose how much memory this process allocates. Wrap the reader "+
			"(io.LimitReader / http.MaxBytesReader), or use an existing bounded helper: "+
			"upstreamErrorFromResponse for a non-2xx delivery response, readProviderBody for a "+
			"provider response. Read one byte PAST the ceiling and fail on overflow: a silently "+
			"truncated body that still parses is worse than an error.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// unboundedRead is one io.ReadAll call with nothing bounding it.
type unboundedRead struct {
	pos      string // file:line
	arg      string // the argument source, e.g. "resp.Body"
	httpBody bool   // the argument is an HTTP .Body, which is the dangerous case
}

func (u unboundedRead) describe() string {
	what := "io.ReadAll(" + u.arg + ")"
	if u.httpBody {
		what += "  <- HTTP body, unbounded"
	}
	return u.pos + ": " + what
}

// scanUnboundedReads parses src and reports every io.ReadAll whose argument is
// not wrapped in a limiting reader, plus a count of the ones that are.
//
// Parsed, not grepped, for two reasons the old regexp guard demonstrated. It had
// to strip comments by hand so the comment EXPLAINING the fix would not trip the
// guard describing it, and it matched the single literal string
// "io.ReadAll(resp.Body)", so io.ReadAll(res.Body), io.ReadAll(response.Body) or
// the same call split across two lines all read as clean.
//
// It takes src rather than a path so the guard's own detector can be exercised
// against synthetic sources below. A detector nobody tests is the next thing to
// quietly stop working.
func scanUnboundedReads(filename string, src []byte) (found []unboundedRead, boundedCount int, err error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, 0, err
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ReadAll" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "io" {
			return true
		}
		arg := call.Args[0]
		if isBoundedReader(arg) {
			boundedCount++
			return true
		}
		found = append(found, unboundedRead{
			pos:      fset.Position(call.Pos()).String(),
			arg:      types.ExprString(arg),
			httpBody: readsAnHTTPBody(arg),
		})
		return true
	})
	return found, boundedCount, nil
}

// isBoundedReader reports whether the expression is a call to something that
// caps how much can be read: io.LimitReader or http.MaxBytesReader.
//
// Matched on the function NAME, not on the package qualifier, so a local wrapper
// named limitReader(...) counts too. The guard's job is to make the ceiling
// visible at the read site; it is not a type checker.
func isBoundedReader(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	name := ""
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		name = fn.Sel.Name
	case *ast.Ident:
		name = fn.Name
	}
	return strings.Contains(name, "LimitReader") || strings.Contains(name, "MaxBytesReader")
}

// readsAnHTTPBody reports whether the expression names an HTTP body
// (resp.Body, r.Body, response.Body, ...). Everything unbounded is reported;
// this only sharpens the message for the case that matters most.
func readsAnHTTPBody(e ast.Expr) bool {
	s := types.ExprString(e)
	return s == "Body" || strings.HasSuffix(s, ".Body")
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

// goModuleRoot walks up from the test's working directory to the directory
// holding go.mod. Tests run in their own package directory, so the guard has to
// find the module itself rather than assume a depth.
func goModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("ABORT: cannot determine the working directory (%v)", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("ABORT: no go.mod above %s; the guard cannot locate the module and would "+
				"otherwise scan an empty tree and pass", dir)
		}
		dir = parent
	}
}

// TestUnboundedReadDetectorActuallyDetects is the guard's own guard.
//
// The tree-wide test above passes when it finds nothing, and "found nothing" is
// exactly what a broken detector reports. These synthetic sources are the
// permanent, in-repo version of the ablation: they contain the violation in
// every shape the old regexp missed, so a detector that stops detecting fails
// HERE instead of silently blessing the whole module.
func TestUnboundedReadDetectorActuallyDetects(t *testing.T) {
	violating := []struct {
		name string
		src  string
	}{
		{"the exact old pattern", "b, _ := io.ReadAll(resp.Body)\n_ = b"},
		{"a different receiver name", "b, _ := io.ReadAll(res.Body)\n_ = b"},
		{"a request body", "b, _ := io.ReadAll(r.Body)\n_ = b"},
		{"error handled, still unbounded", "b, err := io.ReadAll(response.Body)\n_, _ = b, err"},
		{"split across lines", "b, _ := io.ReadAll(\n\tresp.Body,\n)\n_ = b"},
	}
	for _, c := range violating {
		src := "package p\n\nimport \"io\"\n\nfunc f(resp, res, r, response struct{ Body io.Reader }) {\n" + c.src + "\n}\n"
		found, _, err := scanUnboundedReads("synthetic.go", []byte(src))
		if err != nil {
			t.Fatalf("%s: fixture does not parse: %v", c.name, err)
		}
		if len(found) != 1 {
			t.Errorf("%s: detector found %d unbounded reads, want 1. The guard would pass over "+
				"this in production code", c.name, len(found))
			continue
		}
		if !found[0].httpBody {
			t.Errorf("%s: detector did not recognise %q as an HTTP body", c.name, found[0].arg)
		}
	}

	clean := []struct {
		name string
		src  string
	}{
		{"io.LimitReader", "b, _ := io.ReadAll(io.LimitReader(resp.Body, 16))\n_ = b"},
		{"http.MaxBytesReader", "b, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 16))\n_ = b"},
	}
	for _, c := range clean {
		src := "package p\n\nimport (\n\t\"io\"\n\t\"net/http\"\n)\n\nfunc f(w http.ResponseWriter, r *http.Request, resp *http.Response) {\n" + c.src + "\n}\n"
		found, bounded, err := scanUnboundedReads("synthetic.go", []byte(src))
		if err != nil {
			t.Fatalf("%s: fixture does not parse: %v", c.name, err)
		}
		if len(found) != 0 {
			t.Errorf("%s: detector flagged a bounded read (%v); false positives get guards deleted",
				c.name, found)
		}
		if bounded != 1 {
			t.Errorf("%s: bounded count = %d, want 1; the anti-vacuity check depends on this",
				c.name, bounded)
		}
	}
}

// TestProviderReadsGoThroughTheBoundedHelper is the fail-closed half for the
// provider file specifically: the tree guard proves no read is unbounded, this
// proves the bounded reads are still going through readProviderBody rather than
// having been quietly replaced by something else.
func TestProviderReadsGoThroughTheBoundedHelper(t *testing.T) {
	src, err := os.ReadFile("vault_providers.go")
	if err != nil {
		t.Fatalf("ABORT: could not read vault_providers.go (%v); this check would pass vacuously", err)
	}
	if n := strings.Count(string(src), "readProviderBody(resp)"); n < 10 {
		t.Fatalf("ABORT: only %d bounded read sites found; the helper has probably been renamed "+
			"and this guard no longer checks anything", n)
	}
}

// TestProviderBodyIsActuallyTruncated is the behavioural half.
//
// A source guard proves the call sites use the helper; only this proves the
// helper bounds anything.
func TestProviderBodyIsActuallyTruncated(t *testing.T) {
	huge := strings.Repeat("A", maxProviderBody*2)
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pad":"` + huge + `"}`))
	})

	// Any provider will do; Validate is the cheapest path that reads a body.
	p := &TwilioProvider{}
	meta := map[string]string{"account_sid": "AC"}
	_, _ = p.Validate(providerCtx(p, meta), "k", meta)

	// The assertion is on the helper itself, since Validate discards the body.
	resp, err := providerHTTP.Get("http://example.invalid/x")
	if err != nil {
		t.Fatalf("fake upstream: %v", err)
	}
	defer resp.Body.Close()
	body, err := readProviderBody(resp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(body) > maxProviderBody {
		t.Errorf("readProviderBody returned %d bytes, ceiling is %d; the upstream is still "+
			"choosing the allocation", len(body), maxProviderBody)
	}
	if len(body) == 0 {
		t.Error("readProviderBody returned nothing; a truncating reader that returns empty would " +
			"break every provider rather than bound it")
	}
}

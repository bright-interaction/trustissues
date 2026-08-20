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

// unboundedRead is one place a body is handed to a consumer with no ceiling.
type unboundedRead struct {
	pos      string // file:line
	arg      string // the argument source, e.g. "resp.Body"
	callee   string // what consumes it, e.g. "io.ReadAll", "json.NewDecoder"
	httpBody bool   // the argument is an HTTP .Body, which is the dangerous case
}

func (u unboundedRead) describe() string {
	what := u.callee + "(" + u.arg + ")"
	if u.httpBody {
		what += "  <- HTTP body, unbounded"
	}
	return u.pos + ": " + what
}

// RECOGNISING A READ BY THE NAME OF THE FUNCTION DOING IT IS THE SAME MISTAKE
// AS RECOGNISING A DECRYPT BY THE SHAPE OF THE CALL (see docs/audit-history/AUDIT-ROUND-19.md).
//
// The first version of this detector matched one callee: io.ReadAll, with the
// package qualifier `io` and exactly one argument. That is a dialect list, and a
// dialect list only ever contains the spellings somebody thought of. It was blind
// to at least these, every one of which reads an entire body into memory:
//
//	json.NewDecoder(resp.Body).Decode(&v)     xml.NewDecoder(resp.Body)
//	io.Copy(dst, resp.Body)                   io.CopyBuffer(dst, resp.Body, buf)
//	bufio.NewReader(resp.Body)                bufio.NewScanner(resp.Body)
//	io.ReadFull(resp.Body, buf)               ioutil.ReadAll(resp.Body)
//	csv.NewReader(resp.Body)                  gob.NewDecoder(resp.Body)
//
// So the subject is inverted. The detector no longer asks "is this call one of
// the reads I know?" but "does an HTTP body reach a consumer here, and is there
// a ceiling on it?", the haystack rather than the dialects. Anything that takes
// a body as an argument consumes it; the only question worth asking at the site
// is whether something caps how much.
//
// Two consumers are allowed, and both are allowed for a reason visible at the
// call:
//
//   - a bounding wrapper (io.LimitReader, http.MaxBytesReader), which IS the
//     ceiling; and
//   - a drain to io.Discard, which is how a response body is emptied for
//     connection reuse. It allocates a fixed 32 KiB buffer no matter what the
//     upstream sends, and providerHTTP carries a 15s timeout, so the upstream
//     chooses neither the memory nor the duration.
//
// REQUEST bodies are exempted because cmd/server/main.go wraps every ROUTED
// request body in http.MaxBytesReader via the bodyLimits middleware.
//
// "Every routed request", not "every request": handlers can also be invoked
// in-process without touching the router, and one is, mcp.go builds a sub-
// request and calls capability.Issue directly, so bodyLimits never runs on it.
// That one is safe because capability.Issue caps its own body at 4 KiB, but the
// exemption below is router-shaped and an in-process dispatch into a handler
// that does NOT carry its own ceiling would slip past it. Stated plainly here
// rather than left as an overclaim, because the exemption is only as good as
// the sentence justifying it.
// That chokepoint is what makes json.NewDecoder(r.Body) safe in ~30 handlers, so
// it is pinned by TestRequestBodyChokepointIsApplied below. If that guard ever
// fails, this exemption is void and those 30 sites become findings.
//
// A receiver this cannot classify is reported, NOT exempted. "I could not tell
// whether that was a request or a response" must fail towards the answer that
// gets looked at.
func scanUnboundedReads(filename string, src []byte) (found []unboundedRead, boundedCount int, err error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, 0, err
	}

	kinds := classifyBodyReceivers(f)

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := calleeName(call)

		// A ceiling is not a violation; it is the fix. Count it for the
		// anti-vacuity check and stop: its own body argument is bounded here.
		if isBoundedReader(call) {
			for _, a := range call.Args {
				if readsAnHTTPBody(a) {
					boundedCount++
					break
				}
			}
			return true
		}

		for _, arg := range call.Args {
			// A body reaches this call either as `x.Body` or as the whole
			// message: readProviderBody(resp) and httputil.DumpResponse(resp)
			// both consume the body without the word Body appearing anywhere.
			// Matching only the selector is how a guard ends up covering the
			// spelling its author happened to write.
			if !carriesAResponseBody(arg, kinds) {
				continue
			}
			switch classifyConsumer(callee) {
			case consumerStreaming:
				// Streaming callee, but the sink still has to be bounded.
				if callee == "io.Copy" || callee == "io.CopyBuffer" || callee == "io.CopyN" {
					if !copyDestinationIsBounded(call) {
						break // fall through to report
					}
				}
				continue
			case consumerBounded:
				boundedCount++
				continue
			}
			found = append(found, unboundedRead{
				pos:      fset.Position(call.Pos()).String(),
				arg:      types.ExprString(arg),
				callee:   callee,
				httpBody: true,
			})
			break // one finding per call, not one per argument
		}
		return true
	})

	// io.ReadAll of anything else (a file, a pipe, an exec stream) is still
	// worth reporting: the original guard's subject was "no unbounded ReadAll",
	// and narrowing to HTTP bodies would quietly drop coverage it already had.
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || calleeName(call) != "io.ReadAll" {
			return true
		}
		arg := call.Args[0]
		if readsAnHTTPBody(arg) || isBoundedReader(arg) {
			return true // already handled above
		}
		if c, isCall := arg.(*ast.CallExpr); isCall && isBoundedReader(c) {
			return true
		}
		found = append(found, unboundedRead{
			pos:    fset.Position(call.Pos()).String(),
			arg:    types.ExprString(arg),
			callee: "io.ReadAll",
		})
		return true
	})

	return found, boundedCount, nil
}

// copyDestinationIsBounded reports whether an io.Copy-family destination is one
// that does NOT grow with the response.
//
// io.Discard swallows, an http.ResponseWriter streams to the client, and an
// io.Writer parameter is somebody else's problem by contract. A *bytes.Buffer,
// a strings.Builder or an in-memory accumulator is the upstream choosing this
// process's allocation with extra steps.
func copyDestinationIsBounded(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	dst := types.ExprString(call.Args[0])
	switch {
	case dst == "io.Discard", dst == "ioutil.Discard":
		return true
	case strings.HasPrefix(dst, "&bytes.Buffer"), strings.Contains(dst, "bytes.Buffer"),
		strings.Contains(dst, "strings.Builder"), strings.HasPrefix(dst, "&sink"):
		return false
	case dst == "w", dst == "rw", strings.HasSuffix(dst, "ResponseWriter"):
		return true
	}
	// Unknown destination: report it. A sink nobody has classified is exactly
	// how io.Copy(&sink, resp.Body) read as clean.
	return false
}

// consumerKind says what a call DOES with the body it is handed.
type consumerKind int

const (
	// consumerUnknown is the important one. A consumer nobody has classified is
	// reported, because the entire history of this guard is spellings nobody
	// thought of: it matched one callee (io.ReadAll) and was blind to
	// json.NewDecoder, io.Copy, bufio.NewScanner and seven more. A list that
	// PASSES what it does not recognise silently shrinks to the cases its author
	// remembered. A list that FAILS what it does not recognise costs one line to
	// extend and cannot quietly stop covering anything.
	consumerUnknown consumerKind = iota
	// consumerAccumulating reads the body into memory that grows with it. This
	// is the violation: the upstream picks the allocation.
	consumerAccumulating
	// consumerStreaming moves the body through a fixed-size buffer. The upstream
	// picks neither the memory nor (given providerHTTP's 15s timeout) the time.
	consumerStreaming
	// consumerBounded is a module-local helper that imposes its own ceiling.
	// Every name here is pinned by a behavioural test asserting it REFUSES an
	// oversize body, so the classification is a proven property and not a
	// promise made by a function name.
	consumerBounded
)

func classifyConsumer(callee string) consumerKind {
	switch callee {
	// ── reads the whole body into a growable buffer ──────────────────────────
	case "io.ReadAll", "ioutil.ReadAll", "io.ReadFull",
		"json.NewDecoder", "xml.NewDecoder", "gob.NewDecoder", "csv.NewReader",
		"yaml.NewDecoder", "toml.NewDecoder",
		"bufio.NewScanner", "bufio.NewReader", "bufio.NewReadWriter",
		"httputil.DumpResponse", "httputil.DumpRequest", "multipart.NewReader":
		return consumerAccumulating

	// ── streams, but ONLY if the destination does not grow ───────────────────
	// io.Copy's own 32 KiB buffer is fixed; the SINK is not. io.Copy(&bytes.
	// Buffer{}, resp.Body) is exactly as unbounded as io.ReadAll and was
	// classified clean here until an audit planted one in vault_targets.go and
	// watched this guard pass. The destination is checked by the caller, in
	// copyDestinationIsBounded; reaching this case only says the callee streams.
	case "io.Copy", "io.CopyBuffer", "io.CopyN":
		return consumerStreaming
	// Relay is reflectguard's streaming scanner: it flushes whenever pending
	// reaches holdBack and adds at most chunkSize per iteration, so its ceiling
	// is holdBack+chunkSize and its sink is the client's ResponseWriter.
	case "guard.Relay", "s.Relay":
		return consumerStreaming

	// ── module-local ceilings, each proven by a test ─────────────────────────
	case "readProviderBody", "readUpstreamErrorBody", "upstreamErrorFromResponse":
		return consumerBounded
	}
	return consumerUnknown
}

// carriesAResponseBody reports whether an argument hands a response body to the
// call: either the body itself (resp.Body) or the message carrying it (resp).
//
// Request bodies are excluded here, not forgotten: bodyLimits has already capped
// every one of them, which TestRequestBodyChokepointIsApplied proves.
func carriesAResponseBody(arg ast.Expr, kinds map[string]bodyKind) bool {
	if readsAnHTTPBody(arg) {
		switch bodyReceiverKind(arg, kinds) {
		case bodyRequest, bodyNotHTTP:
			return false
		}
		return true
	}
	id, ok := arg.(*ast.Ident)
	return ok && kinds[id.Name] == bodyResponse
}

// bodyKind says whose body an expression names. The distinction matters because
// a request body is bounded once, globally, and a response body is bounded only
// where somebody remembered to.
type bodyKind int

const (
	bodyUnknown bodyKind = iota
	bodyRequest
	bodyResponse
	// bodyNotHTTP is a .Body selector on something that is not an HTTP message
	// at all: upstreamHTTPError.Body is a string field, and slog.String("body",
	// e.Body) is not a read of anything. Classified rather than name-matched,
	// because "does this identifier hold an HTTP response" is a question about
	// its DECLARATION, not about what somebody called the variable.
	bodyNotHTTP
)

// classifyBodyReceivers reads the identifiers in a file that are declared to be
// an *http.Request or an *http.Response, so `r.Body` and `resp.Body` can be told
// apart by DECLARATION rather than by whether somebody named the variable `r`.
//
// It reads three shapes, which is every shape the module actually uses:
//
//	func h(w http.ResponseWriter, r *http.Request)   // parameter
//	resp, err := providerDo(req)                     // assigned from a known ctor
//	var resp *http.Response                          // explicit declaration
//
// Anything it cannot place stays bodyUnknown and is therefore reported.
func classifyBodyReceivers(f *ast.File) map[string]bodyKind {
	kinds := map[string]bodyKind{}

	note := func(name string, expr ast.Expr) {
		if name == "" || name == "_" {
			return
		}
		inner := expr
		if star, ok := inner.(*ast.StarExpr); ok {
			inner = star.X
		}
		if sel, ok := inner.(*ast.SelectorExpr); ok {
			if pkg, isIdent := sel.X.(*ast.Ident); isIdent && pkg.Name == "http" {
				switch sel.Sel.Name {
				case "Request":
					kinds[name] = bodyRequest
					return
				case "Response":
					kinds[name] = bodyResponse
					return
				}
			}
		}
		// Declared, and declared as something that is not an HTTP message.
		kinds[name] = bodyNotHTTP
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Method receivers: (e *upstreamHTTPError) makes e.Body a field
			// read, not a body read.
			if node.Recv != nil {
				for _, rc := range node.Recv.List {
					for _, nm := range rc.Names {
						note(nm.Name, rc.Type)
					}
				}
			}
			if node.Type.Params != nil {
				for _, p := range node.Type.Params.List {
					for _, nm := range p.Names {
						note(nm.Name, p.Type)
					}
				}
			}
		case *ast.FuncLit:
			if node.Type.Params != nil {
				for _, p := range node.Type.Params.List {
					for _, nm := range p.Names {
						note(nm.Name, p.Type)
					}
				}
			}
		case *ast.ValueSpec:
			for _, nm := range node.Names {
				note(nm.Name, node.Type)
			}
		case *ast.AssignStmt:
			// body := resp.Body, one alias used to erase the selector and make
			// every consumer after it invisible. Track it as a response body.
			if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
				if id, ok := node.Lhs[0].(*ast.Ident); ok && readsAnHTTPBody(node.Rhs[0]) {
					if sel, isSel := node.Rhs[0].(*ast.SelectorExpr); isSel {
						if recv, isIdent := sel.X.(*ast.Ident); isIdent && kinds[recv.Name] == bodyResponse {
							kinds[id.Name] = bodyResponse
						}
					}
				}
			}
			// resp, err := <round trip>. TWO results, because that is the shape
			// of every HTTP round-tripper in the standard library and the thing
			// that separates client.Do(req) from r.URL.Query().Get("limit"):
			// without this the guard classified every single-valued .Get() in
			// the module as a response and reported strconv.Atoi(l) as an
			// unbounded body read.
			if len(node.Lhs) != 2 || len(node.Rhs) != 1 {
				break
			}
			id, ok := node.Lhs[0].(*ast.Ident)
			if !ok {
				break
			}
			if call, isCall := node.Rhs[0].(*ast.CallExpr); isCall && returnsHTTPResponse(call) {
				kinds[id.Name] = bodyResponse
			}
		}
		return true
	})
	return kinds
}

// returnsHTTPResponse reports whether a call is one of the module's ways of
// obtaining an *http.Response. These are the round-trippers, named rather than
// type-checked: the guard runs without a type checker, and a NEW round-tripper
// that is not listed here leaves its receiver bodyUnknown, which reports rather
// than exempts.
func returnsHTTPResponse(call *ast.CallExpr) bool {
	switch calleeName(call) {
	case "providerDo", "http.Get", "http.Post", "http.PostForm", "http.Head":
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Do", "RoundTrip":
		// http.Client.Do and http.RoundTripper.RoundTrip have no common
		// single-valued namesake, so the method name alone is enough.
		return true
	case "Get", "Post", "PostForm", "Head":
		// These DO have namesakes, url.Values.Get, http.Header.Get, sync.Map
		// .Load-alikes, so the receiver has to look like an HTTP client. The
		// two-result rule above has already excluded the single-valued ones;
		// this is the second filter, not the only one.
		recv := strings.ToLower(types.ExprString(sel.X))
		return strings.Contains(recv, "client") || strings.Contains(recv, "http")
	}
	return false
}

// bodyReceiverKind resolves `x.Body` to whose body it is.
func bodyReceiverKind(e ast.Expr, kinds map[string]bodyKind) bodyKind {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Body" {
		return bodyUnknown
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return bodyUnknown
	}
	return kinds[id.Name]
}

// calleeName renders the function being called, e.g. "io.ReadAll",
// "json.NewDecoder", "readProviderBody".
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if pkg, ok := fn.X.(*ast.Ident); ok {
			return pkg.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	}
	return types.ExprString(call.Fun)
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
// permanent, in-repo version of the ablation: every one of them is a real way to
// read a response body, and a detector that stops detecting fails HERE instead of
// silently blessing the whole module.
//
// The list is what the PREVIOUS detector missed. It matched the single callee
// io.ReadAll, so ten of the twelve spellings below read as clean code, including
// json.NewDecoder(resp.Body), the one an ordinary Go author reaches for first.
func TestUnboundedReadDetectorActuallyDetects(t *testing.T) {
	// A response, obtained the way the product obtains one, so the receiver
	// classifies as *http.Response rather than as some struct with a Body field.
	const preamble = `package p

import (
	"bufio"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httputil"
)

func f(client *http.Client, req *http.Request, w io.Writer, buf []byte) {
	resp, _ := client.Do(req)
`
	const postamble = "\n}\n"

	violating := []struct {
		name string
		src  string
	}{
		{"io.ReadAll, the exact old pattern", "b, _ := io.ReadAll(resp.Body); _ = b"},
		{"io.ReadAll split across lines", "b, _ := io.ReadAll(\n\t\tresp.Body,\n\t)\n\t_ = b"},
		{"json.NewDecoder", "var v any; _ = json.NewDecoder(resp.Body).Decode(&v)"},
		{"xml.NewDecoder", "var v any; _ = xml.NewDecoder(resp.Body).Decode(&v)"},
		{"gob.NewDecoder", "var v any; _ = gob.NewDecoder(resp.Body).Decode(&v)"},
		{"csv.NewReader", "rec, _ := csv.NewReader(resp.Body).ReadAll(); _ = rec"},
		{"bufio.NewScanner", "sc := bufio.NewScanner(resp.Body); _ = sc"},
		{"bufio.NewReader", "br := bufio.NewReader(resp.Body); _ = br"},
		{"io.ReadFull", "_, _ = io.ReadFull(resp.Body, buf)"},
		{"httputil.DumpResponse", "d, _ := httputil.DumpResponse(resp, true); _ = d"},
	}
	for _, c := range violating {
		src := preamble + "\t" + c.src + postamble
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

	// A CONSUMER NOBODY CLASSIFIED MUST FAIL, NOT PASS.
	//
	// This is the property that separates this detector from the one it replaced.
	// The old one was a list of things to catch and therefore let everything else
	// through; this one is a list of things known to be safe, so tomorrow's read,
	// whatever it is called, lands in consumerUnknown and is reported.
	t.Run("an unclassified consumer is reported", func(t *testing.T) {
		src := preamble + "\tsomeFutureReader(resp.Body)" + postamble
		found, _, err := scanUnboundedReads("synthetic.go", []byte(src))
		if err != nil {
			t.Fatalf("fixture does not parse: %v", err)
		}
		if len(found) != 1 {
			t.Fatalf("detector found %d findings for an unknown consumer, want 1. A consumer "+
				"nobody has classified is exactly the next miss, and it must fail closed", len(found))
		}
	})

	clean := []struct {
		name    string
		src     string
		bounded int
	}{
		{"io.LimitReader", "b, _ := io.ReadAll(io.LimitReader(resp.Body, 16)); _ = b", 1},
		{"a module-local bounded helper", "b, _ := readProviderBody(resp); _ = b", 1},
		{"io.Copy streams in a fixed buffer", "_, _ = io.Copy(w, resp.Body)", 0},
		{"io.Copy drains to Discard", "_, _ = io.Copy(io.Discard, resp.Body)", 0},
		{"io.CopyN is explicitly capped", "_, _ = io.CopyN(w, resp.Body, 16)", 0},
		// The ~30 json.NewDecoder(r.Body) sites in the handlers are safe because
		// bodyLimits wraps every request body once, globally. That exemption is
		// the whole reason this case is clean, and TestRequestBodyChokepointIsApplied
		// is what keeps it true.
		{"a request body, covered by the chokepoint", "var v any; _ = json.NewDecoder(req.Body).Decode(&v)", 0},
	}
	for _, c := range clean {
		src := preamble + "\t" + c.src + postamble
		found, bounded, err := scanUnboundedReads("synthetic.go", []byte(src))
		if err != nil {
			t.Fatalf("%s: fixture does not parse: %v", c.name, err)
		}
		if len(found) != 0 {
			t.Errorf("%s: detector flagged a bounded read (%v); false positives get guards deleted",
				c.name, found)
		}
		if bounded != c.bounded {
			t.Errorf("%s: bounded count = %d, want %d; the anti-vacuity check depends on this",
				c.name, bounded, c.bounded)
		}
	}

	// A .Body that is not an HTTP body at all. upstreamHTTPError.Body is a
	// string field, and slog.String("body", e.Body) was reported as an unbounded
	// read by the first version of this walk purely because the selector ended
	// in ".Body".
	t.Run("a Body field on another type is not a read", func(t *testing.T) {
		src := `package p

import "log/slog"

type e struct{ Body string }

func (x *e) LogValue() slog.Value { return slog.GroupValue(slog.String("body", x.Body)) }
`
		found, _, err := scanUnboundedReads("synthetic.go", []byte(src))
		if err != nil {
			t.Fatalf("fixture does not parse: %v", err)
		}
		if len(found) != 0 {
			t.Errorf("detector flagged a plain struct field as a body read: %v", found)
		}
	})
}

// TestRequestBodyChokepointIsApplied pins the exemption the detector depends on.
//
// scanUnboundedReads skips r.Body because cmd/server/main.go wraps every request
// body in http.MaxBytesReader through the bodyLimits middleware. That is a claim
// about one line in another package, and if it is ever removed the ~30
// json.NewDecoder(r.Body) sites in the handlers become unbounded reads with
// nothing reporting them, the guard would still pass, having exempted them on a
// premise that had quietly become false.
//
// So the premise is checked rather than assumed: bodyLimits must exist, must
// install a MaxBytesReader onto r.Body, and must be registered on the router.
func TestRequestBodyChokepointIsApplied(t *testing.T) {
	path := filepath.Join(goModuleRoot(t), "cmd", "server", "main.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ABORT: cannot read %s (%v); the exemption is unverified", path, err)
	}
	fset := token.NewFileSet()
	f, parseErr := parser.ParseFile(fset, path, src, 0)
	if parseErr != nil {
		t.Fatalf("ABORT: cannot parse %s (%v)", path, parseErr)
	}

	var wrapsBody, registered bool
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name.Name != "bodyLimits" {
				return true
			}
			// r.Body = http.MaxBytesReader(...)
			ast.Inspect(node, func(m ast.Node) bool {
				as, ok := m.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
					return true
				}
				if types.ExprString(as.Lhs[0]) != "r.Body" {
					return true
				}
				if isBoundedReader(as.Rhs[0]) {
					wrapsBody = true
				}
				return true
			})
		case *ast.CallExpr:
			// r.Use(bodyLimits)
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Use" {
				return true
			}
			for _, a := range node.Args {
				if id, isIdent := a.(*ast.Ident); isIdent && id.Name == "bodyLimits" {
					registered = true
				}
			}
		}
		return true
	})

	if !wrapsBody {
		t.Error("bodyLimits no longer assigns http.MaxBytesReader to r.Body. Every " +
			"json.NewDecoder(r.Body) in internal/handlers is exempted by this middleware; " +
			"without it they are unbounded reads and the exemption in scanUnboundedReads is void")
	}
	if !registered {
		t.Error("bodyLimits is no longer passed to r.Use in cmd/server/main.go, so the request-body " +
			"ceiling is defined but not applied to the router")
	}
}

// TestProviderReadsGoThroughTheBoundedHelper is the fail-closed half for the
// provider file specifically: the tree guard proves no read is unbounded, this
// proves the bounded reads still go through readProviderBody rather than having
// been quietly replaced by something else.
//
// COUNTED BY AST, NOT BY strings.Count.
//
// This used to be `strings.Count(src, "readProviderBody(resp)") < 10`, which had
// both failure modes of a text-matching guard at once. The threshold had slack:
// an ablation reverted SEVEN of the seventeen sites to a raw io.ReadAll and the
// guard stayed green, because ten were left. And the subject was prose: writing
// a COMMENT in that file containing the words readProviderBody(resp) pushed the
// count to 18 and failed the build, with the guard unable to tell an explanation
// of a call from a call.
//
// Parsing answers both. Comments are not in the AST, and the count is exact.
func TestProviderReadsGoThroughTheBoundedHelper(t *testing.T) {
	src, err := os.ReadFile("vault_providers.go")
	if err != nil {
		t.Fatalf("ABORT: could not read vault_providers.go (%v); this check would pass vacuously", err)
	}
	fset := token.NewFileSet()
	f, parseErr := parser.ParseFile(fset, "vault_providers.go", src, 0)
	if parseErr != nil {
		t.Fatalf("ABORT: could not parse vault_providers.go (%v)", parseErr)
	}
	sites := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && calleeName(call) == "readProviderBody" {
			sites++
		}
		return true
	})

	// EXACTLY the real number. If a provider is added or removed, update this in
	// the same commit as the code, so the count is a decision rather than a floor.
	const wantBoundedSites = 17
	if sites != wantBoundedSites {
		t.Fatalf("ABORT: %d readProviderBody call sites, expected exactly %d. Either a site "+
			"stopped using the bounded helper (the regression this guards) or one was added "+
			"and this count was not updated", sites, wantBoundedSites)
	}
}

// TestProviderBodyRefusesAnOversizeBody is the behavioural half.
//
// A source guard proves the call sites use the helper; only this proves the
// helper bounds anything, and, since the classifier in scanUnboundedReads calls
// readProviderBody "bounded" and exempts all 17 of its call sites on that word,
// this is the test that keeps the exemption honest.
//
// The assertion is that overflow is an ERROR, not a shorter slice. The helper
// used to return the first maxProviderBody bytes and nil, on the reasoning that
// a truncated body would fail to parse downstream. encoding/json stops at the
// end of the first complete value and ignores whatever follows, so a response
// whose payload fits inside the ceiling unmarshals cleanly from a body that was
// cut, and on a mint path, "cleanly parsed a body we cut" means a credential
// that exists upstream and a wrong secret stored against it.
func TestProviderBodyRefusesAnOversizeBody(t *testing.T) {
	huge := strings.Repeat("A", maxProviderBody*2)
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pad":"` + huge + `"}`))
	})

	resp, err := providerHTTP.Get("http://example.invalid/x")
	if err != nil {
		t.Fatalf("fake upstream: %v", err)
	}
	defer resp.Body.Close()

	body, err := readProviderBody(resp)
	if err == nil {
		t.Fatalf("readProviderBody accepted a %d-byte body under a %d-byte ceiling and returned "+
			"%d bytes with no error; the upstream is still choosing the allocation and the caller "+
			"cannot tell a cut body from a whole one", len(huge), maxProviderBody, len(body))
	}
	if body != nil {
		t.Errorf("readProviderBody returned %d bytes alongside its error; every one of the 17 call "+
			"sites discards the error and unmarshals the body, so a non-nil body here is parsed as "+
			"if it were complete", len(body))
	}
}

// TestProviderBodyAcceptsWhatFitsUnderTheCeiling is the other half of the pair.
//
// A helper that refused everything would pass the test above and break all 17
// providers, and the ablation for a fail-closed change is the case that must
// still succeed.
func TestProviderBodyAcceptsWhatFitsUnderTheCeiling(t *testing.T) {
	for _, size := range []int{0, 1, maxProviderBody - 1, maxProviderBody} {
		payload := strings.Repeat("A", size)
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(payload))
		})
		resp, err := providerHTTP.Get("http://example.invalid/x")
		if err != nil {
			t.Fatalf("size %d: fake upstream: %v", size, err)
		}
		body, err := readProviderBody(resp)
		resp.Body.Close()
		if err != nil {
			t.Errorf("size %d (ceiling %d): readProviderBody refused a body that fits: %v",
				size, maxProviderBody, err)
			continue
		}
		if len(body) != size {
			t.Errorf("size %d: readProviderBody returned %d bytes", size, len(body))
		}
	}
}

// TestUpstreamErrorBodyHelperIsAlsoBounded pins the second name the classifier
// trusts. consumerBounded lists readProviderBody, readUpstreamErrorBody and
// upstreamErrorFromResponse; a name on that list with no test behind it is the
// guard trusting a function because of what it is called.
func TestUpstreamErrorBodyHelperIsAlsoBounded(t *testing.T) {
	over := strings.NewReader(strings.Repeat("A", maxUpstreamErrorBody+1))
	if _, err := readUpstreamErrorBody(over); err == nil {
		t.Errorf("readUpstreamErrorBody accepted a body over its %d-byte ceiling; "+
			"scanUnboundedReads exempts its call sites on the claim that it does not",
			maxUpstreamErrorBody)
	}
	fits := strings.NewReader(strings.Repeat("A", maxUpstreamErrorBody))
	if _, err := readUpstreamErrorBody(fits); err != nil {
		t.Errorf("readUpstreamErrorBody refused a body at exactly its ceiling: %v", err)
	}
}

// TestGuardCatchesTheEvasionShapes pins the shapes an adversarial sweep used to
// walk straight past this guard while it reported the module clean.
//
// Each one is a real, compiling, unbounded read of an operator-supplied
// upstream's body. Two distinct holes produced them: io.Copy was classified as
// "streaming" on the strength of its fixed 32 KiB internal buffer while nothing
// looked at the DESTINATION, and one assignment `body := resp.Body` erased the
// selector so every consumer after it became invisible.
func TestGuardCatchesTheEvasionShapes(t *testing.T) {
	const pre = `package p

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

func f(client *http.Client, req *http.Request, w io.Writer) {
	resp, _ := client.Do(req)
	var sink bytes.Buffer
	_ = sink
`
	cases := []struct{ name, src string }{
		{"io.Copy into a bytes.Buffer", "_, _ = io.Copy(&sink, resp.Body)"},
		{"io.CopyBuffer into a bytes.Buffer", "_, _ = io.CopyBuffer(&sink, resp.Body, nil)"},
		{"alias then json.NewDecoder", "body := resp.Body\n\tvar v any\n\t_ = json.NewDecoder(body).Decode(&v)"},
		{"alias then bufio.NewScanner", "body := resp.Body\n\tsc := bufio.NewScanner(body)\n\t_ = sc"},
		{"alias then io.ReadAll", "body := resp.Body\n\tb, _ := io.ReadAll(body)\n\t_ = b"},
	}
	for _, c := range cases {
		found, _, err := scanUnboundedReads("synthetic.go", []byte(pre+"\t"+c.src+"\n}\n"))
		if err != nil {
			t.Fatalf("%s: fixture does not parse: %v", c.name, err)
		}
		if len(found) == 0 {
			t.Errorf("%s: STILL MISSED, the guard reports clean over a real unbounded read", c.name)
		}
	}

	// The genuinely bounded sink must stay clean; false positives get guards deleted.
	found, _, err := scanUnboundedReads("synthetic.go",
		[]byte(pre+"\t_, _ = io.Copy(io.Discard, resp.Body)\n}\n"))
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("the io.Discard drain was flagged: %v", found)
	}
}

// TestProviderBodyRefusesAPartialRead covers the OTHER branch, which the first
// version of this fix left alone.
//
// io.ReadAll returns the bytes it managed to read alongside the error, so
// `return body, err` handed callers a partial body with the evidence attached to
// an error all 17 of them discard. Fixing the ceiling branch and not this one
// fixed the expensive attack (send 1 MiB) and left the cheap one (announce a
// Content-Length, send a prefix, reset).
func TestProviderBodyRefusesAPartialRead(t *testing.T) {
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Skip("test server does not support hijacking")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// Promise far more than we deliver, then hang up mid-body.
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")
		_, _ = buf.WriteString(`{"secret":"tok","padding":"AAAAAAAAAAAAAAAA`)
		_ = buf.Flush()
	})

	resp, err := providerHTTP.Get("http://example.invalid/x")
	if err != nil {
		t.Fatalf("fake upstream: %v", err)
	}
	defer resp.Body.Close()

	body, err := readProviderBody(resp)
	if err == nil {
		t.Fatalf("readProviderBody accepted a body the upstream never finished sending "+
			"(%d bytes, Content-Length said 4096)", len(body))
	}
	if body != nil {
		t.Errorf("readProviderBody returned %d bytes of a partial read alongside its error; "+
			"all 17 call sites are `body, _ :=` and unmarshal whatever they are handed", len(body))
	}
}

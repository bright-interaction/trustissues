package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// listValuedHeaders are the headers whose value is a LIST.
//
// RFC 9110 §5.3 lets a sender split any list-valued field across several header
// lines, or join it with commas, entirely at its own discretion, the two are
// defined to mean the same thing. http.Header.Get does not: it returns the first
// line and silently discards every other one, so for these names the sender
// chooses how much of their own input the server looks at.
//
// The set is the standard list-valued fields plus the forwarding headers, which
// are list-valued by convention rather than by grammar. Content-Encoding is here
// because it is where this bit: the reflected-credential scanner read
// Content-Encoding with Get, and a second line was enough to carry the injected
// secret past it.
var listValuedHeaders = map[string]string{
	"accept":                         "content negotiation list",
	"accept-charset":                 "content negotiation list",
	"accept-encoding":                "content negotiation list",
	"accept-language":                "content negotiation list",
	"accept-ranges":                  "list",
	"access-control-allow-headers":   "list",
	"access-control-allow-methods":   "list",
	"access-control-expose-headers":  "list",
	"access-control-request-headers": "list",
	"allow":                          "list",
	"cache-control":                  "directive list",
	"connection":                     "list",
	"content-encoding":               "codings applied, in order",
	"content-language":               "list",
	"forwarded":                      "forwarding chain",
	"if-match":                       "entity-tag list",
	"if-none-match":                  "entity-tag list",
	"pragma":                         "directive list",
	"proxy-authenticate":             "challenge list",
	"te":                             "transfer-coding list",
	"trailer":                        "field-name list",
	"transfer-encoding":              "codings applied, in order",
	"upgrade":                        "protocol list",
	"vary":                           "field-name list",
	"via":                            "proxy chain",
	"warning":                        "list",
	"www-authenticate":               "challenge list",
	"x-forwarded-for":                "forwarding chain",
	"x-forwarded-host":               "forwarding chain",
	"x-forwarded-proto":              "forwarding chain",
	"anthropic-beta":                 "comma-separated beta flags",

	// Set-Cookie is the odd one: Get returns only the first cookie, so it has
	// the same first-value-only defect, but its values must NEVER be
	// comma-joined back together. Read it with Values and keep them separate.
	"set-cookie": "one cookie per line, and they must not be joined",

	// Latent today (nothing reads them), listed so the first read is correct
	// rather than the second.
	"link":                     "list",
	"expect":                   "list",
	"accept-patch":             "list",
	"alt-svc":                  "list",
	"clear-site-data":          "list",
	"authentication-info":      "list",
	"sec-websocket-extensions": "list",
	"sec-websocket-protocol":   "list",
	"server-timing":            "list",
	"timing-allow-origin":      "list",
	"keep-alive":               "list",
	"prefer":                   "list",
	"priority":                 "list",
	"report-to":                "list",
	"permissions-policy":       "list",
	"cdn-loop":                 "proxy chain",
}

// positiveControls are header reads that EXIST in this module right now and are
// single-valued, so they are never findings. They are the matcher's proof of
// life.
//
// A count of "how many Header.Get calls did I see" does not prove a matcher
// works, because it stays non-zero while the matcher goes half-blind: changing
// the receiver test from HasSuffix to HasPrefix blinded an earlier version of
// this guard to EVERY resp.Header.Get in the module while ~11 r.Header.Get sites
// kept the counter healthy and both tests green. Naming reads that must be found
// turns proof-of-life into a real assertion.
var positiveControls = []string{"authorization", "x-api-key", "user-agent"}

// listValuedGets is THE matcher, and it is the ONLY matcher.
//
// The tree walk and the ablation both call this. They used to contain two copies
// of the same predicate, which had already drifted, the copy in the ablation
// disagreed with the deployed guard about `h.Get("Vary")`, the very receiver
// spelling used in ai_gateway.go, and, worse, meant the ablation could not
// detect a blinded guard: it was exercising its own copy, which was still fine.
// An ablation that validates a duplicate of the thing under test proves nothing
// about the thing under test.
//
// Keyed on the ARGUMENT, not the receiver. The previous version tested the
// receiver text with strings.HasSuffix(recv, "Header"), which matched r.Header
// and resp.Header and missed twelve other spellings including w.Header().Get,
// the single most common way Go touches a header, because types.ExprString
// renders a call as "w.Header()", ending in a paren. Header names are
// discriminating enough on their own: a single-argument .Get("Transfer-Encoding")
// is a header read whatever the receiver is called, and a non-header map that
// happens to be keyed by "Vary" is worth a look anyway.
func listValuedGets(filename string, src []byte) (findings []string, seenGets map[string]bool, err error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, nil, err
	}
	seenGets = map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Get" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		name, unquoteErr := strconv.Unquote(lit.Value)
		if unquoteErr != nil {
			return true
		}
		lower := strings.ToLower(name)
		seenGets[lower] = true
		if why, listValued := listValuedHeaders[lower]; listValued {
			findings = append(findings, fset.Position(call.Pos()).String()+
				": "+types.ExprString(sel.X)+".Get("+lit.Value+")  <- "+why)
		}
		return true
	})
	return findings, seenGets, nil
}

// TestNoHeaderGetOnAListValuedHeader forbids Get on any of them, module-wide.
//
// THE DEFECT IS THAT Get ANSWERS A DIFFERENT QUESTION THAN THE ONE ASKED.
//
// `r.Header.Get("X-Forwarded-For")` reads as "the forwarding chain" and returns
// "the first X-Forwarded-For line". For a single-valued header those are the
// same sentence. For a list-valued one they differ by exactly the part a caller
// controls, and the difference is invisible at the call site, which is why this
// is checked mechanically rather than by remembering.
//
// It has now bitten twice. The reflected-secret scanner read Content-Encoding
// with Get and a second line carried the injected credential straight through
// it. clientIP counted trusted proxy hops from the right of a chain that Get had
// already truncated from the left, so with the production TRUSTED_PROXY_HOPS=2 a
// caller could name their own source IP: reset their rate-limit bucket, and
// write whatever they liked into the audit trail's remote_ip column.
//
// Use Header.Values(name) and read the whole list. In middleware, forwardedChain
// flattens it.
func TestNoHeaderGetOnAListValuedHeader(t *testing.T) {
	root := goModuleRoot(t)

	var scanned, findings []string
	seenAll := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
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
		hits, seen, scanErr := listValuedGets(rel, src)
		if scanErr != nil {
			return scanErr
		}
		findings = append(findings, hits...)
		for k := range seen {
			seenAll[k] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ABORT: walking %s failed (%v); the guard checked nothing", root, err)
	}

	// ZERO MATCHES IS SILENCE, NOT PROOF.
	if len(scanned) < 60 {
		t.Fatalf("ABORT: only %d product Go files scanned under %s; the walk is not reaching the "+
			"tree and a violation could hide in the part it missed", len(scanned), root)
	}
	// PROOF OF LIFE, not a count. Each of these is a real single-valued header
	// read in this module today. If the matcher stops finding them it has gone
	// blind, and a blind matcher reports "clean" over everything.
	for _, control := range positiveControls {
		if !seenAll[control] {
			t.Fatalf("ABORT: the matcher no longer sees any read of %q, which this module "+
				"definitely performs. It has gone (at least partly) blind, so its silence about "+
				"list-valued headers means nothing", control)
		}
	}

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf("%d read(s) of a list-valued header through Get:\n  %s\n\n"+
			"Get returns the FIRST header line and discards the rest, and a sender may split a "+
			"list-valued field across lines however it likes. Read the whole list with "+
			"Header.Values(name); for a forwarding chain use middleware's forwardedChain, which "+
			"flattens every line into one ordered list.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// TestListValuedHeaderGuardActuallyDetects is the ablation, in-repo and
// permanent. The tree test above passes by finding nothing, which is also what a
// matcher that has stopped matching reports.
//
// It drives listValuedGets, the same function the tree walk calls, rather than
// a copy of it. The previous version re-implemented the predicate, the two
// drifted, and a one-word mutation to the real guard (HasSuffix -> HasPrefix)
// blinded it to every response-header read in the module while BOTH tests stayed
// green. A test that re-implements what it verifies pins only the literals.
func TestListValuedHeaderGuardActuallyDetects(t *testing.T) {
	const tmpl = `package p

import "net/http"

func f(r *http.Request, resp *http.Response, w http.ResponseWriter, hdr, headers http.Header) {
	%s
}
`
	violating := []string{
		`_ = r.Header.Get("X-Forwarded-For")`,
		`_ = r.Header.Get("x-forwarded-for")`, // header names are case-insensitive
		`_ = resp.Header.Get("Content-Encoding")`,
		`_ = resp.Header.Get("Transfer-Encoding")`,
		`_ = resp.Header.Get("Vary")`,
		`_ = resp.Header.Get("WWW-Authenticate")`,
		`_ = r.Header.Get("Accept-Encoding")`,
		`_ = resp.Header.Get("Set-Cookie")`,
		// The receiver spellings the old matcher could not see. w.Header() is
		// the most common way Go touches a header at all, and it was invisible
		// because types.ExprString renders it ending in a paren.
		`_ = w.Header().Get("Vary")`,
		`_ = hdr.Get("Vary")`,
		`_ = headers.Get("Vary")`,
	}
	for _, v := range violating {
		hits, _, err := listValuedGets("synthetic.go", []byte(strings.ReplaceAll(tmpl, "%s", v)))
		if err != nil {
			t.Fatalf("fixture does not parse: %v", err)
		}
		if len(hits) != 1 {
			t.Errorf("matcher found %d findings in %q, want 1; the guard would pass over this", len(hits), v)
		}
	}

	clean := []string{
		`_ = r.Header.Get("Authorization")`, // credentials, single-valued
		`_ = r.Header.Get("X-API-Key")`,
		`_ = r.Header.Get("Content-Type")`,
		`_ = r.Header.Get("Origin")`,
		`_ = r.Header.Values("X-Forwarded-For")`, // the fix
	}
	for _, c := range clean {
		hits, _, err := listValuedGets("synthetic.go", []byte(strings.ReplaceAll(tmpl, "%s", c)))
		if err != nil {
			t.Fatalf("fixture does not parse: %v", err)
		}
		if len(hits) != 0 {
			t.Errorf("matcher flagged %q; false positives get guards deleted", c)
		}
	}

	// The positive controls must be RECOGNISED as header reads even though they
	// are not findings, because that recognition is what the tree walk's
	// proof-of-life check depends on.
	for _, control := range positiveControls {
		src := strings.ReplaceAll(tmpl, "%s", `_ = r.Header.Get("`+control+`")`)
		_, seen, err := listValuedGets("synthetic.go", []byte(src))
		if err != nil {
			t.Fatalf("fixture does not parse: %v", err)
		}
		if !seen[control] {
			t.Errorf("matcher did not register %q as a header read; the tree walk's proof-of-life "+
				"check is asserting something the matcher cannot deliver", control)
		}
	}
}

package flarereport

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	sentry "github.com/getsentry/sentry-go"
)

func headersOf(kv map[string]string) *sentry.Event {
	return &sentry.Event{Request: &sentry.Request{
		URL:     "https://vault.example/api/service-identities/me/secrets?code=abc",
		Method:  "POST",
		Headers: kv,
	}}
}

func TestScrubDropsAuthHeadersInAnyCasing(t *testing.T) {
	// The canonical spelling net/http produces, the lower-case spelling this
	// tree writes by hand, and a shouted spelling: all three must go.
	for _, name := range []string{"X-Service-Key", "x-service-key", "X-SERVICE-KEY", "Authorization", "authorization", "Cookie", "X-Api-Key", "x-api-key", "apikey", "Mcp-Session-Id"} {
		ev := scrubRequestEvent(headersOf(map[string]string{name: "sk_deadbeef"}))
		if v, ok := ev.Request.Headers[name]; ok {
			t.Errorf("header %q survived the scrub with value %q", name, v)
		}
	}
}

func TestScrubKeepsTriageHeaders(t *testing.T) {
	in := map[string]string{
		"Host":         "vault.example",
		"User-Agent":   "trustissues-boot/1.0",
		"Content-Type": "application/json",
		"content-type": "application/json",
	}
	ev := scrubRequestEvent(headersOf(in))
	for name := range in {
		if _, ok := ev.Request.Headers[name]; !ok {
			t.Errorf("triage header %q was dropped; the report is now useless for triage", name)
		}
	}
}

func TestScrubClearsQueryCookiesAndBody(t *testing.T) {
	ev := &sentry.Event{Request: &sentry.Request{
		URL:         "https://vault.example/api/vault/entries?token=reset-me",
		Method:      "POST",
		Data:        `{"value":"sk-ant-api03-REAL-SECRET-VALUE"}`,
		QueryString: "token=reset-me",
		Cookies:     "ti_session=abc123",
		Headers:     map[string]string{},
	}}
	got := scrubRequestEvent(ev).Request
	if got.QueryString != "" {
		t.Errorf("QueryString survived: %q", got.QueryString)
	}
	if got.Cookies != "" {
		t.Errorf("Cookies survived: %q", got.Cookies)
	}
	// Scope.SetRequest buffers the request body and ApplyToEvent copies it into
	// Data, so this field is a real egress path, not a theoretical one.
	if got.Data != "" {
		t.Errorf("request body survived: %q", got.Data)
	}
	if got.URL != "https://vault.example/api/vault/entries" {
		t.Errorf("URL kept its query string: %q", got.URL)
	}
	if got.Method != "POST" {
		t.Errorf("method was lost, so the report cannot be triaged: %q", got.Method)
	}
}

func TestScrubToleratesNilEventAndNilRequest(t *testing.T) {
	if scrubRequestEvent(nil) != nil {
		t.Error("a nil event should come back nil, not be dereferenced")
	}
	ev := &sentry.Event{}
	if scrubRequestEvent(ev).Request != nil {
		t.Error("a nil request should be left alone")
	}
}

// headerCallSite matches the header names this codebase actually reads and
// writes. Anchoring on the http.Header call is what makes the enumeration
// mechanical: it cannot drift the way a hand-maintained list of "the auth
// headers we have" drifts, which is the drift that left X-Service-Key exposed.
var headerCallSite = regexp.MustCompile(`\.Header\.(?:Get|Set|Add|Del|Values)\(\s*"([A-Za-z0-9-]+)"`)

// authWords are the substrings that make a header name credential-bearing.
var authWords = []string{"key", "token", "auth", "secret", "session", "cookie", "credential", "password", "signature", "csrf", "xsrf"}

func looksCredentialBearing(header string) bool {
	lower := strings.ToLower(header)
	for _, w := range authWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// collectHeaderNames walks the module source and returns every header name used
// at an http.Header call site.
func collectHeaderNames(t *testing.T) map[string]string {
	t.Helper()
	root, err := filepath.Abs("../..") // the module root; this package is internal/flarereport
	if err != nil {
		t.Fatalf("resolving module root: %v", err)
	}
	found := map[string]string{} // header name -> the file it was seen in
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "frontend", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, _ := filepath.Rel(root, path)
		for _, m := range headerCallSite.FindAllSubmatch(src, -1) {
			name := string(m[1])
			if _, seen := found[name]; !seen {
				found[name] = rel
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return found
}

// TestEveryAuthHeaderInTreeIsScrubbed is the durable half of the X-Service-Key
// fix. It enumerates the header names this codebase actually uses, keeps the
// credential-bearing ones, and asserts the scrub drops each. Introduce a new
// auth header anywhere in the tree and this test covers it the moment it is
// written, which is the property the old hand-maintained deny-list did not have.
func TestEveryAuthHeaderInTreeIsScrubbed(t *testing.T) {
	names := collectHeaderNames(t)

	// A guard that finds nothing passes trivially and reads as evidence. These
	// three are known to exist at http.Header call sites in this tree; if the
	// enumeration stops finding them, it broke and the rest of this test is
	// worthless.
	for _, sentinel := range []string{"X-Service-Key", "Authorization", "X-API-Key"} {
		if _, ok := names[sentinel]; !ok {
			t.Fatalf("the enumeration failed to find %q, so it is no longer enumerating anything; fix headerCallSite", sentinel)
		}
	}

	checked := 0
	for name, file := range names {
		if !looksCredentialBearing(name) {
			continue
		}
		checked++
		// Every casing, because event.Request.Headers is a plain map that a
		// capture path may fill without going through http.Header.
		for _, variant := range []string{name, strings.ToLower(name), strings.ToUpper(name)} {
			ev := scrubRequestEvent(headersOf(map[string]string{variant: "a-real-looking-credential-value"}))
			if _, ok := ev.Request.Headers[variant]; ok {
				t.Errorf("%s: auth header %q (as %q) is NOT scrubbed; a panic on a route reading it ships the credential to the shared Flare store. Do not add it to reportableHeaders", file, name, variant)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("only %d credential-bearing headers were checked; the filter is too narrow to be a guard", checked)
	}
	t.Logf("checked %d credential-bearing header names out of %d header call sites", checked, len(names))
}

// TestAllowListHoldsNothingCredentialBearing is the same guard from the other
// side. The enumeration above can only fail if a new auth header is ADDED to
// reportableHeaders, so state that rule directly as well: nothing on the
// allow-list may look like a credential.
func TestAllowListHoldsNothingCredentialBearing(t *testing.T) {
	for name := range reportableHeaders {
		if looksCredentialBearing(name) {
			t.Errorf("reportableHeaders contains %q, which reads as credential-bearing; the allow-list is the one place a leak can be reintroduced", name)
		}
		if name != strings.ToLower(name) {
			t.Errorf("reportableHeaders key %q is not lower-case, so headerReportable will never match it", name)
		}
	}
}

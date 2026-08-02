package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/middleware"
)

// There is exactly ONE client-IP derivation in the codebase.
//
// rate_limit.go states the contract outright: ClientIP "is the SINGLE client-IP
// derivation for the whole codebase: rate limiting, login lockouts, and every audit row
// must agree on who the caller is, and must agree on a value the caller cannot choose",
// and warns that a second implementation "lets an attacker reset their own throttle
// bucket and write a forged source IP into the audit trail".
//
// service_secrets.go had one anyway. It took the rightmost X-Forwarded-For entry with NO
// trusted-peer gate, so unlike ClientIP it honoured a forwarded header even when
// TRUSTISSUES_TRUSTED_PROXY_HOPS is 0 or the socket peer is a public address, and its
// value went straight into the service-secret audit trail's remote_ip.
//
// This guard is structural because the property is "no second reader exists", which is a
// statement about the tree rather than about one call. The behavioural half is below.
func TestOnlyOneClientIPDerivation(t *testing.T) {
	// Every non-test Go file outside internal/middleware must not read the
	// forwarding headers itself.
	var offenders []string
	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, filepath.Join("internal", "middleware")) {
			return nil // the one legitimate implementation lives here
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		for _, hdr := range []string{`Header.Get("X-Forwarded-For")`, `Header.Get("X-Real-IP")`} {
			if strings.Contains(string(src), hdr) {
				offenders = append(offenders, path+" reads "+hdr)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("a second client-IP derivation exists:\n  %s\n"+
			"Every caller must go through middleware.ClientIP, or the rate limiter, the "+
			"login lockout and the audit trail can disagree about who the caller is, and the "+
			"one that trusts a forwarded header lets the caller choose it.",
			strings.Join(offenders, "\n  "))
	}
}

// And behaviourally: an untrusted peer cannot choose the IP recorded about them.
//
// The removed implementation returned the rightmost XFF entry whenever the header was
// present, with no check on whether the socket peer was a proxy we trust. A client
// connecting straight to the server could therefore set X-Forwarded-For and pick the
// address written into its own service-secret audit row.
func TestForwardedHeaderCannotForgeTheAuditIP(t *testing.T) {
	// hops defaults to 1 but the PEER here is public, so the header must be ignored.
	req := httptest.NewRequest(http.MethodGet, "/api/service-identities", nil)
	req.RemoteAddr = "203.0.113.9:44321" // a public address, not a trusted proxy
	req.Header.Set("X-Forwarded-For", "10.9.9.9, 198.51.100.7")

	got := requestRemoteIP(req)
	if got != "203.0.113.9" {
		t.Errorf("requestRemoteIP = %q, want the socket peer 203.0.113.9.\n"+
			"A caller reaching the server directly must not be able to choose the IP "+
			"recorded against their own service-secret access.", got)
	}

	// It must also agree with the derivation everything else uses.
	if want := middleware.ClientIP(req); got != want {
		t.Errorf("the audit trail records %q while the rate limiter and lockout see %q; "+
			"they must agree on who the caller is", got, want)
	}
}

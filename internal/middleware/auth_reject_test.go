package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// The FIRST tests in internal/middleware.
//
// This package is the authentication ENFORCEMENT layer (630 lines across auth.go,
// rate_limit.go and security.go) and it had zero test files through seventeen audit
// rounds, so nothing here was pinned by anything. Six lenses read it only in fragments
// as supporting citations.

// A removed identity is a dead session, not a permission problem.
//
// Every enrichUserContext rejection was a flat 403, which conflates two different
// things. "You are authenticated but not allowed to do this" is 403; "the identity
// behind this session no longer exists" is 401, and only the second means the client
// should log out. The SPA drops its session on a 401 only, so an account an admin
// disabled mid-visit kept a fully rendered app full of cached data and a red toast on
// every request, with no indication that access had actually been removed.
//
// A read failure stays a server error, because it says nothing about the caller.
func TestDisabledAccountIsADeadSession(t *testing.T) {
	cases := []struct {
		reject string
		want   int
		why    string
	}{
		{"account is disabled", http.StatusUnauthorized,
			"a disabled account must read as a dead session so the client logs out"},
		{"user not found", http.StatusUnauthorized,
			"a deleted account must read as a dead session, not as a forbidden action"},
		{"internal error", http.StatusInternalServerError,
			"a database read failure says nothing about the caller and must not look like auth"},
		{"some future policy denial", http.StatusForbidden,
			"a genuine authorization denial stays 403"},
	}
	for _, c := range cases {
		t.Run(c.reject, func(t *testing.T) {
			if got := authRejectStatus(c.reject); got != c.want {
				t.Errorf("authRejectStatus(%q) = %d, want %d.\n%s", c.reject, got, c.want, c.why)
			}
		})
	}
}

// Retry-After must be a value clients can actually parse.
//
// RFC 9110 defines it as delta-seconds or an HTTP-date. This emitted
// limiter.window.String(), which is a Go duration literal like "1m0s", so every
// well-behaved client and every SDK with retry support ignored the hint entirely and
// retried at whatever interval it chose. A rate limit that cannot tell a client when to
// come back is doing half its job.
func TestRetryAfterIsDeltaSeconds(t *testing.T) {
	limiter := NewRateLimiter(1, time.Minute)
	h := RateLimit(limiter)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.RemoteAddr = "203.0.113.7:5000"

	// First one is allowed, second trips the limiter.
	h.ServeHTTP(httptest.NewRecorder(), req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("ABORT: got %d, want 429; the limiter did not trip so the header is untested", rec.Code)
	}
	got := rec.Header().Get("Retry-After")
	if got == "" {
		t.Fatal("no Retry-After header at all")
	}
	if _, err := strconv.Atoi(got); err != nil {
		t.Errorf("Retry-After = %q, which is not delta-seconds.\n"+
			"RFC 9110 allows only delta-seconds or an HTTP-date, so a Go duration string "+
			"like \"1m0s\" is silently ignored by every client that would otherwise back off.",
			got)
	}
}

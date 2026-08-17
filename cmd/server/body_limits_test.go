package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/handlers"
)

// driveBodyLimits sends exactly n bytes at path and reports whether the body
// was cut off before the handler could read all of it.
//
// contentLength, when non-zero, overrides the header httptest derives from the
// reader. An earlier version of this file set req.ContentLength = len(body) on
// every case, which read as load-bearing and is not: http.MaxBytesReader counts
// the bytes it actually reads and never consults the header. It is a parameter
// here so that fact is asserted (see the lying-ContentLength cases) instead of
// being implied by a line that does nothing.
func driveBodyLimits(t *testing.T, path string, n int, contentLength int64) (blocked bool, read int) {
	t.Helper()
	var readErr error
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		readErr = err
		read = len(b)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(bytes.Repeat([]byte("a"), n)))
	if contentLength != 0 {
		req.ContentLength = contentLength
	}
	bodyLimits(next).ServeHTTP(httptest.NewRecorder(), req)
	return readErr != nil, read
}

// TestBodyLimitsExactBoundaries is the guard the per-path table could not be.
//
// Every budget is asserted at limit-1, limit and limit+1, in BYTES taken from
// the constants themselves, so the only passing implementation is the exact
// budget. The previous table sized bodies with float64 MiB multiplication, so
// no case could express the limit exactly or limit±1, and its /api/ai/ pair (3
// MiB passes, 6 MiB blocks) was satisfied by any middleware limit between the
// two: setting this middleware to 4 MiB while ai_gateway.go kept 5 MB left the
// whole file green. That is the same defect class the /api/ai/ case exists to
// close, a declared ceiling that is not the effective one, inside its own test.
func TestBodyLimitsExactBoundaries(t *testing.T) {
	budgets := []struct {
		name  string
		path  string
		limit int64
	}{
		{"default", "/api/vault/", defaultBodyLimit},
		{"import", "/api/vault/import/preview", importBodyLimit},
		{"proxy", "/proxy/api.example.com/v1/x", proxyBodyLimit},
		// Derived from the handler's constant, not restated. If the two ever
		// disagree by a single byte this fails, which is precisely what
		// bodyLimits' "must match handlers.MaxAIBody" comment claims and what
		// nothing previously checked.
		{"ai gateway", "/api/ai/anthropic/v1/messages", int64(handlers.MaxAIBody)},
	}

	for _, b := range budgets {
		// http.MaxBytesReader permits exactly limit bytes and fails at limit+1.
		cases := []struct {
			n         int64
			wantBlock bool
		}{
			{b.limit - 1, false},
			{b.limit, false},
			{b.limit + 1, true},
		}
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s/%d bytes", b.name, c.n), func(t *testing.T) {
				blocked, read := driveBodyLimits(t, b.path, int(c.n), 0)
				if blocked != c.wantBlock {
					t.Fatalf("%s at %d bytes (limit %d): blocked = %v, want %v (read %d bytes)",
						b.path, c.n, b.limit, blocked, c.wantBlock, read)
				}
				if !c.wantBlock && int64(read) != c.n {
					t.Fatalf("%s at %d bytes: handler saw %d", b.path, c.n, read)
				}
			})
		}
	}
}

// TestAIBudgetIsTheHANDLERSConstant states the coupling as its own assertion.
//
// The boundary table above would still pass if someone replaced
// int64(handlers.MaxAIBody) in bodyLimits with a hardcoded 5<<20 and later
// changed the handler's constant, because the test would move with the
// middleware. This pins the direction: the middleware budget is whatever
// ai_gateway.go says, and a body one byte over the HANDLER's ceiling must be
// refused by the middleware.
func TestAIBudgetIsTheHandlersConstant(t *testing.T) {
	const aiPath = "/api/ai/anthropic/v1/messages"

	if blocked, _ := driveBodyLimits(t, aiPath, handlers.MaxAIBody, 0); blocked {
		t.Errorf("a body of exactly handlers.MaxAIBody (%d) was blocked by the middleware, so the "+
			"handler's own ceiling is unreachable and its 413 branch is dead code", handlers.MaxAIBody)
	}
	if blocked, read := driveBodyLimits(t, aiPath, handlers.MaxAIBody+1, 0); !blocked {
		t.Errorf("a body of handlers.MaxAIBody+1 (%d) passed the middleware, %d bytes read",
			handlers.MaxAIBody+1, read)
	}
	// And it must be strictly larger than the default, or the /api/ai/ case is
	// doing nothing at all, which was the original bug.
	if int64(handlers.MaxAIBody) <= defaultBodyLimit {
		t.Fatalf("handlers.MaxAIBody (%d) is not above defaultBodyLimit (%d); the /api/ai/ case is inert",
			handlers.MaxAIBody, defaultBodyLimit)
	}
}

// TestContentLengthDoesNotDecideTheLimit proves the header is not consulted, in
// both directions. This is what makes removing it from the other cases safe to
// rely on rather than merely tidy.
func TestContentLengthDoesNotDecideTheLimit(t *testing.T) {
	const path = "/api/vault/"

	// Claims to be tiny, actually one byte over: must still be blocked.
	if blocked, read := driveBodyLimits(t, path, int(defaultBodyLimit)+1, 10); !blocked {
		t.Errorf("an over-limit body with a small Content-Length passed; %d bytes reached the handler", read)
	}
	// Claims to be enormous, actually under: must still pass in full.
	want := int(defaultBodyLimit) - 1
	if blocked, read := driveBodyLimits(t, path, want, 1<<40); blocked || read != want {
		t.Errorf("an under-limit body with a huge Content-Length was blocked (blocked=%v, read=%d, want %d)",
			blocked, read, want)
	}
}

// TestBodyLimitsPerPathBudget keeps the realistic-size table as a readability
// check on the routing: that each prefix lands on the budget a reader would
// expect. The exact enforcement is TestBodyLimitsExactBoundaries' job.
//
// The /api/ai/ cases are the regression check for the bug where that prefix had
// no case at all: every AI-gateway request fell through to defaultBodyLimit (1
// MiB) even though internal/handlers/ai_gateway.go declares and enforces a 5 MB
// ceiling of its own, so a body between 1 MiB and 5 MiB was rejected here,
// before the handler's own check ever ran.
func TestBodyLimitsPerPathBudget(t *testing.T) {
	const MiB = 1 << 20
	cases := []struct {
		name      string
		path      string
		bytes     int
		wantBlock bool
	}{
		{name: "default: under 1 MiB passes", path: "/api/vault/", bytes: MiB / 2},
		{name: "default: over 1 MiB is blocked", path: "/api/vault/", bytes: 3 * MiB / 2, wantBlock: true},

		{name: "import: 5 MiB is under the 10 MiB import budget", path: "/api/vault/import/preview", bytes: 5 * MiB},
		{name: "import: 11 MiB exceeds the 10 MiB import budget", path: "/api/vault/import/preview", bytes: 11 * MiB, wantBlock: true},

		{name: "proxy: 15 MiB is under the 17 MiB proxy budget", path: "/proxy/api.example.com/v1/x", bytes: 15 * MiB},
		{name: "proxy: 18 MiB exceeds the 17 MiB proxy budget", path: "/proxy/api.example.com/v1/x", bytes: 18 * MiB, wantBlock: true},

		{name: "ai gateway: 3 MiB is over the 1 MiB default but under the 5 MB AI budget",
			path: "/api/ai/anthropic/v1/messages", bytes: 3 * MiB},
		{name: "ai gateway: 6 MiB exceeds the 5 MB AI budget",
			path: "/api/ai/anthropic/v1/messages", bytes: 6 * MiB, wantBlock: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, read := driveBodyLimits(t, tc.path, tc.bytes, 0)
			if blocked != tc.wantBlock {
				t.Fatalf("path %s, body %d bytes: blocked = %v (read=%d), want blocked = %v",
					tc.path, tc.bytes, blocked, read, tc.wantBlock)
			}
			if !tc.wantBlock && read != tc.bytes {
				t.Fatalf("path %s: expected the full %d-byte body to pass through, got %d bytes",
					tc.path, tc.bytes, read)
			}
		})
	}
}

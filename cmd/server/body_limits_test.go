package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBodyLimitsPerPathBudget proves bodyLimits' per-path switch enforces the
// budget it claims for each special-cased prefix, not just the 1 MB default.
//
// The /api/ai/ cases are the regression check for the bug where that prefix
// had no case at all: every AI-gateway request fell through to
// defaultBodyLimit (1 MiB) even though internal/handlers/ai_gateway.go
// declares and enforces a 5 MB ceiling of its own. A body between 1 MiB and 5
// MiB used to be rejected here, at the middleware layer, before the handler's
// own check ever ran.
func TestBodyLimitsPerPathBudget(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		bodyMiB   float64 // size of the request body, in MiB
		wantBlock bool
	}{
		{name: "default: under 1 MiB passes", path: "/api/vault/", bodyMiB: 0.5},
		{name: "default: over 1 MiB is blocked", path: "/api/vault/", bodyMiB: 1.5, wantBlock: true},

		{name: "import: 5 MiB is under the 10 MiB import budget", path: "/api/vault/import/preview", bodyMiB: 5},
		{name: "import: 11 MiB exceeds the 10 MiB import budget", path: "/api/vault/import/preview", bodyMiB: 11, wantBlock: true},

		{name: "proxy: 15 MiB is under the 17 MiB proxy budget", path: "/proxy/api.example.com/v1/x", bodyMiB: 15},
		{name: "proxy: 18 MiB exceeds the 17 MiB proxy budget", path: "/proxy/api.example.com/v1/x", bodyMiB: 18, wantBlock: true},

		// The fix under test: /api/ai/ now gets its own case.
		{name: "ai gateway: 3 MiB is over the 1 MiB default but under the 5 MB AI budget",
			path: "/api/ai/anthropic/v1/messages", bodyMiB: 3},
		{name: "ai gateway: 6 MiB exceeds the 5 MB AI budget",
			path: "/api/ai/anthropic/v1/messages", bodyMiB: 6, wantBlock: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bodySize := int(tc.bodyMiB * (1 << 20))
			body := bytes.Repeat([]byte("a"), bodySize)

			var readErr error
			var readLen int
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				readErr = err
				readLen = len(b)
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(body))
			req.ContentLength = int64(bodySize)
			rec := httptest.NewRecorder()
			bodyLimits(next).ServeHTTP(rec, req)

			blocked := readErr != nil
			if blocked != tc.wantBlock {
				t.Fatalf("path %s, body %.1f MiB: blocked = %v (err=%v, read=%d bytes), want blocked = %v",
					tc.path, tc.bodyMiB, blocked, readErr, readLen, tc.wantBlock)
			}
			if !tc.wantBlock && readLen != bodySize {
				t.Fatalf("path %s: expected the full %d-byte body to pass through, got %d bytes",
					tc.path, bodySize, readLen)
			}
		})
	}
}

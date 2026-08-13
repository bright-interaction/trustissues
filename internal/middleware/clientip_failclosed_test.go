package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// clientIP is one of the two net.ParseIP call sites the P0-4 primitive sweep
// allowlisted as fail-CLOSED. The allowlist row in
// internal/handlers/parseip_primitive_guard_test.go names this test, so the
// claim is checked rather than asserted.
//
// The claim: when net.ParseIP returns nil (which it does for any zoned IPv6
// literal, "::1%1" included), trustedPeer stays false and the whole
// X-Forwarded-For branch is skipped. The caller therefore loses the ability to
// name its own client IP, which is the strict direction. A fail-OPEN version of
// this site would do the opposite: treat the unparseable peer as trusted and let
// the header win, which resets a throttle bucket and forges the audit source.

// TestClientIPUnparseableRemoteAddrFailsClosed proves nil makes this site
// stricter, for every spelling net.ParseIP refuses.
func TestClientIPUnparseableRemoteAddrFailsClosed(t *testing.T) {
	// One trusted hop, the intended deploy shape, so the XFF branch is live for
	// any peer that IS trusted. Without this the test would pass vacuously.
	ConfigureProxy(1, false)
	t.Cleanup(func() { ConfigureProxy(1, false) })

	// Positive control first: a genuinely trusted (loopback) peer DOES honour
	// the forwarded chain. If this stops holding, every assertion below is
	// vacuous, because nothing would be trusting the header in the first place.
	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.RemoteAddr = "127.0.0.1:5555"
	trusted.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := ClientIP(trusted); got != "203.0.113.9" {
		t.Fatalf("control failed: a loopback peer with one trusted hop should yield the forwarded "+
			"client 203.0.113.9, got %q. The XFF branch is not reachable, so this test proves nothing.", got)
	}

	// The zoned spellings net.ParseIP returns nil for. Each must be treated as
	// an UNTRUSTED peer, so the attacker-supplied header is discarded.
	unparseable := []string{
		"[::1%1]:5555",
		"[::1%lo0]:5555",
		"[fe80::1%eth0]:5555",
		"[fd00::1%2]:5555",
		"[::ffff:127.0.0.1%1]:5555",
		"not-an-address:5555",
	}
	for _, remote := range unparseable {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Real-IP", "203.0.113.9")

		got := ClientIP(r)
		if got == "203.0.113.9" {
			t.Errorf("RemoteAddr %q: ClientIP honoured the attacker-supplied forwarding header and "+
				"returned %q. net.ParseIP returning nil must leave the peer UNTRUSTED, or a caller "+
				"picks its own rate-limit bucket and its own audit-trail source IP.", remote, got)
		}
	}
}

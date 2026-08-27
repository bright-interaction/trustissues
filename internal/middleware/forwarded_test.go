package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// withProxyConfig sets the package-level trust configuration for one test.
func withProxyConfig(t *testing.T, hops int, xRealIP bool) {
	t.Helper()
	oldHops, oldXRI, oldPeers := trustedProxyHops, trustXRealIP, trustedProxyPeers
	trustedProxyHops, trustXRealIP = hops, xRealIP
	if err := ConfigureTrustedProxyPeers("127.0.0.1,::1"); err != nil {
		t.Fatalf("configure loopback proxy: %v", err)
	}
	t.Cleanup(func() {
		trustedProxyHops, trustXRealIP, trustedProxyPeers = oldHops, oldXRI, oldPeers
	})
}

// req builds a request from a trusted peer (loopback) carrying the given
// X-Forwarded-For LINES, exactly as they would arrive on the wire.
func req(lines ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	if len(lines) > 0 {
		r.Header["X-Forwarded-For"] = lines
	}
	return r
}

// TestClientIPIgnoresAttackerControlledChain is the regression.
//
// http.Header.Get returns the FIRST header line and silently discards the rest,
// and a forwarding chain may legally arrive as several lines. clientIP counts
// trusted hops from the RIGHT so that entries a caller prepends land outside the
// window, but when Get handed it only line one, the window was computed over a
// list the caller wrote in full, and the proxy's own appended entry was in the
// part that had been thrown away.
//
// Production runs TRUSTISSUES_TRUSTED_PROXY_HOPS=2, so both hop counts are here.
// Each case is a value the CALLER chose; every one of them must be refused.
func TestClientIPIgnoresAttackerControlledChain(t *testing.T) {
	cases := []struct {
		name    string
		hops    int
		lines   []string
		forbid  string
		wantAny []string // acceptable answers: a real hop or the socket peer
	}{
		{
			name:    "one attacker line, one proxy line, 1 hop",
			hops:    1,
			lines:   []string{"9.9.9.9", "203.0.113.7"},
			forbid:  "9.9.9.9",
			wantAny: []string{"203.0.113.7"},
		},
		{
			// Under Header.Get this read as the 2-element chain the caller
			// wrote, so idx = 2-2 = 0 landed on the caller's first entry.
			name:    "caller writes a padded line, two proxies append their own, 2 hops",
			hops:    2,
			lines:   []string{"9.9.9.9, 8.8.8.8", "198.51.100.4", "203.0.113.7"},
			forbid:  "9.9.9.9",
			wantAny: []string{"198.51.100.4"},
		},
		{
			name:    "three lines, 2 hops",
			hops:    2,
			lines:   []string{"9.9.9.9", "198.51.100.4", "203.0.113.7"},
			forbid:  "9.9.9.9",
			wantAny: []string{"198.51.100.4"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withProxyConfig(t, c.hops, false)
			got := clientIP(req(c.lines...))
			if got == c.forbid {
				t.Fatalf("clientIP returned %q, which the caller chose. Header.Get would have "+
					"seen only %q of the chain %q, and the hop window was computed over that. "+
					"A caller who can pick this value resets their own rate-limit bucket and "+
					"writes a forged source IP into every audit row",
					got, c.lines[0], c.lines)
			}
			for _, ok := range c.wantAny {
				if got == ok {
					return
				}
			}
			t.Fatalf("clientIP = %q, want one of %q", got, c.wantAny)
		})
	}
}

// TestForwardedChainSpellingIsIrrelevant is the property underneath the fix.
//
// "a, b, c" on one line and "a" / "b" / "c" on three lines are the SAME chain
// on the wire; RFC 7230 §3.2.2 lets a sender choose either. Any difference in
// what clientIP returns between the two is a difference an attacker picks.
func TestForwardedChainSpellingIsIrrelevant(t *testing.T) {
	for _, hops := range []int{1, 2, 3} {
		t.Run("", func(t *testing.T) {
			withProxyConfig(t, hops, false)
			joined := clientIP(req("9.9.9.9, 198.51.100.4, 203.0.113.7"))
			split := clientIP(req("9.9.9.9", "198.51.100.4", "203.0.113.7"))
			mixed := clientIP(req("9.9.9.9, 198.51.100.4", "203.0.113.7"))
			if joined != split || joined != mixed {
				t.Errorf("hops=%d: the same chain read three ways gave %q / %q / %q; the sender "+
					"chooses the spelling, so any disagreement here is a value the sender picks",
					hops, joined, split, mixed)
			}
		})
	}
}

// TestClientIPSingleLineBehaviourUnchanged is the no-regression half. The fix
// must not move the answer for the shape that was already correct: one line,
// comma-joined, which is what nginx and Caddy actually emit.
func TestClientIPSingleLineBehaviourUnchanged(t *testing.T) {
	cases := []struct {
		hops int
		xff  string
		want string
	}{
		{1, "9.9.9.9, 203.0.113.7", "203.0.113.7"},
		{2, "9.9.9.9, 198.51.100.4, 203.0.113.7", "198.51.100.4"},
		{1, "203.0.113.7", "203.0.113.7"},
		{3, "203.0.113.7", "127.0.0.1"},          // chain shorter than the hop count -> socket peer
		{0, "9.9.9.9, 203.0.113.7", "127.0.0.1"}, // no trusted proxy -> socket peer
	}
	for _, c := range cases {
		withProxyConfig(t, c.hops, false)
		if got := clientIP(req(c.xff)); got != c.want {
			t.Errorf("hops=%d xff=%q: clientIP = %q, want %q", c.hops, c.xff, got, c.want)
		}
	}
}

// TestClientIPIgnoresForwardedHeadersFromAnUntrustedPeer keeps the outer gate
// pinned: a caller reaching the server directly from a public address has no
// proxy vouching for anything it sent.
func TestClientIPIgnoresForwardedHeadersFromAnUntrustedPeer(t *testing.T) {
	withProxyConfig(t, 2, true)
	r := req("9.9.9.9", "8.8.8.8")
	r.RemoteAddr = "198.51.100.9:5555" // public peer
	r.Header.Set("X-Real-IP", "9.9.9.9")
	if got := clientIP(r); got != "198.51.100.9" {
		t.Errorf("clientIP = %q, want the socket peer 198.51.100.9", got)
	}
}

// A private socket peer is not synonymous with our reverse proxy. Production
// runs on a shared RFC1918 bridge, so trusting the whole address class lets any
// neighbouring container choose its audit identity and a fresh limiter bucket.
func TestClientIPIgnoresForwardedHeadersFromUnlistedPrivatePeer(t *testing.T) {
	withProxyConfig(t, 2, true)
	r := req("9.9.9.9", "8.8.8.8")
	r.RemoteAddr = "10.0.6.99:5555"
	r.Header.Set("X-Real-IP", "9.9.9.9")
	if got := clientIP(r); got != "10.0.6.99" {
		t.Fatalf("clientIP = %q, want the unlisted private socket peer 10.0.6.99", got)
	}
	if ForwardedProtoHTTPS(r) {
		t.Fatal("an unlisted private peer was allowed to assert X-Forwarded-Proto")
	}
}

func TestConfiguredPrivateProxyMayForward(t *testing.T) {
	withProxyConfig(t, 1, false)
	if err := ConfigureTrustedProxyPeers("10.0.6.17/32"); err != nil {
		t.Fatal(err)
	}
	r := req("203.0.113.9")
	r.RemoteAddr = "10.0.6.17:5555"
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want forwarded client", got)
	}
	if !ForwardedProtoHTTPS(r) {
		t.Fatal("the explicitly configured proxy could not report HTTPS")
	}
}

func TestConfigureTrustedProxyPeersRejectsPartialMalformedSet(t *testing.T) {
	withProxyConfig(t, 1, false)
	before := append([]netip.Prefix(nil), trustedProxyPeers...)
	if err := ConfigureTrustedProxyPeers("10.0.6.17, definitely-not-an-ip"); err == nil {
		t.Fatal("malformed proxy set was accepted")
	}
	if !reflect.DeepEqual(trustedProxyPeers, before) {
		t.Fatalf("malformed proxy set partially applied: got %v want %v", trustedProxyPeers, before)
	}
}

func TestConfigureTrustedProxyPeersEmptyTrustsNobody(t *testing.T) {
	withProxyConfig(t, 1, false)
	if err := ConfigureTrustedProxyPeers(""); err != nil {
		t.Fatalf("configure empty proxy set: %v", err)
	}
	if len(trustedProxyPeers) != 0 {
		t.Fatalf("empty proxy set installed %v, want no trusted peers", trustedProxyPeers)
	}

	r := req("203.0.113.9")
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := clientIP(r); got != "127.0.0.1" {
		t.Fatalf("empty proxy set accepted X-Forwarded-For: got %q", got)
	}
	if ForwardedProtoHTTPS(r) {
		t.Fatal("empty proxy set accepted X-Forwarded-Proto")
	}
}

// TestForwardedProtoCannotBeAssertedByTheCaller covers the same defect on the
// other forwarded header.
//
// Three places decided "was this request HTTPS" with
// r.Header.Get("X-Forwarded-Proto") == "https": the HSTS header, the MCP
// endpoint scheme and the capability proxy base URL. That believed any caller on
// any connection, and read one line of a list.
func TestForwardedProtoCannotBeAssertedByTheCaller(t *testing.T) {
	t.Run("an untrusted peer cannot assert https", func(t *testing.T) {
		withProxyConfig(t, 2, false)
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "198.51.100.9:5555"
		r.Header.Set("X-Forwarded-Proto", "https")
		if ForwardedProtoHTTPS(r) {
			t.Error("a caller connecting directly over plaintext asserted https by sending a header")
		}
	})

	// THE MULTI-LINE CASES STATE A DELIBERATE CHOICE, so read the reasoning
	// before changing them to match whatever the code happens to do.
	//
	// These two subtests originally asserted the opposite: that the LAST entry
	// wins, on the reasoning that it is the one our own proxy wrote and so the
	// caller cannot choose it. That reading was abandoned for the leftmost one,
	// which is what the header actually means, the scheme the ORIGINAL client
	// used, and which matches how X-Forwarded-For is read two functions up.
	//
	// The choice is nearly moot in practice: nginx and Caddy both SET this
	// header rather than appending, so the real chain is length 1 and every
	// reading agrees. It matters only if some future hop appends, and there:
	//
	//   - leftmost reports the outermost proxy's record of the real client
	//     connection, which is the question being asked;
	//   - last reports the innermost hop's own scheme, plain http on the
	//     container network, which answers a question nobody asked.
	//
	// Leftmost can be pushed to "https" by a caller if an appending edge ever
	// preserves their line. That is the harmless direction: an HSTS header on a
	// plaintext response is required to be ignored (RFC 6797 §8.1), and the
	// https:// URL lands in the caller's own response body, it is not signed
	// into the capability token, not stored on the audit row, and not sent to
	// anyone else. Being wrong upward costs an ignored header; being wrong
	// downward strips real users' HSTS and puts capability tokens on port 80.
	t.Run("the leftmost entry is the original client's scheme", func(t *testing.T) {
		withProxyConfig(t, 1, false)
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header["X-Forwarded-Proto"] = []string{"https", "http"}
		if !ForwardedProtoHTTPS(r) {
			t.Error("the leftmost entry said https and was not believed")
		}
	})

	t.Run("an inner hop's own scheme does not override the client's", func(t *testing.T) {
		withProxyConfig(t, 1, false)
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		// The client reached the edge over plaintext; a later hop recording
		// "https" about some inner link must not turn that into a TLS session.
		r.Header["X-Forwarded-Proto"] = []string{"http", "https"}
		if ForwardedProtoHTTPS(r) {
			t.Error("an inner hop's scheme was reported as the client's transport")
		}
	})

	t.Run("real TLS needs no header", func(t *testing.T) {
		withProxyConfig(t, 0, false)
		r := httptest.NewRequest("GET", "/", nil)
		r.TLS = &tls.ConnectionState{}
		if !ForwardedProtoHTTPS(r) {
			t.Error("a genuine TLS connection was not recognised")
		}
	})
}

// TestForwardedChainDropsEmptyElements pins the flattener itself. An empty list
// element is not a hop (RFC 7230 §7 says recipients ignore them), and counting
// one would let padding shift the trusted-hop window.
func TestForwardedChainDropsEmptyElements(t *testing.T) {
	h := http.Header{}
	h["X-Forwarded-For"] = []string{" 9.9.9.9, ", "", "  203.0.113.7"}
	got := forwardedChain(h, "X-Forwarded-For")
	want := []string{"9.9.9.9", "203.0.113.7"}
	if len(got) != len(want) {
		t.Fatalf("forwardedChain = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("forwardedChain = %q, want %q", got, want)
		}
	}
	if n := forwardedChain(http.Header{}, "X-Forwarded-For"); n != nil {
		t.Errorf("an absent header gave %q, want nil", n)
	}
}

// TestForwardedProtoAtEveryHopCount is the test whose absence let a CRITICAL
// ship.
//
// The original suite asserted the positive X-Forwarded-Proto case only at
// hops=1, the package default. Production runs 2. Because X-Forwarded-Proto is
// SET by each hop rather than appended, its chain is always length 1, and the
// first implementation indexed it with the X-Forwarded-For hop count, so at
// hops=2 the index was -1 and the function returned false for every request the
// product served. No Strict-Transport-Security on a credential vault, and
// http:// capability URLs. A guard that only ever runs at the default cannot see
// a defect that only exists at the deployed value.
//
// So this runs the real production wire shape at every hop count an operator can
// configure. All of them must agree, because the chain does not change shape
// with the hop count.
func TestForwardedProtoAtEveryHopCount(t *testing.T) {
	for _, hops := range []int{0, 1, 2, 3} {
		withProxyConfig(t, hops, false)
		if err := ConfigureTrustedProxyPeers("10.0.6.1/32"); err != nil {
			t.Fatal(err)
		}

		// Exactly what the public path delivers: explicitly configured Caddy
		// peer, a two-entry XFF, and a ONE-entry XFP.
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.6.1:44444"
		r.Header.Set("X-Forwarded-For", "84.55.97.134, 10.0.6.1")
		r.Header.Set("X-Forwarded-Proto", "https")

		if !ForwardedProtoHTTPS(r) {
			t.Errorf("hops=%d: a real user's TLS session was read as plaintext. The "+
				"X-Forwarded-Proto chain is length 1 at every hop count because each proxy "+
				"SETS it; anything that indexes it by the XFF hop count is reading a position "+
				"that does not exist", hops)
		}
	}
}

// TestForwardedProtoIsNotIndexedByTheHopCount states the property directly, so a
// future change that reintroduces hop arithmetic on this header fails here with
// the reason rather than somewhere downstream with a missing header.
func TestForwardedProtoIsNotIndexedByTheHopCount(t *testing.T) {
	answers := map[bool]int{}
	for _, hops := range []int{0, 1, 2, 3, 4, 9} {
		withProxyConfig(t, hops, false)
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("X-Forwarded-Proto", "https")
		answers[ForwardedProtoHTTPS(r)]++
	}
	if len(answers) != 1 {
		t.Errorf("the same request got different answers at different hop counts (%v). "+
			"X-Forwarded-Proto is set, not appended, so the trusted-hop count is not a "+
			"position in it and must not change the result", answers)
	}
}

// TestClientIPRejectsAValueThatIsNotAnIP proves the value check the parseIP
// allowlist row claims. The selected chain element is caller-influenced text and
// lands verbatim in append-only audit columns and a slog attribute, so anything
// that is not an IP must fall back to the socket peer.
func TestClientIPRejectsAValueThatIsNotAnIP(t *testing.T) {
	withProxyConfig(t, 1, false)
	for _, bad := range []string{
		"unknown", "_hidden", "evil.example.com", "9.9.9.9:1234",
		"10.0.0.1\nlevel=INFO msg=\"forged\"", strings.Repeat("A", 300),
	} {
		r := req(bad)
		if got := clientIP(r); got != "127.0.0.1" {
			t.Errorf("clientIP returned %q for a non-IP chain element; it should have fallen "+
				"back to the socket peer", got)
		}
	}
	// A real IP still comes through.
	if got := clientIP(req("203.0.113.7")); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want 203.0.113.7", got)
	}
}

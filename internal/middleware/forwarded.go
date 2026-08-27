package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// A FORWARDING HEADER IS A LIST, AND http.Header.Get RETURNS ONE LINE OF IT.
//
// Go stores repeated headers as a slice: two `X-Forwarded-For:` lines on the
// wire become Header["X-Forwarded-For"] = ["9.9.9.9", "203.0.113.7"], and
// Header.Get returns element 0 and silently discards the rest. Every
// list-valued header in RFC 7230 §3.2.2 may legally arrive either as one
// comma-joined line or as several lines, and the sender chooses which.
//
// That made clientIP's trusted-hop arithmetic defeatable. It counts hops from
// the RIGHT of the chain precisely so that entries an attacker prepends land
// left of the index and are ignored. But when the chain arrives as multiple
// lines, Get hands it only the FIRST line, which is exactly the part the
// attacker wrote; the proxy's own appended line is in the part that was thrown
// away. With TRUSTISSUES_TRUSTED_PROXY_HOPS=2 (the production value) a request
// carrying `X-Forwarded-For: 9.9.9.9, 8.8.8.8` reaching a proxy that appends a
// separate line resolves to 8.8.8.8, a caller-chosen value, which resets
// their own rate-limit bucket and writes a forged source IP into every audit
// row. See TestClientIPIgnoresAttackerControlledChain.
//
// So the chain is read with Values (every line) and flattened. Both spellings
// of the same chain must produce the same answer, because on the wire they ARE
// the same chain: that equivalence is what forwardedChain exists to restore,
// and what the guard in forwarded_test.go pins.
func forwardedChain(h http.Header, name string) []string {
	lines := h.Values(name)
	if len(lines) == 0 {
		return nil
	}
	// Pre-size for the common single-line, single-element case.
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		for _, part := range strings.Split(line, ",") {
			// An empty list element is not a hop. RFC 7230 §7 says senders
			// should not emit them and recipients must ignore them; dropping
			// them here keeps the index arithmetic counting real hops only,
			// rather than letting padding shift the window.
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// peerIsConfiguredProxy reports the direct socket peer's IP and whether it is
// in the operator's explicit proxy set. A private address is not sufficient:
// production container bridges are shared with unrelated workloads, and any
// peer we trust here can choose rate-limit and audit identities through XFF.
func peerIsConfiguredProxy(r *http.Request) (remoteIP string, trusted bool) {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}
	parsed, err := netip.ParseAddr(strings.Trim(remoteIP, "[]"))
	if err != nil || parsed.Zone() != "" {
		return remoteIP, false
	}
	parsed = parsed.Unmap()
	for _, prefix := range trustedProxyPeers {
		if prefix.Contains(parsed) {
			return remoteIP, true
		}
	}
	return remoteIP, false
}

// peerIsTrustedProxy is explicit peer trust AND a positive hop count: the gate
// for reading X-Forwarded-For, where the hop count makes the index meaningful.
func peerIsTrustedProxy(r *http.Request) (remoteIP string, trusted bool) {
	remoteIP, configured := peerIsConfiguredProxy(r)
	return remoteIP, trustedProxyHops > 0 && configured
}

// ForwardedProtoHTTPS reports whether the ORIGINAL client reached the edge over
// TLS, according to the trusted proxy chain.
//
// X-FORWARDED-PROTO IS SET BY EACH HOP, NOT APPENDED, SO IT IS NOT INDEXED LIKE
// X-FORWARDED-FOR.
//
// The first version of this function assumed the two headers were built the same
// way and pulled the entry at len(chain)-trustedProxyHops. They are not built the
// same way, and the assumption disabled the function completely in production:
//
//   - nginx emits `proxy_set_header X-Forwarded-Proto $scheme`, a SET. nginx has
//     no $proxy_add_x_forwarded_proto variable at all, so it cannot append this
//     header even if someone wanted it to.
//   - Caddy's reverse_proxy resolves the value (honouring the incoming one when
//     the peer is in trusted_proxies) and calls Header.Set.
//
// So X-Forwarded-For arrives with 2+ entries while X-Forwarded-Proto arrives with
// exactly ONE, on every ingress. With TRUSTED_PROXY_HOPS=2 the old index was
// 1-2 = -1, out of range, and this returned false for every request the product
// has ever served, no Strict-Transport-Security on a credential vault, and
// http:// capability URLs. The header a real user's TLS session produced was
// discarded because it was read at a position derived from a different header.
//
// The correct read is the LEFTMOST element, which is what the header means: the
// scheme the ORIGINAL client used to reach the edge. In the set-semantics regime
// that both proxies actually implement the chain is length 1 and every reading
// agrees, so this choice only matters if some future hop appends. There the
// leftmost entry is the outermost proxy's record of the real client connection,
// while the last entry would be the innermost hop's own scheme, plain http on
// the container network, which would answer "was the client on TLS" with the
// state of a link the client never touched.
//
// Leftmost also fails in the harmless direction. A wrong "https" costs an HSTS
// header on a plaintext response, which RFC 6797 §8.1 requires user agents to
// ignore, and an https:// URL in the caller's own response body. A wrong "http"
// strips the HSTS pin from real users and puts capability tokens on port 80.
// Given a choice of which way to be wrong, be wrong upward.
//
// Gated on peerIsConfiguredProxy rather than peerIsTrustedProxy: a caller reaching the
// port directly from a public address still cannot assert its own transport
// security, but an operator running with TRUSTED_PROXY_HOPS=0 behind a
// TLS-terminating proxy keeps working.
func ForwardedProtoHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// The private listener has an explicit HTTPS origin in configuration and is
	// reachable only through the application-owned Unix socket. Its local proxy
	// hop is plaintext HTTP by design, so neither r.TLS nor a TCP peer exists at
	// this boundary. Treat the listener stamp as the transport contract instead
	// of trusting an X-Forwarded-Proto header from request data. This preserves
	// HSTS and keeps minted capability/MCP URLs on https for private users.
	if IsPrivateIngress(r.Context()) {
		return true
	}
	if _, trusted := peerIsConfiguredProxy(r); !trusted {
		return false
	}
	chain := forwardedChain(r.Header, "X-Forwarded-Proto")
	if len(chain) == 0 {
		return false
	}
	return strings.EqualFold(chain[0], "https")
}

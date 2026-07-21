package handlers

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// hardenedOutboundClient returns the ONE blessed http.Client for every
// SERVER-ORIGINATED outbound call in the vault/rotation subsystem: provider API
// calls, rotation delivery to a user-set webhook_url, and verify probes. Those
// calls carry freshly-rotated CLEARTEXT secrets, so a bare &http.Client{}
// pointed (via a user URL or a redirect) at 169.254.169.254 / an internal host
// would exfiltrate them.
//
// It (1) refuses to follow redirects, so a public URL that 3xx-redirects to a
// private/metadata host cannot leak the payload, and (2) re-checks the RESOLVED
// IP at DIAL time via a Dialer.Control hook (not just at config time), defeating
// a DNS-rebinding domain that flips to a private address after a set-time check.
// Mirrors internal/alerts/channels.go, the estate's blessed egress shape.
// allowPrivateOutbound disables the private-IP dial guard. It is false in
// production and set true ONLY by tests, which must reach httptest loopback
// servers. Never flip it outside a test.
var allowPrivateOutbound = false

func hardenedOutboundClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
				Control: func(_, address string, _ syscall.RawConn) error {
					host, _, err := net.SplitHostPort(address)
					if err != nil {
						return err
					}
					if ip := net.ParseIP(host); ip != nil && !allowPrivateOutbound && isPrivateIP(ip) {
						return fmt.Errorf("blocked outbound to private address %s", address)
					}
					return nil
				},
			}).DialContext,
		},
	}
}

// isPrivateIP returns true if the IP is in a private, loopback, link-local,
// or otherwise non-routable range. (Copied from dockyard's servers.go; lives
// here because Trustissues has no server-agent surface.)
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // Link-local
		"0.0.0.0/8",      // Current network
		"100.64.0.0/10",  // Shared address space (CGNAT/Tailscale)
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

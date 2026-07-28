package handlers

import (
	"fmt"
	"net"
	"strings"
)

// maxDestinationPatterns bounds the ceiling so one entry cannot become an
// allow-everything list by accretion.
const maxDestinationPatterns = 20

// ValidateDestinationPatterns checks an operator-supplied capability ceiling.
//
// This is the list that decides where a minted capability token may send the
// secret, so a permissive entry here is the whole security boundary. The rules
// exist because each one was a way to write a pattern that looks like a
// restriction and is not:
//
//   - a bare "*" or "*/..." allows every host on the internet
//   - a wildcard anywhere in the HOST allows every sibling on a shared,
//     registrable suffix (the "*.supabase.co" class: anyone can register
//     attacker.supabase.co). Tenant scoping is done by the preset placeholders,
//     not by user-supplied wildcards.
//   - a scheme or userinfo means the caller is pasting a URL, and "https://x"
//     would be matched as a host literally named "https:" that never matches
//   - a private, loopback or link-local host turns the proxy into an SSRF tool
//     pointed at the operator's own network
//
// A path glob is allowed and encouraged ("api.example.com/v1/*"); narrowing the
// path is the main way an operator tightens a ceiling.
func ValidateDestinationPatterns(patterns []string) error {
	if len(patterns) > maxDestinationPatterns {
		return fmt.Errorf("at most %d destination patterns", maxDestinationPatterns)
	}
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			return fmt.Errorf("destination pattern must not be empty")
		}
		if strings.Contains(p, "://") || strings.Contains(p, "@") {
			return fmt.Errorf("destination %q must be host/path, not a URL (drop the scheme and any credentials)", raw)
		}
		if strings.ContainsAny(p, " \t\\") {
			return fmt.Errorf("destination %q must not contain spaces or backslashes", raw)
		}

		host := p
		if i := strings.Index(p, "/"); i >= 0 {
			host = p[:i]
		}
		if host == "" {
			return fmt.Errorf("destination %q has no host", raw)
		}
		if strings.Contains(host, "*") {
			return fmt.Errorf("destination %q wildcards the host; that allows every sibling domain on that suffix. "+
				"Name the exact host and narrow with a path glob instead, e.g. api.example.com/v1/*", raw)
		}
		// Strip an explicit port before the IP/hostname checks.
		hostOnly := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			hostOnly = h
		}
		if strings.EqualFold(hostOnly, "localhost") {
			return fmt.Errorf("destination %q points at this machine; the capability proxy must not be aimed inside your own network", raw)
		}
		if ip := net.ParseIP(hostOnly); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				return fmt.Errorf("destination %q is a private or loopback address; the capability proxy must not be aimed inside your own network", raw)
			}
		}
		if !strings.Contains(hostOnly, ".") {
			return fmt.Errorf("destination %q is not a fully qualified host", raw)
		}
	}
	return nil
}

// NormalizeDestinationPatterns trims and de-duplicates while preserving order.
// Call it after validation.
func NormalizeDestinationPatterns(patterns []string) []string {
	seen := make(map[string]bool, len(patterns))
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

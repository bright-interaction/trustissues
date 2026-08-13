package handlers

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/bright-interaction/trustissues/internal/alerts"
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
		// Strip an explicit port and any IPv6 brackets before the IP/hostname
		// checks, so every encoding of the same literal reaches the same parser.
		hostOnly := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			hostOnly = h
		}
		hostOnly = trimIPv6Brackets(hostOnly)
		if strings.EqualFold(hostOnly, "localhost") {
			return fmt.Errorf("destination %q points at this machine; the capability proxy must not be aimed inside your own network", raw)
		}
		if err := rejectNonPublicDestinationHost(hostOnly, raw); err != nil {
			return err
		}
		if !strings.Contains(hostOnly, ".") {
			return fmt.Errorf("destination %q is not a fully qualified host", raw)
		}
	}
	return nil
}

// trimIPv6Brackets removes the URL-authority brackets around an IPv6 literal.
// net.SplitHostPort only strips them when a port is present, so "[::1]" with no
// port arrives here still bracketed, and a bracketed literal parses as nothing
// at all. That mattered: "[::ffff:127.0.0.1]/v1/*" carries the dot the trailing
// FQDN check wants, so an unparsed bracketed literal was accepted as if it were
// a hostname.
func trimIPv6Brackets(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// rejectNonPublicDestinationHost refuses a destination host that is an IP
// literal pointing inside the operator's own network.
//
// It used to read, inline:
//
//	if ip := net.ParseIP(hostOnly); ip != nil {
//	    if ip.IsLoopback() || ip.IsPrivate() || ... { reject }
//	}
//
// which is the fail-OPEN shape. net.ParseIP does not accept an IPv6 zone id, so
// it returned nil for anything carrying one and the whole private-address test
// was SKIPPED rather than failed. The "::ffff:" prefix then supplied the dot the
// trailing FQDN check wants, so these were all stored as a ceiling:
//
//	::ffff:169.254.169.254%1/latest/*   the cloud metadata endpoint
//	::ffff:10.0.0.5%1/v1/*
//	[::ffff:127.0.0.1%251]/v1/*
//
// while the plain "127.0.0.1/v1/*" was refused. netip.ParseAddr parses zones, so
// a zoned literal now reaches the classifier instead of vanishing before it.
//
// Unlike the dial-time guard this one cannot fail closed on a parse failure: a
// destination pattern is USUALLY a hostname, and refusing everything that is not
// an IP literal would refuse every legitimate ceiling. The boundary that binds
// is still alerts.guardDialAddress, which sees the resolved address; this is the
// write-time layer that stops an operator storing a ceiling that is obviously
// pointed inward.
func rejectNonPublicDestinationHost(hostOnly, raw string) error {
	addr, err := netip.ParseAddr(hostOnly)
	if err != nil {
		// Not an IP literal in any encoding, including zoned and bracketed
		// ones. It is a name, and where a name resolves to is the dial guard's
		// question, not this one's.
		return nil
	}
	// A zone id names a local interface. It is never needed to reach a public
	// host, it defeats range matching outright (::1%1 is not inside ::1/128 as
	// far as any parser is concerned), and it is exactly what walked through the
	// old check. Its presence alone disqualifies.
	if addr.Zone() != "" {
		return fmt.Errorf("destination %q carries an IPv6 zone id, which names a local interface; the capability proxy must not be aimed inside your own network", raw)
	}
	// Unmap first so ::ffff:127.0.0.1 and ::ffff:7f00:1 are classified as the
	// IPv4 loopback they actually route to. alerts.IsNonPublicAddr is the one
	// range table in this module; see its comment for why this is shared rather
	// than restated here.
	if alerts.IsNonPublicAddr(addr.Unmap()) {
		return fmt.Errorf("destination %q is a private or loopback address; the capability proxy must not be aimed inside your own network", raw)
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

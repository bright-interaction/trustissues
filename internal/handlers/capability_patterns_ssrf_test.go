package handlers

import (
	"fmt"
	"strings"
	"testing"
)

// The P0-4 fix hardened the DIALER and left the twin USE of the same fail-open
// primitive in place. ValidateDestinationPatterns read
//
//	if ip := net.ParseIP(hostOnly); ip != nil { if isPrivate(ip) { reject } }
//
// and net.ParseIP does not accept an IPv6 zone id, so a "%1" made it return nil
// and SKIPPED the private-address test entirely, while the "::ffff:" prefix
// supplied the dot the trailing FQDN check wants. The cloud metadata endpoint
// was storable as a capability ceiling:
//
//	::ffff:169.254.169.254%1/latest/*  ACCEPTED
//	::ffff:169.254.169.254/latest/*    blocked
//	127.0.0.1/v1/*                     blocked
//
// These tests pin the INVARIANT (no encoding of a non-routable address is
// accepted as a ceiling) rather than the shape of the check, because the
// original ablation for this class of bug is "delete the call" and the check
// survives that ablation while still being wrong. Every assertion below goes
// through the exported ValidateDestinationPatterns, so making the predicate a
// NO-OP fails it just as loudly as deleting it does.

// nonRoutableDestinationEncodings is one address family per group, spelled every
// way a URL authority can spell it. The point is that the list has many rows and
// ONE rule: if it resolves inside the operator's network, in any encoding, it is
// not a ceiling.
var nonRoutableDestinationEncodings = []struct {
	name    string
	pattern string
}{
	// Plain literals. These were already refused; they are the control group
	// that proves the validator is reachable at all.
	{"ipv4 loopback", "127.0.0.1/v1/*"},
	{"ipv4 private 10", "10.0.0.5/v1/*"},
	{"ipv4 private 192", "192.168.1.10/v1/*"},
	{"ipv4 private 172", "172.16.0.1/v1/*"},
	{"ipv4 link local metadata", "169.254.169.254/latest/*"},
	{"ipv4 unspecified", "0.0.0.0/v1/*"},
	{"cgnat tailscale space", "100.64.0.1/v1/*"},

	// IPv4-mapped IPv6. The "::ffff:" prefix is what smuggled a dot past the
	// FQDN check, so every one of these looked fully qualified.
	{"mapped loopback", "::ffff:127.0.0.1/v1/*"},
	{"mapped metadata", "::ffff:169.254.169.254/latest/*"},
	{"mapped private", "::ffff:10.0.0.5/v1/*"},

	// The proven bypasses: a zone id defeats net.ParseIP outright.
	{"zoned mapped metadata", "::ffff:169.254.169.254%1/latest/*"},
	{"zoned mapped private", "::ffff:10.0.0.5%1/v1/*"},
	{"zoned mapped loopback", "::ffff:127.0.0.1%1/v1/*"},
	{"named zone mapped metadata", "::ffff:169.254.169.254%eth0/latest/*"},

	// Bracketed, with and without the URL percent-encoding of "%".
	// net.SplitHostPort only unwraps brackets when a port is present, so these
	// arrived at the parser still bracketed and parsed as nothing at all.
	{"bracketed mapped loopback", "[::ffff:127.0.0.1]/v1/*"},
	{"bracketed zoned mapped loopback", "[::ffff:127.0.0.1%251]/v1/*"},
	{"bracketed zoned mapped metadata", "[::ffff:169.254.169.254%251]/latest/*"},
	{"bracketed mapped metadata with port", "[::ffff:169.254.169.254]:80/latest/*"},

	// Native IPv6, bracketed so the FQDN check is not what does the work.
	{"bracketed ipv6 loopback with port", "[::1]:8080/v1/*"},
	{"bracketed ipv6 ula with port", "[fd00::1]:8080/v1/*"},
	{"bracketed ipv6 link local with port", "[fe80::1]:8080/v1/*"},
	{"bracketed zoned ipv6 loopback with port", "[::1%251]:8080/v1/*"},

	// Hex spelling of the same loopback.
	{"mapped loopback hex", "[::ffff:7f00:1]:80/v1/*"},
}

// TestDestinationCeilingRefusesEveryNonRoutableEncoding is the repro for the
// P0-4 twin.
//
// It deliberately asserts on BEHAVIOUR through the exported entry point rather
// than on the presence of a call, because the structural half of the original
// P0-4 test (TestEveryDialControlFailsClosed in internal/alerts) is scoped to
// net.Dialer Control hooks and is therefore blind to every other use of the same
// primitive. That blind spot is what left this site alive after the dialer was
// fixed. A guard that watches one call SITE cannot see the next one; a test that
// watches the PROPERTY can.
func TestDestinationCeilingRefusesEveryNonRoutableEncoding(t *testing.T) {
	for _, tc := range nonRoutableDestinationEncodings {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDestinationPatterns([]string{tc.pattern})
			if err == nil {
				t.Fatalf("ceiling %q was ACCEPTED. That pattern names an address inside the "+
					"operator's own network, so the capability proxy would carry a minted token's "+
					"secret to it. Every encoding of a non-routable address must be refused, not "+
					"just the ones net.ParseIP happens to parse.", tc.pattern)
			}
		})
	}
}

// TestDestinationCeilingStillAcceptsRealDestinations is the positive control. A
// validator that refuses everything passes the test above and ships an outage,
// and "reject on any parse failure" is exactly the wrong fix here: a ceiling is
// USUALLY a hostname, and where a hostname resolves is the dial guard's
// question, not this one's.
func TestDestinationCeilingStillAcceptsRealDestinations(t *testing.T) {
	allowed := []string{
		"api.openai.com/*",
		"api.example.com/v1/chat/*",
		"abcdefgh.supabase.co/*",
		"api.example.com:8443/v1/*",
		"sentry.io/api/*",
		// Public unicast literals. The guard classifies, it does not blanket-ban
		// IP literals.
		"8.8.8.8/v1/*",
		"1.1.1.1/*",
		"93.184.216.34/v1/*",
	}
	for _, p := range allowed {
		if err := ValidateDestinationPatterns([]string{p}); err != nil {
			t.Errorf("legitimate ceiling %q was rejected: %v", p, err)
		}
	}
}

// TestDestinationCeilingZoneIsRefusedOnItsOwn pins the specific sub-property
// that the zone id alone disqualifies, independent of what the address is.
//
// Without this a future "simplification" could drop the explicit Zone() check
// and stay green on the table above, since every entry there is ALSO
// non-routable once unmapped. A zone id names a local interface; it is never
// needed to reach a public host and it defeats prefix matching outright, so a
// zoned PUBLIC address must be refused too.
func TestDestinationCeilingZoneIsRefusedOnItsOwn(t *testing.T) {
	zonedPublic := []string{
		"::ffff:8.8.8.8%1/v1/*",
		"::ffff:1.1.1.1%eth0/v1/*",
		"[::ffff:93.184.216.34%251]/v1/*",
	}
	for _, p := range zonedPublic {
		err := ValidateDestinationPatterns([]string{p})
		if err == nil {
			t.Errorf("ceiling %q was ACCEPTED. The address is public but it carries an IPv6 zone "+
				"id, which names a local interface and defeats every prefix match. The zone alone "+
				"must disqualify, or the range table is decorative.", p)
			continue
		}
		if !strings.Contains(err.Error(), "zone") {
			t.Errorf("ceiling %q was refused for the wrong reason (%v); the operator needs to be "+
				"told it was the zone id", p, err)
		}
	}
}

// TestDestinationCeilingAgreesAcrossEncodingsOfOneAddress is the anti-drift
// assertion: the same address written four ways must get four identical
// verdicts. Before the fix these disagreed, which is the only reason the bypass
// existed at all.
func TestDestinationCeilingAgreesAcrossEncodingsOfOneAddress(t *testing.T) {
	groups := map[string][]string{
		"metadata endpoint": {
			"169.254.169.254/latest/*",
			"::ffff:169.254.169.254/latest/*",
			"::ffff:169.254.169.254%1/latest/*",
			"[::ffff:169.254.169.254%251]/latest/*",
			"[::ffff:169.254.169.254]:80/latest/*",
		},
		"ipv4 loopback": {
			"127.0.0.1/v1/*",
			"::ffff:127.0.0.1/v1/*",
			"::ffff:127.0.0.1%1/v1/*",
			"[::ffff:127.0.0.1%251]/v1/*",
			"[::ffff:7f00:1]:80/v1/*",
		},
	}
	for name, encodings := range groups {
		t.Run(name, func(t *testing.T) {
			var verdicts []string
			for _, p := range encodings {
				v := "ACCEPTED"
				if ValidateDestinationPatterns([]string{p}) != nil {
					v = "refused"
				}
				verdicts = append(verdicts, fmt.Sprintf("%s -> %s", p, v))
				if v == "ACCEPTED" {
					t.Errorf("%s: encodings of the same address disagree, and %q is the one that "+
						"got through:\n  %s", name, p, strings.Join(verdicts, "\n  "))
				}
			}
		})
	}
}

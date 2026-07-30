package handlers

import "testing"

// A host-wildcarded destination is REFUSED at match time.
//
// This test asserted the opposite, and the inversion is deliberate rather than a
// convenience. It was written when the grafana, auth0 and supabase presets shipped
// bare "*." hosts, and destMatches carried a leadingWildcardMatch helper so those
// presets would work. The provider code has since moved to tenant placeholders,
// "{instance}.grafana.net/*", "{tenant}.auth0.com/*", "{project_ref}.supabase.co/*",
// expanded at seed time into a single concrete host, and capability_providers.go now
// argues against the old shape in as many words:
//
//	a preset of "*.supabase.co/*" is not a ceiling at all: anyone can register
//	attacker.supabase.co ... and a capability token minted for one tenant's key
//	would happily send it there
//
// ValidateDestinationPatterns agrees and rejects any "*" in a host on write. The MATCHER did
// not, so a stored row carrying "*.supabase.co/*" (an older binary, a hand edit, a
// restore from an old backup) was still enforced as a valid ceiling even though the
// product would refuse to save it today, and nothing normalised existing rows.
//
// Refusing at match time is what closes that, because a validator only guards new
// writes. So this file now pins the AGREEMENT between the two rather than the
// divergence, and the non-wildcard cases still confirm the delegation to the audited
// package matcher is intact.
func TestDestMatchesRefusesWildcardHosts(t *testing.T) {
	grafana := []string{"*.grafana.net/*"}
	auth0 := []string{"*.auth0.com/*"}
	supabase := []string{"*.supabase.co/*"}

	cases := []struct {
		name  string
		dests []string
		host  string
		path  string
		want  bool
	}{
		// The whole point: a wildcard host grants provider-wide reach into a domain
		// space an attacker can join, so it authorises nothing at all.
		{"grafana subdomain refused", grafana, "stack.grafana.net", "/api/dashboards", false},
		{"grafana nested subdomain refused", grafana, "eu.stack.grafana.net", "/api", false},
		{"auth0 tenant refused", auth0, "acme.auth0.com", "/oauth/token", false},
		{"supabase project refused", supabase, "abcdefgh.supabase.co", "/rest/v1/rpc", false},

		// These were already rejected and must stay rejected.
		{"grafana apex refused", grafana, "grafana.net", "/api", false},
		{"grafana sibling suffix refused", grafana, "notgrafana.net", "/api", false},
		{"grafana suffix-in-host refused", grafana, "grafana.net.evil.com", "/api", false},
		{"supabase impostor refused", supabase, "supabase.co.attacker.dev", "/x", false},

		// A wildcard entry must not poison a list that also holds a valid one: the
		// concrete pattern still works and the wildcard is simply ignored.
		{"valid pattern beside a wildcard still matches",
			[]string{"*.grafana.net/*", "api.cloudflare.com/*"}, "api.cloudflare.com", "/v4/zones", true},
		{"wildcard beside a valid pattern grants nothing extra",
			[]string{"*.grafana.net/*", "api.cloudflare.com/*"}, "stack.grafana.net", "/api", false},

		// The expanded, concrete form of those same presets is what production stores
		// now, and it must keep working.
		{"expanded grafana host matches", []string{"stack.grafana.net/*"}, "stack.grafana.net", "/api", true},
		{"expanded supabase host matches", []string{"abc.supabase.co/*"}, "abc.supabase.co", "/rest/v1", true},
		{"expanded host does not cover a sibling", []string{"stack.grafana.net/*"}, "other.grafana.net", "/api", false},

		// Non-wildcard delegation to the audited package matcher, unchanged.
		{"exact trailing glob matches", []string{"api.cloudflare.com/*"}, "api.cloudflare.com", "/v4/zones", true},
		{"exact host mismatch refused", []string{"api.cloudflare.com/*"}, "api.openai.com", "/v1", false},
		{"path glob is still a glob", []string{"api.example.com/v1/*"}, "api.example.com", "/v1/things", true},
		{"path outside the glob refused", []string{"api.example.com/v1/*"}, "api.example.com", "/v2/things", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := destMatches(tc.dests, tc.host, tc.path); got != tc.want {
				t.Errorf("destMatches(%v, %q, %q) = %v, want %v", tc.dests, tc.host, tc.path, got, tc.want)
			}
		})
	}
}

// TestMatcherAndValidatorAgreeOnWildcardHosts states the invariant directly, so the
// two cannot drift apart again without something going red.
//
// A pattern the validator refuses to STORE must not be honoured when MATCHING. The
// previous divergence stayed invisible precisely because each side had its own test
// and nothing compared them.
func TestMatcherAndValidatorAgreeOnWildcardHosts(t *testing.T) {
	checked := 0
	for _, c := range []struct{ pat, host, path string }{
		{"*.grafana.net/*", "sub.grafana.net", "/api"},
		{"*.auth0.com/*", "sub.auth0.com", "/api"},
		{"*.supabase.co/*", "sub.supabase.co", "/api"},
		{"*.example.com/*", "sub.example.com", "/x"},
		{"a.*.example.com/*", "a.b.example.com", "/x"},
	} {
		checked++
		refusedOnWrite := ValidateDestinationPatterns([]string{c.pat}) != nil
		honouredOnMatch := destMatches([]string{c.pat}, c.host, c.path)
		if refusedOnWrite && honouredOnMatch {
			t.Errorf("ValidateDestinationPatterns REFUSES %q but destMatches honours it against %s%s.\n"+
				"A stored row carrying it would be enforced as a valid ceiling that the product "+
				"would not let anyone create today.", c.pat, c.host, c.path)
		}
		if !refusedOnWrite {
			t.Errorf("ValidateDestinationPatterns now ACCEPTS the host-wildcarded %q; if that is "+
				"intentional this whole file needs revisiting, because the matcher refuses it", c.pat)
		}
	}
	if checked < 5 {
		t.Fatalf("ABORT: only %d patterns checked; this invariant is not being exercised", checked)
	}
}

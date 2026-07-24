package handlers

import "testing"

// TestDestMatchesLeadingWildcard covers the leading "*." host-wildcard presets
// (grafana / auth0 / supabase) that capability.DestMatches alone cannot match,
// plus a couple of non-wildcard cases to confirm the delegation to the audited
// package matcher is intact. The wildcard must accept real subdomains while
// rejecting the apex and any sibling-suffix impostor.
func TestDestMatchesLeadingWildcard(t *testing.T) {
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
		{"grafana subdomain matches", grafana, "stack.grafana.net", "/api/dashboards", true},
		{"grafana nested subdomain matches", grafana, "eu.stack.grafana.net", "/api", true},
		{"grafana host-only matches", grafana, "stack.grafana.net", "", true},
		{"grafana case-insensitive matches", grafana, "Stack.Grafana.NET", "/API", true},
		{"grafana apex rejected", grafana, "grafana.net", "/api", false},
		{"grafana sibling suffix rejected", grafana, "notgrafana.net", "/api", false},
		{"grafana suffix-in-host rejected", grafana, "grafana.net.evil.com", "/api", false},
		{"auth0 tenant matches", auth0, "acme.auth0.com", "/oauth/token", true},
		{"auth0 apex rejected", auth0, "auth0.com", "/oauth/token", false},
		{"supabase project matches", supabase, "abcdefgh.supabase.co", "/rest/v1/rpc", true},
		{"supabase impostor rejected", supabase, "supabase.co.attacker.dev", "/x", false},

		// Non-wildcard presets still delegate to capability.DestMatches.
		{"exact trailing glob matches", []string{"api.cloudflare.com/*"}, "api.cloudflare.com", "/v4/zones", true},
		{"exact host mismatch rejected", []string{"api.cloudflare.com/*"}, "api.openai.com", "/v1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := destMatches(tc.dests, tc.host, tc.path); got != tc.want {
				t.Errorf("destMatches(%v, %q, %q) = %v, want %v", tc.dests, tc.host, tc.path, got, tc.want)
			}
		})
	}
}

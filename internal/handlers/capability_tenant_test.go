package handlers

import (
	"strings"
	"testing"
)

// TestNoPresetShipsARegistrableWildcardCeiling locks the fix for ceilings that
// were not ceilings.
//
// Three presets shipped a leading host wildcard on a SHARED, REGISTRABLE suffix:
// "*.supabase.co/*", "*.auth0.com/*", "*.grafana.net/*". Anyone can create
// attacker.supabase.co, so a capability token minted for one tenant's key could
// be sent straight to an attacker's project on the same suffix. The pattern read
// like a restriction while granting reach over a domain space the attacker can
// join at will, and the owner had no way to narrow it.
//
// The invariant: a preset may pin a concrete host, or name a {tenant}
// placeholder expanded from the entry's own provider_meta, but never a bare
// wildcard label.
func TestNoPresetShipsARegistrableWildcardCeiling(t *testing.T) {
	if len(CapabilityDefaults) == 0 {
		t.Fatal("ABORT: no presets loaded, this test would pass vacuously")
	}
	for provider, def := range CapabilityDefaults {
		for _, pattern := range def.Destinations {
			if strings.HasPrefix(pattern, "*.") || strings.HasPrefix(pattern, "*") {
				t.Errorf("provider %q ships wildcard ceiling %q: any tenant on that suffix can receive the secret. "+
					"Use a {meta_key} placeholder resolved from the entry's provider_meta instead", provider, pattern)
			}
			// A wildcard anywhere in the HOST portion is the same problem.
			host := pattern
			if i := strings.Index(pattern, "/"); i >= 0 {
				host = pattern[:i]
			}
			if strings.Contains(host, "*") {
				t.Errorf("provider %q has a wildcard in the host of %q", provider, pattern)
			}
		}
	}
}

// TestTenantExpansionFailsClosed proves the placeholder resolves to a single
// concrete host when the tenant is known, and to NOTHING when it is not.
//
// Falling back to the old wildcard on missing data would be a security default
// that degrades to "allow", which is not a default at all. Seeding no ceiling
// makes the bridge refuse to mint, which is a visible and fixable error.
func TestTenantExpansionFailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		meta     map[string]string
		want     string
	}{
		{"supabase with project_ref", "supabase", map[string]string{"project_ref": "abcdefgh"}, `["abcdefgh.supabase.co/*"]`},
		{"auth0 with tenant", "auth0", map[string]string{"tenant": "acme"}, `["acme.auth0.com/*"]`},
		{"grafana with instance", "grafana", map[string]string{"instance": "acmeco"}, `["acmeco.grafana.net/*"]`},
		{"supabase without project_ref", "supabase", nil, ""},
		{"auth0 with empty tenant", "auth0", map[string]string{"tenant": "   "}, ""},
		{"non-tenant provider is untouched", "openai", nil, `["api.openai.com/*"]`},
	}
	for _, tc := range cases {
		dests, inj := MarshalCapabilityDefaults(tc.provider, tc.meta)
		if dests != tc.want {
			t.Errorf("%s: dests = %q, want %q", tc.name, dests, tc.want)
		}
		// The injection spec should survive either way: it is not a ceiling.
		if inj == "" {
			t.Errorf("%s: injection spec was dropped", tc.name)
		}
	}
}

// TestTenantValueCannotWidenThePattern guards the substitution itself. A tenant
// value carrying a dot, a slash or a star would let a malicious or careless
// provider_meta escape the intended host.
func TestTenantValueCannotWidenThePattern(t *testing.T) {
	hostile := []string{
		"evil.com",              // a dot escapes the label
		"a/../..",               // path traversal
		"*",                     // the wildcard we just removed
		"x.supabase.co/../y",    // both
		"a b",                   // whitespace
		"a\tb",                  // control whitespace
		"a@b",                   // URL userinfo delimiter
		"a:443",                 // port
		`a\b`,                   // backslash
		"-leading",              // not a DNS label
		"trailing-",             // not a DNS label
		strings.Repeat("a", 64), // DNS labels are at most 63 bytes
	}
	for _, v := range hostile {
		got := ExpandCapabilityDestinations([]string{"{project_ref}.supabase.co/*"}, map[string]string{"project_ref": v})
		if got != nil {
			t.Errorf("tenant value %q was accepted and produced %v; it must fail closed", v, got)
		}
	}

	// A normal label still works, including digits and hyphens.
	for _, v := range []string{"abcdefgh", "my-project-1", "A1"} {
		got := ExpandCapabilityDestinations([]string{"{project_ref}.supabase.co/*"}, map[string]string{"project_ref": v})
		if len(got) != 1 || got[0] != v+".supabase.co/*" {
			t.Errorf("legitimate tenant %q did not expand: %v", v, got)
		}
	}
}

package handlers

import (
	"testing"
)

func TestDefaultInjection(t *testing.T) {
	cases := []struct {
		in   InjectionSpec
		want InjectionSpec
	}{
		{InjectionSpec{Type: "bearer"}, InjectionSpec{Type: "header", Name: "Authorization", Format: "Bearer {value}"}},
		{InjectionSpec{Type: "basic"}, InjectionSpec{Type: "header", Name: "Authorization", Format: "Basic {value}"}},
		{InjectionSpec{Type: "header", Name: "X-Foo"}, InjectionSpec{Type: "header", Name: "X-Foo", Format: "{value}"}},
		{InjectionSpec{Type: "query", Name: "api_key"}, InjectionSpec{Type: "query", Name: "api_key", Format: "{value}"}},
	}
	for _, tc := range cases {
		got := DefaultInjection(tc.in)
		if got != tc.want {
			t.Errorf("DefaultInjection(%+v) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestMarshalCapabilityDefaults(t *testing.T) {
	dests, inj := MarshalCapabilityDefaults("cloudflare")
	if dests == "" || inj == "" {
		t.Fatalf("cloudflare defaults missing: dests=%s inj=%s", dests, inj)
	}
	if dests != `["api.cloudflare.com/*"]` {
		t.Errorf("cloudflare dests = %s", dests)
	}
	if dests, inj = MarshalCapabilityDefaults("manual"); dests != "" || inj != "" {
		t.Errorf("manual provider should have empty defaults: %s / %s", dests, inj)
	}
}

func TestCapabilityDefaults_NoInstanceSpecificHosts(t *testing.T) {
	// Trustissues is a standalone product: no default may point at a
	// host that only exists on one operator's infrastructure.
	for provider, d := range CapabilityDefaults {
		for _, dest := range d.Destinations {
			if dest == "" {
				t.Errorf("provider %q has an empty destination pattern", provider)
			}
		}
	}
	if _, ok := CapabilityDefaults["zitadel"]; ok {
		t.Error("zitadel is self-hosted; it must not have a global default destination")
	}
}

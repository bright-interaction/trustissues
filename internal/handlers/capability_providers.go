package handlers

import (
	"encoding/json"
	"regexp"
	"strings"
)

// InjectionSpec describes how to insert a decrypted secret into an
// outbound HTTP request that has been routed through the capability
// proxy. Stored per vault entry as JSON in the injection_spec column;
// pre-seeded from a per-provider default in CapabilityDefaults below.
type InjectionSpec struct {
	Type   string `json:"type"`             // "header" | "query" | "basic" | "bearer"
	Name   string `json:"name,omitempty"`   // header name or query parameter name
	Format string `json:"format,omitempty"` // template, "{value}" is substituted; defaults to "{value}"
}

// DefaultInjection returns the default InjectionSpec for spec.Type when
// optional fields are unset. Most secrets ship with the right defaults
// from the provider table; an entry-level override wins when present.
func DefaultInjection(s InjectionSpec) InjectionSpec {
	if s.Format == "" {
		switch s.Type {
		case "bearer":
			s.Format = "Bearer {value}"
			if s.Name == "" {
				s.Name = "Authorization"
			}
			s.Type = "header"
		case "basic":
			s.Format = "Basic {value}"
			if s.Name == "" {
				s.Name = "Authorization"
			}
			s.Type = "header"
		default:
			s.Format = "{value}"
		}
	}
	if s.Type == "header" && s.Name == "" {
		s.Name = "Authorization"
	}
	return s
}

// CapabilityDefaults maps provider Name() to the default destination
// patterns + injection spec the capability bridge auto-applies when an
// entry is enrolled with that provider. Vault entries with provider =
// "manual" or any name not in this map keep an empty default; the
// agent must call use_secret() with explicit destinations.
//
// Defaults are conservative on purpose: prefix-matched against the
// canonical API host, no path globbing beyond /*. Operators wanting
// finer scoping (e.g. only /v1/chat/completions) edit the entry.
//
// Providers whose API host is instance-specific (self-hosted Forgejo,
// self-hosted Zitadel) have no safe global default and are intentionally
// absent; the owner sets destination_patterns on the entry instead.
var CapabilityDefaults = map[string]struct {
	Destinations []string
	Injection    InjectionSpec
}{
	"cloudflare":   {[]string{"api.cloudflare.com/*"}, InjectionSpec{Type: "bearer"}},
	"vercel":       {[]string{"api.vercel.com/*"}, InjectionSpec{Type: "bearer"}},
	"resend":       {[]string{"api.resend.com/*"}, InjectionSpec{Type: "bearer"}},
	"sendgrid":     {[]string{"api.sendgrid.com/*"}, InjectionSpec{Type: "bearer"}},
	"twilio":       {[]string{"api.twilio.com/*"}, InjectionSpec{Type: "basic"}},
	"linode":       {[]string{"api.linode.com/*"}, InjectionSpec{Type: "bearer"}},
	"neon":         {[]string{"console.neon.tech/api/*"}, InjectionSpec{Type: "bearer"}},
	"datadog":      {[]string{"api.datadoghq.com/*", "api.datadoghq.eu/*"}, InjectionSpec{Type: "header", Name: "DD-API-KEY"}},
	// {instance} is expanded from the entry's provider_meta at seed time. See
	// tenantPlaceholder below for why these three cannot ship a bare "*." host.
	"grafana":      {[]string{"{instance}.grafana.net/*"}, InjectionSpec{Type: "bearer"}},
	"fastly":       {[]string{"api.fastly.com/*"}, InjectionSpec{Type: "header", Name: "Fastly-Key"}},
	"auth0":        {[]string{"{tenant}.auth0.com/*"}, InjectionSpec{Type: "bearer"}},
	"backblaze":    {[]string{"api.backblazeb2.com/*"}, InjectionSpec{Type: "header", Name: "Authorization"}},
	"forgejo":      {[]string{"code.forgejo.org/*"}, InjectionSpec{Type: "header", Name: "Authorization", Format: "token {value}"}},
	"github":       {[]string{"api.github.com/*", "uploads.github.com/*"}, InjectionSpec{Type: "bearer"}},
	"openai":       {[]string{"api.openai.com/*"}, InjectionSpec{Type: "bearer"}},
	"anthropic":    {[]string{"api.anthropic.com/*"}, InjectionSpec{Type: "header", Name: "x-api-key"}},
	"stripe":       {[]string{"api.stripe.com/*"}, InjectionSpec{Type: "basic"}},
	"groq":         {[]string{"api.groq.com/*"}, InjectionSpec{Type: "bearer"}},
	"mistral":      {[]string{"api.mistral.ai/*"}, InjectionSpec{Type: "bearer"}},
	"together":     {[]string{"api.together.xyz/*"}, InjectionSpec{Type: "bearer"}},
	"replicate":    {[]string{"api.replicate.com/*"}, InjectionSpec{Type: "bearer"}},
	"digitalocean": {[]string{"api.digitalocean.com/*"}, InjectionSpec{Type: "bearer"}},
	"hetzner":      {[]string{"api.hetzner.cloud/*"}, InjectionSpec{Type: "bearer"}},
	"sentry":       {[]string{"sentry.io/api/*"}, InjectionSpec{Type: "bearer"}},
	"postmark":     {[]string{"api.postmarkapp.com/*"}, InjectionSpec{Type: "header", Name: "X-Postmark-Server-Token"}},
	"mollie":       {[]string{"api.mollie.com/*"}, InjectionSpec{Type: "bearer"}},
	"supabase":     {[]string{"{project_ref}.supabase.co/*"}, InjectionSpec{Type: "header", Name: "apikey"}},
	"railway":      {[]string{"backboard.railway.app/*"}, InjectionSpec{Type: "bearer"}},
	"render":       {[]string{"api.render.com/*"}, InjectionSpec{Type: "bearer"}},
}

// tenantPlaceholderRe matches a "{key}" placeholder in a destination pattern.
//
// Three providers host every customer on a shared registrable suffix, so a
// preset of "*.supabase.co/*" is not a ceiling at all: anyone can register
// attacker.supabase.co (or .auth0.com, or .grafana.net) and a capability token
// minted for one tenant's key would happily send it there. The wildcard reads
// like a restriction while granting provider-wide reach to a domain space the
// attacker can join.
//
// The entry already knows its own tenant (Supabase requires project_ref, Auth0
// requires tenant, Grafana requires instance), so the preset names the meta key
// and it is expanded at seed time into a single concrete host.
var tenantPlaceholderRe = regexp.MustCompile(`\{([a-z_]+)\}`)

// ExpandCapabilityDestinations substitutes {key} placeholders from the entry's
// provider_meta.
//
// If any placeholder cannot be resolved, it returns nil rather than a partially
// expanded or wildcarded pattern. Seeding nothing is the safe outcome: the
// capability bridge then refuses to mint for that entry until the owner sets a
// destination explicitly, which is a visible, fixable error. Falling back to the
// wildcard would silently hand out provider-wide reach, and a security default
// that degrades to "allow" when data is missing is not a default at all.
func ExpandCapabilityDestinations(patterns []string, meta map[string]string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if !strings.Contains(p, "{") {
			out = append(out, p)
			continue
		}
		resolved := p
		missing := false
		for _, m := range tenantPlaceholderRe.FindAllStringSubmatch(p, -1) {
			v := strings.TrimSpace(meta[m[1]])
			// A tenant id has to be a single DNS label. Anything with a dot or a
			// slash could widen the pattern past the intended host.
			if v == "" || strings.ContainsAny(v, "./*: \\") {
				missing = true
				break
			}
			resolved = strings.ReplaceAll(resolved, m[0], v)
		}
		if missing {
			return nil
		}
		out = append(out, resolved)
	}
	return out
}

// MarshalCapabilityDefaults returns (destinations_json, injection_json)
// for the given provider name. Empty strings when no default exists,
// which the caller stores as '[]' / '{}' to keep the column NOT NULL.
//
// meta supplies tenant values for providers whose preset is tenant-scoped; pass
// nil when none is available, in which case those providers seed no destinations
// and the bridge refuses to mint until the owner sets one.
func MarshalCapabilityDefaults(provider string, meta map[string]string) (string, string) {
	d, ok := CapabilityDefaults[provider]
	if !ok {
		return "", ""
	}
	expanded := ExpandCapabilityDestinations(d.Destinations, meta)
	inj, _ := json.Marshal(d.Injection)
	if len(expanded) == 0 {
		// Injection spec is still useful; the ceiling stays empty on purpose.
		return "", string(inj)
	}
	dests, _ := json.Marshal(expanded)
	return string(dests), string(inj)
}

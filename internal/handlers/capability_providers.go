package handlers

import (
	"encoding/json"
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
	"grafana":      {[]string{"*.grafana.net/*"}, InjectionSpec{Type: "bearer"}},
	"fastly":       {[]string{"api.fastly.com/*"}, InjectionSpec{Type: "header", Name: "Fastly-Key"}},
	"auth0":        {[]string{"*.auth0.com/*"}, InjectionSpec{Type: "bearer"}},
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
	"supabase":     {[]string{"*.supabase.co/*"}, InjectionSpec{Type: "header", Name: "apikey"}},
	"railway":      {[]string{"backboard.railway.app/*"}, InjectionSpec{Type: "bearer"}},
	"render":       {[]string{"api.render.com/*"}, InjectionSpec{Type: "bearer"}},
}

// MarshalCapabilityDefaults returns (destinations_json, injection_json)
// for the given provider name. Empty strings when no default exists,
// which the caller stores as '[]' / '{}' to keep the column NOT NULL.
func MarshalCapabilityDefaults(provider string) (string, string) {
	d, ok := CapabilityDefaults[provider]
	if !ok {
		return "", ""
	}
	dests, _ := json.Marshal(d.Destinations)
	inj, _ := json.Marshal(d.Injection)
	return string(dests), string(inj)
}

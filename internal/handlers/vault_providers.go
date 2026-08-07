package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// KeyProvider defines the interface for services that support programmatic API key rotation.
type KeyProvider interface {
	Name() string
	CanAutoRotate() bool
	DashboardURL(meta map[string]string) string
	Rotate(ctx context.Context, currentKey string, meta map[string]string) (newKey string, err error)
	Validate(ctx context.Context, key string, meta map[string]string) (valid bool, err error)
}

// ProviderRegistry holds all registered key providers.
var ProviderRegistry = map[string]KeyProvider{}

func init() {
	for _, p := range []KeyProvider{
		// Auto-rotate capable
		&CloudflareTokenProvider{},
		&VercelTokenProvider{},
		&ResendProvider{},
		&SendGridProvider{},
		&TwilioProvider{},
		&LinodeProvider{},
		&NeonProvider{},
		&DatadogProvider{},
		&GrafanaProvider{},
		&FastlyProvider{},
		&Auth0Provider{},
		&ZitadelProvider{},
		&BackblazeProvider{},
		&ForgejoProvider{},
		// Validate-only (reminder for rotation)
		&GitHubTokenProvider{},
		&AWSIAMProvider{},
		&OpenAIProvider{},
		&AnthropicProvider{},
		&StripeProvider{},
		&GroqProvider{},
		&MistralProvider{},
		&TogetherAIProvider{},
		&ReplicateProvider{},
		&DigitalOceanProvider{},
		&HetznerProvider{},
		&SentryProvider{},
		&PostmarkProvider{},
		&MollieProvider{},
		&SupabaseProvider{},
		&RailwayProvider{},
		&RenderProvider{},
		&ManualProvider{},
		&SharedSecretProvider{},
		&GeneratedKey32Provider{},
	} {
		ProviderRegistry[p.Name()] = p
	}
}

// ProviderInfo is the JSON-serializable info about a provider for the frontend.
type ProviderInfo struct {
	Name          string `json:"name"`
	Label         string `json:"label"`
	CanAutoRotate bool   `json:"can_auto_rotate"`
	// RevokesPredecessor is kept for existing callers of this endpoint: true only
	// for the providers predecessorFate has SETTLED as revoking. It intentionally
	// does NOT distinguish "confirmed does not revoke" from "nobody has checked
	// yet" - both are false here, which is exactly the ambiguity PredecessorFate
	// below exists to remove. New code should read PredecessorFate, not this.
	RevokesPredecessor bool `json:"revokes_predecessor"`
	// PredecessorFate is the honest three-plus-one-valued answer:
	//   "revokes"        - confirmed: rotation destroys the key it replaces
	//   "leaves_live"     - confirmed: rotation mints a successor and the old key
	//                        keeps authenticating at the vendor
	//   "not_applicable" - there is no vendor-side key to revoke (a local secret
	//                        this server generates and owns outright)
	//   "unknown"         - NOT YET VERIFIED against the vendor's API; PredecessorNote
	//                        says what is outstanding. This is the state 9 of the
	//                        11 non-revoking providers were in while the API only
	//                        ever said `false`, which a caller reasonably reads as
	//                        a confirmed "no". Render this one as a question mark,
	//                        never as "both keys stay live" and never as "revoked".
	PredecessorFate string            `json:"predecessor_fate"`
	PredecessorNote string            `json:"predecessor_note,omitempty"`
	DashboardURL    string            `json:"dashboard_url"`
	RequiredMeta    map[string]string `json:"required_meta"`
}

var providerLabels = map[string]string{
	"cloudflare":       "Cloudflare",
	"vercel":           "Vercel",
	"resend":           "Resend",
	"sendgrid":         "SendGrid",
	"twilio":           "Twilio",
	"linode":           "Linode / Akamai",
	"neon":             "Neon (Postgres)",
	"datadog":          "Datadog",
	"grafana":          "Grafana Cloud",
	"fastly":           "Fastly",
	"auth0":            "Auth0",
	"zitadel":          "Zitadel",
	"backblaze":        "Backblaze B2",
	"forgejo":          "Forgejo / Gitea",
	"github":           "GitHub",
	"aws":              "AWS IAM",
	"openai":           "OpenAI",
	"anthropic":        "Anthropic",
	"stripe":           "Stripe",
	"groq":             "Groq",
	"mistral":          "Mistral AI",
	"together":         "Together AI",
	"replicate":        "Replicate",
	"digitalocean":     "DigitalOcean",
	"hetzner":          "Hetzner",
	"sentry":           "Sentry",
	"postmark":         "Postmark",
	"mollie":           "Mollie",
	"supabase":         "Supabase",
	"railway":          "Railway",
	"render":           "Render",
	"manual":           "Manual",
	"shared-secret":    "Shared Secret (HMAC, 32 bytes hex)",
	"generated-key-32": "Generated AES-256 Key (32 ASCII chars)",
}

// predecessorFateStatus is the honest, four-valued answer to "what happens to
// the key a rotation replaces". It replaces a bare bool specifically because the
// bool could not distinguish "verified: this vendor leaves the old key live"
// from "nobody has checked yet", and both printed as `false`. An operator
// rotating a credential they believe compromised needs to know which one they
// are looking at; "false" alone told them neither.
type predecessorFateStatus string

const (
	// fateRevokes: confirmed, rotation destroys the key it replaces.
	fateRevokes predecessorFateStatus = "revokes"
	// fateLeavesLive: confirmed, rotation mints a successor and the old key goes
	// on authenticating at the vendor. This is a settled fact, not a guess.
	fateLeavesLive predecessorFateStatus = "leaves_live"
	// fateNotApplicable: there is no vendor-side key at all (a local secret this
	// server generates and owns), so "does rotation revoke the predecessor" does
	// not apply. Distinct from fateLeavesLive: nothing persists anywhere else.
	fateNotApplicable predecessorFateStatus = "not_applicable"
	// fateUnknown: NOT yet verified against the vendor's API. The note says what
	// is outstanding. Nine of the eleven non-revoking providers below are this,
	// not fateLeavesLive, and rendering them as a confident "both keys stay
	// live" would assert something nobody has actually checked.
	fateUnknown predecessorFateStatus = "unknown"
)

// predecessorFate declares, for every auto-rotating provider, whether rotation also
// destroys the key it replaces.
//
// The product's promise is "the old key is dead and the new one works". Nine adapters
// mint a successor and leave the predecessor live, and the rotation is still recorded
// as a clean success with no alert, because the orchestration layer only knows about a
// revoke that was QUEUED. An operator rotating a credential they believe is compromised
// is therefore told it worked while the compromised key still authenticates.
//
// Whether each of these SHOULD revoke is a per-vendor API question that cannot be
// settled by reading this repo: some vendors roll a token in place (nothing to revoke),
// others create a second credential (the old one persists). So this table does not
// guess. It records the fate as it stands, forces every new auto-rotating provider to
// declare one, and surfaces it through ListProviders so the UI can tell the operator
// what a rotation of this provider does and does not do.
//
// fateUnknown rows are open questions, not decisions: the Note says what to verify
// against the vendor's API before the status can move to fateRevokes or
// fateLeavesLive.
var predecessorFate = map[string]struct {
	Status predecessorFateStatus
	Note   string
}{
	// Revoke the predecessor as part of rotation.
	"backblaze": {fateRevokes, ""},
	"neon":      {fateRevokes, ""},
	"resend":    {fateRevokes, ""},
	"sendgrid":  {fateRevokes, ""},
	"twilio":    {fateRevokes, ""},

	// No upstream key exists, so there is nothing to revoke. Not a gap.
	"shared-secret":    {fateNotApplicable, "local secret: this server owns the value, there is no upstream key"},
	"generated-key-32": {fateNotApplicable, "local secret: this server owns the value, there is no upstream key"},

	// Mint a successor and leave the predecessor live. Each needs its vendor API
	// checked before the status can move to fateLeavesLive (confirmed) or
	// fateRevokes, which is why they are fateUnknown with a note and not a
	// silent fateLeavesLive.
	"auth0":      {fateUnknown, "TODO: verify whether the Management API client-secret rotate replaces in place or creates a second credential"},
	"cloudflare": {fateUnknown, "TODO: verify whether token roll replaces the token in place (if so this is correct and the note should say so)"},
	"datadog":    {fateUnknown, "TODO: the old API key is not deleted; confirm Datadog's delete endpoint and required scopes"},
	"fastly":     {fateUnknown, "TODO: the old token is not revoked; Fastly exposes DELETE /tokens/{id} but the id is not recorded"},
	"forgejo":    {fateUnknown, "TODO: the old access token is not deleted; needs the token id, which is not recorded"},
	"grafana":    {fateUnknown, "TODO: service-account tokens are additive; the old token id is not recorded so it cannot be deleted"},
	"linode":     {fateUnknown, "TODO: the old personal access token is not revoked; needs its id"},
	"vercel":     {fateUnknown, "TODO: the old token is not deleted; Vercel exposes DELETE /v3/user/tokens/{id} but the id is not recorded"},
	"zitadel":    {fateUnknown, "TODO: the old machine key is not deleted; needs the key id"},
}

// requiredProviderMeta declares, per provider, the provider_meta fields whose
// ABSENCE makes Rotate or Validate return an error (grep the two functions for
// `required in provider_meta` / `X required`; that error string is what a field
// being listed here means). Fields with a code-side default (key_name,
// token_name, token_label, sendgrid's scopes, datadog's site) are left out on
// purpose: the adapter works without them, so forcing an operator to fill one in
// would be the frontend inventing a requirement the backend does not have.
//
// This was ProviderInfo.RequiredMeta's whole reason to exist: the field was
// declared on the struct and never populated, so GET /api/vault/providers always
// answered `"required_meta": null` and the only way for a caller to know Twilio
// needs account_sid was to already have read this file. That is exactly the
// parallel-list drift this codebase keeps finding: one true source (the adapter
// code) and a second, silently empty one (the API contract) standing in for it.
// The map keys must be real ProviderRegistry names:
// TestRequiredProviderMetaMatchesRegistry checks that.
var requiredProviderMeta = map[string]map[string]string{
	"twilio":    {"account_sid": "Account SID"},
	"backblaze": {"key_id": "Application Key ID", "account_id": "Account ID"},
	"auth0":     {"tenant": "Tenant (subdomain of *.auth0.com)", "client_id": "Client ID"},
	"forgejo":   {"instance": "Instance base URL (e.g. https://git.example.com)"},
	"grafana": {
		"instance":           "Instance (subdomain of *.grafana.net)",
		"service_account_id": "Service account ID",
	},
	"zitadel": {
		"instance": "Instance base URL (e.g. https://auth.example.com)",
		"user_id":  "User ID",
	},
	"datadog":  {"app_key": "Application Key (separate from the API key stored as the secret)"},
	"supabase": {"project_ref": "Project ref (subdomain of *.supabase.co)"},
}

func ListProviders() []ProviderInfo {
	infos := make([]ProviderInfo, 0, len(ProviderRegistry))
	for _, p := range ProviderRegistry {
		label := providerLabels[p.Name()]
		if label == "" {
			label = p.Name()
		}
		fate := predecessorFate[p.Name()]
		status := fate.Status
		if status == "" {
			// Not in the table at all (e.g. a validate-only provider that never
			// mints a successor, so the question does not apply).
			status = fateNotApplicable
		}
		required := requiredProviderMeta[p.Name()]
		if required == nil {
			required = map[string]string{}
		}
		infos = append(infos, ProviderInfo{
			Name:          p.Name(),
			Label:         label,
			CanAutoRotate: p.CanAutoRotate(),
			// Backward-compat: true only for the settled-revokes rows, byte-for-byte
			// what this field returned before PredecessorFate existed.
			RevokesPredecessor: status == fateRevokes,
			PredecessorFate:    string(status),
			PredecessorNote:    fate.Note,
			DashboardURL:       p.DashboardURL(nil),
			RequiredMeta:       required,
		})
	}
	return infos
}

// Shared HTTP client for provider API calls + rotation delivery. SSRF-hardened
// (no redirect follow + dial-time private-IP block): these calls carry the
// freshly-rotated cleartext key and decrypted auth tokens, so the target host
// (some are user-controlled instance/tenant URLs) must never be an internal
// one. Uses the platform's guarded client; tests swap this var for a plain
// client to reach httptest loopback servers.
//
// NOTHING IN THIS PACKAGE CALLS providerHTTP.Do DIRECTLY. Every outbound
// request goes through providerDo (egress_authority.go), which checks the host
// against the egress authority the caller installed when it decrypted the
// secret. The private-IP block answers "is this destination internal"; the
// authority answers the question that kept coming back, "who chose this
// destination, and were they allowed to". TestNoProviderCallBypassesTheEgressGate
// fails if a call site goes around it.
var providerHTTP = alerts.GuardedWebhookClient(15 * time.Second)

// Transient meta keys describing a revoke that has been DEFERRED until the new
// value is safely persisted. Like last_revoke_error they are stripped before
// provider_meta is written, so they never reach the database.
const (
	pendingRevokeMethod = "pending_revoke_method"
	pendingRevokeURL    = "pending_revoke_url"
	// pendingRevokeAuth names the auth SCHEME the deferred revoke must use,
	// because "authenticate as the new key" is not one rule: Resend, SendGrid
	// and Neon accept "Authorization: Bearer <secret>", Twilio's Basic auth is
	// (ApiKeySid, ApiKeySecret) and NEVER a bare bearer token, and Backblaze
	// needs an authorize-then-delete round trip that has no single header at
	// all. Hardcoding Bearer here once sent every Twilio deferred revoke out as
	// a 401: meta["key_sid"] had already advanced to the successor, so the
	// orphaned key was never a revoke candidate again and a compromised Twilio
	// credential had no remaining path to be killed.
	pendingRevokeAuth = "pending_revoke_auth"
)

// The values pendingRevokeAuth may hold. An empty/unrecognised value falls
// back to bearer, which is what every scheme used to be hardcoded to.
const (
	revokeAuthBearer = "bearer"
	revokeAuthBasic  = "basic"
	revokeAuthB2     = "b2"
)

// basicAuthUsernameMetaKey names, per provider, which provider_meta key holds
// the USERNAME half of a "basic" scheme deferred revoke. The password half is
// always the freshly rotated secret (Twilio pairs ApiKeySid with
// ApiKeySecret, never the account sid). Only providers that actually use the
// basic scheme need an entry; performPendingRevoke refuses the revoke rather
// than sending a malformed header when one is missing.
var basicAuthUsernameMetaKey = map[string]string{
	"twilio": "key_sid",
}

// successorScopes builds the scope/capability list for a newly minted key: the
// operator's own list from provider_meta when set (comma or space separated),
// otherwise the provider's default, always unioned with the scopes the rotation
// chain itself depends on.
//
// The union is NOT a privilege escalation. The mint authenticates as the
// CURRENT key, so the current key demonstrably already holds these scopes;
// minting a successor without them is a silent DEMOTION that ends the chain.
// That is exactly what SendGrid and Backblaze did, and each broke after one
// rotation in three places at once:
//
//   - the deferred revoke runs as the NEW key, so it 403s and the predecessor
//     stays live at the provider forever
//   - the NEXT rotation's own mint 403s, so auto-rotation is dead
//   - Validate lists keys, so it reports a freshly minted key as invalid
//
// The operator override exists because the hardcoded defaults also discarded
// whatever the predecessor could actually do: a SendGrid key used for stats or
// marketing came back able only to send mail.
func successorScopes(meta map[string]string, metaKey string, fallback, required []string) []string {
	declared := fallback
	if raw := strings.TrimSpace(meta[metaKey]); raw != "" {
		declared = strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n'
		})
	}
	seen := make(map[string]bool, len(declared)+len(required))
	out := make([]string, 0, len(declared)+len(required))
	for _, s := range append(append([]string{}, declared...), required...) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// deferRevokeOldProviderKey records a revoke to run AFTER the caller has stored
// the new value, instead of performing it inline.
//
// Ordering is the whole point. Rotate used to delete the old key at the
// provider before returning, so the window between "old key destroyed" and "new
// key committed to our database" was covered by an encrypt step and a DB write.
// A failure in that window (encrypt error, disk full, SQLITE_BUSY, process
// killed) left the old credential dead upstream and the new one discarded: the
// secret was gone with no copy anywhere. Persisting first turns that same
// failure into a recoverable "both keys live" state, which the existing
// last_revoke_error / partial-rotation path already knows how to report.
//
// The new key is not stored here. The caller passes it to
// performPendingRevoke, so no secret is ever written into provider_meta.
//
// authScheme is one of revokeAuthBearer, revokeAuthBasic or revokeAuthB2 and is
// the whole point of taking a parameter here rather than assuming Bearer: the
// three registered auto-rotating providers that defer a revoke each authenticate
// differently, and getting this wrong is not a degraded revoke but a guaranteed
// 401/403 that leaves the predecessor live forever with no further mechanism to
// kill it (see performPendingRevoke).
//
// For revokeAuthB2, url does NOT carry a request URL: B2's delete endpoint is
// only known after an authorize round trip performed with the NEW credentials,
// so there is nothing fixed to store at defer time. It carries the OLD key id
// to delete instead; performPendingRevoke's b2 arm does the round trip itself.
func deferRevokeOldProviderKey(meta map[string]string, method, url, authScheme string) {
	meta[pendingRevokeMethod] = method
	meta[pendingRevokeURL] = url
	meta[pendingRevokeAuth] = authScheme
}

// performPendingRevoke runs a revoke recorded by deferRevokeOldProviderKey,
// authenticating with the NEW key THE WAY THE PROVIDER ACTUALLY ACCEPTS, and
// clears the transient markers.
//
// Call it only after the new value is durably stored. A failure sets
// meta["last_revoke_error"], which downgrades the rotation to partial and
// alarms, exactly as an inline failure used to.
//
// newKey is opaque. The revoke sends it, authenticated per pendingRevokeAuth, to
// a method and URL taken out of provider_meta (or, for scheme "b2", derived from
// an authorize round trip B2 itself requires), so it is an EXIT and it takes the
// entry's own recorded destinations to authorise it, exactly like the Rotate call
// that minted the value.
func performPendingRevoke(ctx context.Context, meta map[string]string, provider string,
	newKey secretexit.Plaintext) {

	method, url, scheme := meta[pendingRevokeMethod], meta[pendingRevokeURL], meta[pendingRevokeAuth]
	delete(meta, pendingRevokeMethod)
	delete(meta, pendingRevokeURL)
	delete(meta, pendingRevokeAuth)
	if url == "" {
		return
	}
	if newKey.IsZero() || newKey.Empty() {
		return
	}
	exitCtx, plain, err := secretexit.ExitString(ctx, newKey,
		secretexit.ToHosts("the deferred revoke for provider "+provider,
			secretexit.ChosenByTheEntrysOwnRecord(), declaredProviderEgress(provider, meta)))
	if err != nil {
		meta["last_revoke_error"] = "revoke old key: " + err.Error()
		return
	}
	ctx = exitCtx

	switch scheme {
	case revokeAuthB2:
		// url carries the OLD key id (see deferRevokeOldProviderKey's doc).
		// meta["key_id"] already holds the NEW key id: Backblaze's Rotate writes
		// it before deferring, precisely so this authorize step can authenticate
		// as the key that is about to survive the rotation.
		newKeyID := meta["key_id"]
		if newKeyID == "" {
			meta["last_revoke_error"] = "revoke old key: no new key id recorded to authorize the b2 revoke with"
			return
		}
		backblazeRevokeOldKey(ctx, meta, newKeyID, plain, url)
	case revokeAuthBasic:
		userKey := basicAuthUsernameMetaKey[provider]
		user := ""
		if userKey != "" {
			user = meta[userKey]
		}
		if user == "" {
			meta["last_revoke_error"] = "revoke old key: no basic-auth username recorded for provider " + provider
			return
		}
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+plain))
		revokeOldProviderKey(ctx, meta, method, url, auth)
	default: // revokeAuthBearer, and an unset/unrecognised scheme as a safe default
		revokeOldProviderKey(ctx, meta, method, url, "Bearer "+plain)
	}
}

// revokeOldProviderKey issues a revoke (usually DELETE) of the previous key and
// records the outcome in meta["last_revoke_error"] instead of swallowing it. A
// failed revoke means the OLD key is still live at the provider, so the rotation
// is only PARTIAL - the caller/flow surfaces this rather than reporting success.
// A 404 is treated as already-revoked (success). On success any prior error flag
// is cleared. Providers set meta["key_id"] to the NEW id separately.
func revokeOldProviderKey(ctx context.Context, meta map[string]string, method, url, authHeader string) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		meta["last_revoke_error"] = "build revoke request: " + err.Error()
		return
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := providerDo(req)
	if err != nil {
		meta["last_revoke_error"] = "revoke old key: " + err.Error()
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		meta["last_revoke_error"] = fmt.Sprintf("revoke old key: HTTP %d", resp.StatusCode)
		return
	}
	delete(meta, "last_revoke_error")
}

// RotationLogEntry records a single rotation event.
type RotationLogEntry struct {
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
	Provider  string `json:"provider"`
	Error     string `json:"error,omitempty"`
	Method    string `json:"method"`
}

func AppendRotationLog(existing string, entry RotationLogEntry) string {
	var log []RotationLogEntry
	if existing != "" && existing != "[]" {
		_ = json.Unmarshal([]byte(existing), &log)
	}
	log = append(log, entry)
	if len(log) > 50 {
		log = log[len(log)-50:]
	}
	out, _ := json.Marshal(log)
	return string(out)
}

// ParseProviderMeta decodes provider_meta into a map that is ALWAYS non-nil.
//
// The seeded map is not enough on its own: for the JSON literal `null`,
// encoding/json sets the destination map to nil rather than leaving it alone. So
// a column holding "null" (which round-trips out of any json.Marshal of a nil
// map, and is what an unset column becomes once anything writes one) produced a
// nil map here, and the first provider write-back (meta["key_id"] = ...) panicked
// with "assignment to entry in nil map". That panic happens inside the
// auto-rotation goroutine, which had no recover, so it took the whole process
// down: a crash loop where the upstream key had already been minted but was
// never persisted.
func ParseProviderMeta(raw string) map[string]string {
	m := map[string]string{}
	if raw != "" && raw != "{}" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	if m == nil {
		m = map[string]string{}
	}
	return m
}

// providerGet is a helper for simple GET-based validation calls.
func providerGet(ctx context.Context, url, authHeader string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", authHeader)
	resp, err := providerDo(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// ════════════════════════════════════════════════════════════════════════════
// AUTO-ROTATE PROVIDERS
// ════════════════════════════════════════════════════════════════════════════

// maxProviderBody bounds a provider response. Every one of these is a small JSON
// object carrying a key or an id; a megabyte is already far more than any of them
// sends, and the point is that an upstream cannot choose the number.
const maxProviderBody = 1 << 20

// readProviderBody reads a provider's response with a hard ceiling.
//
// All 16 read sites in this file used io.ReadAll(resp.Body), which lets the UPSTREAM
// decide how much memory this process allocates. That matters more here than in a
// typical client: several providers (grafana, zitadel, forgejo, datadog, supabase)
// talk to an operator-supplied instance URL, so the host is not always a vendor, and
// this is a single-process secrets manager. An OOM kill landing AFTER a successful
// mint leaves the credential created upstream with nothing stored and nothing
// recorded, which is the same stranded-secret state the rotation work has been closing
// all along, reached by exhaustion instead of by logic.
//
// The AI gateway already bounds its upstream reads with io.LimitReader; this file
// simply never adopted it. Errors are deliberately swallowed the way the original
// io.ReadAll calls were: every caller checks the status code and unmarshals, so a
// truncated body surfaces as a parse failure rather than as a silent success.
func readProviderBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxProviderBody))
}

// ─── Cloudflare ─────────────────────────────────────────────────────────────

// cloudflareAPIBase is the Cloudflare v4 API root (in dockyard this lives in
// the DNS handler, which trustissues does not carry).
const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// cfResponse is the common Cloudflare API response wrapper.
type cfResponse struct {
	Success bool      `json:"success"`
	Errors  []cfError `json:"errors"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CloudflareTokenProvider struct{}

func (p *CloudflareTokenProvider) Name() string        { return "cloudflare" }
func (p *CloudflareTokenProvider) CanAutoRotate() bool { return true }
func (p *CloudflareTokenProvider) DashboardURL(_ map[string]string) string {
	return "https://dash.cloudflare.com/profile/api-tokens"
}

func (p *CloudflareTokenProvider) Rotate(ctx context.Context, currentKey string, _ map[string]string) (string, error) {
	tokenID, err := p.getTokenID(ctx, currentKey)
	if err != nil {
		return "", fmt.Errorf("identify token: %w", err)
	}
	return p.rollToken(ctx, currentKey, tokenID)
}

func (p *CloudflareTokenProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cloudflareAPIBase+"/user/tokens/verify", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var result cfResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Success, nil
}

func (p *CloudflareTokenProvider) getTokenID(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cloudflareAPIBase+"/user/tokens/verify", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	var result struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if !result.Success || result.Result.ID == "" {
		return "", fmt.Errorf("token verification failed")
	}
	return result.Result.ID, nil
}

func (p *CloudflareTokenProvider) rollToken(ctx context.Context, currentToken, tokenID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "PUT", cloudflareAPIBase+"/user/tokens/"+tokenID+"/value", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	var result struct {
		Success bool                       `json:"success"`
		Result  string                     `json:"result"`
		Errors  []struct{ Message string } `json:"errors"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if !result.Success || result.Result == "" {
		msgs := make([]string, 0)
		for _, e := range result.Errors {
			msgs = append(msgs, e.Message)
		}
		return "", fmt.Errorf("roll failed: %s", strings.Join(msgs, "; "))
	}
	return result.Result, nil
}

// ─── Vercel ─────────────────────────────────────────────────────────────────

type VercelTokenProvider struct{}

func (p *VercelTokenProvider) Name() string        { return "vercel" }
func (p *VercelTokenProvider) CanAutoRotate() bool { return true }
func (p *VercelTokenProvider) DashboardURL(_ map[string]string) string {
	return "https://vercel.com/account/tokens"
}

func (p *VercelTokenProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	tokenName := meta["token_name"]
	if tokenName == "" {
		tokenName = "rotated-" + time.Now().Format("20060102-150405")
	}
	payload, _ := json.Marshal(map[string]string{"name": tokenName})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.vercel.com/v3/user/tokens", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 200 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		BearerToken string `json:"bearerToken"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.BearerToken == "" {
		return "", fmt.Errorf("empty bearer token returned")
	}
	return result.BearerToken, nil
}

func (p *VercelTokenProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.vercel.com/v2/user", "Bearer "+key)
	return code == 200, err
}

// ─── Resend ─────────────────────────────────────────────────────────────────

type ResendProvider struct{}

func (p *ResendProvider) Name() string        { return "resend" }
func (p *ResendProvider) CanAutoRotate() bool { return true }
func (p *ResendProvider) DashboardURL(_ map[string]string) string {
	return "https://resend.com/api-keys"
}

func (p *ResendProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	name := meta["key_name"]
	if name == "" {
		name = "rotated-" + time.Now().Format("20060102-150405")
	}
	payload, _ := json.Marshal(map[string]string{"name": name, "permission": "full_access"})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.resend.com/api-keys", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 201 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", fmt.Errorf("empty token returned")
	}
	// Revoke the OLD key, then record the NEW key's provider-side id so the NEXT
	// rotation can revoke THIS key. Without the write-back meta["key_id"] stays the
	// old (now-deleted) id and every rotation leaves its immediate predecessor live.
	oldID := meta["key_id"]
	if oldID != "" && oldID != result.ID {
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/"+oldID, revokeAuthBearer)
	}
	meta["key_id"] = result.ID
	return result.Token, nil
}

func (p *ResendProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.resend.com/api-keys", "Bearer "+key)
	return code == 200, err
}

// ─── SendGrid ───────────────────────────────────────────────────────────────

type SendGridProvider struct{}

func (p *SendGridProvider) Name() string        { return "sendgrid" }
func (p *SendGridProvider) CanAutoRotate() bool { return true }
func (p *SendGridProvider) DashboardURL(_ map[string]string) string {
	return "https://app.sendgrid.com/settings/api_keys"
}

func (p *SendGridProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	name := meta["key_name"]
	if name == "" {
		name = "rotated-" + time.Now().Format("20060102-150405")
	}
	// api_keys.* is what keeps the chain alive: create for the next rotation's
	// mint, delete for this rotation's revoke of the predecessor, read for
	// Validate. See successorScopes.
	scopes := successorScopes(meta, "scopes",
		[]string{"mail.send", "sender_verification"},
		[]string{"api_keys.create", "api_keys.read", "api_keys.delete"})
	payload, _ := json.Marshal(map[string]any{"name": name, "scopes": scopes})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.sendgrid.com/v3/api_keys", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 201 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		APIKey   string `json:"api_key"`
		APIKeyID string `json:"api_key_id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.APIKey == "" {
		return "", fmt.Errorf("empty api_key returned")
	}
	// Revoke the old key, then record the NEW key's id so the NEXT rotation
	// revokes THIS key (without the write-back meta["api_key_id"] stays the old
	// deleted id and every rotation leaves its predecessor live).
	oldID := meta["api_key_id"]
	if oldID != "" && oldID != result.APIKeyID {
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.sendgrid.com/v3/api_keys/"+oldID, revokeAuthBearer)
	}
	meta["api_key_id"] = result.APIKeyID
	return result.APIKey, nil
}

func (p *SendGridProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.sendgrid.com/v3/api_keys", "Bearer "+key)
	return code == 200, err
}

// ─── Twilio ─────────────────────────────────────────────────────────────────

type TwilioProvider struct{}

func (p *TwilioProvider) Name() string        { return "twilio" }
func (p *TwilioProvider) CanAutoRotate() bool { return true }
func (p *TwilioProvider) DashboardURL(_ map[string]string) string {
	return "https://console.twilio.com/us1/account/keys-credentials/api-keys"
}

func (p *TwilioProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	accountSid := meta["account_sid"]
	if accountSid == "" {
		return "", fmt.Errorf("account_sid is required in provider_meta")
	}
	name := meta["key_name"]
	if name == "" {
		name = "rotated-" + time.Now().Format("20060102")
	}
	payload := "FriendlyName=" + name
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.twilio.com/2010-04-01/Accounts/"+accountSid+"/Keys.json",
		strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	// Authenticate with the API Key SID once we have one. Twilio Basic auth is
	// (AccountSid, AuthToken) OR (ApiKeySid, ApiKeySecret) and NEVER
	// (AccountSid, ApiKeySecret), so an entry that has already rotated must present
	// its key sid or every subsequent call 401s.
	req.SetBasicAuth(twilioAuthUser(meta, accountSid), currentKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 201 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		Sid    string `json:"sid"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Secret == "" {
		return "", fmt.Errorf("empty secret returned")
	}
	// CRITICAL: record the NEW key's sid, and refuse the rotation if Twilio did not
	// give us one.
	//
	// The sid used to be parsed and thrown away. Twilio Basic auth is
	// (ApiKeySid, ApiKeySecret), so the vault ended up holding a secret whose sid
	// existed nowhere in the product: Validate answered valid:false on a
	// freshly-rotated entry, the NEXT rotation's own mint call 401'd and was recorded
	// rotFailProvider on every pass forever, and every consumer the value was
	// delivered to started failing auth. All of it recorded as status "success" with
	// last_rotation_error NULL and no alert, because Twilio queued no revoke.
	//
	// Same rule Backblaze states above: leaving the id as the OLD one pairs it with
	// the NEW secret and breaks auth immediately. Returning an error here is correct
	// rather than storing an unusable value, because the orchestration layer's
	// provider-failure path leaves the stored secret untouched.
	if result.Sid == "" {
		return "", fmt.Errorf("twilio returned a key with no sid; refusing to store a secret that cannot be paired")
	}
	oldSid := meta["key_sid"]
	meta["key_sid"] = result.Sid
	// Queue the predecessor's deletion. Only a PREVIOUS API key can be deleted; the
	// account Auth Token is not a key and has no sid, which is why this is skipped on
	// the first rotation.
	if oldSid != "" && oldSid != result.Sid {
		deferRevokeOldProviderKey(meta, "DELETE",
			"https://api.twilio.com/2010-04-01/Accounts/"+accountSid+"/Keys/"+oldSid+".json", revokeAuthBasic)
	}
	return result.Secret, nil
}

// twilioAuthUser returns the Basic-auth username for a Twilio call.
//
// Before the first rotation the stored value is the account Auth Token, which pairs
// with the AccountSid. After a rotation it is an API Key secret, which pairs with
// that key's SK sid. Getting this wrong is not a degraded state but a hard 401 on
// every call.
func twilioAuthUser(meta map[string]string, accountSid string) string {
	if sid := meta["key_sid"]; sid != "" {
		return sid
	}
	return accountSid
}

func (p *TwilioProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	accountSid := meta["account_sid"]
	if accountSid == "" {
		return false, fmt.Errorf("account_sid required")
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.twilio.com/2010-04-01/Accounts/"+accountSid+".json", nil)
	if err != nil {
		return false, err
	}
	// Same pairing rule as Rotate: an entry that has rotated holds an API Key secret
	// and must authenticate with that key's sid, not the account sid.
	req.SetBasicAuth(twilioAuthUser(meta, accountSid), key)
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// ─── Linode / Akamai ────────────────────────────────────────────────────────

type LinodeProvider struct{}

func (p *LinodeProvider) Name() string        { return "linode" }
func (p *LinodeProvider) CanAutoRotate() bool { return true }
func (p *LinodeProvider) DashboardURL(_ map[string]string) string {
	return "https://cloud.linode.com/profile/tokens"
}

func (p *LinodeProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	label := meta["token_label"]
	if label == "" {
		label = "rotated-" + time.Now().Format("20060102-150405")
	}
	payload, _ := json.Marshal(map[string]any{"label": label, "scopes": "*"})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.linode.com/v4/profile/tokens", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 200 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", fmt.Errorf("empty token returned")
	}
	return result.Token, nil
}

func (p *LinodeProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.linode.com/v4/profile", "Bearer "+key)
	return code == 200, err
}

// ─── Neon (Postgres) ────────────────────────────────────────────────────────

type NeonProvider struct{}

func (p *NeonProvider) Name() string        { return "neon" }
func (p *NeonProvider) CanAutoRotate() bool { return true }
func (p *NeonProvider) DashboardURL(_ map[string]string) string {
	return "https://console.neon.tech/app/settings/api-keys"
}

func (p *NeonProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	name := meta["key_name"]
	if name == "" {
		name = "rotated-" + time.Now().Format("20060102-150405")
	}
	payload, _ := json.Marshal(map[string]string{"key_name": name})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://console.neon.tech/api/v2/api_keys", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		ID  int64  `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Key == "" {
		return "", fmt.Errorf("empty key returned")
	}
	// Revoke the old key, then record the NEW key's id so the NEXT rotation
	// revokes THIS key (without the write-back meta["key_id"] stays the old
	// deleted id and every rotation leaves its predecessor live).
	newID := fmt.Sprintf("%d", result.ID)
	oldID := meta["key_id"]
	if oldID != "" && oldID != newID {
		deferRevokeOldProviderKey(meta, "DELETE", "https://console.neon.tech/api/v2/api_keys/"+oldID, revokeAuthBearer)
	}
	if result.ID != 0 {
		meta["key_id"] = newID
	}
	return result.Key, nil
}

func (p *NeonProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://console.neon.tech/api/v2/projects", "Bearer "+key)
	return code == 200, err
}

// ─── Datadog ────────────────────────────────────────────────────────────────

type DatadogProvider struct{}

func (p *DatadogProvider) Name() string        { return "datadog" }
func (p *DatadogProvider) CanAutoRotate() bool { return true }
func (p *DatadogProvider) DashboardURL(_ map[string]string) string {
	return "https://app.datadoghq.com/organization-settings/api-keys"
}

func (p *DatadogProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	appKey := meta["app_key"]
	if appKey == "" {
		return "", fmt.Errorf("app_key (Application Key) is required in provider_meta to manage API keys")
	}
	site := meta["site"]
	if site == "" {
		site = "datadoghq.com"
	}
	name := "rotated-" + time.Now().Format("20060102-150405")
	payload, _ := json.Marshal(map[string]any{"data": map[string]any{"type": "api_keys", "attributes": map[string]string{"name": name}}})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api."+site+"/api/v2/api_keys", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("DD-API-KEY", currentKey)
	req.Header.Set("DD-APPLICATION-KEY", appKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 201 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		Data struct {
			Attributes struct {
				Key string `json:"key"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Data.Attributes.Key == "" {
		return "", fmt.Errorf("empty key returned")
	}
	return result.Data.Attributes.Key, nil
}

func (p *DatadogProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	site := meta["site"]
	if site == "" {
		site = "datadoghq.com"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api."+site+"/api/v1/validate", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("DD-API-KEY", key)
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// ─── Grafana Cloud ──────────────────────────────────────────────────────────

type GrafanaProvider struct{}

func (p *GrafanaProvider) Name() string        { return "grafana" }
func (p *GrafanaProvider) CanAutoRotate() bool { return true }
func (p *GrafanaProvider) DashboardURL(meta map[string]string) string {
	instance := meta["instance"]
	if instance != "" {
		return "https://" + instance + ".grafana.net/org/serviceaccounts"
	}
	return "https://grafana.com/orgs"
}

func (p *GrafanaProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	instance := meta["instance"]
	saID := meta["service_account_id"]
	if instance == "" || saID == "" {
		return "", fmt.Errorf("instance and service_account_id required in provider_meta")
	}
	name := "rotated-" + time.Now().Format("20060102-150405")
	payload, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://"+instance+".grafana.net/api/serviceaccounts/"+saID+"/tokens",
		strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 200 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Key == "" {
		return "", fmt.Errorf("empty key returned")
	}
	return result.Key, nil
}

func (p *GrafanaProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	instance := meta["instance"]
	if instance == "" {
		return false, fmt.Errorf("instance required")
	}
	code, err := providerGet(ctx, "https://"+instance+".grafana.net/api/org/", "Bearer "+key)
	return code == 200, err
}

// ─── Fastly ─────────────────────────────────────────────────────────────────

type FastlyProvider struct{}

func (p *FastlyProvider) Name() string        { return "fastly" }
func (p *FastlyProvider) CanAutoRotate() bool { return true }
func (p *FastlyProvider) DashboardURL(_ map[string]string) string {
	return "https://manage.fastly.com/account/personal/tokens"
}

func (p *FastlyProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	// Fastly token creation requires username/password or existing token with scope
	name := "rotated-" + time.Now().Format("20060102-150405")
	payload, _ := json.Marshal(map[string]any{"name": name, "scope": "global"})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.fastly.com/tokens", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Fastly-Key", currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 200 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("empty access_token returned")
	}
	return result.AccessToken, nil
}

func (p *FastlyProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.fastly.com/tokens/self", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Fastly-Key", key)
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// ─── Auth0 ──────────────────────────────────────────────────────────────────

type Auth0Provider struct{}

func (p *Auth0Provider) Name() string        { return "auth0" }
func (p *Auth0Provider) CanAutoRotate() bool { return true }
func (p *Auth0Provider) DashboardURL(meta map[string]string) string {
	tenant := meta["tenant"]
	if tenant != "" {
		return "https://manage.auth0.com/dashboard/eu/" + tenant + "/applications"
	}
	return "https://manage.auth0.com"
}

func (p *Auth0Provider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	tenant := meta["tenant"]
	clientID := meta["client_id"]
	if tenant == "" || clientID == "" {
		return "", fmt.Errorf("tenant and client_id required in provider_meta")
	}
	// POST /api/v2/clients/{client_id}/rotate-secret
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://"+tenant+".auth0.com/api/v2/clients/"+clientID+"/rotate-secret", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentKey)
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 200 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.ClientSecret == "" {
		return "", fmt.Errorf("empty client_secret returned")
	}
	return result.ClientSecret, nil
}

func (p *Auth0Provider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	tenant := meta["tenant"]
	clientID := meta["client_id"]
	if tenant == "" || clientID == "" {
		return false, fmt.Errorf("tenant and client_id required")
	}
	payload := fmt.Sprintf(`{"grant_type":"client_credentials","client_id":"%s","client_secret":"%s","audience":"https://%s.auth0.com/api/v2/"}`, clientID, key, tenant)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+tenant+".auth0.com/oauth/token", strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// ─── Zitadel ────────────────────────────────────────────────────────────────

type ZitadelProvider struct{}

func (p *ZitadelProvider) Name() string        { return "zitadel" }
func (p *ZitadelProvider) CanAutoRotate() bool { return true }
func (p *ZitadelProvider) DashboardURL(meta map[string]string) string {
	instance := meta["instance"]
	if instance != "" {
		return instance + "/ui/console"
	}
	return ""
}

func (p *ZitadelProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	instance := meta["instance"]
	userID := meta["user_id"]
	if instance == "" {
		return "", fmt.Errorf("instance required in provider_meta (e.g. https://auth.example.com)")
	}
	if userID == "" {
		return "", fmt.Errorf("user_id required in provider_meta")
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		instance+"/management/v1/users/"+userID+"/pats",
		strings.NewReader(`{}`))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 200 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", fmt.Errorf("empty token returned")
	}
	return result.Token, nil
}

func (p *ZitadelProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	instance := meta["instance"]
	if instance == "" {
		return false, fmt.Errorf("instance required")
	}
	code, err := providerGet(ctx, instance+"/auth/v1/users/me", "Bearer "+key)
	return code == 200, err
}

// ─── Backblaze B2 ───────────────────────────────────────────────────────────

type BackblazeProvider struct{}

func (p *BackblazeProvider) Name() string        { return "backblaze" }
func (p *BackblazeProvider) CanAutoRotate() bool { return true }
func (p *BackblazeProvider) DashboardURL(_ map[string]string) string {
	return "https://secure.backblaze.com/app_keys.htm"
}

func (p *BackblazeProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	keyID := meta["key_id"]
	accountID := meta["account_id"]
	if keyID == "" || accountID == "" {
		return "", fmt.Errorf("key_id and account_id required in provider_meta")
	}
	name := "rotated-" + time.Now().Format("20060102")
	// writeKeys is what b2_create_key itself requires and deleteKeys what
	// b2_delete_key requires, so without them this mint is the last one that can
	// ever succeed and backblazeRevokeOldKey below can never delete anything.
	// See successorScopes.
	caps := successorScopes(meta, "capabilities",
		[]string{"listBuckets", "readFiles", "writeFiles", "deleteFiles", "listFiles"},
		[]string{"writeKeys", "deleteKeys", "listKeys"})
	payload, _ := json.Marshal(map[string]any{
		"accountId":    accountID,
		"keyName":      name,
		"capabilities": caps,
	})
	auth := base64.StdEncoding.EncodeToString([]byte(keyID + ":" + currentKey))
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.backblazeb2.com/b2api/v3/b2_create_key", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 200 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		ApplicationKey   string `json:"applicationKey"`
		ApplicationKeyID string `json:"applicationKeyId"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.ApplicationKey == "" {
		return "", fmt.Errorf("empty applicationKey returned")
	}
	// CRITICAL: record the NEW key's id BEFORE deferring the revoke. Backblaze
	// Basic-auth is keyID:secret, so leaving meta["key_id"] as the OLD id would
	// pair it with the NEW secret and break auth on the very next
	// Validate/Rotate (not just leak the old key). It also has to happen first
	// for a second reason now: performPendingRevoke's b2 arm authenticates B2's
	// authorize step as the NEW key pair, and reads the id straight out of
	// meta["key_id"].
	if result.ApplicationKeyID != "" {
		meta["key_id"] = result.ApplicationKeyID
	}
	// Queue the predecessor's deletion. This used to run INLINE, right here,
	// before Rotate returned - "best-effort, because b2_delete_key needs an
	// authorize step first" - which meant the old key was destroyed at
	// Backblaze before the caller had encrypted or persisted the new one, and
	// before the caller's compare-and-swap could even fail. Every other
	// adapter defers (see deferRevokeOldProviderKey's doc); Backblaze was the
	// one exception, and the exception was the bug: a CAS conflict on the
	// caller's write discarded the newly minted key while the old one was
	// ALREADY gone upstream, leaving nobody holding a working credential.
	//
	// B2 still needs its authorize round trip before b2_delete_key, so there is
	// no fixed delete URL to store here; performPendingRevoke's "b2" scheme
	// arm does that round trip itself, once the caller says the new value is
	// durably stored.
	if result.ApplicationKeyID != "" && keyID != result.ApplicationKeyID {
		deferRevokeOldProviderKey(meta, "DELETE", keyID, revokeAuthB2)
	}
	return result.ApplicationKey, nil
}

// backblazeRevokeOldKey deletes the previous B2 application key. B2 requires a
// b2_authorize_account round-trip (with the NEW creds) to discover the storage
// apiUrl + a short-lived token before b2_delete_key can be called. Any failure
// is recorded in meta["last_revoke_error"] and never fails the rotation.
//
// Called from exactly one place: performPendingRevoke's "b2" scheme arm, once
// the caller has durably stored the new value. It used to be called inline from
// Rotate, before the new value was persisted; see deferRevokeOldProviderKey's
// doc for why that was the bug this file exists to have fixed.
func backblazeRevokeOldKey(ctx context.Context, meta map[string]string, newKeyID, newKey, oldKeyID string) {
	auth := base64.StdEncoding.EncodeToString([]byte(newKeyID + ":" + newKey))
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.backblazeb2.com/b2api/v3/b2_authorize_account", nil)
	if err != nil {
		meta["last_revoke_error"] = "b2 authorize: " + err.Error()
		return
	}
	req.Header.Set("Authorization", "Basic "+auth)
	resp, err := providerDo(req)
	if err != nil {
		meta["last_revoke_error"] = "b2 authorize: " + err.Error()
		return
	}
	body, _ := readProviderBody(resp)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		meta["last_revoke_error"] = fmt.Sprintf("b2 authorize: HTTP %d", resp.StatusCode)
		return
	}
	var authResp struct {
		AuthorizationToken string `json:"authorizationToken"`
		APIInfo            struct {
			StorageAPI struct {
				APIURL string `json:"apiUrl"`
			} `json:"storageApi"`
		} `json:"apiInfo"`
	}
	if err := json.Unmarshal(body, &authResp); err != nil || authResp.APIInfo.StorageAPI.APIURL == "" {
		meta["last_revoke_error"] = "b2 authorize: could not resolve apiUrl"
		return
	}
	delPayload, _ := json.Marshal(map[string]string{"applicationKeyId": oldKeyID})
	delReq, err := http.NewRequestWithContext(ctx, "POST",
		authResp.APIInfo.StorageAPI.APIURL+"/b2api/v3/b2_delete_key", strings.NewReader(string(delPayload)))
	if err != nil {
		meta["last_revoke_error"] = "b2 delete key: " + err.Error()
		return
	}
	delReq.Header.Set("Authorization", authResp.AuthorizationToken)
	delReq.Header.Set("Content-Type", "application/json")
	dr, err := providerDo(delReq)
	if err != nil {
		meta["last_revoke_error"] = "b2 delete key: " + err.Error()
		return
	}
	defer dr.Body.Close()
	_, _ = io.Copy(io.Discard, dr.Body)
	if dr.StatusCode/100 != 2 {
		meta["last_revoke_error"] = fmt.Sprintf("b2 delete key: HTTP %d", dr.StatusCode)
		return
	}
	delete(meta, "last_revoke_error")
}

func (p *BackblazeProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	keyID := meta["key_id"]
	if keyID == "" {
		return false, fmt.Errorf("key_id required")
	}
	auth := base64.StdEncoding.EncodeToString([]byte(keyID + ":" + key))
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.backblazeb2.com/b2api/v3/b2_authorize_account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Basic "+auth)
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// ─── Forgejo / Gitea ────────────────────────────────────────────────────────

type ForgejoProvider struct{}

func (p *ForgejoProvider) Name() string        { return "forgejo" }
func (p *ForgejoProvider) CanAutoRotate() bool { return true }
func (p *ForgejoProvider) DashboardURL(meta map[string]string) string {
	instance := meta["instance"]
	if instance != "" {
		return instance + "/user/settings/applications"
	}
	return ""
}

func (p *ForgejoProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	instance := meta["instance"]
	if instance == "" {
		return "", fmt.Errorf("instance required in provider_meta (e.g. https://git.example.com)")
	}
	name := "rotated-" + time.Now().Format("20060102-150405")
	payload, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequestWithContext(ctx, "POST", instance+"/api/v1/users/tokens", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+currentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := readProviderBody(resp)
	if resp.StatusCode != 201 {
		return "", newUpstreamHTTPError(resp.StatusCode, body)
	}
	var result struct {
		Sha1 string `json:"sha1"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Sha1 == "" {
		return "", fmt.Errorf("empty token returned")
	}
	return result.Sha1, nil
}

func (p *ForgejoProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	instance := meta["instance"]
	if instance == "" {
		return false, fmt.Errorf("instance required")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", instance+"/api/v1/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "token "+key)
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// ════════════════════════════════════════════════════════════════════════════
// VALIDATE-ONLY PROVIDERS (reminder for manual rotation)
// ════════════════════════════════════════════════════════════════════════════

type GitHubTokenProvider struct{}

func (p *GitHubTokenProvider) Name() string        { return "github" }
func (p *GitHubTokenProvider) CanAutoRotate() bool { return false }
func (p *GitHubTokenProvider) DashboardURL(_ map[string]string) string {
	return "https://github.com/settings/tokens"
}
func (p *GitHubTokenProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("GitHub PATs cannot be rotated programmatically; create a new token at https://github.com/settings/tokens")
}
func (p *GitHubTokenProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

type AWSIAMProvider struct{}

func (p *AWSIAMProvider) Name() string        { return "aws" }
func (p *AWSIAMProvider) CanAutoRotate() bool { return false }
func (p *AWSIAMProvider) DashboardURL(_ map[string]string) string {
	return "https://console.aws.amazon.com/iam/home#/security_credentials"
}
func (p *AWSIAMProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("AWS IAM rotation requires the AWS SDK (not included); rotate at https://console.aws.amazon.com/iam/home#/security_credentials")
}
func (p *AWSIAMProvider) Validate(_ context.Context, _ string, _ map[string]string) (bool, error) {
	return false, fmt.Errorf("AWS key validation requires AWS SDK")
}

type OpenAIProvider struct{}

func (p *OpenAIProvider) Name() string        { return "openai" }
func (p *OpenAIProvider) CanAutoRotate() bool { return false }
func (p *OpenAIProvider) DashboardURL(_ map[string]string) string {
	return "https://platform.openai.com/api-keys"
}
func (p *OpenAIProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("OpenAI does not support programmatic key creation")
}
func (p *OpenAIProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.openai.com/v1/models", "Bearer "+key)
	return code == 200, err
}

type AnthropicProvider struct{}

func (p *AnthropicProvider) Name() string        { return "anthropic" }
func (p *AnthropicProvider) CanAutoRotate() bool { return false }
func (p *AnthropicProvider) DashboardURL(_ map[string]string) string {
	return "https://console.anthropic.com/settings/keys"
}
func (p *AnthropicProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Anthropic does not support programmatic key creation")
}
func (p *AnthropicProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	payload := `{"model":"claude-haiku-4-5-20251001","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200 || resp.StatusCode == 429, nil
}

type StripeProvider struct{}

func (p *StripeProvider) Name() string        { return "stripe" }
func (p *StripeProvider) CanAutoRotate() bool { return false }
func (p *StripeProvider) DashboardURL(_ map[string]string) string {
	return "https://dashboard.stripe.com/apikeys"
}
func (p *StripeProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Stripe does not support programmatic secret key rotation")
}
func (p *StripeProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, "")
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

type GroqProvider struct{}

func (p *GroqProvider) Name() string        { return "groq" }
func (p *GroqProvider) CanAutoRotate() bool { return false }
func (p *GroqProvider) DashboardURL(_ map[string]string) string {
	return "https://console.groq.com/keys"
}
func (p *GroqProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Groq does not support programmatic key rotation")
}
func (p *GroqProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.groq.com/openai/v1/models", "Bearer "+key)
	return code == 200, err
}

type MistralProvider struct{}

func (p *MistralProvider) Name() string        { return "mistral" }
func (p *MistralProvider) CanAutoRotate() bool { return false }
func (p *MistralProvider) DashboardURL(_ map[string]string) string {
	return "https://console.mistral.ai/api-keys"
}
func (p *MistralProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Mistral does not support programmatic key rotation")
}
func (p *MistralProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.mistral.ai/v1/models", "Bearer "+key)
	return code == 200, err
}

type TogetherAIProvider struct{}

func (p *TogetherAIProvider) Name() string        { return "together" }
func (p *TogetherAIProvider) CanAutoRotate() bool { return false }
func (p *TogetherAIProvider) DashboardURL(_ map[string]string) string {
	return "https://api.together.xyz/settings/api-keys"
}
func (p *TogetherAIProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Together AI does not support programmatic key rotation")
}
func (p *TogetherAIProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.together.xyz/v1/models", "Bearer "+key)
	return code == 200, err
}

type ReplicateProvider struct{}

func (p *ReplicateProvider) Name() string        { return "replicate" }
func (p *ReplicateProvider) CanAutoRotate() bool { return false }
func (p *ReplicateProvider) DashboardURL(_ map[string]string) string {
	return "https://replicate.com/account/api-tokens"
}
func (p *ReplicateProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Replicate does not support programmatic key rotation")
}
func (p *ReplicateProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.replicate.com/v1/account", "Bearer "+key)
	return code == 200, err
}

type DigitalOceanProvider struct{}

func (p *DigitalOceanProvider) Name() string        { return "digitalocean" }
func (p *DigitalOceanProvider) CanAutoRotate() bool { return false }
func (p *DigitalOceanProvider) DashboardURL(_ map[string]string) string {
	return "https://cloud.digitalocean.com/account/api/tokens"
}
func (p *DigitalOceanProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("DigitalOcean does not support programmatic token rotation")
}
func (p *DigitalOceanProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.digitalocean.com/v2/account", "Bearer "+key)
	return code == 200, err
}

type HetznerProvider struct{}

func (p *HetznerProvider) Name() string        { return "hetzner" }
func (p *HetznerProvider) CanAutoRotate() bool { return false }
func (p *HetznerProvider) DashboardURL(_ map[string]string) string {
	return "https://console.hetzner.cloud"
}
func (p *HetznerProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Hetzner does not support programmatic token rotation")
}
func (p *HetznerProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.hetzner.cloud/v1/servers?per_page=1", "Bearer "+key)
	return code == 200, err
}

type SentryProvider struct{}

func (p *SentryProvider) Name() string        { return "sentry" }
func (p *SentryProvider) CanAutoRotate() bool { return false }
func (p *SentryProvider) DashboardURL(_ map[string]string) string {
	return "https://sentry.io/settings/account/api/auth-tokens/"
}
func (p *SentryProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Sentry does not support programmatic auth token rotation")
}
func (p *SentryProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://sentry.io/api/0/", "Bearer "+key)
	return code == 200, err
}

type PostmarkProvider struct{}

func (p *PostmarkProvider) Name() string        { return "postmark" }
func (p *PostmarkProvider) CanAutoRotate() bool { return false }
func (p *PostmarkProvider) DashboardURL(_ map[string]string) string {
	return "https://account.postmarkapp.com"
}
func (p *PostmarkProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Postmark does not support programmatic token rotation")
}
func (p *PostmarkProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.postmarkapp.com/server", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Postmark-Server-Token", key)
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

type MollieProvider struct{}

func (p *MollieProvider) Name() string        { return "mollie" }
func (p *MollieProvider) CanAutoRotate() bool { return false }
func (p *MollieProvider) DashboardURL(_ map[string]string) string {
	return "https://my.mollie.com/dashboard/developers/api-keys"
}
func (p *MollieProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Mollie does not support programmatic API key rotation")
}
func (p *MollieProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.mollie.com/v2/organizations/me", "Bearer "+key)
	return code == 200, err
}

type SupabaseProvider struct{}

func (p *SupabaseProvider) Name() string        { return "supabase" }
func (p *SupabaseProvider) CanAutoRotate() bool { return false }
func (p *SupabaseProvider) DashboardURL(meta map[string]string) string {
	ref := meta["project_ref"]
	if ref != "" {
		return "https://supabase.com/dashboard/project/" + ref + "/settings/api"
	}
	return "https://supabase.com/dashboard"
}
func (p *SupabaseProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Supabase key rotation resets ALL keys; rotate manually in the dashboard")
}
func (p *SupabaseProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	ref := meta["project_ref"]
	if ref == "" {
		return false, fmt.Errorf("project_ref required")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+ref+".supabase.co/rest/v1/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("apikey", key)
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

type RailwayProvider struct{}

func (p *RailwayProvider) Name() string        { return "railway" }
func (p *RailwayProvider) CanAutoRotate() bool { return false }
func (p *RailwayProvider) DashboardURL(_ map[string]string) string {
	return "https://railway.app/account/tokens"
}
func (p *RailwayProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Railway does not support programmatic token rotation")
}
func (p *RailwayProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	payload := `{"query":"{ me { email } }"}`
	req, err := http.NewRequestWithContext(ctx, "POST", "https://backboard.railway.app/graphql/v2", strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerDo(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

type RenderProvider struct{}

func (p *RenderProvider) Name() string        { return "render" }
func (p *RenderProvider) CanAutoRotate() bool { return false }
func (p *RenderProvider) DashboardURL(_ map[string]string) string {
	return "https://dashboard.render.com/u/settings#api-keys"
}
func (p *RenderProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("Render does not support programmatic API key rotation")
}
func (p *RenderProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	code, err := providerGet(ctx, "https://api.render.com/v1/owners", "Bearer "+key)
	return code == 200, err
}

type ManualProvider struct{}

func (p *ManualProvider) Name() string                            { return "manual" }
func (p *ManualProvider) CanAutoRotate() bool                     { return false }
func (p *ManualProvider) DashboardURL(_ map[string]string) string { return "" }
func (p *ManualProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("manual rotation only")
}
func (p *ManualProvider) Validate(_ context.Context, _ string, _ map[string]string) (bool, error) {
	return false, fmt.Errorf("no validation for manual provider")
}

// SharedSecretProvider generates inter-service shared HMAC secrets. Auto-
// rotate produces a fresh 32-byte hex value; delivery to the consuming
// service happens through the configured rotation targets (webhook or
// forgejo_secret).
type SharedSecretProvider struct{}

func (p *SharedSecretProvider) Name() string        { return "shared-secret" }
func (p *SharedSecretProvider) CanAutoRotate() bool { return true }
func (p *SharedSecretProvider) DashboardURL(_ map[string]string) string {
	return ""
}
func (p *SharedSecretProvider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	// Generate a 32-byte random value, hex-encoded (the common shape for
	// HMAC verifier secrets).
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
func (p *SharedSecretProvider) Validate(_ context.Context, _ string, _ map[string]string) (bool, error) {
	// Validation happens implicitly through delivery: if a webhook or
	// forgejo_secret target fails, the rotator records the failure and the
	// user sees it in rotation_log. There's no out-of-band validation to
	// perform here.
	return true, nil
}

// GeneratedKey32Provider rotates AES-256-GCM keys consumed by services that
// take the env-var bytes verbatim as the cipher key. Generates exactly 32
// ASCII alphanumeric characters so `len(key) == 32` AND `[]byte(key)` is a
// usable 32-byte AES-256 key without any decode step. Distinct from
// shared-secret which emits 64 hex characters and would fail a strict
// 32-byte length guard.
type GeneratedKey32Provider struct{}

func (p *GeneratedKey32Provider) Name() string                            { return "generated-key-32" }
func (p *GeneratedKey32Provider) CanAutoRotate() bool                     { return true }
func (p *GeneratedKey32Provider) DashboardURL(_ map[string]string) string { return "" }
func (p *GeneratedKey32Provider) Rotate(_ context.Context, _ string, _ map[string]string) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// Reject biased modulo: 256 % 62 = 8, so a naive byte%62 over-samples
	// the first 8 chars by ~13%. Sample one byte at a time and discard
	// any draw >= 256 - (256 % 62) = 248. Average rejections per char is
	// 8/256 = 3%, negligible.
	const cap = 256 - (256 % 62)
	out := make([]byte, 32)
	buf := make([]byte, 1)
	for i := 0; i < 32; {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("rand: %w", err)
		}
		if int(buf[0]) >= cap {
			continue
		}
		out[i] = charset[int(buf[0])%len(charset)]
		i++
	}
	return string(out), nil
}
func (p *GeneratedKey32Provider) Validate(_ context.Context, _ string, _ map[string]string) (bool, error) {
	// No external validation surface; delivery outcomes (webhook or
	// forgejo_secret) are recorded in rotation_log.
	return true, nil
}

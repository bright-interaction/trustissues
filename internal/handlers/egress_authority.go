package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// WHERE A DECRYPTED SECRET IS ALLOWED TO GO, STATED ONCE.
//
// This file exists because the same defect has now been reported four rounds
// running, and each round closed one NAMED COLUMN:
//
//	round 1  the proxy PATH was the destination           -> path allowlist
//	round 2  so the attacker moved the HOST               -> inference allowlist
//	round 3  so the attacker rewrote destination_patterns -> the pin + a widening right
//	round 4  so the attacker rewrote provider_meta        -> ...and here we are
//
// Round 4's report named the shape exactly: "provider_meta is an ungated second
// host-choosing column: an accepted vault_only editor sets provider /
// provider_meta / auto_rotate via the same PUT with no password, and the
// rotation scheduler delivers the operator's decrypted gateway key to
// attacker.grafana.net (or any host at all via datadog's site field)".
//
// Fixing provider_meta and stopping produces round 5, because the class is not
// "these two columns". The class is:
//
//	A caller who lacks the authority to redirect a secret must not be able to
//	influence, through ANY writable field or ANY route, the destination a
//	decrypted secret is ultimately sent to.
//
// Note "influence". datadog's `site` is the warning: it is not spelled like a
// host and it holds "datadoghq.eu", yet the code writes "https://api."+site and
// so it IS the host. grafana's `instance`, auth0's `tenant`, supabase's
// `project_ref`, zitadel's and forgejo's `instance` are all the same shape. A
// reviewer scanning for fields called "url" finds none of them.
//
// TWO enforcement points, and they are deliberately different in kind:
//
//  1. THE WRITE GATE (authorityForEgressChange, used by PUT /api/vault/{id}).
//     Any write that ADDS a host to the set this entry's secret can reach needs
//     more than manage: the entry's creator or an instance admin, the same
//     right destination_patterns already requires. It is computed from the
//     DECLARED host set, so it covers provider, provider_meta, and every meta
//     key a future provider adds, on the day it is added.
//
//  2. THE DERIVATION GATE (providerDo). Every outbound provider request is
//     checked, at the moment it leaves, against the host set DECLARED for the
//     provider whose secret it carries. That is the round-5 stopper: if a new
//     preset builds a host out of a meta field nobody classified, the declared
//     set and the real request disagree and the request is refused. The write
//     gate cannot catch that on its own, because a field it does not know about
//     is a field it does not compare.
//
// A request with no authority in its context is REFUSED. Fail-closed is the
// point: a new call site that forgets to say which secret it is spending does
// not get a free pass, it gets a loud error and a red test.

// ── the authority carried alongside a request ───────────────────────────────

type egressAuthorityKeyType struct{}

// egressAuthorityKey is the context key holding the egressAuthority for the
// operation currently in flight.
var egressAuthorityKey = egressAuthorityKeyType{}

type egressRecorderKeyType struct{}

// egressRecorderKey is an OBSERVATION hook, never an authorization one. The
// coverage guard installs it to tell "reached a declared host" apart from
// "reached nothing at all", which is the difference between a guard and a
// vacuous one. It changes no decision: providerDo enforces identically whether
// or not a recorder is present.
var egressRecorderKey = egressRecorderKeyType{}

// egressAttempt is one observed outbound provider request.
type egressAttempt struct {
	host    string
	refused bool
	reason  string
}

// egressAuthority is the answer to "where may the secret this operation holds
// be sent?", resolved once by the caller that decrypted it and carried to the
// point the request actually leaves.
type egressAuthority struct {
	// what names the operation for the refusal message ("provider datadog",
	// "rotation delivery target").
	what string
	// allow is the host set. Empty means this operation may not egress at all,
	// which is the correct answer for a local generator such as shared-secret.
	allow egressAllowance
}

// egressAllowance is a host set. Exact hosts are the normal case; suffixes
// exist for the one vendor that hands back its own storage host at runtime and
// are spelled out at each use.
type egressAllowance struct {
	hosts    []string
	suffixes []string
}

func (a egressAllowance) empty() bool { return len(a.hosts) == 0 && len(a.suffixes) == 0 }

// allows reports whether host is inside the allowance. Normalization matches
// providerAPIHost exactly (lowercase, explicit port stripped) so a spelling the
// inference allowlist would accept cannot be refused here and vice versa.
func (a egressAllowance) allows(host string) bool {
	h := providerAPIHost(host)
	if h == "" {
		return false
	}
	for _, want := range a.hosts {
		if h == providerAPIHost(want) {
			return true
		}
	}
	for _, suffix := range a.suffixes {
		s := strings.ToLower(suffix)
		if strings.HasSuffix(h, s) && len(h) > len(s) {
			return true
		}
	}
	return false
}

// describe renders the allowance for an error message.
func (a egressAllowance) describe() string {
	parts := append([]string{}, a.hosts...)
	for _, s := range a.suffixes {
		parts = append(parts, "*"+s)
	}
	if len(parts) == 0 {
		return "nowhere (this operation is not allowed to make outbound requests)"
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// withProviderEgress installs the authority for spending a vault secret through
// its configured provider. Call it wherever a stored (provider, provider_meta)
// pair is about to be handed to a KeyProvider.
func withProviderEgress(ctx context.Context, provider string, meta map[string]string) context.Context {
	return context.WithValue(ctx, egressAuthorityKey, egressAuthority{
		what:  "provider " + provider,
		allow: declaredProviderEgress(provider, meta),
	})
}

// providerEgressContextFor is what the three paths that SPEND a stored provider
// configuration call: POST /api/vault/{id}/validate, POST /api/vault/{id}/rotate
// and the scheduled sweep.
//
// It does two things the plain withProviderEgress does not, and both matter for
// a row this process did not write:
//
//   - it refuses when the entry is PINNED (an admin wired it into the AI gateway
//     via the AdminOnly ai_key_* setting) and the stored provider configuration
//     resolves anywhere other than that provider's own host. The write gate can
//     only guard writes it sees; this also refuses a row from an older binary, a
//     restored backup, or an import. That is the load-bearing half, because the
//     declared allowance for a meta-derived provider is computed FROM the same
//     meta and therefore cannot, by itself, tell a forged row from a real one.
//   - it fails closed on a read error rather than treating "cannot tell" as
//     "allowed", which is how a guard stops guarding without anybody noticing.
func providerEgressContextFor(ctx context.Context, q settingReader, entryID, provider string,
	meta map[string]string) (context.Context, error) {

	allow := declaredProviderEgress(provider, meta)
	pin, err := providerPinFor(ctx, q, entryID)
	if err != nil {
		return ctx, fmt.Errorf("the entry's AI provider binding could not be read, so its secret "+
			"was not sent anywhere: %w", err)
	}
	if pin.pinned() {
		for _, h := range allow.hosts {
			if !pin.allowsHost(h) {
				return ctx, fmt.Errorf("this secret is the instance's AI provider key and is only ever "+
					"delivered to %s, but its provider configuration resolves to %q. Unwire it in "+
					"Settings > AI gateway before using it as a general-purpose secret", pin.describe(), h)
			}
		}
		if len(allow.suffixes) > 0 {
			return ctx, fmt.Errorf("this secret is the instance's AI provider key and is only ever "+
				"delivered to %s; a provider whose host is chosen by the upstream cannot be used for it",
				pin.describe())
		}
	}
	return context.WithValue(ctx, egressAuthorityKey, egressAuthority{
		what:  "provider " + provider,
		allow: allow,
	}), nil
}

// withDeliveryEgress installs the authority for delivering a rotated secret to
// one operator-configured rotation target.
//
// The allowance is the target's own host, which sounds circular and is not: the
// point is that the chokepoint has NO default. A future delivery type that
// builds its host from somewhere other than the target row it was authorized
// against is refused rather than silently trusted, which is precisely how
// provider_meta got in.
func withDeliveryEgress(ctx context.Context, rawURL, what string) context.Context {
	var allow egressAllowance
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil && u.Hostname() != "" {
		allow.hosts = []string{u.Hostname()}
	}
	return context.WithValue(ctx, egressAuthorityKey, egressAuthority{what: what, allow: allow})
}

// withEgressRecorder attaches an observation hook. Tests only; see
// egressRecorderKey.
func withEgressRecorder(ctx context.Context, rec *[]egressAttempt) context.Context {
	return context.WithValue(ctx, egressRecorderKey, rec)
}

// providerDo is the ONE door every outbound provider and delivery request goes
// through. It is the derivation gate described at the top of this file.
//
// It deliberately takes no allowance argument. An argument is something a call
// site can get wrong quietly; a context value installed by whoever decrypted
// the secret is something a call site can only get wrong LOUDLY, because
// forgetting it refuses the request.
func providerDo(req *http.Request) (*http.Response, error) {
	auth, ok := req.Context().Value(egressAuthorityKey).(egressAuthority)
	host := ""
	if req.URL != nil {
		host = req.URL.Hostname()
	}

	var err error
	switch {
	case !ok:
		err = fmt.Errorf("egress refused: an outbound request to %q was built with no egress authority in "+
			"its context. Whoever resolves the secret must call withProviderEgress or withDeliveryEgress "+
			"first; see egress_authority.go", host)
	case !auth.allow.allows(host):
		err = fmt.Errorf("egress refused: %s may only reach %s, and %q is not that. If this host is "+
			"legitimate, declare it in providerEgress (egress_authority.go) so the write gate can also "+
			"require the right authority to choose it", auth.what, auth.allow.describe(), host)
	}

	if rec, hasRec := req.Context().Value(egressRecorderKey).(*[]egressAttempt); hasRec && rec != nil {
		reason := ""
		if err != nil {
			reason = err.Error()
		}
		*rec = append(*rec, egressAttempt{host: host, refused: err != nil, reason: reason})
	}

	if err != nil {
		return nil, err
	}
	return providerHTTP.Do(req)
}

// ── the declaration: which hosts each provider may reach ────────────────────

// providerEgressDecl is one provider's answer to "which hosts can your secret
// reach, given this provider_meta?".
//
// metaKeys is not decoration. It is the enumeration the write gate and the
// coverage guard both read: a provider_meta key listed here is understood to
// choose a destination, so changing it is an egress widening and needs the
// widening right. A key that feeds a URL and is NOT listed here is the bug this
// whole file exists to make impossible to ship, and
// TestProviderRequestsStayInsideTheirDeclaredHosts is what finds it.
type providerEgressDecl struct {
	metaKeys []string
	hosts    func(meta map[string]string) []string
	suffixes []string
	why      string
}

// fixedHost declares a provider that always speaks to one vendor host.
func fixedHost(hosts ...string) func(map[string]string) []string {
	return func(map[string]string) []string { return hosts }
}

// metaLabelHost declares a host built as <label>.<suffix> from a provider_meta
// value that is a single DNS label (grafana instance, auth0 tenant, supabase
// project ref).
func metaLabelHost(key, suffix string) func(map[string]string) []string {
	return func(meta map[string]string) []string {
		v := strings.TrimSpace(meta[key])
		if v == "" {
			return nil
		}
		return []string{strings.ToLower(v) + suffix}
	}
}

// metaURLHost declares a host taken from a provider_meta value that is a whole
// base URL (self-hosted zitadel, self-hosted forgejo).
func metaURLHost(key string) func(map[string]string) []string {
	return func(meta map[string]string) []string {
		u, err := url.Parse(strings.TrimSpace(meta[key]))
		if err != nil || u.Hostname() == "" {
			return nil
		}
		return []string{u.Hostname()}
	}
}

// providerEgress is the declaration table, one row per registered provider.
//
// TestEveryProviderDeclaresItsEgress enumerates the REAL ProviderRegistry and
// fails when a provider ships without a row here, so a new adapter cannot reach
// the network until somebody has written down where it goes. An absent row is
// not "unrestricted", it is "nowhere": providerDo refuses an empty allowance.
var providerEgress = map[string]providerEgressDecl{
	// ── fixed vendor hosts ──────────────────────────────────────────────
	"cloudflare":   {hosts: fixedHost("api.cloudflare.com"), why: "cloudflareAPIBase is a compile-time constant"},
	"vercel":       {hosts: fixedHost("api.vercel.com"), why: "literal endpoints"},
	"resend":       {hosts: fixedHost("api.resend.com"), why: "literal endpoints, including the deferred DELETE"},
	"sendgrid":     {hosts: fixedHost("api.sendgrid.com"), why: "literal endpoints, including the deferred DELETE"},
	"twilio":       {hosts: fixedHost("api.twilio.com"), why: "account_sid and key_sid land in the PATH, never the host"},
	"linode":       {hosts: fixedHost("api.linode.com"), why: "literal endpoints"},
	"neon":         {hosts: fixedHost("console.neon.tech"), why: "literal endpoints, including the deferred DELETE"},
	"fastly":       {hosts: fixedHost("api.fastly.com"), why: "literal endpoints"},
	"github":       {hosts: fixedHost("api.github.com"), why: "validate-only against a literal endpoint"},
	"openai":       {hosts: fixedHost("api.openai.com"), why: "validate-only against a literal endpoint"},
	"anthropic":    {hosts: fixedHost("api.anthropic.com"), why: "validate-only against a literal endpoint"},
	"stripe":       {hosts: fixedHost("api.stripe.com"), why: "validate-only against a literal endpoint"},
	"groq":         {hosts: fixedHost("api.groq.com"), why: "validate-only against a literal endpoint"},
	"mistral":      {hosts: fixedHost("api.mistral.ai"), why: "validate-only against a literal endpoint"},
	"together":     {hosts: fixedHost("api.together.xyz"), why: "validate-only against a literal endpoint"},
	"replicate":    {hosts: fixedHost("api.replicate.com"), why: "validate-only against a literal endpoint"},
	"digitalocean": {hosts: fixedHost("api.digitalocean.com"), why: "validate-only against a literal endpoint"},
	"hetzner":      {hosts: fixedHost("api.hetzner.cloud"), why: "validate-only against a literal endpoint"},
	"sentry":       {hosts: fixedHost("sentry.io"), why: "validate-only against a literal endpoint"},
	"postmark":     {hosts: fixedHost("api.postmarkapp.com"), why: "validate-only against a literal endpoint"},
	"mollie":       {hosts: fixedHost("api.mollie.com"), why: "validate-only against a literal endpoint"},
	"railway":      {hosts: fixedHost("backboard.railway.app"), why: "validate-only against a literal endpoint"},
	"render":       {hosts: fixedHost("api.render.com"), why: "validate-only against a literal endpoint"},

	// ── hosts chosen by provider_meta. These are the round-4 class. ──────
	//
	// Each of these is a legitimate feature (Datadog has regional sites, Grafana
	// Cloud and Auth0 and Supabase are per-tenant, Zitadel and Forgejo are
	// self-hosted). None of them is a field a reviewer would guess is a host,
	// which is exactly why the key is written down here: authorityForEgressChange
	// turns "this key moved" into "this needs the widening right" without anybody
	// having to remember that site is a host.
	"datadog": {
		metaKeys: []string{"site"},
		hosts: func(meta map[string]string) []string {
			site := strings.TrimSpace(meta["site"])
			if site == "" {
				site = "datadoghq.com" // the adapter's own default
			}
			return []string{"api." + strings.ToLower(site)}
		},
		why: `Rotate and Validate build "https://api."+meta["site"]; site is a whole domain, so it is the host`,
	},
	"grafana": {
		metaKeys: []string{"instance"},
		hosts:    metaLabelHost("instance", ".grafana.net"),
		why:      `Rotate and Validate build "https://"+meta["instance"]+".grafana.net"`,
	},
	"auth0": {
		metaKeys: []string{"tenant"},
		hosts:    metaLabelHost("tenant", ".auth0.com"),
		why:      `Rotate and Validate build "https://"+meta["tenant"]+".auth0.com"`,
	},
	"supabase": {
		metaKeys: []string{"project_ref"},
		hosts:    metaLabelHost("project_ref", ".supabase.co"),
		why:      `Validate builds "https://"+meta["project_ref"]+".supabase.co"`,
	},
	"zitadel": {
		metaKeys: []string{"instance"},
		hosts:    metaURLHost("instance"),
		why:      `self-hosted: meta["instance"] is the whole base URL`,
	},
	"forgejo": {
		metaKeys: []string{"instance"},
		hosts:    metaURLHost("instance"),
		why:      `self-hosted: meta["instance"] is the whole base URL`,
	},

	// ── the one vendor that names its own second host at runtime ────────
	"backblaze": {
		hosts: fixedHost("api.backblazeb2.com"),
		// b2_authorize_account answers with the account's storage apiUrl
		// (api005.backblazeb2.com and friends) and the delete call has to go
		// there. The chooser is Backblaze, authenticated as the key we just
		// minted, not anybody local, so the allowance is their own domain and
		// nothing wider.
		suffixes: []string{".backblazeb2.com"},
		why:      "b2_delete_key must follow the storage apiUrl Backblaze returns",
	},

	// ── providers that never make an outbound request ───────────────────
	//
	// Declared explicitly rather than omitted. An omission reads the same as an
	// oversight, and the whole point of this table is that the two are told
	// apart.
	"aws":              {why: "Rotate and Validate both refuse; the AWS SDK is not vendored"},
	"manual":           {why: "no provider API at all"},
	"shared-secret":    {why: "local generator; the value is created in-process"},
	"generated-key-32": {why: "local generator; the value is created in-process"},
}

// declaredProviderEgress resolves a provider's allowance for one entry's meta.
//
// An unknown provider gets an EMPTY allowance, which providerDo refuses. That
// is deliberate: an unrecognised provider name must not be a way to opt out of
// the gate.
func declaredProviderEgress(provider string, meta map[string]string) egressAllowance {
	decl, ok := providerEgress[strings.TrimSpace(provider)]
	if !ok {
		return egressAllowance{}
	}
	var allow egressAllowance
	if decl.hosts != nil {
		for _, h := range decl.hosts(meta) {
			h = providerAPIHost(h)
			if h != "" {
				allow.hosts = append(allow.hosts, h)
			}
		}
	}
	allow.suffixes = append(allow.suffixes, decl.suffixes...)
	sort.Strings(allow.hosts)
	return allow
}

// ── the write gate ──────────────────────────────────────────────────────────

// egressChange is what one write does to an entry's reachable host set.
type egressChange struct {
	// added are hosts the write puts within reach that were not before. A
	// non-empty added is a WIDENING and needs the widening right.
	added []string
	// after is the full resulting host set, for the pin check.
	after []string
}

// widensEgress reports whether this write adds reach.
func (c egressChange) widensEgress() bool { return len(c.added) > 0 }

// authorityForEgressChange computes what a (provider, provider_meta) write does
// to where this entry's secret can be sent.
//
// It is intentionally symmetric with widenedDestinations in secret_egress.go
// and answers the same question about a different pair of columns:
//
//	NARROWING or unchanged  anybody with manage. Clearing a provider is a
//	                        legitimate edit and taking it away would leave an
//	                        editor unable to correct a typo on a shared entry.
//	ADDING a host           the entry's creator or an instance admin, exactly as
//	                        for destination_patterns. Editing an entry is not the
//	                        right to choose where its value is delivered.
//
// Both sides are computed from the DECLARED host set, never from the raw column
// text, so "site: datadoghq.eu" -> "site: evil.example" is seen as adding
// api.evil.example rather than as an opaque string edit.
func authorityForEgressChange(beforeProvider string, beforeMeta map[string]string,
	afterProvider string, afterMeta map[string]string) egressChange {

	before := declaredProviderEgress(beforeProvider, beforeMeta)
	after := declaredProviderEgress(afterProvider, afterMeta)

	have := make(map[string]bool, len(before.hosts))
	for _, h := range before.hosts {
		have[h] = true
	}
	// A suffix allowance carried forward covers its own hosts. Only backblaze
	// has one and it is a compile-time constant, so this can never be used to
	// launder a new host in: it is here so re-saving an unchanged backblaze
	// entry is not reported as a widening.
	covered := func(h string) bool {
		if have[h] {
			return true
		}
		for _, s := range before.suffixes {
			if strings.HasSuffix(h, strings.ToLower(s)) && len(h) > len(s) {
				return true
			}
		}
		return false
	}

	var change egressChange
	change.after = append(change.after, after.hosts...)
	for _, h := range after.hosts {
		if !covered(h) {
			change.added = append(change.added, h)
		}
	}
	sort.Strings(change.added)
	return change
}

// egressInfluencingMetaKeys is every provider_meta key, across every declared
// provider, that feeds a host. Used by the refusal message and by the coverage
// guard, so an operator reading a 403 is told which field did it.
func egressInfluencingMetaKeys() []string {
	seen := map[string]bool{}
	var out []string
	for _, decl := range providerEgress {
		for _, k := range decl.metaKeys {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// reservedProviderMetaKeys are provider_meta keys the SERVER owns. They are
// transient markers written by an adapter mid-rotation and stripped before the
// column is persisted (see deferRevokeOldProviderKey's doc), so a client
// sending one is either confused or aiming a request.
//
// pending_revoke_url is the sharpest of them: performPendingRevoke issues
// method+URL straight out of the map with "Authorization: Bearer <the new
// secret>". A client that could plant it would have the rotation scheduler post
// the freshly minted credential wherever it said. providerDo refuses that today
// (the URL is outside the provider's declared hosts), and refusing the WRITE as
// well means the row never carries the attempt at all.
var reservedProviderMetaKeys = []string{pendingRevokeMethod, pendingRevokeURL, "last_revoke_error"}

// rejectReservedProviderMetaKeys reports the first server-owned key found in a
// client-supplied provider_meta, if any.
func rejectReservedProviderMetaKeys(meta map[string]string) (string, bool) {
	for _, k := range reservedProviderMetaKeys {
		if _, ok := meta[k]; ok {
			return k, true
		}
	}
	return "", false
}

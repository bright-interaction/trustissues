package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/bright-interaction/trustissues/internal/secretexit"
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
//
// ROUND 7 CHANGED WHERE THIS COMES FROM, AND ONLY THAT.
//
// providerDo is unchanged in spirit: it is still the one door every outbound
// provider and delivery request goes through, and it still refuses a host that
// is not the one the operation declared. What changed is who installs the
// declaration. There used to be three installers (withProviderEgress,
// withDeliveryEgress, providerEgressContextFor) and any new call site could add
// a fourth. Now there is exactly one, secretexit.Exit, and it is the same
// function that hands over the bytes: a request carrying a secret has a receipt
// because obtaining the secret is what created it.
//
// That closes the residual an argument-shaped gate always leaves. Claim a host
// the owner did not authorise and Exit refuses; claim one they did and then send
// somewhere else and providerDo refuses, because the receipt says where the
// exit was authorised FOR.

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

// egressAllowance is a host set. It is now secretexit.HostSet, so the set the
// exit authorised and the set the chokepoint enforces are literally the same
// type and cannot drift in their spelling rules.
type egressAllowance = secretexit.HostSet

// spendProviderSecret is what the three paths that SPEND a stored provider
// configuration call: POST /api/vault/{id}/validate, POST /api/vault/{id}/rotate
// and the scheduled sweep.
//
// It is the round-7 replacement for providerEgressContextFor plus
// withProviderEgress. Those installed an authority ALONGSIDE a plaintext the
// caller had already obtained; this one obtains the plaintext THROUGH the exit,
// so there is no arrangement of the code in which the value is in hand and the
// authority is not.
//
// It keeps the two things the old function did, and both still matter for a row
// this process did not write:
//
//   - the PIN. An entry an admin wired into the AI gateway (an AdminOnly ai_key_*
//     setting) is only ever delivered to that provider's own host, so a stored
//     provider configuration resolving anywhere else is refused. That is the
//     load-bearing half, because the declared allowance for a meta-derived
//     provider is computed FROM the same meta and cannot, by itself, tell a
//     forged row from a real one.
//   - it fails closed on a read error rather than treating "cannot tell" as
//     "allowed".
func spendProviderSecret(ctx context.Context, q settingReader, pt secretexit.Plaintext,
	entryID, provider string, meta map[string]string) (context.Context, string, error) {

	allow := declaredProviderEgress(provider, meta)
	pin, err := providerPinFor(ctx, q, entryID)
	if err != nil {
		return ctx, "", fmt.Errorf("the entry's AI provider binding could not be read, so its secret "+
			"was not sent anywhere: %w", err)
	}
	if pin.pinned() {
		for _, h := range allow.Hosts {
			if !pin.allowsHost(h) {
				return ctx, "", fmt.Errorf("this secret is the instance's AI provider key and is only ever "+
					"delivered to %s, but its provider configuration resolves to %q. Unwire it in "+
					"Settings > AI gateway before using it as a general-purpose secret", pin.describe(), h)
			}
		}
		if len(allow.Suffixes) > 0 {
			return ctx, "", fmt.Errorf("this secret is the instance's AI provider key and is only ever "+
				"delivered to %s; a provider whose host is chosen by the upstream cannot be used for it",
				pin.describe())
		}
	}
	// A provider that DECLARES NO HOSTS makes no outbound request: the local
	// generators (shared-secret, generated-key-32), manual, and aws (whose SDK is
	// not vendored). They still need the value, so it is released with an
	// IN-PROCESS destination, which mints no receipt. If one of them ever builds
	// a request, CheckHost refuses it for having no receipt at all, so the
	// failure is loud on the day it is written rather than an inherited pass.
	if allow.Empty() {
		return secretexit.ExitString(ctx, pt, secretexit.ToNowhere("provider "+provider+
			" (declares no hosts, so it may not egress)"))
	}
	// The destination is read off the SECRET'S OWN entry row (its provider and
	// provider_meta columns), so the authority re-derives what that entry
	// currently records and requires the host to be inside it.
	return secretexit.ExitString(ctx, pt, secretexit.ToHosts("provider "+provider,
		secretexit.ChosenByTheEntrysOwnRecord(), allow))
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
// site can get wrong quietly; a receipt minted by secretexit.Exit, in the same
// call that handed over the bytes, is something a call site can only get wrong
// LOUDLY, because a request built without one is refused.
func providerDo(req *http.Request) (*http.Response, error) {
	host := ""
	if req.URL != nil {
		host = req.URL.Hostname()
	}

	err := secretexit.CheckHost(req.Context(), host)

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
				allow.Hosts = append(allow.Hosts, h)
			}
		}
	}
	allow.Suffixes = append(allow.Suffixes, decl.suffixes...)
	sort.Strings(allow.Hosts)
	return allow
}

// metaIndependentProviderEgress is the part of a provider's allowance that NO
// writable field can move.
//
// It exists for the one question ownerRecordedDestinations has to ask about
// step 3: which of these hosts did somebody CHOOSE, and which are compile-time
// constants nobody had to vouch for. "openai -> api.openai.com" is written in
// providerEgress and in the adapter; no column moves it, so it needs no
// provenance. "forgejo -> whatever meta[instance] says" is the round-4 class and
// is exactly what an attacker holding the row writes.
//
// The answer is computed rather than listed: resolve the allowance with the
// entry's real meta, resolve it again with NO meta, and keep the intersection. A
// provider whose hosts ignore meta yields the same set both times and loses
// nothing. A provider whose hosts are built out of meta yields either nothing
// (grafana, auth0, supabase, zitadel, forgejo, whose builders return nil for an
// absent key) or its own vendor default (datadog's api.datadoghq.com), and keeps
// only the host it would have reached with the column blank.
//
// Computing it means a NEW meta-derived provider is covered on the day it is
// added, with nobody having to remember this function exists. Listing the
// meta-derived providers here instead would be the enumeration-of-inputs shape
// that rounds 3 through 6 kept losing to.
//
// Suffixes are carried through unchanged: only backblaze declares one, it is a
// compile-time constant, and declaredProviderEgress reads it straight off the
// declaration without consulting meta.
func metaIndependentProviderEgress(provider string, meta map[string]string) egressAllowance {
	withMeta := declaredProviderEgress(provider, meta)
	blank := declaredProviderEgress(provider, nil)

	keep := make(map[string]bool, len(blank.Hosts))
	for _, h := range blank.Hosts {
		keep[h] = true
	}
	var out egressAllowance
	for _, h := range withMeta.Hosts {
		if keep[h] {
			out.Hosts = append(out.Hosts, h)
		}
	}
	out.Suffixes = append(out.Suffixes, blank.Suffixes...)
	sort.Strings(out.Hosts)
	return out
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

	have := make(map[string]bool, len(before.Hosts))
	for _, h := range before.Hosts {
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
		for _, s := range before.Suffixes {
			if strings.HasSuffix(h, strings.ToLower(s)) && len(h) > len(s) {
				return true
			}
		}
		return false
	}

	var change egressChange
	change.after = append(change.after, after.Hosts...)
	for _, h := range after.Hosts {
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

// reservedProviderMetaKeys are provider_meta keys the SERVER owns. A client
// sending one is either confused or aiming a request.
//
// THEY DO REACH THE DATABASE. This comment used to say they were "stripped
// before the column is persisted, so they never reach the database", and every
// other surface was built on that absolute. It stopped being true the moment a
// failed deferred revoke was allowed to keep its retry coordinates: the markers
// are now the ONLY record of what to revoke and how, so performPendingRevoke
// deletes them on a confirmed success and deliberately preserves them on
// failure, and the caller persists meta right afterwards.
//
// Relaxing that invariant is a migration, not an edit. Three surfaces encoded
// the old absolute and had to move with it: this list's own write-path
// validator below (which still rejects client-supplied markers, and must),
// redactReservedProviderMetaKeys (new, because the read path handed the markers
// to a client that PUTs the whole map back), and the doc comments in
// vault_providers.go and vault_rotation_core.go. Anything added here that
// assumes a reserved key cannot be in a stored row is wrong.
//
// pending_revoke_url is the sharpest of them: performPendingRevoke issues
// method+URL straight out of the map, authenticated per pending_revoke_auth. A
// client that could plant pending_revoke_url would have the rotation scheduler
// post the freshly minted credential wherever it said. providerDo refuses that
// today (the URL is outside the provider's declared hosts), and refusing the
// WRITE as well means the row never carries the attempt at all.
//
// pending_revoke_auth is reserved for the same reason: it selects which
// credentials the deferred revoke sends ("basic" pairs a meta-recorded id with
// the new secret, "b2" drives a whole authorize-then-delete flow), so a client
// that could plant it could redirect what gets authenticated where, same as the
// method/URL pair.
var reservedProviderMetaKeys = []string{pendingRevokeMethod, pendingRevokeURL, pendingRevokeAuth, "last_revoke_error"}

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

// redactReservedProviderMetaKeys removes the server-owned keys from a
// provider_meta JSON object on its way OUT to a client, and returns the object
// re-encoded.
//
// THE VALIDATOR ABOVE AND THIS FUNCTION ARE ONE MECHANISM, NOT TWO.
//
// Once a failed revoke was allowed to persist its coordinates, the write-path
// validator alone became an operator lockout. The read path returned the whole
// decrypted column verbatim; RotationManager.tsx copies every string key into
// form state (they render no input, so nothing is visible on screen) and PUTs
// the entire map back on save. So the ordinary recovery flow (a revoke fails
// with a 503, the operator opens the rotation panel to correct the provider
// config that caused it, and clicks Save) resubmitted the markers the server
// had just written and was refused:
//
//	400 provider_meta may not contain pending_revoke_method: that key is
//	    written by the rotation engine itself
//
// The check is gated on the field being PRESENT, not CHANGED, and the Save
// button has no dirty-check, so an untouched resubmit tripped the same 400 as a
// hostile one. The live-but-unrevokable upstream key stayed live and the
// product's own remediation path was shut; recovery needed a hand-crafted PUT
// omitting the three keys, because the write is a full column replace.
//
// Redacting on the way out fixes that without weakening the validator: a client
// never learns the keys exist, so it cannot echo them back, and one that sends
// them anyway is still doing something it was never handed and is still
// refused. The alternative, tolerating a value byte-identical to what is
// stored, keeps a client-supplied marker on the accepted path and was rejected
// for that reason.
//
// last_revoke_error is redacted too, and loses nothing: the rotation responses
// lift it out and report it separately (vault.go and vault_rotation_core.go
// both read it, delete it, and surface it as a partial-rotation warning), and
// no frontend surface reads it off provider_meta.
//
// It reads the column through ParseProviderMeta, the SAME parse the validator
// uses, and that symmetry is the correctness argument rather than an accident:
// a key this function cannot see is a key rejectReservedProviderMetaKeys cannot
// see either, so it can never be the cause of the 400 above. A column that is
// not a JSON object of strings therefore returns unchanged: it carries no
// reserved key that either side can act on, and the read path's job is to
// render what is there, not to repair it.
func redactReservedProviderMetaKeys(raw string) string {
	meta := ParseProviderMeta(raw)
	if len(meta) == 0 {
		return raw
	}
	found := false
	for _, k := range reservedProviderMetaKeys {
		if _, ok := meta[k]; ok {
			delete(meta, k)
			found = true
		}
	}
	if !found {
		return raw
	}
	out, err := json.Marshal(meta)
	if err != nil {
		// Unreachable for map[string]string, and the safe direction if it ever
		// is reached: an empty object leaks nothing, where returning raw would
		// hand back the markers this function exists to remove.
		return "{}"
	}
	return string(out)
}

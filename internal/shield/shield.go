// Package shield is the LLM-boundary tokenizer for atomicsite's MCP server.
//
// When the MCP server returns data to an external agent (Claude on Anthropic,
// Groq, etc.), every PII field gets replaced with a marker of the form
//
//	[shield:<kind>:tok_<hex>:<hint>]
//
// The agent reasons over the marker plus its hint metadata (e.g. email
// domain, name initials, value length) without ever seeing the raw value.
// When the agent calls a write tool with marker-bearing arguments, the
// server resolves markers back to plaintext locally before executing the
// underlying logic. The agent + the upstream LLM provider never see the
// real value.
//
// Token format: "[shield:<kind>:tok_<hex>:<hint>]". <kind> is one of the
// constants in this file. tok_ + 8 hex chars is the lookup key. <hint>
// is a comma-separated key=value list whose keys must be whitelisted per
// kind (HintRules in this file). Hints are domain-truthful but never
// leak the raw value.
//
// Storage: per-MCP-connection rows in shield_sessions + shield_tokens.
// Ciphertext = base64(AES-256-GCM(value, ATOMICSITE_SHIELD_KEY)).
//
// Privacy invariant: when shield_enabled is on, no MCP tool response
// leaves this server with a tagged PII field in plaintext, and no MCP
// tool argument runs against the store with an unresolved marker.
package shield

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Kind is a PII category. Add new kinds by extending this list and
// updating HintRules + redactPatterns where applicable.
type Kind string

const (
	KindEmail        Kind = "email"
	KindName         Kind = "name"
	KindPhone        Kind = "phone"
	KindCompany      Kind = "company"
	KindPersonnummer Kind = "personnummer"
	KindIBAN         Kind = "iban"
	KindOrgNumber    Kind = "orgnr"
	KindFreeform     Kind = "freeform"
	// Infra identifiers and secrets that the dockyard MCP surface exposes
	// (server IPs, hostnames/FQDNs, SSH key fingerprints, API tokens / keys).
	// Kept lowercase-letter-only so MarkerPattern ([a-z]+) round-trips them.
	KindIPAddress      Kind = "ip"
	KindHostname       Kind = "hostname"
	KindSSHFingerprint Kind = "sshfp"
	KindSecret         Kind = "secret"
)

// HintRules is the whitelist of metadata keys allowed per kind. Any key
// not present in this map is rejected at Shield time so mistakes like
// hint="value=anna@example.com" cannot ship.
//
// `len_bucket` + `industry` are the HintBucketed/HintMinimal coarsened
// variants the buildHintAtLevel() pipeline emits; whitelisted on every
// kind so the bucketed pipeline doesn't get rejected.
var HintRules = map[Kind]map[string]bool{
	KindEmail:          {"domain": true, "len": true, "industry": true, "len_bucket": true},
	KindName:           {"initials": true, "len": true, "len_bucket": true},
	KindPhone:          {"country": true, "len": true, "len_bucket": true},
	KindCompany:        {"industry": true, "country": true, "len": true, "len_bucket": true},
	KindPersonnummer:   {"century": true, "len_bucket": true},
	KindIBAN:           {"country": true, "len_bucket": true},
	KindOrgNumber:      {"country": true, "len_bucket": true},
	KindFreeform:       {"len": true, "len_bucket": true},
	KindIPAddress:      {"len_bucket": true},
	KindHostname:       {"len_bucket": true},
	KindSSHFingerprint: {"len_bucket": true},
	KindSecret:         {"len_bucket": true},
}

// MarkerPattern matches a [shield:...] marker for unshield + redact
// passes. Groups: 1 = kind, 2 = token id (tok_<hex>), 3 = hint (or empty).
var MarkerPattern = regexp.MustCompile(`\[shield:([a-z]+):(tok_[0-9a-f]+)(?::([^\]]*))?\]`)

// FormatMarker produces "[shield:<kind>:<tokenID>:<hint>]" with hint
// omitted entirely when empty. tokenID must include the "tok_" prefix.
func FormatMarker(kind Kind, tokenID, hint string) string {
	if hint == "" {
		return fmt.Sprintf("[shield:%s:%s]", kind, tokenID)
	}
	return fmt.Sprintf("[shield:%s:%s:%s]", kind, tokenID, hint)
}

// validateHint enforces HintRules for the given kind. Returns nil when
// hint is empty or all key=value pairs fall in the whitelist.
func validateHint(kind Kind, hint string) error {
	if hint == "" {
		return nil
	}
	rules, ok := HintRules[kind]
	if !ok {
		return fmt.Errorf("shield: unknown kind %q", kind)
	}
	for _, kv := range strings.Split(hint, ",") {
		k, _, found := strings.Cut(strings.TrimSpace(kv), "=")
		if !found || k == "" {
			return fmt.Errorf("shield: malformed hint pair %q", kv)
		}
		if !rules[k] {
			return fmt.Errorf("shield: hint key %q not allowed for kind %q", k, kind)
		}
	}
	return nil
}

// Common errors returned by the Session API.
var (
	ErrSessionExpired = errors.New("shield: session expired")
	ErrTokenNotFound  = errors.New("shield: token not found in session")
	ErrUnknownKind    = errors.New("shield: unknown kind")
)

// HintLevel dials how much value-derived metadata the agent sees in
// markers. Pick per deployment based on the threat model.
//
// HintFull is the default and preserves backward-compat behavior:
// every key the tag declared is extracted (domain, initials, len,
// etc). Useful when the agent must reason about industry/role.
//
// HintBucketed coarsens specifics into ranges: domains map to
// industry buckets, lengths to short/medium/long. Lets the agent
// reason about category without leaking the exact identifier.
//
// HintMinimal exposes only `len_bucket` (or nothing) so two tokens
// can be told apart by rough size only. The right pick when the
// CRM is small enough that "domain=lawfirm.se" all but identifies
// the firm.
//
// HintNone strips every value-derived hint. Combined with
// deterministic token ids (Tokenize uses HMAC(session_key, value)),
// the agent still gets a stable per-session identity it can refer
// back to across turns, but no information about who that identity
// belongs to.
type HintLevel int

const (
	HintFull HintLevel = iota
	HintBucketed
	HintMinimal
	HintNone
)

// HintLevelNames lists every accepted TRUSTISSUES_SHIELD_HINT_LEVEL value, in
// decreasing order of disclosure. Exported so config validation can reject an
// unrecognised value and name the alternatives instead of guessing for the
// operator.
var HintLevelNames = []string{"full", "bucketed", "minimal", "none"}

// ValidHintLevel reports whether s is a recognised level.
//
// This exists because ParseHintLevel falls back to HintFull, the MOST verbose
// level, for anything it does not recognise. That default is right for a value
// that was never set, and dangerous for one that was set and misspelled: an
// operator writing "None", "nonw" or "minimum" is trying to REDUCE what leaves the
// building, and silently got the maximum instead (email domain, exact value length,
// personnummer century, all egressed to the model provider). It was the only Shield
// setting with no validation.
//
// So the parse stays lenient and the CONFIG refuses. A typo is a startup error, in
// the same spirit as the required-secret checks: never silently weaken a protection
// because an input was malformed.
func ValidHintLevel(s string) bool {
	for _, n := range HintLevelNames {
		if s == n {
			return true
		}
	}
	return false
}

// ParseHintLevel maps env-var strings to a HintLevel. Unknown values
// fall back to HintFull (safe default that preserves the v1 surface).
// Callers that read operator input must gate on ValidHintLevel first.
func ParseHintLevel(s string) HintLevel {
	switch s {
	case "bucketed":
		return HintBucketed
	case "minimal":
		return HintMinimal
	case "none":
		return HintNone
	default:
		return HintFull
	}
}

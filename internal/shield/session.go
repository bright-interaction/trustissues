package shield

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Store is the minimal logical surface Session needs. Each calling
// service supplies an implementation: shield.SQLStore wraps database/sql
// (SQLite) for atomicsite + dockyard; brightcrm's mcp package provides a
// pgx-backed implementation. The interface keeps the shield package
// pure logic + crypto so the same code ships unchanged across services.
type Store interface {
	// InsertSession creates one row in shield_sessions. id is the MCP
	// connection identifier; expiresAt is absolute UTC.
	InsertSession(ctx context.Context, id string, expiresAt time.Time) error

	// GetSession returns the stored expiry. found=false when the id is
	// unknown. err is non-nil only on driver-level failure.
	GetSession(ctx context.Context, id string) (expiresAt time.Time, found bool, err error)

	// UpdateSessionExpiry refreshes last_seen + expires_at on an
	// existing session. No-op when id is unknown (caller treats that
	// case as create).
	UpdateSessionExpiry(ctx context.Context, id string, expiresAt time.Time) error

	// SweepExpiredSessions deletes every session whose expires_at is
	// strictly before the given cutoff. ON DELETE CASCADE removes the
	// associated tokens.
	SweepExpiredSessions(ctx context.Context, before time.Time) error

	// InsertToken records one new token. token is the "tok_<hex>" id
	// (no marker brackets); kind/hint are the metadata; ciphertext is
	// base64 AES-256-GCM(value, key).
	InsertToken(ctx context.Context, sessionID, token, kind, hint, ciphertext string) error

	// GetTokenCiphertext returns the encrypted blob for the token if
	// it is bound to sessionID. found=false when the token is unknown
	// or belongs to a different session (the caller treats both as
	// ErrTokenNotFound for replay protection).
	GetTokenCiphertext(ctx context.Context, sessionID, token string) (ciphertext string, found bool, err error)
}

// Session is one MCP connection's token vault. Safe for concurrent
// use; the Store implementation is responsible for its own locking.
type Session struct {
	ID        string
	store     Store
	key       []byte // master key (used for value encryption)
	subkey    []byte // per-session HMAC key (used for deterministic token ids)
	ttl       time.Duration
	hintLevel HintLevel
}

// NewSession looks up an existing session and touches expires_at, or
// creates a fresh row when the id is unknown. Returns an active
// Session bound to the given store + key. Caller is expected to have
// authenticated the MCP request (X-Agent-Key, etc.) before calling.
//
// hintLevel controls how much value-derived metadata appears on
// markers. HintFull is the default; pass HintMinimal/HintNone for
// stricter deployments where the moat needs to deny the agent
// the ability to reason about who a token represents.
//
// Expired sessions are auto-revived. See atomicsite shield/session.go
// for the long-form rationale; in short, the X-Agent-Key auth check
// upstream is the security boundary and the TTL is housekeeping. Old
// tokens cascade away via SweepExpiredSessions before the new row is
// inserted so the agent cannot redeem stale markers across the gap.
func NewSession(ctx context.Context, store Store, sessionID string, key []byte, ttl time.Duration, hintLevel HintLevel) (*Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("shield: empty session id")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("shield: key must be 32 bytes, got %d", len(key))
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	newExpiry := now.Add(ttl)

	expiresAt, found, err := store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("shield: lookup session: %w", err)
	}
	if found && expiresAt.Before(now) {
		if err := store.SweepExpiredSessions(ctx, now); err != nil {
			return nil, fmt.Errorf("shield: sweep expired: %w", err)
		}
		found = false
	}
	if found {
		if err := store.UpdateSessionExpiry(ctx, sessionID, newExpiry); err != nil {
			return nil, fmt.Errorf("shield: touch session: %w", err)
		}
	} else {
		if err := store.InsertSession(ctx, sessionID, newExpiry); err != nil {
			return nil, fmt.Errorf("shield: create session: %w", err)
		}
	}
	return &Session{
		ID:        sessionID,
		store:     store,
		key:       key,
		subkey:    derivedSessionKey(key, sessionID),
		ttl:       ttl,
		hintLevel: hintLevel,
	}, nil
}

// SweepExpired deletes session rows past their expires_at. Cascading
// FK takes the tokens with them. Safe to call from a janitor goroutine.
func SweepExpired(ctx context.Context, store Store) error {
	return store.SweepExpiredSessions(ctx, time.Now().UTC())
}

// Tokenize records one new token and returns its full marker string.
// hint may be empty. Returns ErrUnknownKind for unsupported kinds and
// a wrapped error for non-whitelisted hint keys.
//
// Determinism: the token id is HMAC-SHA256(per-session-subkey, kind +
// value), truncated to 12 hex. The same input within the same session
// always produces the same marker, so the agent can recognise a
// recurring entity across turns; different sessions produce different
// markers, so cross-session linkability is broken. InsertToken is
// idempotent: a second call with the same id is a no-op (the row
// already maps to the right ciphertext).
func (s *Session) Tokenize(ctx context.Context, kind Kind, value, hint string) (string, error) {
	if _, ok := HintRules[kind]; !ok {
		return "", ErrUnknownKind
	}
	if err := validateHint(kind, hint); err != nil {
		return "", err
	}
	tokenID := deterministicTokenID(s.subkey, kind, value)
	ct, err := encrypt(value, s.key)
	if err != nil {
		return "", err
	}
	if err := s.store.InsertToken(ctx, s.ID, tokenID, string(kind), hint, ct); err != nil {
		return "", fmt.Errorf("shield: insert token: %w", err)
	}
	return FormatMarker(kind, tokenID, hint), nil
}

// Resolve maps a "tok_<hex>" id back to its plaintext value. Returns
// ErrTokenNotFound when the id is unknown or scoped to another session
// (replay protection: tokens issued for session A cannot be redeemed
// in session B).
func (s *Session) Resolve(ctx context.Context, tokenID string) (string, error) {
	if !strings.HasPrefix(tokenID, "tok_") {
		return "", ErrTokenNotFound
	}
	ct, found, err := s.store.GetTokenCiphertext(ctx, s.ID, tokenID)
	if err != nil {
		return "", fmt.Errorf("shield: lookup token: %w", err)
	}
	if !found {
		return "", ErrTokenNotFound
	}
	return decrypt(ct, s.key)
}

// Shield walks v recursively and replaces every shield-tagged string
// field with a marker. v must be a pointer to a struct. Untagged
// fields, non-string types, and unexported fields pass through. Slices,
// maps, pointers, and interfaces are descended.
//
// Tag format: `shield:"tokenize,kind=email,hint=domain len"`. The kind=
// part is required; hint= is optional and lists the metadata keys to
// auto-extract from the value.
//
// `shield:"id"` and `shield:"-"` are explicit "leave alone" markers
// (the field is not tokenized but is still descended for nested types).
func (s *Session) Shield(ctx context.Context, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf("shield: Shield requires a pointer, got %T", v)
	}
	return s.shieldValue(ctx, rv.Elem())
}

func (s *Session) shieldValue(ctx context.Context, rv reflect.Value) error {
	if !rv.IsValid() {
		return nil
	}
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return s.shieldValue(ctx, rv.Elem())
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if err := s.shieldValue(ctx, rv.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := rv.MapRange()
		for iter.Next() {
			elem := iter.Value()
			tmp := reflect.New(elem.Type()).Elem()
			tmp.Set(elem)
			if err := s.shieldValue(ctx, tmp); err != nil {
				return err
			}
			rv.SetMapIndex(iter.Key(), tmp)
		}
	case reflect.Struct:
		t := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := f.Tag.Get("shield")
			fv := rv.Field(i)
			if tag == "" || tag == "-" || tag == "id" {
				if err := s.shieldValue(ctx, fv); err != nil {
					return err
				}
				continue
			}
			kind, hintKeys, err := parseShieldTag(tag)
			if err != nil {
				return err
			}
			if err := s.shieldField(ctx, fv, kind, hintKeys); err != nil {
				return err
			}
		}
	}
	return nil
}

// shieldField replaces a single tagged field's value with its marker.
// String fields are tokenized; pointer-to-string is dereferenced and
// tokenized in place. Other types pass through (logged via the tag
// validator: a tag on a non-string field is a programmer error caught
// in the unit tests).
func (s *Session) shieldField(ctx context.Context, fv reflect.Value, kind Kind, hintKeys []string) error {
	if !fv.CanSet() {
		return fmt.Errorf("shield: tagged field is not settable (likely unexported)")
	}
	switch fv.Kind() {
	case reflect.String:
		raw := fv.String()
		if raw == "" {
			return nil
		}
		hint := buildHintAtLevel(kind, raw, hintKeys, s.hintLevel)
		marker, err := s.Tokenize(ctx, kind, raw, hint)
		if err != nil {
			return err
		}
		fv.SetString(marker)
	case reflect.Ptr:
		if !fv.IsNil() {
			return s.shieldField(ctx, fv.Elem(), kind, hintKeys)
		}
	}
	return nil
}

// Unshield walks v recursively and replaces every shield marker back
// to its plaintext. Used by write-tool argument handlers before
// executing the underlying logic. Markers belonging to other sessions
// or expired tokens cause the call to fail with ErrTokenNotFound,
// which write handlers should surface as an MCP error to the agent.
func (s *Session) Unshield(ctx context.Context, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf("shield: Unshield requires a pointer, got %T", v)
	}
	return s.unshieldValue(ctx, rv.Elem())
}

func (s *Session) unshieldValue(ctx context.Context, rv reflect.Value) error {
	if !rv.IsValid() {
		return nil
	}
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return s.unshieldValue(ctx, rv.Elem())
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if err := s.unshieldValue(ctx, rv.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := rv.MapRange()
		for iter.Next() {
			elem := iter.Value()
			tmp := reflect.New(elem.Type()).Elem()
			tmp.Set(elem)
			if err := s.unshieldValue(ctx, tmp); err != nil {
				return err
			}
			rv.SetMapIndex(iter.Key(), tmp)
		}
	case reflect.Struct:
		for i := 0; i < rv.NumField(); i++ {
			if err := s.unshieldValue(ctx, rv.Field(i)); err != nil {
				return err
			}
		}
	case reflect.String:
		if rv.CanSet() {
			out, err := s.UnshieldString(ctx, rv.String())
			if err != nil {
				return err
			}
			rv.SetString(out)
		}
	}
	return nil
}

// UnshieldString resolves every [shield:...] marker in the input back
// to plaintext. Strings without markers are returned unchanged.
func (s *Session) UnshieldString(ctx context.Context, in string) (string, error) {
	if !strings.Contains(in, "[shield:") {
		return in, nil
	}
	var firstErr error
	out := MarkerPattern.ReplaceAllStringFunc(in, func(match string) string {
		groups := MarkerPattern.FindStringSubmatch(match)
		if len(groups) < 3 {
			return match
		}
		tokenID := groups[2]
		pt, err := s.Resolve(ctx, tokenID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return match
		}
		return pt
	})
	return out, firstErr
}

// UnshieldJSON parses a JSON document, walks every string node, and
// resolves markers back to plaintext. Returns the re-marshaled JSON.
// Convenient for MCP tool-call argument blobs that arrive as
// json.RawMessage.
func (s *Session) UnshieldJSON(ctx context.Context, raw []byte) ([]byte, error) {
	v, err := decodeJSONExact(raw)
	if err != nil {
		return nil, err
	}
	// Keep the partial result: a marker this session cannot resolve must not cost
	// the caller every marker it CAN resolve. The error is returned alongside so
	// the caller can log it, and a genuine marshal failure is still fatal.
	resolved, unshieldErr := s.unshieldAny(ctx, v)
	out, marshalErr := json.Marshal(resolved)
	if marshalErr != nil {
		return nil, fmt.Errorf("shield: marshal: %w", marshalErr)
	}
	return out, unshieldErr
}

// ShieldJSON parses a JSON document, walks every string node, runs the
// regex bank over each string value to replace any inline PII with
// markers, and returns the re-marshaled JSON. Used by the MCP
// dispatcher as a safety net so tool handlers that build raw JSON
// without typed structs still get redacted output. Strings that already
// contain markers are not touched (the redact pass is idempotent).
func (s *Session) ShieldJSON(ctx context.Context, raw []byte) ([]byte, error) {
	v, err := decodeJSONExact(raw)
	if err != nil {
		return nil, err
	}
	redacted, err := s.shieldAny(ctx, v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(redacted)
}

// decodeJSONExact decodes into any WITHOUT turning numbers into float64.
//
// Both JSON entry points used plain json.Unmarshal, which decodes every number
// as a float64 and then re-marshals it. That is lossy above 2^53 and it changes
// the literal below it, so merely enabling Shield silently rewrote payloads it
// was only supposed to redact, in BOTH directions (request and response):
//
//	{"seed":9007199254740993}       ->  {"seed":9007199254740992}
//	{"external_id":12345678901234567890} -> {"external_id":12345678901234567000}
//	{"temperature":1.0}             ->  {"temperature":1}
//
// with err == nil every time. Snowflake ids, ledger amounts and idempotency
// keys are exactly the large integers that travel through an API gateway, and a
// privacy control must not corrupt the data it passes through.
//
// json.Number keeps the original literal as a string, and json.Marshal writes
// it back verbatim. It is a distinct type from string, so the redaction walk
// skips it the same way it skipped float64.
func decodeJSONExact(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("shield: unmarshal: %w", err)
	}
	return v, nil
}

// dereferencedURLKeys are JSON keys whose string value is a URL the PROVIDER
// will fetch, not prose the model reads.
//
// shieldAny has no knowledge of the key, so every string leaf went through
// RedactString and the hostname pattern rewrote these into
// [shield:hostname:tok_...]. The provider then tried to fetch that as a URL and
// returned 400, so a vision request with an image_url, a document URL, or an
// mcp_servers block failed outright whenever Shield was on. Tokenizing them
// protects nothing either: the caller chose the destination and the provider has
// to resolve it to do the work.
var dereferencedURLKeys = map[string]bool{
	"url": true, "image_url": true, "audio_url": true, "video_url": true,
	"document_url": true, "file_url": true, "source_url": true, "server_url": true,
}

func (s *Session) shieldAny(ctx context.Context, v any) (any, error) {
	return s.shieldAnyUnderKey(ctx, "", v)
}

// shieldAnyUnderKey carries the enclosing JSON key so leaves that are
// provider-dereferenced URLs can be left intact.
func (s *Session) shieldAnyUnderKey(ctx context.Context, key string, v any) (any, error) {
	switch t := v.(type) {
	case string:
		// The exemption is for URLs the provider has to FETCH, so it is gated on
		// the value actually being one. Keying it on the enclosing name alone
		// exempted any content that happened to sit under a url-ish key:
		//
		//	{"url":"anna@example.se"}              -> unredacted
		//	{"url":["anna@example.se","+46 70..."]} -> every element unredacted
		//
		// and because an array inherits its parent key, that covered every string
		// leaf at any depth beneath url, image_url, audio_url, video_url,
		// document_url, file_url, source_url and server_url. A caller putting a
		// customer list under "source_url" got no redaction at all.
		if dereferencedURLKeys[key] && looksLikeDereferenceableURL(t) {
			return t, nil
		}
		return s.RedactString(ctx, t)
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			// An array inherits its parent key: image_url: [...] is still a list
			// of URLs.
			r, err := s.shieldAnyUnderKey(ctx, key, item)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			r, err := s.shieldAnyUnderKey(ctx, k, val)
			if err != nil {
				return nil, err
			}
			// The KEY is content too. The walker used to recurse into values only
			// and copy keys straight through, so an address, phone number,
			// personnummer or IBAN used as an object key egressed verbatim:
			//
			//	{"anna@example.se":"note about the client"}  -> unchanged
			//
			// That shape is not exotic. A per-customer aggregation keys on the
			// customer, and a tool_use.input object or an input_schema.properties
			// map carried in conversation history can key on anything the caller
			// chose. Redacting is a no-op for ordinary schema names because they do
			// not match any pattern.
			//
			// unshieldAny restores keys symmetrically; the two must always be
			// changed together or the round-trip silently stops returning the
			// original document.
			outKey, kErr := s.RedactString(ctx, k)
			if kErr != nil {
				return nil, kErr
			}
			out[outKey] = r
		}
		return out, nil
	default:
		return v, nil
	}
}

// unshieldAny walks the document resolving markers. It keeps the PARTIAL result
// and reports the first error, rather than discarding everything.
//
// It used to `return nil, err` on the first unresolvable marker, which made the
// whole response fall back to the shielded body: one bad marker anywhere and the
// caller got [shield:email:tok_...] instead of every address in the document,
// with a 200 and no indication why. That is easy to trigger without meaning to,
// because the model is free to reformat: quoting a marker with one digit
// mistyped, or abbreviating it, is enough. Untrusted text being summarised can
// also contain a marker-shaped string, which then breaks resolution of the real
// ones.
//
// UnshieldString already has exactly this contract (leave what it cannot resolve
// in place, keep going), so the walk was the only piece disagreeing.
func (s *Session) unshieldAny(ctx context.Context, v any) (any, error) {
	switch t := v.(type) {
	case string:
		// UnshieldString returns its partial result alongside any error.
		return s.UnshieldString(ctx, t)
	case []any:
		var firstErr error
		out := make([]any, len(t))
		for i, item := range t {
			r, err := s.unshieldAny(ctx, item)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			out[i] = r
		}
		return out, firstErr
	case map[string]any:
		var firstErr error
		out := make(map[string]any, len(t))
		for k, val := range t {
			r, err := s.unshieldAny(ctx, val)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			// Keys are shielded (see shieldAnyUnderKey), so they must be unshielded
			// too. Restoring values but not keys would return a document whose keys
			// are still markers.
			outKey, kErr := s.UnshieldString(ctx, k)
			if kErr != nil && firstErr == nil {
				firstErr = kErr
			}
			out[outKey] = r
		}
		return out, firstErr
	default:
		return v, nil
	}
}

// parseShieldTag splits "tokenize,kind=email,hint=domain len" into
// kind + an ordered list of hint keys. The "tokenize" verb is
// currently the only one; the slot exists so future verbs (drop,
// hash) can plug in without changing the tag format.
func parseShieldTag(tag string) (Kind, []string, error) {
	parts := strings.Split(tag, ",")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) != "tokenize" {
		return "", nil, fmt.Errorf("shield: tag must start with 'tokenize', got %q", tag)
	}
	var kind Kind
	var hintKeys []string
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		k, v, found := strings.Cut(p, "=")
		if !found {
			return "", nil, fmt.Errorf("shield: malformed tag part %q", p)
		}
		switch k {
		case "kind":
			kind = Kind(v)
		case "hint":
			for _, hk := range strings.Split(v, " ") {
				hk = strings.TrimSpace(hk)
				if hk != "" {
					hintKeys = append(hintKeys, hk)
				}
			}
		default:
			return "", nil, fmt.Errorf("shield: unknown tag key %q", k)
		}
	}
	if kind == "" {
		return "", nil, errors.New("shield: tag missing kind")
	}
	if _, ok := HintRules[kind]; !ok {
		return "", nil, fmt.Errorf("shield: tag references unknown kind %q", kind)
	}
	return kind, hintKeys, nil
}

// buildHint is buildHintAtLevel(HintFull). Kept for free-form-text
// callers (RedactString) that don't carry a per-call level.
func buildHint(kind Kind, raw string, keys []string) string {
	return buildHintAtLevel(kind, raw, keys, HintFull)
}

// buildHintAtLevel extracts the hint keys named in the tag from the
// raw value, then filters/coarsens based on level.
//
//   - HintFull: every whitelisted key passes through verbatim.
//   - HintBucketed: domain -> industry-bucket, len -> short|medium|long,
//     initials -> first-letter-only. Lets the agent reason in coarse
//     categories without leaking the specific identifier.
//   - HintMinimal: only `len_bucket` survives (small/medium/large).
//   - HintNone: empty string. Combined with deterministic per-session
//     token ids, the agent gets stable identity without any value-
//     derived metadata at all.
func buildHintAtLevel(kind Kind, raw string, keys []string, level HintLevel) string {
	if level == HintNone {
		return ""
	}
	if level == HintMinimal {
		return "len_bucket=" + lengthBucket(raw)
	}
	if len(keys) == 0 {
		return ""
	}
	rules := HintRules[kind]
	var pairs []string
	for _, k := range keys {
		if !rules[k] {
			continue
		}
		v := extractHint(kind, raw, k)
		if v == "" {
			continue
		}
		if level == HintBucketed {
			v = bucketHintValue(kind, k, v)
			if v == "" {
				continue
			}
			k = bucketHintKey(k)
		} else if k == "domain" {
			// The domain hint is coarsened at EVERY level, not just bucketed.
			//
			// It published raw[at+1:] verbatim, which is the one thing a hint
			// must never do: emit a value Shield's own rules classify as
			// sensitive. The same string standalone is tokenized:
			//
			//	connect to edge-node.internal   ->  [shield:hostname:tok_...]
			//	mail admin@edge-node.internal   ->  [shield:email:...,domain=edge-node.internal]
			//
			// so redacting an address republished the infrastructure hostname
			// inside the marker that was supposed to conceal it, on EVERY email,
			// with an IP literal (user@192.168.1.1) as the sharpest case rather
			// than a special one. looksLikeHostname claims essentially every real
			// domain, so there is no subset that is safe to print verbatim.
			//
			// The industry bucket keeps what the agent actually reasons over
			// (personal webmail vs business vs government) and drops the
			// identifier. Emitted under the "industry" key so the marker does not
			// claim to carry a domain it no longer carries.
			v = domainIndustry(v)
			if v == "" {
				continue
			}
			k = "industry"
		}
		pairs = append(pairs, k+"="+sanitizeHintValue(v))
	}
	return strings.Join(pairs, ",")
}

// sanitizeHintValue strips characters that would break the marker grammar.
//
// Hint values were interpolated straight into [shield:kind:token:k=v,...], so a
// value containing "]" ended the marker early and the remainder of the hint was
// emitted as ordinary text. That corrupts the round trip: UnshieldJSON then
// restores against a marker whose closing bracket is in the wrong place and
// returns mangled output with err == nil, which is the silent-corruption shape
// this codebase keeps producing. Separators are stripped too, since "," and "="
// delimit the pairs and ":" delimits the marker fields.
func sanitizeHintValue(v string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '[', ']', ':', ',', '=':
			return -1
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// lengthBucket coarsens a raw value's length into small/medium/large
// so the agent can tell two markers apart by rough size without
// learning the exact count of characters.
func lengthBucket(raw string) string {
	switch n := len(raw); {
	case n <= 8:
		return "small"
	case n <= 32:
		return "medium"
	default:
		return "large"
	}
}

// bucketHintValue rewrites a full-mode hint value into a coarser
// HintBucketed equivalent. Returns "" to suppress entirely (the
// caller drops the pair).
func bucketHintValue(kind Kind, key, full string) string {
	switch key {
	case "len":
		return lengthBucket(full)
	case "domain":
		return domainIndustry(full)
	case "initials":
		if full == "" {
			return ""
		}
		return string(full[0])
	case "country":
		return full
	case "century":
		return full
	}
	return ""
}

// bucketHintKey renames a key when its semantics change between
// HintFull and HintBucketed (len -> len_bucket, domain -> industry).
func bucketHintKey(key string) string {
	switch key {
	case "len":
		return "len_bucket"
	case "domain":
		return "industry"
	}
	return key
}

// domainIndustry maps a known TLD or 2nd-level pattern to a coarse
// category. Unknown domains return "other" so the agent can
// distinguish "personal-ish" from "business" without learning the
// specific firm name.
func domainIndustry(domain string) string {
	d := strings.ToLower(domain)
	switch {
	case strings.HasSuffix(d, ".gov"), strings.HasSuffix(d, ".gov.se"):
		return "government"
	case strings.HasSuffix(d, ".edu"), strings.HasSuffix(d, ".ac.uk"):
		return "academic"
	case strings.HasSuffix(d, "gmail.com"),
		strings.HasSuffix(d, "outlook.com"),
		strings.HasSuffix(d, "icloud.com"),
		strings.HasSuffix(d, "yahoo.com"),
		strings.HasSuffix(d, "hotmail.com"),
		strings.HasSuffix(d, "proton.me"),
		strings.HasSuffix(d, "protonmail.com"):
		return "personal"
	default:
		return "business"
	}
}

// extractHint returns the value of one whitelisted hint key for the
// given kind + raw value. Centralised so HintRules + this function
// are the only places to update when a new hint key is added.
func extractHint(kind Kind, raw, key string) string {
	switch key {
	case "len":
		return fmt.Sprintf("%d", len(raw))
	case "domain":
		if kind == KindEmail {
			if at := strings.LastIndex(raw, "@"); at >= 0 && at < len(raw)-1 {
				return raw[at+1:]
			}
		}
	case "initials":
		if kind == KindName {
			fields := strings.Fields(raw)
			var b strings.Builder
			for _, f := range fields {
				if f != "" {
					b.WriteByte(f[0])
				}
			}
			return strings.ToUpper(b.String())
		}
	case "country":
		switch kind {
		case KindPhone:
			if strings.HasPrefix(raw, "+46") {
				return "SE"
			}
			if strings.HasPrefix(raw, "+1") {
				return "US"
			}
			if strings.HasPrefix(raw, "+44") {
				return "GB"
			}
		case KindIBAN:
			if len(raw) >= 2 {
				return strings.ToUpper(raw[:2])
			}
		}
	case "century":
		if kind == KindPersonnummer && len(raw) >= 2 {
			if raw[0] == '1' || raw[0] == '2' {
				return raw[:2]
			}
		}
	}
	return ""
}

// looksLikeDereferenceableURL reports whether a value under a url-ish key is
// actually something a provider would fetch.
//
// Deliberately narrow: an absolute http(s) URL or a data: URI. The exemption
// exists so Shield does not corrupt a link or an inline attachment the provider
// must dereference, and nothing else under those keys has that justification.
func looksLikeDereferenceableURL(v string) bool {
	t := strings.TrimSpace(v)
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return true
	}
	// A bare "data:" prefix was a general redaction off-switch.
	//
	// The exemption exists for BINARY payloads the provider decodes rather than
	// reads as prose (an inline image on a vision request). "data:" alone also
	// covers data:text/plain, so anything under a url-ish key prefixed with it
	// egressed verbatim:
	//
	//	{"image_url":"data:text/plain,anna@example.se +46 70 123 45 67"}
	//
	// Restricted to non-text media with base64 content, which is what the
	// exemption was actually for. A text/* payload is prose and gets redacted
	// like any other string.
	if !strings.HasPrefix(t, "data:") {
		return false
	}
	meta, _, found := strings.Cut(strings.TrimPrefix(t, "data:"), ",")
	if !found {
		return false
	}
	meta = strings.ToLower(meta)
	if !strings.HasSuffix(meta, ";base64") {
		return false
	}
	mediaType := strings.TrimSuffix(meta, ";base64")
	// An omitted media type defaults to text/plain per RFC 2397.
	if mediaType == "" || strings.HasPrefix(mediaType, "text/") {
		return false
	}
	return true
}

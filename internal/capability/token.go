// Package capability mints and verifies short-lived signed tokens that
// represent permission to use a specific vault secret against a specific
// destination, for a specific HTTP method, for a single use, within a
// short time window.
//
// The substitution proxy in handlers/capability.go consumes these tokens
// and swaps the real secret into the outbound request. The AI agent
// never sees the secret value; it only ever holds the token.
//
// # Format
//
// Token is base64url(payload).base64url(hmac-sha256(payload, key))
// where payload is the JSON-encoded Token struct. We avoid a full JWT
// library to keep the parser tiny and the threat surface obvious; the
// signed payload is two segments only.
//
// The signing key is derived from the trustissues vault key via HKDF
// with a "capability/v1" info string so a vault-key disclosure does
// not let an attacker mint capability tokens unless they also know the
// derivation context (and vice versa). The handler holds the derived
// key in memory only.
package capability

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Token is the canonical capability payload. Field names are kept short
// because they appear in every outbound request header.
type Token struct {
	V        int      `json:"v"`         // schema version
	Secret   string   `json:"secret"`    // vault entry name
	SecretID string   `json:"secret_id"` // vault entry id (immutable; defends against rename races)
	Agent    string   `json:"agent"`     // requesting agent_id
	Dests    []string `json:"dests"`     // allowed host+path globs (e.g. "api.cloudflare.com/*")
	Method   string   `json:"method"`    // allowed HTTP method, "*" for any
	IAT      int64    `json:"iat"`       // issued-at, unix seconds
	EXP      int64    `json:"exp"`       // expires-at, unix seconds
	Nonce    string   `json:"nonce"`     // hex-encoded 16 random bytes; single-use
}

// SigningKey is the HMAC-SHA256 key used to sign capability tokens.
// Always 32 bytes. Derive via DeriveSigningKey from the vault key.
type SigningKey [32]byte

// DeriveSigningKey turns the trustissues secret-source string into a
// dedicated capability signing key via HKDF-SHA256.
//
// The source is cfg.VaultKey (the same source the vault encryption key
// derives from). We HKDF it with a fixed info label so the capability
// key is cryptographically distinct from the vault encryption key
// derived from the same source: leaking one does not reveal the other
// without also breaking SHA-256.
func DeriveSigningKey(source string) (SigningKey, error) {
	if len(source) < 16 {
		return SigningKey{}, fmt.Errorf("capability: signing source too short (%d, need >=16)", len(source))
	}
	salt := []byte("trustissues:capability:v1:salt")
	info := []byte("trustissues:capability:v1:hmac")
	r := hkdf.New(sha256.New, []byte(source), salt, info)
	var key SigningKey
	if _, err := r.Read(key[:]); err != nil {
		return SigningKey{}, fmt.Errorf("capability: hkdf: %w", err)
	}
	return key, nil
}

// NewNonce returns a hex-encoded 16-byte cryptographic random nonce.
func NewNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("capability: nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Sign serializes t and returns "<payload>.<sig>" where both segments
// are base64url-without-padding. Mutates t.IAT/EXP/Nonce only when they
// are zero so callers can pre-fill them for tests; production callers
// pass an empty Token and let Sign default everything but the
// caller-controlled fields (Secret, SecretID, Agent, Dests, Method).
func Sign(t Token, key SigningKey, ttl time.Duration) (string, error) {
	if t.V == 0 {
		t.V = 1
	}
	if t.Secret == "" || t.SecretID == "" || t.Agent == "" {
		return "", errors.New("capability: secret, secret_id, and agent are required")
	}
	if len(t.Dests) == 0 {
		return "", errors.New("capability: at least one destination pattern required")
	}
	if t.Method == "" {
		t.Method = "*"
	}
	if t.IAT == 0 {
		t.IAT = time.Now().Unix()
	}
	if t.EXP == 0 {
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		t.EXP = t.IAT + int64(ttl.Seconds())
	}
	if t.Nonce == "" {
		n, err := NewNonce()
		if err != nil {
			return "", err
		}
		t.Nonce = n
	}

	payload, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("capability: marshal: %w", err)
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write(payload)
	sig := mac.Sum(nil)

	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// VerifyError values let callers distinguish "tampered token" from
// "expired" from "wrong destination" so the audit log captures the
// real reason.
var (
	ErrMalformed    = errors.New("capability: token malformed")
	ErrBadSignature = errors.New("capability: signature does not verify")
	ErrExpired      = errors.New("capability: token expired")
	ErrNotYet       = errors.New("capability: token issued in the future")
	ErrWrongVersion = errors.New("capability: unsupported token version")
	ErrEmpty        = errors.New("capability: empty token")
)

// Verify decodes a signed token, checks the HMAC in constant time,
// validates expiry, and returns the Token struct. Destination /
// method matching against the actual request is the caller's job
// (DestMatches helper below); this returns a verified-shape token
// that the caller can then check against the inbound request URL.
func Verify(signed string, key SigningKey, now time.Time) (Token, error) {
	if signed == "" {
		return Token{}, ErrEmpty
	}
	parts := strings.SplitN(signed, ".", 3)
	if len(parts) != 2 {
		return Token{}, ErrMalformed
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(parts[0])
	if err != nil {
		return Token{}, fmt.Errorf("%w: payload b64: %v", ErrMalformed, err)
	}
	sig, err := enc.DecodeString(parts[1])
	if err != nil {
		return Token{}, fmt.Errorf("%w: sig b64: %v", ErrMalformed, err)
	}
	expected := hmac.New(sha256.New, key[:])
	expected.Write(payload)
	if !hmac.Equal(sig, expected.Sum(nil)) {
		return Token{}, ErrBadSignature
	}
	var t Token
	if err := json.Unmarshal(payload, &t); err != nil {
		return Token{}, fmt.Errorf("%w: payload json: %v", ErrMalformed, err)
	}
	if t.V != 1 {
		return Token{}, ErrWrongVersion
	}
	nowUnix := now.Unix()
	if nowUnix >= t.EXP {
		return Token{}, ErrExpired
	}
	// Clock-skew tolerance: 30s.
	if t.IAT > nowUnix+30 {
		return Token{}, ErrNotYet
	}
	return t, nil
}

// DestMatches reports whether destination dest (e.g. "api.cloudflare.com/v4/zones")
// is allowed by at least one of the token's destination patterns. Patterns
// support a trailing "/*" wildcard; otherwise prefix match is used so callers
// can write "api.cloudflare.com" to allow any path. Both pattern and dest are
// lowered before match so pattern authors do not have to think about case.
// HTTP path case-sensitivity is handled at the upstream; for routing
// purposes, "api.openai.com/v1/X" and "api.openai.com/v1/x" land at the
// same secret.
func DestMatches(t Token, host, path string) bool {
	dest := strings.ToLower(host + path)
	for _, pat := range t.Dests {
		if patternMatch(strings.ToLower(pat), dest) {
			return true
		}
	}
	return false
}

func patternMatch(pat, dest string) bool {
	// Glob limited to a single trailing /* for now. Anything more
	// expressive needs a real matcher; the limited grammar makes the
	// security review a one-liner.
	if strings.HasSuffix(pat, "/*") {
		prefix := strings.TrimSuffix(pat, "/*")
		return dest == prefix || strings.HasPrefix(dest, prefix+"/")
	}
	return dest == pat || strings.HasPrefix(dest, pat+"/")
}

// MethodMatches reports whether the token allows the given HTTP method.
// The token's Method field is "*" (any) or an explicit verb match.
func MethodMatches(t Token, method string) bool {
	return t.Method == "*" || strings.EqualFold(t.Method, method)
}

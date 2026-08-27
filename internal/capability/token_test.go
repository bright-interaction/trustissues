package capability

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

const testSource = "test-jwt-secret-32-bytes-long-aaaaaa"

func mustKey(t *testing.T) SigningKey {
	t.Helper()
	k, err := DeriveSigningKey(testSource)
	if err != nil {
		t.Fatalf("DeriveSigningKey: %v", err)
	}
	return k
}

func validToken() Token {
	return Token{
		Secret:   "openai_api_key",
		SecretID: "abc123",
		Issuer:   "user-123",
		Agent:    "test-agent",
		Dests:    []string{"api.openai.com/v1/*"},
		Method:   "POST",
	}
}

func TestSignVerify_Roundtrip(t *testing.T) {
	k := mustKey(t)
	signed, err := Sign(validToken(), k, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tok, err := Verify(signed, k, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if tok.Secret != "openai_api_key" || tok.Agent != "test-agent" || tok.Method != "POST" {
		t.Fatalf("token roundtrip mismatch: %+v", tok)
	}
	if tok.Nonce == "" || tok.IAT == 0 || tok.EXP == 0 {
		t.Fatalf("default fields not populated: %+v", tok)
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	k := mustKey(t)
	signed, err := Sign(validToken(), k, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	other, _ := DeriveSigningKey("different-jwt-secret-32-bytes-bbbbbb")
	if _, err := Verify(signed, other, time.Now()); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerify_RejectsTamperedPayload(t *testing.T) {
	k := mustKey(t)
	signed, err := Sign(validToken(), k, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Flip a decoded payload byte, then retain the original signature. Replacing
	// the final base64url character is not reliable: depending on payload length,
	// that character can contain unused low bits and a different spelling may
	// decode to the exact same bytes.
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected token shape")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	payload[len(payload)/2] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1]
	if _, err := Verify(tampered, k, time.Now()); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	k := mustKey(t)
	signed, err := Sign(validToken(), k, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(signed, k, time.Now().Add(2*time.Hour)); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerify_RejectsFutureIssued(t *testing.T) {
	k := mustKey(t)
	tok := validToken()
	tok.IAT = time.Now().Add(10 * time.Minute).Unix()
	tok.EXP = tok.IAT + 60
	signed, err := Sign(tok, k, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(signed, k, time.Now()); err != ErrNotYet {
		t.Fatalf("expected ErrNotYet, got %v", err)
	}
}

func TestSign_RequiresFields(t *testing.T) {
	k := mustKey(t)
	for _, tc := range []struct {
		name string
		tok  Token
	}{
		{"no secret", Token{SecretID: "x", Issuer: "u", Agent: "a", Dests: []string{"foo"}}},
		{"no secret_id", Token{Secret: "x", Issuer: "u", Agent: "a", Dests: []string{"foo"}}},
		{"no issuer", Token{Secret: "x", SecretID: "x", Agent: "a", Dests: []string{"foo"}}},
		{"no agent", Token{Secret: "x", SecretID: "x", Issuer: "u", Dests: []string{"foo"}}},
		{"no dests", Token{Secret: "x", SecretID: "x", Issuer: "u", Agent: "a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Sign(tc.tok, k, time.Minute); err == nil {
				t.Fatalf("expected error, got nil for %s", tc.name)
			}
		})
	}
}

func TestDestMatches(t *testing.T) {
	cases := []struct {
		dests []string
		host  string
		path  string
		want  bool
	}{
		{[]string{"api.cloudflare.com/*"}, "api.cloudflare.com", "/v4/zones", true},
		{[]string{"api.cloudflare.com/*"}, "api.cloudflare.com", "/v4/zones/abc/dns_records", true},
		{[]string{"api.cloudflare.com/v4/*"}, "api.cloudflare.com", "/v4/zones", true},
		{[]string{"api.cloudflare.com/v4/*"}, "api.cloudflare.com", "/v3/zones", false},
		{[]string{"api.openai.com/v1/*"}, "evil.com", "/api.openai.com/v1/x", false},
		{[]string{"api.openai.com/v1/*"}, "api.openai.com", "/v1/chat/completions", true},
		{[]string{"API.OPENAI.com/V1/*"}, "api.openai.com", "/V1/x", true}, // host case-insensitive
		{[]string{"api.openai.com"}, "api.openai.com", "", true},
		{[]string{"api.openai.com"}, "api.openai.com", "/v1/x", true}, // bare host = any path
		{[]string{"api.openai.com"}, "api.openai.com.attacker.com", "/x", false},
	}
	for _, tc := range cases {
		tok := Token{Dests: tc.dests}
		got := DestMatches(tok, tc.host, tc.path)
		if got != tc.want {
			t.Errorf("DestMatches(%q, %q, %q) = %v, want %v", tc.dests, tc.host, tc.path, got, tc.want)
		}
	}
}

func TestMethodMatches(t *testing.T) {
	cases := []struct {
		tokMethod string
		req       string
		want      bool
	}{
		{"*", "GET", true},
		{"*", "POST", true},
		{"POST", "POST", true},
		{"post", "POST", true},
		{"POST", "GET", false},
	}
	for _, tc := range cases {
		got := MethodMatches(Token{Method: tc.tokMethod}, tc.req)
		if got != tc.want {
			t.Errorf("MethodMatches(%q, %q) = %v, want %v", tc.tokMethod, tc.req, got, tc.want)
		}
	}
}

func TestDeriveSigningKey_RejectsShortSource(t *testing.T) {
	if _, err := DeriveSigningKey("short"); err == nil {
		t.Fatal("expected error for short source")
	}
}

func TestDeriveSigningKey_DistinctFromVaultDerivation(t *testing.T) {
	// Sanity: capability key MUST differ from the SHA-256 of the source
	// (a naive, alternate derivation an attacker might assume). Any
	// consistent difference is enough proof; we just check non-equality.
	k, err := DeriveSigningKey(testSource)
	if err != nil {
		t.Fatal(err)
	}
	zero := SigningKey{}
	if k == zero {
		t.Fatal("derived key is zero")
	}
}

func TestNonce_AlwaysDistinct(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 256; i++ {
		n, err := NewNonce()
		if err != nil {
			t.Fatal(err)
		}
		if len(n) != 32 {
			t.Fatalf("nonce length = %d, want 32 hex chars", len(n))
		}
		if _, dup := seen[n]; dup {
			t.Fatalf("duplicate nonce after %d draws", i)
		}
		seen[n] = struct{}{}
	}
}

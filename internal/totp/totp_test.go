package totp

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// This package had no tests. It is the whole second factor: the code generator,
// the drift window, and the recovery codes. What coverage existed came through
// internal/handlers, which exercises the handler ordering around it and never
// checks that a generated code is the code RFC 6238 says it should be.

// rfcSecret is the RFC 6238 SHA1 test key, the ASCII string "12345678901234567890",
// base32-encoded the way GenerateSecret encodes.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestGenerateCodeMatchesRFC6238 checks the implementation against the
// standard's own vectors rather than against itself.
//
// A round-trip test (generate then validate) passes just as happily on an
// implementation that is internally consistent and wrong, and a wrong TOTP is
// not a broken feature, it is a second factor that silently disagrees with every
// authenticator app the user owns. The RFC publishes 8-digit codes; this
// implementation truncates to 6, which is the same value modulo 10^6, so the
// expectation is the last six digits.
func TestGenerateCodeMatchesRFC6238(t *testing.T) {
	// Sanity-check the vector itself before trusting anything it proves.
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(rfcSecret)
	if err != nil {
		t.Fatalf("ABORT: the RFC test secret does not decode: %v", err)
	}
	if string(decoded) != "12345678901234567890" {
		t.Fatalf("ABORT: the RFC test secret decodes to %q, not the standard key", decoded)
	}

	cases := []struct {
		unix     int64
		rfc8     string
		expected string
	}{
		{59, "94287082", "287082"},
		{1111111109, "07081804", "081804"},
		{1111111111, "14050471", "050471"},
		{1234567890, "89005924", "005924"},
		{2000000000, "69279037", "279037"},
		{20000000000, "65353130", "353130"},
	}

	for _, tc := range cases {
		got, err := GenerateCode(rfcSecret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("t=%d: %v", tc.unix, err)
		}
		if got != tc.expected {
			t.Errorf("t=%d: got %s, want %s (RFC 6238 8-digit vector %s truncated to 6).\n"+
				"A TOTP that disagrees with the RFC disagrees with every authenticator app.",
				tc.unix, got, tc.expected, tc.rfc8)
		}
	}
}

func TestGenerateSecretIsUsableAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		s, err := GenerateSecret()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if seen[s] {
			t.Fatal("GenerateSecret repeated a secret; the entropy source is not random")
		}
		seen[s] = true

		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
		if err != nil {
			t.Fatalf("a generated secret does not decode as unpadded base32 (%q): %v", s, err)
		}
		if len(raw) != 20 {
			t.Fatalf("secret is %d bytes, want 20 (RFC 4226 recommends 160 bits)", len(raw))
		}
		if _, err := GenerateCode(s, time.Now()); err != nil {
			t.Fatalf("a freshly generated secret cannot produce a code: %v", err)
		}
	}
}

// TestValidateCodeStepAcceptsDriftAndNothingElse pins the exact width of the
// acceptance window, in both directions.
//
// The window is what makes a captured code useful to an attacker for longer than
// one step, so it must be exactly as wide as clock drift needs and not one step
// wider. spendTOTPStep in internal/handlers refuses a replay within the window;
// this pins what the window IS.
func TestValidateCodeStepAcceptsDriftAndNothingElse(t *testing.T) {
	now := time.Now()
	const step = 30 * time.Second

	cases := []struct {
		label  string
		at     time.Time
		accept bool
	}{
		{"current step", now, true},
		{"previous step (clock drift)", now.Add(-step), true},
		{"two steps back", now.Add(-2 * step), false},
		{"next step (future)", now.Add(step), false},
		{"far past", now.Add(-time.Hour), false},
		{"far future", now.Add(time.Hour), false},
	}

	for _, tc := range cases {
		code, err := GenerateCode(rfcSecret, tc.at)
		if err != nil {
			t.Fatalf("%s: generate: %v", tc.label, err)
		}
		gotStep, ok := ValidateCodeStep(rfcSecret, code)
		if ok != tc.accept {
			t.Errorf("%s: accepted=%v, want %v. The acceptance window decides how long a "+
				"captured code stays usable.", tc.label, ok, tc.accept)
			continue
		}
		if ok {
			want := tc.at.Unix() / 30
			if gotStep != want {
				t.Errorf("%s: reported step %d, want %d. spendTOTPStep claims this value, so a "+
					"wrong one either lets a replay through or refuses a legitimate login.",
					tc.label, gotStep, want)
			}
		}
	}
}

func TestValidateCodeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "000000", "abcdef", "12345", "1234567", "  ", "＠＃＄％＾＆"} {
		// 000000 could legitimately be the current code roughly once in a million
		// windows; skip that one case rather than flake.
		if cur, err := GenerateCode(rfcSecret, time.Now()); err == nil && cur == bad {
			continue
		}
		if ValidateCode(rfcSecret, bad) {
			t.Errorf("ValidateCode accepted %q", bad)
		}
	}
}

func TestValidateCodeWithAnUnusableSecret(t *testing.T) {
	// A secret that does not decode must not authenticate anything. This is the
	// shape decryptTOTPSecret produces when a seed fails to decrypt and the raw
	// stored value is handed through, so it is a real state, not a hypothetical.
	if ValidateCode("not-valid-base32-!!!", "123456") {
		t.Fatal("a code validated against an undecodable secret")
	}
	if _, ok := ValidateCodeStep("", "123456"); ok {
		t.Fatal("a code validated against an empty secret")
	}
}

// TestRecoveryCodesAreEightSingleUse64BitCodes pins the shape the threat model
// and the enrolment UI both describe.
func TestRecoveryCodesAreEightSingleUseCodes(t *testing.T) {
	plain, hashed, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(plain) != 8 || len(hashed) != 8 {
		t.Fatalf("got %d plaintext and %d hashed codes, want 8 of each", len(plain), len(hashed))
	}

	seen := map[string]bool{}
	for _, p := range plain {
		// 8 random bytes rendered as hex is 16 characters. The doc comment on
		// GenerateRecoveryCodes said "8 hex characters (4 random bytes)", which
		// described an earlier, narrower code space; recoveryCodeBytes is 8.
		if len(p) != 16 {
			t.Errorf("recovery code %q is %d chars, want 16 (8 random bytes, 64 bits). "+
				"A narrower code space is brute-forceable under a diluted login limiter.", p, len(p))
		}
		if strings.ToLower(p) != p || strings.TrimLeft(p, "0123456789abcdef") != "" {
			t.Errorf("recovery code %q is not lowercase hex", p)
		}
		if seen[p] {
			t.Errorf("recovery code %q was issued twice", p)
		}
		seen[p] = true
	}

	// The stored form must be a hash, never the code.
	for i, h := range hashed {
		if h == plain[i] {
			t.Fatal("a recovery code is stored in plaintext")
		}
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(plain[i])) != nil {
			t.Fatalf("stored hash %d does not verify against its own plaintext", i)
		}
	}
}

func TestValidateRecoveryCodeRemovesExactlyTheMatch(t *testing.T) {
	plain, hashed, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	remaining, ok := ValidateRecoveryCode(hashed, plain[3])
	if !ok {
		t.Fatal("a freshly issued recovery code did not validate")
	}
	if len(remaining) != 7 {
		t.Fatalf("remaining set has %d codes, want 7", len(remaining))
	}

	// The used one must be gone and every other one must still work.
	if _, stillOK := ValidateRecoveryCode(remaining, plain[3]); stillOK {
		t.Fatal("the consumed recovery code still validates against the remaining set; each code " +
			"is a standalone 2FA bypass and must be single use")
	}
	for i, p := range plain {
		if i == 3 {
			continue
		}
		if _, otherOK := ValidateRecoveryCode(remaining, p); !otherOK {
			t.Fatalf("recovery code %d stopped working after a different one was spent", i)
		}
	}

	// A wrong code must change nothing.
	after, ok := ValidateRecoveryCode(remaining, "ffffffffffffffff")
	if ok {
		t.Fatal("an unissued code validated")
	}
	if len(after) != len(remaining) {
		t.Fatal("a failed validation altered the remaining set")
	}

	// And an empty set must not panic or accept.
	if _, emptyOK := ValidateRecoveryCode(nil, plain[0]); emptyOK {
		t.Fatal("a code validated against an empty recovery set")
	}
}

func TestGenerateOTPAuthURIEscapesItsParts(t *testing.T) {
	// An email with characters that would break the URI if interpolated raw.
	uri := GenerateOTPAuthURI("a b+c@example.com", "Trustissues", rfcSecret)

	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("the generated otpauth URI does not parse: %v (%s)", err, uri)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("scheme/host = %s://%s, want otpauth://totp", u.Scheme, u.Host)
	}
	if got := u.Query().Get("secret"); got != rfcSecret {
		t.Fatalf("secret param = %q, want %q; an authenticator would enrol the wrong seed", got, rfcSecret)
	}
	if got := u.Query().Get("issuer"); got != "Trustissues" {
		t.Fatalf("issuer param = %q", got)
	}
	if !strings.Contains(u.Path, "Trustissues") {
		t.Fatalf("label path %q does not carry the issuer", u.Path)
	}
	// The label must survive a round trip, or the user sees a mangled account
	// name in their authenticator.
	if !strings.Contains(u.Path, "a b+c@example.com") {
		t.Fatalf("label path %q lost or mangled the account name", u.Path)
	}
}

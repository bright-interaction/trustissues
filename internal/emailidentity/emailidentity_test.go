package emailidentity

import (
	"net/mail"
	"testing"
)

func TestCanonical(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "ASCII case and surrounding space", raw: "  Alice+Ops@Example.COM\t", want: "alice+ops@example.com"},
		{name: "RFC 6532 Unicode case and IDNA domain", raw: "  ÜSER@EXÄMPLE.TEST ", want: "üser@xn--exmple-cua.test"},
		{name: "Unicode canonical equivalence", raw: "  U\u0308SER@EXA\u0308MPLE.TEST ", want: "üser@xn--exmple-cua.test"},
		{name: "display name becomes bare address", raw: "Victim <Victim@Example.COM>", want: "victim@example.com"},
		{name: "quoted display name becomes bare address", raw: `"Victim, Inc." <Victim@Example.COM>`, want: "victim@example.com"},
		{name: "quoted local space is reserialized", raw: `"Foo Bar"@Example.COM`, want: `"foo bar"@example.com`},
		{name: "quoted local embedded at is reserialized", raw: `"Foo@Bar"@Example.COM`, want: `"foo@bar"@example.com`},
		{name: "display quoted local U-label and root dot", raw: `"Ops, Inc." <"Foo@Bar"@BÜCHER.DE.>`, want: `"foo@bar"@xn--bcher-kva.de`},
		{name: "A-label converges with U-label", raw: `"FOO@BAR"@XN--BCHER-KVA.DE`, want: `"foo@bar"@xn--bcher-kva.de`},
		{name: "bare terminal root dot is stripped", raw: "Root@Example.COM.", want: "root@example.com"},
		{name: "interior space untouched", raw: "a b@example.com", want: "a b@example.com"},
		{name: "malformed input remains malformed", raw: "  NOT AN ADDRESS  ", want: "not an address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Canonical(tc.raw); got != tc.want {
				t.Fatalf("Canonical(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCanonicalStrictRejectsInvalidIdentityForms(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"",
		"not an address",
		"user@-example.com",
		"user@example..com",
		"user@example.com..",
		"user@xn--",
		// GO-2026-5026: an A-label that decodes to ASCII-only text must not
		// alias the ordinary label through IDNA conversion.
		"user@xn--example-.com",
		// Compatibility-only Unicode must likewise not manufacture a second
		// spelling of an ordinary ASCII identity.
		"user@ｅｘａｍｐｌｅ.com",
		"user@[127.0.0.1]",
	} {
		t.Run(raw, func(t *testing.T) {
			if got, err := CanonicalStrict(raw); err == nil {
				t.Fatalf("CanonicalStrict(%q) = %q, want an error", raw, got)
			}
		})
	}
}

func TestCanonicalStrictProducesParseableQuotedAddrSpec(t *testing.T) {
	t.Parallel()

	got, err := CanonicalStrict(`Display <"A@B C\\D\"E"@bücher.example.>`)
	if err != nil {
		t.Fatalf("CanonicalStrict: %v", err)
	}
	parsed, err := mail.ParseAddress(got)
	if err != nil {
		t.Fatalf("canonical quoted local-part is not parseable: %q: %v", got, err)
	}
	if parsed.Address != `a@b c\d"e@xn--bcher-kva.example` {
		t.Fatalf("parsed canonical address = %q, want semantic quoted local-part to survive", parsed.Address)
	}
}

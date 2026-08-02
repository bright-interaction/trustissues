package shield

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func egressSession(t *testing.T, level HintLevel) (*Session, context.Context) {
	t.Helper()
	ctx := context.Background()
	s, err := NewSession(ctx, NewMemoryStore(), "egress", testKey(), time.Minute, level)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return s, ctx
}

// A marker must never republish a value Shield itself would tokenize.
//
// The domain hint emitted raw[at+1:] verbatim, so redacting an address printed the
// address's own domain in cleartext inside the marker meant to conceal it. The same
// string standalone IS tokenized, which is the contradiction:
//
//	connect to edge-node.internal   ->  [shield:hostname:tok_...]
//	mail admin@edge-node.internal   ->  [shield:email:...,domain=edge-node.internal]
//
// It was filed as an IP-literal edge case (user@192.168.1.1 republishing the IP), but
// the IP is just the sharpest instance of a channel open on EVERY email. Fixing only
// the IP shape would have left the hole and pinned it with a passing test.
func TestAMarkerNeverRepublishesATokenizableValue(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// the substring that must NOT survive anywhere in the output
		leaked string
	}{
		{"internal hostname", "mail admin@edge-node.internal today", "edge-node.internal"},
		{"ipv4 literal", "mail ops@192.168.1.1 today", "192.168.1.1"},
		{"ipv6 literal", "mail ops@[2001:db8::1] today", "2001:db8"},
		{"business domain", "mail anna@andersson-law.se today", "andersson-law.se"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx := egressSession(t, HintFull)
			out, err := s.RedactString(ctx, tc.in)
			if err != nil {
				t.Fatalf("redact: %v", err)
			}
			if !strings.Contains(out, "[shield:") {
				t.Fatalf("ABORT: nothing was tokenized (%q), the assertion below is vacuous", out)
			}
			if strings.Contains(out, tc.leaked) {
				t.Errorf("the marker republished %q, which Shield tokenizes on its own:\n  %s",
					tc.leaked, out)
			}
		})
	}
}

// The local part is matched WHOLE, or the name in front of it egresses.
//
// A character missing from the local-part class does not fail the match, it moves the
// match start past that character, so the leading fragment survives in cleartext while
// the output still looks redacted. TestAnAddressIsNeverSplit passed clean through this
// because its splitBefore invariant requires a letter/mark/digit immediately before the
// marker and its 12 local-part shapes contain no punctuation. The alphabet was the bug,
// not the invariant, for the fourth time in this file's history.
func TestRFCLegalLocalPartsAreNotSplit(t *testing.T) {
	// Every character here is RFC 5322 atext and legal unquoted.
	locals := []string{
		"anna!svensson", "o'brien", "a#b", "a$b", "a&b", "a*b", "a/b", "a=b",
		"a?b", "a^b", "a_b", "a{b}c", "a|b", "a~b", "anna.svensson", "anna+tag",
		"anna%test", "anna-svensson",
	}
	for _, lp := range locals {
		t.Run(lp, func(t *testing.T) {
			s, ctx := egressSession(t, HintFull)
			in := "mail " + lp + "@example.se today"
			out, err := s.RedactString(ctx, in)
			if err != nil {
				t.Fatalf("redact: %v", err)
			}
			if !strings.Contains(out, "[shield:email:") {
				t.Fatalf("%q was not recognised as an email at all: %s", lp, out)
			}
			// The invariant is about the BOUNDARY, not the whole string.
			//
			// The first version of this test asserted the whole local part was
			// absent, and an ablation reverting the character class passed it
			// clean: with anna!svensson@example.se the output is
			// "anna![shield:email:...]", so the FULL local part is indeed gone
			// while the leaked fragment "anna!" sits right there. Checking for
			// the whole value cannot see a partial match, which is the only way
			// this bug ever manifests.
			//
			// What must hold is that the marker begins at an address boundary:
			// the character before it is whitespace or start-of-string. Anything
			// else means the match started mid-address and whatever precedes it
			// is unredacted PII.
			i := strings.Index(out, "[shield:email:")
			if i < 0 {
				t.Fatalf("no email marker in %q", out)
			}
			if i > 0 {
				prev := rune(out[i-1])
				if prev != ' ' && prev != '\t' && prev != '\n' {
					t.Errorf("the marker is glued to %q, so the address was matched from the "+
						"middle and the leading fragment egressed in cleartext:\n  %s",
						out[:i], out)
				}
			}
		})
	}
}

// An IBAN in the form banks actually print must be detected.
//
// The pattern required a contiguous run, so the grouped presentation, which is what
// appears on invoices and gets pasted into chat, egressed verbatim. Nothing caught it:
// the corpus has no IBAN line at all, and the only IBAN assertion pins the contiguous
// form, so recall for the common shape was measured by nothing.
func TestIBANIsDetectedInPrintedGrouping(t *testing.T) {
	for _, in := range []string{
		"iban SE45 5000 0000 0583 9825 7466 on file",
		"iban SE4550000000058398257466 on file",
		"iban DE89 3704 0044 0532 0130 00 please",
	} {
		t.Run(in, func(t *testing.T) {
			s, ctx := egressSession(t, HintFull)
			out, err := s.RedactString(ctx, in)
			if err != nil {
				t.Fatalf("redact: %v", err)
			}
			if !strings.Contains(out, "[shield:iban:") {
				t.Errorf("the IBAN was not tokenized and egressed verbatim: %s", out)
			}
		})
	}
}

// Enabling Shield must not rewrite the numbers it passes through.
//
// Both JSON entry points decoded into any via json.Unmarshal, which makes every number
// a float64, then re-marshalled. Above 2^53 that is lossy and below it the literal
// still changes, so a privacy control silently corrupted snowflake ids, ledger amounts
// and idempotency keys in BOTH directions, always with err == nil.
func TestShieldJSONPreservesNumbersExactly(t *testing.T) {
	const in = `{"seed":9007199254740993,"external_id":12345678901234567890,` +
		`"temperature":1.0,"ratio":0.30,"neg":-9007199254740993}`

	s, ctx := egressSession(t, HintFull)
	out, err := s.ShieldJSON(ctx, []byte(in))
	if err != nil {
		t.Fatalf("shield: %v", err)
	}
	for _, want := range []string{
		`"seed":9007199254740993`,
		`"external_id":12345678901234567890`,
		`"temperature":1.0`,
		`"ratio":0.30`,
		`"neg":-9007199254740993`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("number was rewritten, wanted %s in:\n  %s", want, out)
		}
	}

	// And the same on the way back, which is the response path.
	back, err := s.UnshieldJSON(ctx, out)
	if err != nil {
		t.Fatalf("unshield: %v", err)
	}
	if !strings.Contains(string(back), `"external_id":12345678901234567890`) {
		t.Errorf("the response path rewrote the number: %s", back)
	}
	// Still valid JSON, not just a string that happens to contain the digits.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(back, &probe); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

// The dereferenced-URL exemption covers binary payloads, not prose.
//
// It was keyed on a bare "data:" prefix, and data:text/plain is a data: URL, so any
// value under a url-ish key could opt out of redaction entirely by prefixing itself.
// The exemption exists so a provider can fetch an inline image; text is what the model
// reads, which is exactly what must be redacted.
func TestDataURLExemptionIsNotARedactionOffSwitch(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		exempt   bool
		mustHide string
	}{
		{"plain text masquerading as a data url", "data:text/plain,anna@example.se", false, "anna@example.se"},
		{"base64 text is still text", "data:text/plain;base64,YW5uYUBleGFtcGxlLnNl", false, ""},
		{"no media type defaults to text", "data:,anna@example.se", false, "anna@example.se"},
		{"a real inline image is exempt", "data:image/png;base64,iVBORw0KGgo=", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeDereferenceableURL(tc.value); got != tc.exempt {
				t.Errorf("looksLikeDereferenceableURL(%q) = %v, want %v", tc.value, got, tc.exempt)
			}
			if tc.mustHide == "" {
				return
			}
			s, ctx := egressSession(t, HintFull)
			out, err := s.ShieldJSON(ctx, []byte(`{"image_url":`+quote(tc.value)+`}`))
			if err != nil {
				t.Fatalf("shield: %v", err)
			}
			if strings.Contains(string(out), tc.mustHide) {
				t.Errorf("PII under a url-ish key egressed verbatim: %s", out)
			}
		})
	}
}

// A hint value can never break out of the marker grammar.
//
// Hints were interpolated straight into [shield:kind:token:k=v]. A value containing "]"
// closed the marker early, so the rest of the hint became ordinary text and the round
// trip returned mangled output with err == nil.
func TestHintValuesCannotBreakTheMarkerGrammar(t *testing.T) {
	// Assert through buildHint, NOT through sanitizeHintValue directly.
	//
	// The first version called the helper, and an ablation that deleted the
	// CALL SITE (leaving the helper intact and unused) passed it clean. Same
	// trap as the notify-only guard last round: a test that exercises the
	// sanitizer proves the sanitizer works, never that anything calls it.
	//
	// KindName/initials is the path that can still carry hostile bytes, since
	// initials are taken from the raw value's first bytes.
	hostile := buildHint(KindName, "]evil ]person", []string{"initials"})
	for _, bad := range []string{"[", "]", ",", ":"} {
		// "=" is the pair separator produced by buildHint itself, so only the
		// VALUE half is checked for it.
		if strings.Contains(strings.SplitN(hostile, "=", 2)[len(strings.SplitN(hostile, "=", 2))-1], bad) {
			t.Errorf("buildHint emitted %q, which carries %q and breaks the marker grammar",
				hostile, bad)
		}
	}

	// End to end: an address whose local part carries a bracket must still round trip.
	s, ctx := egressSession(t, HintFull)
	const in = `mail admin@[2001:db8::1] today`
	out, err := s.RedactString(ctx, in)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	blob, err := s.UnshieldJSON(ctx, []byte(`{"m":`+quote(out)+`}`))
	if err != nil {
		t.Fatalf("unshield: %v", err)
	}
	var round struct {
		M string `json:"m"`
	}
	if err := json.Unmarshal(blob, &round); err != nil {
		t.Fatalf("round trip is not valid JSON: %v", err)
	}
	if round.M != in {
		t.Errorf("round trip corrupted the text:\n  in:  %s\n  out: %s", in, round.M)
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

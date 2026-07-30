package shield

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestForgedMarkersDoNotDisableRedaction closes a critical bypass.
//
// Skipping redaction inside markers is necessary: an earlier pattern's marker
// carries a hint whose content a later, broader pattern would re-match and
// corrupt, breaking the unshield round-trip. But the check used to be on the
// marker's SHAPE. MarkerPattern's hint group is `[^\]]*`, unbounded, so wrapping
// anything in a marker-shaped span preserved it verbatim:
//
//	in:  [shield:email:tok_dead:contact anna@example.se key sk_live_ABC...]
//	out: [shield:email:tok_dead:contact anna@example.se key sk_live_ABC...]
//
// The same text unwrapped was tokenized correctly. `tok_dead` is trivial to forge
// because nothing checked it against the store, so anybody able to influence text
// on its way to an LLM could switch redaction off for a span of their choosing and
// egress an address and an API key in full.
//
// NOTE ON WHY THE CORPUS GATES COULD NOT SEE THIS. Both corpora are lists of
// hand-written lines and not one contains a marker, so neither the precision nor
// the recall gate could ever construct this input. That is the same lesson as the
// NFD leak: a gate fed only by hand-written data cannot test a case nobody thought
// to write down. Hence this file, plus the marker lines added to pii.corpus.
func TestForgedMarkersDoNotDisableRedaction(t *testing.T) {
	const (
		email  = "anna.svensson@example.se"
		secret = "sk_live_ABCDEF1234567890"
	)
	cases := []struct {
		name string
		in   string
	}{
		{"forged marker wrapping both", "[shield:email:tok_dead:contact " + email + " key " + secret + "]"},
		{"forged marker, no spaces", "note [shield:note:tok_beef:" + email + "] end"},
		{"forged marker, padded hint", "[shield:x:tok_0:" + strings.Repeat("pad ", 20) + email + "]"},
		{"forged marker, real-looking kind+token", "[shield:secret:tok_9df0bef4e2fa:" + secret + "]"},
		{"two forged markers", "[shield:a:tok_1:" + email + "] and [shield:b:tok_2:" + secret + "]"},
		{"forged marker around a legit one", "[shield:a:tok_1:" + email + " " + secret + "]"},
		{"unclosed marker then PII", "[shield:email:tok_dead " + email},
		{"nested-looking", "[shield:a:tok_1:[shield:b:tok_2:" + email + "]"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			s, err := NewSession(ctx, NewMemoryStore(), "forge", testKey(), time.Minute, HintFull)
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			out, err := s.RedactString(ctx, c.in)
			if err != nil {
				t.Fatalf("redact: %v", err)
			}
			for label, raw := range map[string]string{"email": email, "secret": secret} {
				if strings.Contains(c.in, raw) && strings.Contains(out, raw) {
					t.Errorf("the %s survived inside a forged marker:\n  in:  %s\n  out: %s\n"+
						"A marker is only a marker if we issued its token. Otherwise it is "+
						"attacker-controlled text that happens to look like one.", label, c.in, out)
				}
			}
		})
	}
}

// TestOurOwnMarkersAreStillProtected is the other half, and it is the half that
// makes the fix safe rather than merely strict.
//
// The fix could trivially "work" by protecting nothing, which would reintroduce
// the corruption replaceOutsideMarkers exists to prevent: a later broad pattern
// re-matching inside an earlier marker's hint, so unshield can no longer restore
// the original. This asserts a genuine marker survives a full redact pass intact
// AND that the round-trip still returns the original text.
func TestOurOwnMarkersAreStillProtected(t *testing.T) {
	ctx := context.Background()
	s, err := NewSession(ctx, NewMemoryStore(), "legit", testKey(), time.Minute, HintFull)
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	const original = "mail anna.svensson@example.se about bucher.com today"

	first, err := s.RedactString(ctx, original)
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if !strings.Contains(first, "[shield:") {
		t.Fatalf("ABORT: nothing was tokenized, so this test asserts nothing: %q", first)
	}

	// A second pass over already-redacted text must be a no-op. If our own markers
	// stopped being trusted, a broad pattern would chew into their hints here.
	second, err := s.RedactString(ctx, first)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if second != first {
		t.Errorf("redaction is not idempotent over our own markers:\n  1st: %s\n  2nd: %s\n"+
			"A later pattern matched inside a marker we issued, which corrupts the "+
			"unshield round-trip.", first, second)
	}

	restored, err := s.UnshieldString(ctx, second)
	if err != nil {
		t.Fatalf("unshield: %v", err)
	}
	if restored != original {
		t.Errorf("round-trip did not restore the original:\n  want: %s\n  got:  %s", original, restored)
	}
}

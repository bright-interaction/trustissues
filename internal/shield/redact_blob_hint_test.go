package shield

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// TestEncodedBlobsAreNeverTokenized locks the attachment-corruption fix.
//
// ShieldJSON recurses into every string leaf, so an image attachment (Anthropic
// messages[].content[].source.data, or an OpenAI data: URI) was run through the
// PII regexes. Base64 is a dense run of letters and digits, so the phone and
// personnummer patterns match by chance: a marker gets spliced into the payload,
// the provider receives a corrupt image, and unshielding cannot restore it
// because the surrounding bytes shifted. It corrupted only SOME uploads, which
// is worse than failing every time.
func TestEncodedBlobsAreNeverTokenized(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)

		// Many random blobs: the corruption is probabilistic, so one sample
		// could pass against the bug by luck.
		for i := 0; i < 40; i++ {
			buf := make([]byte, 4000)
			if _, err := rand.Read(buf); err != nil {
				t.Fatalf("rand: %v", err)
			}
			b64 := base64.StdEncoding.EncodeToString(buf)
			out, err := s.RedactString(ctx, b64)
			if err != nil {
				t.Fatalf("redact: %v", err)
			}
			if out != b64 {
				t.Fatalf("blob %d CORRUPTED (len %d -> %d, %d markers): the provider would receive a broken attachment",
					i, len(b64), len(out), strings.Count(out, "[shield:"))
			}
		}

		// A data: URI payload is the OpenAI shape and must be left alone too.
		buf := make([]byte, 2000)
		rand.Read(buf)
		uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf)
		if out, err := s.RedactString(ctx, uri); err != nil || out != uri {
			t.Fatalf("data URI was modified (err %v)", err)
		}

		// AND the guard must not swallow real text. A short base64-looking value
		// is below the threshold, and prose contains characters base64 never has.
		prose := "Contact me at anna.svensson@example.com or +46 70 123 45 67 about it."
		out, err := s.RedactString(ctx, prose)
		if err != nil {
			t.Fatalf("redact prose: %v", err)
		}
		if !strings.Contains(out, "[shield:") {
			t.Fatal("the blob guard swallowed ordinary prose: PII would reach the provider untokenized")
		}
		if strings.Contains(out, "anna.svensson@example.com") {
			t.Fatal("email survived untokenized")
		}
		// A long line of PROSE (over the length threshold) must still be scanned.
		long := strings.Repeat("please email anna@example.com about the invoice. ", 30)
		if out, _ := s.RedactString(ctx, long); !strings.Contains(out, "[shield:") {
			t.Fatal("a long prose string was treated as a blob")
		}
	})
}

// TestHintLevelIsHonouredByRedactString locks the other half: the env var was
// inert on this path because it called buildHint, which hardcodes HintFull. The
// struct-tag path already respected the level, so the two silently disagreed and
// every deployment egressed full hints regardless of configuration.
func TestHintLevelIsHonouredByRedactString(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		const in = "reach me at anna.svensson@example.com"

		full, _ := NewSession(ctx, store, "full", testKey(), time.Minute, HintFull)
		outFull, err := full.RedactString(ctx, in)
		if err != nil {
			t.Fatalf("redact full: %v", err)
		}
		// Guard the setup: without a hint at HintFull there is nothing to compare.
		if !strings.Contains(outFull, "domain=") {
			t.Fatalf("ABORT: HintFull produced no domain hint (%q); the comparison below would be vacuous", outFull)
		}

		none, _ := NewSession(ctx, store, "none", testKey(), time.Minute, HintNone)
		outNone, err := none.RedactString(ctx, in)
		if err != nil {
			t.Fatalf("redact none: %v", err)
		}
		if strings.Contains(outNone, "domain=") || strings.Contains(outNone, "len=") {
			t.Fatalf("HintNone still egressed value-derived metadata: %q", outNone)
		}
		if strings.Contains(outNone, "example.com") {
			t.Fatalf("HintNone leaked the domain itself: %q", outNone)
		}
		// It must still tokenize, just without the metadata.
		if !strings.Contains(outNone, "[shield:email:") {
			t.Fatalf("HintNone stopped tokenizing entirely: %q", outNone)
		}
	})
}

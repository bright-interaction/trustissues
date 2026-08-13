package shield

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The redaction walk had no json.Number case, so a personnummer was protected
// only if the exporting system happened to quote it.
//
// decodeJSONExact switched both JSON entry points to UseNumber() to stop Shield
// silently rewriting large integers, and its comment recorded that the walk
// "skips it the same way it skipped float64". That was true, and it was a
// statement about exactness rather than a decision about PII: the effect was
// that {"personnummer":198501011234} egressed to Anthropic or OpenAI verbatim.
// Swedish systems export the number both ways, so which spelling arrives is the
// exporter's choice, not the caller's.
func TestShieldJSONRedactsUnquotedNumericPII(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		doc  string
		// the raw digits that must not survive anywhere in the output
		leak string
	}{
		{"bare 12-digit personnummer", `{"personnummer":198501011234}`, "198501011234"},
		{"bare 10-digit personnummer", `{"pnr":8501011234}`, "8501011234"},
		{"nested under a tool input", `{"tool_use":{"input":{"id":198501011234}}}`, "198501011234"},
		{"inside an array", `{"rows":[198501011234,42]}`, "198501011234"},
		{"as a value beside prose", `{"note":"see id","id":8501011234}`, "8501011234"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSession(ctx, NewMemoryStore(), "num-"+tc.name, testKey(), time.Minute, HintFull)
			if err != nil {
				t.Fatal(err)
			}
			out, err := s.ShieldJSON(ctx, []byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), tc.leak) {
				t.Fatalf("personnummer egressed unredacted\n  in:  %s\n  out: %s", tc.doc, out)
			}
			if !strings.Contains(string(out), "[shield:") {
				t.Fatalf("expected a marker in the output, got %s", out)
			}
		})
	}
}

// The counterweight to the test above, and the reason this file carries BOTH
// directions.
//
// Scanning numeric leaves makes every latent numeric false positive reachable at
// once. In atomicsite that exact step turned a SQLite timestamp into
// [shield:phone:tok_...] in every agent response, silently, with a 200. A
// tokenized timestamp is corruption of data that was never PII.
//
// It is safe here because the numeric patterns are narrowed by validators rather
// than by shape alone (plausiblePersonnummer, looksLikePhone). This test is what
// keeps that true: if a future widening drops a validator, the timestamps and
// ids below start tokenizing and this fails, rather than the corruption reaching
// a provider first.
func TestShieldJSONLeavesMachineNumbersExact(t *testing.T) {
	ctx := context.Background()

	// Every one of these must survive byte-for-byte.
	for _, lit := range []string{
		"1786655165",           // unix seconds, 10 digits: the personnummer shape
		"1786655165123",        // unix millis
		"1699999999",           // unix seconds
		"9007199254740993",     // 2^53+1, the literal decodeJSONExact exists for
		"1234567890123456789",  // snowflake id
		"12345678901234567890", // 20 digits, past int64
		"20240620",             // date rendered as an integer
		"1.0",                  // float that json.Unmarshal would render as 1
		"0.7",                  // temperature
		"1e3",                  // exponent form
		"-1",
		"4096",
		"0",
	} {
		t.Run(lit, func(t *testing.T) {
			s, err := NewSession(ctx, NewMemoryStore(), "machine-"+lit, testKey(), time.Minute, HintFull)
			if err != nil {
				t.Fatal(err)
			}
			doc := `{"v":` + lit + `}`
			out, err := s.ShieldJSON(ctx, []byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != doc {
				t.Fatalf("machine number was rewritten\n  in:  %s\n  out: %s", doc, out)
			}
		})
	}
}

// A redacted number leaves as a STRING, because a marker is not valid JSON
// number syntax. That is the unavoidable cost of the fix and it is pinned here
// so it is a decision on the record rather than a surprise at a provider that
// schema-types the field as an integer.
func TestRedactedNumberBecomesAStringMarker(t *testing.T) {
	ctx := context.Background()
	s, err := NewSession(ctx, NewMemoryStore(), "typechange", testKey(), time.Minute, HintFull)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.ShieldJSON(ctx, []byte(`{"pnr":198501011234}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"pnr":"[shield:`) {
		t.Fatalf("expected the marker to be quoted, got %s", out)
	}
}

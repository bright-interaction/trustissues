package shield

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

var anyMarker = regexp.MustCompile(`\[shield:[a-z_]+:tok_`)

// TestNoiseCorpusProducesNoMarkers is the precision gate.
//
// Six rounds of regex patching each widened a pattern to catch a true positive
// and created a new false positive nobody measured: the hostname pattern ate
// strings.HasPrefix, then (after that fix) res.data; the phone pattern ate ISO
// dates, trace ids and card numbers. Every one of those was found by an auditor
// days later rather than by the commit that caused it.
//
// This file is the thing that was missing. A pattern change that starts
// tokenizing ordinary prose fails here immediately, with the offending line
// named. Adding a pattern is now cheap to do safely, which is the actual goal:
// the bank should be easy to extend without a round trip through production.
func TestNoiseCorpusProducesNoMarkers(t *testing.T) {
	f, err := os.Open("testdata/noise.corpus")
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	ctx := context.Background()
	s, _ := NewSession(ctx, NewMemoryStore(), "corpus", testKey(), time.Minute, HintFull)

	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines++
		out, err := s.RedactString(ctx, line)
		if err != nil {
			t.Fatalf("redact %q: %v", line, err)
		}
		if m := anyMarker.FindString(out); m != "" {
			t.Errorf("ordinary text was tokenized (%s):\n  in:  %s\n  out: %s\n"+
				"A pattern got wider. Either narrow it, or if this line really should be "+
				"redacted, move it out of the noise corpus and say why.", m, line, out)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Fail closed: an empty or unreadable corpus must not read as "all clean".
	if lines < 20 {
		t.Fatalf("ABORT: only %d corpus lines were checked; this gate is nearly vacuous", lines)
	}
	t.Logf("checked %d noise lines, zero markers", lines)
}

// TestPIICorpusIsTokenized is the recall half of the gate.
//
// noise.corpus alone is dangerous: the cheapest way to satisfy it is to stop
// detecting things. For a redactor that trade is backwards, because a false
// positive only mangles prose while a false negative sends PII to a third-party
// model. This file pins what must still be caught, and the expected KIND, so a
// validator added to fix a false positive cannot quietly reclassify or drop a
// true one.
func TestPIICorpusIsTokenized(t *testing.T) {
	f, err := os.Open("testdata/pii.corpus")
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	ctx := context.Background()
	s, _ := NewSession(ctx, NewMemoryStore(), "pii", testKey(), time.Minute, HintFull)

	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		parts := strings.SplitN(raw, "\t", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed corpus line (want kind<TAB>text): %q", raw)
		}
		wantKind, line := strings.TrimSpace(parts[0]), parts[1]
		lines++

		out, err := s.RedactString(ctx, line)
		if err != nil {
			t.Fatalf("redact %q: %v", line, err)
		}
		want := "[shield:" + wantKind + ":tok_"
		if !strings.Contains(out, want) {
			t.Errorf("expected a %s marker and got none:\n  in:  %s\n  out: %s\n"+
				"Detection regressed. If a validator was added to fix a false positive, it is "+
				"now rejecting a real one.", wantKind, line, out)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if lines < 15 {
		t.Fatalf("ABORT: only %d PII lines checked; this gate is nearly vacuous", lines)
	}
	t.Logf("checked %d PII lines", lines)
}

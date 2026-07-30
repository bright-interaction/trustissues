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

// markerGluedToText catches the PARTIAL-leak class directly.
//
// A correct redaction replaces the whole match, so its marker is preceded by
// whitespace, punctuation, or the start of the string. A marker welded to a
// letter, mark or digit means the pattern stopped early and left part of the
// real value in the output:
//
//	"mail Åsa.Ö[shield:email:tok_...] today"
//
// This is a stronger assertion than "a marker is present", which is what the
// recall gate checks and which a partial leak satisfies perfectly. Every
// iteration of this bug (ASCII class, then \p{L}, then \p{L}\p{M}) would have
// been caught by this line.
var markerGluedToText = regexp.MustCompile(`[\p{L}\p{M}\p{N}]\[shield:`)

// markerAfterAtSign catches the OTHER half of the same failure, which the glued
// check above cannot see.
//
// When the email pattern fails to match an address, the ordered bank falls through
// to the hostname pattern, which matches the domain half quite happily:
//
//	mail "anna svensson"@example.se  ->  mail "anna svensson"@[shield:hostname:...]
//
// The local part survives in the clear and the output LOOKS redacted. The glued
// check passes it because the character immediately before the marker is "@", not
// a letter, so the leak sits one position further left than that regex looks.
//
// A marker preceded by "@" is never legitimate: it means an address was matched
// from the domain inwards. Found by adding a quoted local part (legal per RFC
// 5321) to the corpus, which is the fourth distinct route into this one failure
// class, so state the invariant rather than keep patching the character class.
var markerAfterAtSign = regexp.MustCompile(`@\[shield:`)

// nfdDecompose rewrites precomposed Latin letters as base + combining mark.
//
// This is deliberately a small explicit table rather than golang.org/x/text/
// unicode/norm: the project has no x/text dependency and pulling one in for a
// single test is a poor trade. It is NOT full Unicode NFD. It does not need to
// be, because its job is to turn every accented character that appears in the
// corpus into the decomposed form that broke the pattern, and the corpus is
// Swedish-first.
//
// If a corpus line ever needs a script this table does not cover, add the
// mapping rather than skipping the line.
var nfdDecompose = strings.NewReplacer(
	"Å", "Å", "å", "å", // combining ring above
	"Ö", "Ö", "ö", "ö", // combining diaeresis
	"Ä", "Ä", "ä", "ä",
	"Ü", "Ü", "ü", "ü",
	"É", "É", "é", "é", // combining acute
	"È", "È", "è", "è", // combining grave
	"Ê", "Ê", "ê", "ê", // combining circumflex
	"Ñ", "Ñ", "ñ", "ñ", // combining tilde
	"Ç", "Ç", "ç", "ç", // combining cedilla
)

// TestPIICorpusSurvivesUnicodeNormalization derives its own cases from the
// corpus, which is the point.
//
// The three NFD lines added to pii.corpus by hand were reverted along with the
// regex in a parallel session's merge, and because BOTH sides went back together
// the suite stayed green: consistent old pattern, consistent old corpus, nothing
// red. A hand-written case can be reverted into agreement with the bug it exists
// to catch.
//
// This test cannot. It builds the decomposed variant of every corpus line at run
// time, so any accented address anywhere in the corpus generates its own NFD
// case. Deleting the three explicit lines changes nothing as long as one
// accented address remains, and deleting the regex fix alone turns it red.
func TestPIICorpusSurvivesUnicodeNormalization(t *testing.T) {
	f, err := os.Open("testdata/pii.corpus")
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	ctx := context.Background()
	s, _ := NewSession(ctx, NewMemoryStore(), "nfd", testKey(), time.Minute, HintFull)

	derived := 0
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

		// Both forms, always. The composed form is the recall gate's job, but
		// asserting it here too costs nothing and pins that the two forms behave
		// identically, which is the actual invariant.
		for _, v := range []struct {
			form string
			text string
		}{
			{"NFC", line},
			{"NFD", nfdDecompose.Replace(line)},
		} {
			// Only the decomposed variant is a new case, and only when the
			// replacer actually changed something.
			if v.form == "NFD" && v.text == line {
				continue
			}
			if v.form == "NFD" {
				derived++
			}

			out, err := s.RedactString(ctx, v.text)
			if err != nil {
				t.Fatalf("redact %s %q: %v", v.form, v.text, err)
			}

			want := "[shield:" + wantKind + ":tok_"
			if !strings.Contains(out, want) {
				t.Errorf("%s form lost detection entirely:\n  in:  %s\n  out: %s\n"+
					"want a %s marker", v.form, v.text, out, wantKind)
				continue
			}
			// The real assertion. A marker is present either way; the question is
			// whether any of the original value survived in front of it.
			if m := markerAfterAtSign.FindString(out); m != "" {
				t.Errorf("%s form matched an address from the DOMAIN inwards, leaving its local "+
					"part in the clear:\n  in:  %s\n  out: %s\n"+
					"A marker preceded by \"@\" always means the email pattern failed and the "+
					"hostname pattern picked up the second half. The output looks redacted and is not.",
					v.form, v.text, out)
			}
			if m := markerGluedToText.FindString(out); m != "" {
				t.Errorf("%s form leaked the prefix of a real value (%q sits against the marker):\n"+
					"  in:  %s\n  out: %s\n"+
					"The character class stops short of some part of the value. Combining marks "+
					"are \\p{M}, not \\p{L}.", v.form, m, v.text, out)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Fail closed. If the table stops matching the corpus (all accented lines
	// removed, or the replacer emptied), this gate silently becomes a no-op.
	if derived < 3 {
		t.Fatalf("ABORT: only %d decomposed variants were derived from the corpus, so this gate "+
			"is nearly vacuous. Either the corpus lost its accented addresses or nfdDecompose "+
			"stopped matching them.", derived)
	}
	t.Logf("derived and checked %d decomposed variants", derived)
}

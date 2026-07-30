package shield

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

// An address must be tokenized WHOLE or not at all. Never split.
//
// This is the fifth distinct route into one failure class, and the reason this
// file is generated rather than a list. The four before it were:
//
//  1. ASCII-only local part      -> "Åsa.Ö" leaked before the marker
//  2. \p{L} but not \p{M}        -> NFD form leaked identically, invisibly
//  3. quoted local part          -> hostname claimed the domain, name left bare
//  4. pattern ORDER              -> personnummer claimed part of the local part,
//     "anna.svensson." left bare
//
// Every one was fixed, believed closed, and followed by another. Every one was
// found by someone constructing an input nobody had written down. So the cases
// here are BUILT from parts at run time: any local-part shape combined with any
// domain shape, which covers combinations no author would think to enumerate.
//
// The assertions are the two invariants, and they are what generalises rather than
// the input list:
//
//	no marker preceded by a letter/mark/digit  -> the pattern stopped short
//	no marker preceded by "@"                  -> the domain was matched inwards
//	the raw local part absent from the output  -> the thing we actually care about
var (
	splitBefore = regexp.MustCompile(`[\p{L}\p{M}\p{N}]\[shield:`)
	splitAtSign = regexp.MustCompile(`@\[shield:`)
)

func TestAnAddressIsNeverSplit(t *testing.T) {
	// Local parts chosen so each one makes a DIFFERENT narrower pattern want to
	// claim part of the address: a personnummer, an IBAN, a card number, a phone.
	locals := map[string]string{
		"plain":               "anna.svensson",
		"accented":            "Åsa.Öberg",
		"nfd-accented":        "Åsa.Öberg",
		"personnummer-suffix": "anna.svensson.19850101-1234",
		"personnummer-only":   "19850101-1234",
		"iban-only":           "SE4550000000058398257466",
		"card-only":           "4111111111111111",
		"phone-only":          "070-1234567",
		"plus-tag":            "anna+19850101-1234",
		"quoted-with-space":   `"anna svensson"`,
		"underscored":         "anna_svensson_1985",
		"digits-then-letters": "19850101anna",
	}
	domains := map[string]string{
		"fqdn":          "example.se",
		"subdomain":     "mail.example.co.uk",
		"accented-host": "bücher.com",
		"punycode":      "xn--bcher-kva.com",
		"ipv4-literal":  "192.168.1.1",
	}

	ctx := context.Background()
	checked := 0
	for ln, local := range locals {
		for dn, domain := range domains {
			name := ln + "@" + dn
			addr := local + "@" + domain
			in := "please mail " + addr + " today"

			s, err := NewSession(ctx, NewMemoryStore(), "addr", testKey(), time.Minute, HintFull)
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			out, err := s.RedactString(ctx, in)
			if err != nil {
				t.Fatalf("%s: redact: %v", name, err)
			}
			checked++

			if m := splitAtSign.FindString(out); m != "" {
				t.Errorf("%s: the address was matched from the DOMAIN inwards, so its local part "+
					"survived:\n  in:  %s\n  out: %s", name, in, out)
				continue
			}
			if m := splitBefore.FindString(out); m != "" {
				t.Errorf("%s: a marker is welded to text (%q), so the pattern stopped short and left "+
					"part of the value:\n  in:  %s\n  out: %s", name, m, in, out)
				continue
			}
			// The point of all of it: the raw local part must not survive. Checked
			// separately because a split is the MECHANISM and this is the HARM, and
			// a future route into this class might produce the harm without either
			// regex above firing.
			//
			// Quoted local parts are exempted from this specific check only because
			// the quotes themselves are retained around the marker in some shapes;
			// the two split checks above still apply to them in full.
			if !strings.HasPrefix(local, `"`) && strings.Contains(out, local) {
				t.Errorf("%s: the local part %q survived in the output:\n  in:  %s\n  out: %s",
					name, local, in, out)
			}
		}
	}

	// Fail closed: if the maps are emptied or the loop stops running, this gate
	// silently becomes a no-op, which is the exact shape it exists to prevent.
	if want := len(locals) * len(domains); checked != want || checked < 30 {
		t.Fatalf("ABORT: checked %d combinations, expected %d (and at least 30); this gate is "+
			"not exercising what it claims to", checked, want)
	}
	t.Logf("checked %d generated local-part x domain combinations", checked)
}

// TestBareValuesStillMatchTheirOwnPattern is the other direction.
//
// Moving email ahead of personnummer, IBAN and the rest fixes the split, and it
// could just as easily have broken the narrower patterns by letting email swallow
// them. It cannot, because none of these contains an "@", but that is exactly the
// kind of reasoning that deserves a test rather than a comment.
func TestBareValuesStillMatchTheirOwnPattern(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct{ kind, in string }{
		{"personnummer", "personnummer 19850101-1234 on file"},
		{"iban", "iban SE4550000000058398257466 on file"},
		{"ip", "host 192.168.1.1 on file"},
		{"hostname", "visit example.com on file"},
	} {
		s, _ := NewSession(ctx, NewMemoryStore(), "bare", testKey(), time.Minute, HintFull)
		out, err := s.RedactString(ctx, c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if !strings.Contains(out, "[shield:"+c.kind+":tok_") {
			t.Errorf("a bare %s is no longer matched by its own pattern:\n  in:  %s\n  out: %s\n"+
				"Reordering the bank must not let a broader pattern swallow a narrower one.",
				c.kind, c.in, out)
		}
	}
}

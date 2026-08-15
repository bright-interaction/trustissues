package reflectguard

import (
	"bytes"
	"strings"
	"testing"
)

// THE UPSTREAM IS NOT WRITTEN IN GO.
//
// Every body below is the REAL output of a standard library in another
// language reflecting the same credential, and every one of them walked
// straight through this guard until Scan started decoding: the needle set was
// built by asking Go to escape the secret and then demanding a byte-exact
// match, which quietly scoped the whole package to Go-speaking upstreams.
//
// Keep this table in terms of "which encoder produced this", not "which
// characters are in it". The failure was never a missing character class, it
// was the assumption that one language's escaping is the escaping.
//
// The escapes below are written with SINGLE backslashes inside backquoted Go
// raw strings, which is what the upstream actually sends. Writing them in an
// interpreted "..." literal instead, or letting a scripted edit double them,
// produces a body containing a literal backslash-backslash that no upstream
// emits, the case then proves nothing, and it still reads correct. That
// mistake is the reason this comment exists.
func TestNonGoEncodingDialectsAreCaught(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		body   string
		// viaDecoder says this case MUST be caught by one of the decoded
		// readings. Three of the cases in the first draft of this table were
		// caught by the pre-existing Go-built needles instead -- the bodies
		// looked like another language's output but were byte-identical to
		// Go's, so they passed with the fix reverted and proved nothing. The
		// label is checked rather than trusted for exactly that reason.
		viaDecoder bool
	}{
		{
			// PHP escapes '/' by default; Go never does. '/' is in the base64
			// alphabet, so this hits ordinary API keys, not exotic ones.
			name:       "php json_encode escapes the forward slash",
			secret:     "sk-live/AbCdEf/1234",
			body:       `{"error":"invalid token sk-live\/AbCdEf\/1234"}`,
			viaDecoder: true,
		},
		{
			// Python's json.dumps defaults to ensure_ascii=True and PHP's
			// json_encode escapes non-ASCII unless told otherwise. Go emits the
			// UTF-8 bytes, so neither the plaintext needle nor the json needle
			// matches what either of them sends.
			name:       "python json.dumps escapes non-ascii as \\uXXXX",
			secret:     "passphrase-café-1234",
			body:       `{"error":"passphrase-caf\u00e9-1234"}`,
			viaDecoder: true,
		},
		{
			name:       "python html.escape spells the apostrophe &#x27;",
			secret:     "tok'en-abcdefgh",
			body:       `<p>rejected: tok&#x27;en-abcdefgh</p>`,
			viaDecoder: true,
		},
		{
			name:       "php htmlspecialchars spells it &#039;",
			secret:     "tok'en-abcdefgh",
			body:       `<p>rejected: tok&#039;en-abcdefgh</p>`,
			viaDecoder: true,
		},
		{
			name:       "an xml serializer spells it &apos;",
			secret:     "tok'en-abcdefgh",
			body:       `<p>rejected: tok&apos;en-abcdefgh</p>`,
			viaDecoder: true,
		},
		{
			// Go's url.QueryEscape emits uppercase hex. Plenty of encoders emit
			// lowercase, and bytes.Contains does not care what RFC 3986 says
			// about them being equivalent.
			name:       "a percent-encoder that emits lowercase hex",
			secret:     "sk-live/AbCdEf/1234",
			body:       `{"redirect":"https://x.test/cb?t=sk-live%2fAbCdEf%2f1234"}`,
			viaDecoder: true,
		},
		{
			// The escapings compose: base64 first, then a PHP JSON encoder
			// escaping the '/' that base64 put there. Caught by the base64
			// needle only because the JSON reading undoes the escape first.
			name:   "base64 of the secret, then php json escaping of its slash",
			secret: "binary-credential\xff\xe0-bytes-here",
			// The base64 is YmluYXJ5LWNyZWRlbnRpYWz/4C1ieXRlcy1oZXJl and PHP
			// escapes the '/' 23 characters in. It has to be IN THE MIDDLE to
			// prove anything: New() also builds phase-shifted base64 needles
			// that trim the head, so an escape on the first character leaves a
			// phase needle matching the rest and the case passes with the
			// decoding reverted. That is how this one was written the first
			// time, and viaDecoder is what caught it.
			body:       `{"echo":"YmluYXJ5LWNyZWRlbnRpYWz\/4C1ieXRlcy1oZXJl"}`,
			viaDecoder: true,
		},
		{
			// A form-encoded reflection, where '+' is a space and not a plus.
			// url.QueryEscape("pass phrase/with spaces") is
			// "pass+phrase%2Fwith+spaces", so a lowercase-hex encoder defeats
			// the existing needle and only the form reading (+ as space, hex
			// case-insensitive) gets there.
			name:       "form-encoded body, lowercase hex, + meaning space",
			secret:     "pass phrase/with spaces",
			body:       `q=pass+phrase%2fwith+spaces&ok=0`,
			viaDecoder: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New([]byte(c.secret))
			enc, hit := s.Scan([]byte(c.body))
			if !hit {
				t.Fatalf("MISSED a reflected credential.\n  secret %q\n  body   %s", c.secret, c.body)
			}
			if c.viaDecoder && !strings.Contains(enc, "(") {
				t.Fatalf("caught as %q, which is a RAW needle match: this body is\n"+
					"byte-identical to something Go's own encoders produce, so the\n"+
					"case would pass with the decoding reverted and guards nothing.\n"+
					"  secret %q\n  body   %s", enc, c.secret, c.body)
			}
			t.Logf("caught as %s", enc)
		})
	}
}

// The other half of the claim: decoding must not turn ordinary traffic into a
// detection. A guard that fires on clean responses is removed within a week,
// and these readings are exactly the kind of change that could do it -- a body
// full of percent signs and backslashes now gets searched three more times.
func TestDecodedReadingsDoNotFireOnCleanTraffic(t *testing.T) {
	// Deliberately the same shape as the dialect table's fixtures rather than a
	// high-entropy `secret := "sk-live-<32 hex>"`. gitleaks' generic-api-key
	// rule fires on an entropy-dense string next to the keyword "secret" or
	// "token", and internal/reflectguard is not in .gitleaks.toml's allowlisted
	// test paths -- so writing the realistic-looking version here turns the
	// secret scan red and the fix for that is either to weaken the scan over
	// this package or to stop scanning it. Neither is worth it: nothing in this
	// test depends on the fixture's entropy.
	credential := "sk-live/AbCdEf/1234/XyZ"
	s := New([]byte(credential))
	clean := []string{
		`{"path":"/usr/local/bin","escaped":"a\/b\/c","pct":"%2F%2F%2F"}`,
		`<html><body>&amp;&lt;&gt;&quot;&apos;&#39;&#x27;</body></html>`,
		`q=a+b+c&r=100%25&s=%zz%2&t=AB😀\uDEAD`,
		strings.Repeat(`\\%%&&##;;`, 500),
		`{"other":"sk-live/AbCdEf/1234/XyQ"}`, // one character off the credential
	}
	for _, body := range clean {
		if enc, hit := s.Scan([]byte(body)); hit {
			t.Errorf("false positive as %q on clean body: %s", enc, body)
		}
	}
}

// A reflection that lands across a chunk boundary has to be caught in its
// ESCAPED length, not its plaintext length. That is what Overlap's
// maxEscapeExpansion buys: the carried tail has to be long enough to hold a
// whole escaped occurrence, and an escaped occurrence is several times longer
// than any needle.
//
// The placement below is the entire test. Landing the reflection a few bytes
// before the boundary proves nothing -- it then sits inside the carried tail
// whatever the overlap is, and the case passes with the fix reverted. It has to
// straddle by MORE than the old overlap, which is asserted rather than
// eyeballed.
func TestRelayCatchesAnEscapedSecretStraddlingAChunkBoundary(t *testing.T) {
	secret := "sk-live/AbCdEf/1234/XyZ"
	s := New([]byte(secret))

	// \u-escape every byte, which is the longest form a JSON encoder produces
	// and so the one most likely to outrun the overlap.
	var escaped bytes.Buffer
	for _, r := range secret {
		if r == '/' {
			escaped.WriteString(`\/`)
			continue
		}
		const hexd = "0123456789abcdef"
		escaped.WriteString(`\u00`)
		escaped.WriteByte(hexd[byte(r)>>4])
		escaped.WriteByte(hexd[byte(r)&0xf])
	}
	esc := escaped.String()

	// What Overlap() returned before this was fixed: one byte short of the
	// longest NEEDLE, which knows nothing about escaping.
	oldOverlap := s.maxLen - 1
	inFirstChunk := oldOverlap + 8
	if len(esc) <= inFirstChunk {
		t.Fatalf("setup: the escaped form is %d bytes and %d of it would sit in the first chunk, "+
			"so the whole reflection fits in the old overlap and this case cannot fail", len(esc), inFirstChunk)
	}

	prefix := `{"e":"`
	head := strings.Repeat("a", chunkSize-inFirstChunk-len(prefix))
	body := head + prefix + esc + `"}`

	var out bytes.Buffer
	committed, err := s.Relay(&out, strings.NewReader(body), DefaultHoldBack, func() {})
	if err == nil {
		t.Fatalf("relayed an escaped reflected credential straddling the chunk boundary "+
			"(committed=%v, %d bytes written, %d of %d escaped bytes in the first chunk)",
			committed, out.Len(), inFirstChunk, len(esc))
	}
	refl, ok := err.(*ReflectedError)
	if !ok {
		t.Fatalf("expected a ReflectedError, got %T: %v", err, err)
	}
	t.Logf("caught as %s (%d of %d escaped bytes in the first chunk, old overlap was %d)",
		refl.Encoding, inFirstChunk, len(esc), oldOverlap)
}

// Wipe has to reach the decoded readings too: they are response-body bytes,
// which is to say they are the secret whenever the scan hit.
func TestWipeZeroesTheDecodedReadings(t *testing.T) {
	secret := "sk-live/AbCdEf/1234"
	s := New([]byte(secret))
	if _, hit := s.Scan([]byte(`{"error":"sk-live\/AbCdEf\/1234"}`)); !hit {
		t.Fatal("setup: the reflection was not detected, so nothing was decoded")
	}
	found := false
	for _, b := range s.scratch {
		if bytes.Contains(b[:cap(b)], []byte(secret)) {
			found = true
		}
	}
	if !found {
		t.Fatal("setup: no scratch buffer holds the decoded secret, so this proves nothing")
	}
	s.Wipe()
	for i, b := range s.scratch {
		full := b[:cap(b)]
		if bytes.Contains(full, []byte(secret)) {
			t.Errorf("scratch[%d] still holds the plaintext secret after Wipe", i)
		}
		for j, c := range full {
			if c != 0 {
				t.Errorf("scratch[%d][%d] = %d, want 0", i, j, c)
				break
			}
		}
	}
}

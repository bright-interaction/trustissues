package reflectguard

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const theSecret = "sk-live-AbC/dEf+GhI-0123456789"

// TestScannerCoversTheEncodingsItClaims is the list from the package doc turned
// into assertions. Each case is a shape an upstream realistically returns, and
// each one defeats a naive bytes.Contains on the raw plaintext.
func TestScannerCoversTheEncodingsItClaims(t *testing.T) {
	s := New([]byte(theSecret))
	defer s.Wipe()

	jsonEscaped := func(v string) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(b[1 : len(b)-1])
	}

	cases := []struct {
		name string
		body string
	}{
		{"raw plaintext in a JSON body", `{"received":{"authorization":"Bearer ` + theSecret + `"}}`},
		{"percent-encoded in a reflected URL", `{"url":"https://up.example/cb?token=` + url.QueryEscape(theSecret) + `"}`},
		{"json-escaped", `{"echo":"` + jsonEscaped(theSecret) + `"}`},
		{"hex lower", `{"raw":"` + hex.EncodeToString([]byte(theSecret)) + `"}`},
		{"hex upper", `{"raw":"` + strings.ToUpper(hex.EncodeToString([]byte(theSecret))) + `"}`},
		{"base64 of the value alone", `{"b":"` + base64.StdEncoding.EncodeToString([]byte(theSecret)) + `"}`},
		{"base64url of the value alone", `{"b":"` + base64.RawURLEncoding.EncodeToString([]byte(theSecret)) + `"}`},
		// The alignment cases. The secret sits at offsets 7, 6 and 5 of the
		// encoded blob, so it starts at all three positions within base64's
		// 3-byte groups. Without phaseSlice, none of these match anything.
		{"base64 of Bearer + value", `{"b":"` + base64.StdEncoding.EncodeToString([]byte("Bearer "+theSecret)) + `"}`},
		{"base64 of Basic user:value", `{"b":"` + base64.StdEncoding.EncodeToString([]byte("api:"+theSecret)) + `"}`},
		{"base64 of a 5-byte prefix + value", `{"b":"` + base64.StdEncoding.EncodeToString([]byte("key: "+theSecret)) + `"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc, hit := s.Scan([]byte(c.body))
			if !hit {
				t.Fatalf("the secret went undetected in %q", c.body)
			}
			t.Logf("caught as %s", enc)
		})
	}
}

// TestScannerDoesNotFireOnCleanTraffic is the other half. A guard that fails
// closed on ordinary responses is a denial of service against its own users, so
// the false-positive side is load-bearing.
func TestScannerDoesNotFireOnCleanTraffic(t *testing.T) {
	s := New([]byte(theSecret))
	defer s.Wipe()
	for _, clean := range []string{
		`{"id":"msg_01","model":"claude-3","content":[{"type":"text","text":"hello"}]}`,
		`{"error":{"type":"invalid_request_error","message":"invalid api key"}}`,
		`sk-live-`,
		`{"b":"` + base64.StdEncoding.EncodeToString([]byte("some other value entirely")) + `"}`,
		"",
	} {
		if enc, hit := s.Scan([]byte(clean)); hit {
			t.Fatalf("false positive (%s) on clean body %q", enc, clean)
		}
	}
}

// TestShortSecretsAreNotSubstringScanned pins the documented limit, so nobody
// later reads a passing suite as proof that a 4-character secret is covered.
func TestShortSecretsAreNotSubstringScanned(t *testing.T) {
	s := New([]byte("abc"))
	defer s.Wipe()
	if _, hit := s.Scan([]byte("the alphabet starts abc and continues")); hit {
		t.Fatal("a 3-byte secret must not be substring-scanned; it would match everything")
	}
	if !s.Equals([]byte("abc")) {
		t.Fatal("a short secret must still be caught by whole-value equality")
	}
	if s.Equals([]byte("abd")) {
		t.Fatal("Equals matched a different value")
	}
}

func TestScanHeaderCatchesAReflectedCredential(t *testing.T) {
	s := New([]byte(theSecret))
	defer s.Wipe()
	h := http.Header{
		"Content-Type": []string{"application/json"},
		"Set-Cookie":   []string{"last_key=" + theSecret + "; Path=/"},
	}
	name, enc, hit := s.ScanHeader(h)
	if !hit {
		t.Fatal("a secret reflected into Set-Cookie reached the caller")
	}
	if name != "Set-Cookie" {
		t.Fatalf("wrong header named: %s (%s)", name, enc)
	}
	clean := http.Header{"Content-Type": []string{"application/json"}, "X-Request-Id": []string{"req_123"}}
	if _, _, hit := s.ScanHeader(clean); hit {
		t.Fatal("false positive on clean headers")
	}
}

// TestRelayHoldsBackBeforeCommitting is the property the clean 502 depends on:
// while the body still fits in the hold-back, a detection must leave the
// response completely unstarted so the handler can send its own error.
func TestRelayHoldsBackBeforeCommitting(t *testing.T) {
	s := New([]byte(theSecret))
	defer s.Wipe()

	var out bytes.Buffer
	began := false
	body := strings.NewReader(`{"you_sent":"Bearer ` + theSecret + `"}`)
	committed, err := s.Relay(&out, body, DefaultHoldBack, func() { began = true })

	var refl *ReflectedError
	if !errors.As(err, &refl) {
		t.Fatalf("Relay returned %v, want a ReflectedError", err)
	}
	if committed || began {
		t.Fatal("Relay committed the response despite finding the secret inside the hold-back")
	}
	if out.Len() != 0 {
		t.Fatalf("%d bytes reached the caller: %q", out.Len(), out.String())
	}
	if strings.Contains(refl.Error(), theSecret) {
		t.Fatalf("the error message carries the secret: %s", refl.Error())
	}
}

// TestRelayCatchesASecretStraddlingAChunkBoundary is why the tail carry exists.
// Past the hold-back the body is scanned and released chunk by chunk, and a
// needle sitting across the seam is exactly what a naive per-chunk scan misses.
func TestRelayCatchesASecretStraddlingAChunkBoundary(t *testing.T) {
	s := New([]byte(theSecret))
	defer s.Wipe()

	// Hold back one chunk only, then place the secret so it begins a few bytes
	// before a chunk boundary and ends after it.
	hold := chunkSize
	pad := strings.Repeat("x", hold+chunkSize-5)
	body := strings.NewReader(pad + theSecret + strings.Repeat("y", 100))

	var out bytes.Buffer
	committed, err := s.Relay(&out, body, hold, func() {})
	var refl *ReflectedError
	if !errors.As(err, &refl) {
		t.Fatalf("Relay returned %v, want a ReflectedError", err)
	}
	if !committed {
		t.Fatal("expected the response to have been committed by this point")
	}
	if bytes.Contains(out.Bytes(), []byte(theSecret)) {
		t.Fatal("the secret reached the caller")
	}
}

// TestRelayIsBoundedAndDoesNotBufferTheWholeBody. The sibling io.ReadAll finding
// in this codebase is what this asserts against: a 40 MiB upstream must stream
// through a fixed-size window, not land in memory.
func TestRelayIsBoundedAndDoesNotBufferTheWholeBody(t *testing.T) {
	s := New([]byte(theSecret))
	defer s.Wipe()

	const total = 40 << 20
	src := &countingReader{remaining: total, fill: 'a'}
	sink := &countingWriter{}
	committed, err := s.Relay(sink, src, DefaultHoldBack, func() {})
	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if !committed {
		t.Fatal("a clean body must be committed and delivered")
	}
	if sink.n != total {
		t.Fatalf("delivered %d bytes of %d", sink.n, total)
	}
	if src.maxRead > chunkSize {
		t.Fatalf("Relay read %d bytes at once; the window is supposed to be bounded at %d", src.maxRead, chunkSize)
	}
}

// TestRelayDoesNotForwardABodyItCouldNotFinishReading. A read error mid-body is
// a body that was never fully scanned, and forwarding the scanned prefix would
// be forwarding a decision that was never made.
func TestRelayDoesNotForwardABodyItCouldNotFinishReading(t *testing.T) {
	s := New([]byte(theSecret))
	defer s.Wipe()

	boom := errors.New("connection reset")
	src := io.MultiReader(strings.NewReader(`{"partial":`), &erroringReader{err: boom})
	var out bytes.Buffer
	committed, err := s.Relay(&out, src, DefaultHoldBack, func() {})
	if !errors.Is(err, boom) {
		t.Fatalf("Relay returned %v, want the read error", err)
	}
	if committed || out.Len() != 0 {
		t.Fatalf("forwarded %d bytes of an unfinished body", out.Len())
	}
}

func TestRelayDeliversACleanBodyUnchanged(t *testing.T) {
	s := New([]byte(theSecret))
	defer s.Wipe()
	const want = `{"id":"msg_01","content":"hello"}`
	var out bytes.Buffer
	committed, err := s.Relay(&out, strings.NewReader(want), DefaultHoldBack, func() {})
	if err != nil || !committed {
		t.Fatalf("Relay(clean) = %v, committed=%v", err, committed)
	}
	if out.String() != want {
		t.Fatalf("body altered: %q", out.String())
	}
}

// TestWipeZeroesEveryEncodedForm. New derives eight-odd copies of a decrypted
// credential; leaving them in the heap after the request would trade one leak
// for another.
func TestWipeZeroesEveryEncodedForm(t *testing.T) {
	s := New([]byte(theSecret))
	if len(s.needles) < 4 {
		t.Fatalf("expected several encoded forms, got %d", len(s.needles))
	}
	s.Wipe()
	for _, n := range s.needles {
		for _, b := range n.b {
			if b != 0 {
				t.Fatalf("needle %s survived Wipe", n.label)
			}
		}
	}
	for _, b := range s.raw {
		if b != 0 {
			t.Fatal("the raw copy survived Wipe")
		}
	}
}

func TestUnarmedScannerIsATransparentCopy(t *testing.T) {
	s := New(nil)
	if s.Armed() {
		t.Fatal("an empty secret must not arm the scanner")
	}
	var out bytes.Buffer
	began := 0
	committed, err := s.Relay(&out, strings.NewReader("hello"), DefaultHoldBack, func() { began++ })
	if err != nil || !committed || out.String() != "hello" || began != 1 {
		t.Fatalf("Relay(unarmed) = %v committed=%v began=%d body=%q", err, committed, began, out.String())
	}
}

type countingReader struct {
	remaining int
	fill      byte
	maxRead   int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = r.fill
	}
	r.remaining -= n
	return n, nil
}

type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }

type erroringReader struct{ err error }

func (r *erroringReader) Read([]byte) (int, error) { return 0, r.err }

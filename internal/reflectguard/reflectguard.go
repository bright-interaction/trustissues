// Package reflectguard catches an injected secret coming back OUT of the
// upstream it was injected into.
//
// # WHY THIS EXISTS
//
// The capability bridge's whole promise is USE-without-SEE: a caller drives
// /proxy/{host}/{path}, the server decrypts the credential and injects it into
// the outbound request, and the caller never holds the bytes. THREAT-MODEL.md
// states it as a guarantee ("The AI and the human never see the secret, in use
// or at rest").
//
// Injection is only half of that promise. The other half is the RESPONSE. An
// upstream that echoes what it was sent hands the credential straight back
// through a proxy that, until this package existed, relayed the body verbatim:
//
//   - a debug or "whoami" endpoint that returns the received headers,
//   - a validation error quoting the offending token,
//   - a 401 body repeating the credential it just rejected,
//   - a Set-Cookie or X-Echo-* header carrying it back,
//   - any upstream a widened destination pattern points at, which is a host the
//     caller had a hand in choosing.
//
// None of those require the upstream to be malicious. Several are ordinary
// developer conveniences. The caller is by construction not allowed to have the
// plaintext, so any of them turns USE into SEE with a 200.
//
// # WHAT IT COVERS, AND WHAT IT DELIBERATELY DOES NOT
//
// A bare bytes.Contains on the raw plaintext is not enough: an upstream that
// reflects into JSON, a URL, or an HTTP Basic credential re-encodes on the way
// out. Covered encodings, each realistically reachable through this proxy:
//
//	plaintext            the raw bytes, in a body or a header value
//	percent-encoded      reflected inside a URL or a form body (query + path forms)
//	json-escaped         reflected into a JSON string that needed escaping
//	html-escaped         reflected into an HTML error page
//	hex                  lower and upper, the usual debug-dump rendering
//	base64               std and url alphabets, padded and unpadded, and the
//	                     three phase alignments so the secret is still found
//	                     when it is base64'd as PART of a larger blob (an
//	                     Authorization: Basic user:secret echo, for instance)
//
// NOT covered, consciously:
//
//   - Compressed bodies. Handled at the call site instead, and handled by
//     REFUSAL rather than by scanning: the proxy no longer forwards the
//     caller's Accept-Encoding (so Go's transport negotiates gzip itself and
//     hands us plaintext), and a response that still arrives with a
//     Content-Encoding is refused unscanned rather than relayed. Scanning
//     compressed bytes for a plaintext needle finds nothing, which is the
//     failure mode that looks like success.
//   - Encryption, and any encoding the upstream invents. A hostile upstream
//     colluding with the caller can always exfiltrate through a channel we
//     cannot recognise. This guard is aimed at the honest-but-echoing upstream,
//     which is the reachable case; a caller who can choose a colluding host has
//     already been given the credential by the destination allow-list.
//   - Secrets shorter than minNeedle bytes are not substring-scanned, because a
//     4-character needle matches half the JSON on the internet and would fail
//     every integration closed. They are still compared for EQUALITY, in
//     constant time, against whole header values, which is the reflection shape
//     a short value actually takes.
//   - Split reflections (the secret returned in two pieces across two fields).
//
// FAILURE MODE: CLOSED
//
// On detection the bytes are not delivered. There is no redact-and-forward:
// redaction on a stream means deciding what to do with a needle that straddles
// a chunk boundary, and getting that wrong ships the tail of the credential.
// Refusing is a broken integration; redacting wrongly is a leaked credential.
// Every detection is written to the audit trail by the caller, because a silent
// block is nearly as bad as a leak for an operator trying to explain why an
// integration stopped working.
package reflectguard

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// minNeedle is the shortest byte string this package will substring-scan for.
// See the package doc: below it the false-positive rate makes the guard a
// denial of service against its own users.
const minNeedle = 8

// DefaultHoldBack is how many bytes [Scanner.Relay] accumulates, scanned but
// unwritten, before it commits to a response.
//
// It is the knob that buys a CLEAN refusal. While the whole body is still in
// hand, a detection can be answered with a proper status code and an error body
// that explains itself. Past this point the status line is already on the wire
// and the only honest answer left is to abort the connection.
//
// 1 MiB covers essentially every shape a reflection actually takes: a JSON API
// response, a validation error, a 401 body, an HTML error page. Larger than
// that is a download or a stream, where the reflection would have to be sitting
// past the first megabyte.
const DefaultHoldBack = 1 << 20

// chunkSize bounds the read, and with it the memory this package adds on top of
// the hold-back. Relay never reads an unbounded body into memory: it holds at
// most DefaultHoldBack + chunkSize + one needle's overlap, whatever the
// upstream sends.
const chunkSize = 32 << 10

// needle is one encoded form of the secret, with the label that names the
// encoding in the audit row.
type needle struct {
	label string
	b     []byte
}

// Scanner holds every encoded form of one secret. Build it with [New], use it
// for one request, and [Scanner.Wipe] it when the request is done: the encoded
// forms are derived copies of a decrypted credential and are exactly as
// sensitive as the original.
type Scanner struct {
	raw     []byte
	needles []needle
	maxLen  int
}

// New builds a scanner for one secret. The secret is copied, so the caller may
// wipe its own buffer independently.
func New(secret []byte) *Scanner {
	s := &Scanner{}
	if len(secret) == 0 {
		return s
	}
	s.raw = append([]byte(nil), secret...)
	str := string(secret)

	s.add("plaintext", s.raw)
	s.add("percent-encoded", []byte(url.QueryEscape(str)))
	s.add("percent-encoded", []byte(url.PathEscape(str)))
	if j, err := json.Marshal(str); err == nil && len(j) >= 2 {
		// Marshal wraps in quotes; the reflected form is what is BETWEEN them.
		s.add("json-escaped", j[1:len(j)-1])
	}
	s.add("html-escaped", []byte(html.EscapeString(str)))
	lower := hex.EncodeToString(secret)
	s.add("hex", []byte(lower))
	s.add("hex", []byte(strings.ToUpper(lower)))

	// Whole-value base64, both alphabets, padded.
	s.add("base64", []byte(base64.StdEncoding.EncodeToString(secret)))
	s.add("base64url", []byte(base64.URLEncoding.EncodeToString(secret)))
	// Embedded base64: the secret encoded as part of a larger blob. Which
	// output characters depend only on the secret is a function of where the
	// secret starts within the encoder's 3-byte groups, so all three alignments
	// are needed. Without them, base64("user:" + secret) contains none of the
	// needles above and the guard misses an Authorization: Basic echo.
	for phase := 0; phase < 3; phase++ {
		s.add("base64", phaseSlice(base64.RawStdEncoding, secret, phase))
		s.add("base64url", phaseSlice(base64.RawURLEncoding, secret, phase))
	}
	return s
}

// phaseSlice returns the run of base64 output characters that depends ONLY on
// secret when secret begins at byte offset `phase` (mod 3) of a larger input.
//
// Base64 maps every 3 input bytes onto 4 output characters. A secret that does
// not start on a group boundary shares its first output characters with the
// bytes in front of it and its last with the bytes behind it, so both ends have
// to be trimmed away before the middle is a valid needle.
func phaseSlice(enc *base64.Encoding, secret []byte, phase int) []byte {
	if phase < 0 || phase > 2 {
		return nil
	}
	padded := make([]byte, phase+len(secret))
	copy(padded[phase:], secret)
	out := []byte(enc.EncodeToString(padded))
	// Head: characters carrying bits of the filler in front.
	head := [3]int{0, 2, 3}[phase]
	// Tail: only COMPLETE 3-byte groups produce characters that a following
	// suffix could not change.
	keep := ((phase + len(secret)) / 3) * 4
	if keep > len(out) {
		keep = len(out)
	}
	if head >= keep {
		return nil
	}
	// Copied, not sub-sliced, so Wipe zeroes the whole backing array.
	return append([]byte(nil), out[head:keep]...)
}

func (s *Scanner) add(label string, b []byte) {
	if len(b) < minNeedle {
		return
	}
	for _, existing := range s.needles {
		if bytes.Equal(existing.b, b) {
			return
		}
	}
	if len(b) > s.maxLen {
		s.maxLen = len(b)
	}
	s.needles = append(s.needles, needle{label: label, b: b})
}

// Armed reports whether this scanner has anything to look for. A scanner built
// from an empty secret is not armed; a scanner built from a secret shorter than
// minNeedle is armed only for [Scanner.Equals].
func (s *Scanner) Armed() bool { return len(s.raw) > 0 }

// Overlap is how many trailing bytes of an already-scanned window must be
// carried into the next one so a needle straddling the boundary is still found.
func (s *Scanner) Overlap() int {
	if s.maxLen <= 1 {
		return 0
	}
	return s.maxLen - 1
}

// Wipe zeroes every encoded form. Best effort, same contract as
// secretexit.Plaintext.Wipe: the derived encodings are the secret in another
// alphabet and must not outlive the request.
func (s *Scanner) Wipe() {
	for i := range s.raw {
		s.raw[i] = 0
	}
	for _, n := range s.needles {
		for i := range n.b {
			n.b[i] = 0
		}
	}
}

// Equals reports, in constant time, whether candidate IS the secret.
//
// This is the direct equality check, and it is constant-time because it is one:
// an upstream that reflects a credential into a header of its own reflects the
// WHOLE value, and comparing it byte by byte with an early return would leak a
// prefix length through timing to a caller who controls how often the
// comparison runs. The substring scanning below cannot be constant-time (a
// search is data-dependent by nature) and does not claim to be.
func (s *Scanner) Equals(candidate []byte) bool {
	if len(s.raw) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(s.raw, candidate) == 1
}

// Scan reports the first encoding of the secret found in b.
func (s *Scanner) Scan(b []byte) (string, bool) {
	for _, n := range s.needles {
		if bytes.Contains(b, n.b) {
			return n.label, true
		}
	}
	return "", false
}

// ScanHeader looks for the secret in a response header set: in the values, in
// the names, and as a whole value under constant-time equality.
//
// Headers matter as much as the body. An upstream can reflect a credential into
// a Set-Cookie, into a WWW-Authenticate challenge, or into an X-Echo-* header a
// gateway added for debugging, and header bytes reach the caller before a
// single byte of body does.
func (s *Scanner) ScanHeader(h http.Header) (name, encoding string, found bool) {
	for k, vs := range h {
		if enc, hit := s.Scan([]byte(k)); hit {
			return k, enc, true
		}
		for _, v := range vs {
			if s.Equals([]byte(v)) {
				return k, "plaintext", true
			}
			if enc, hit := s.Scan([]byte(v)); hit {
				return k, enc, true
			}
		}
	}
	return "", "", false
}

// ReflectedError says the upstream sent the injected secret back. Its message
// carries the encoding and the location and NOTHING derived from the value: it
// is written to capability_log.error and shown to an operator, and this package
// exists precisely because that value must not travel.
type ReflectedError struct {
	Encoding string // which encoded form matched
	Where    string // "header" or "body"
	Header   string // header name, when Where is "header"
}

func (e *ReflectedError) Error() string {
	if e.Where == "header" {
		return "upstream reflected the injected secret in response header " + e.Header + " (" + e.Encoding + ")"
	}
	return "upstream reflected the injected secret in the response body (" + e.Encoding + ")"
}

// Relay copies src to dst, scanning EVERY byte before it is written.
//
// begin is called at most once, immediately before the first byte reaches dst,
// and is where the caller writes response headers and the status code. It is
// NOT called when the reflection is found while the body is still held back,
// which is what leaves the caller free to send a clean error response instead.
// The returned committed flag says which of those happened.
//
// Memory is bounded by holdBack + chunkSize + Overlap() regardless of how much
// the upstream sends, so there is no size ceiling to trip over and no body that
// gets forwarded unscanned because it was too big to buffer. Streaming still
// works: past the hold-back, chunks are scanned and released one at a time.
//
// A detection after the commit point returns the ReflectedError with
// committed=true and stops writing. The bytes already written were scanned and
// carry no part of the secret; the caller decides how to abort what is left.
func (s *Scanner) Relay(dst io.Writer, src io.Reader, holdBack int, begin func()) (committed bool, err error) {
	if !s.Armed() || len(s.needles) == 0 {
		// Nothing to look for. Still routed through begin so the call site has
		// exactly one ordering to reason about.
		begin()
		_, cErr := io.Copy(dst, src)
		return true, cErr
	}
	if holdBack < chunkSize {
		holdBack = chunkSize
	}
	overlap := s.Overlap()

	pending := make([]byte, 0, holdBack+chunkSize)
	var tail, window []byte
	chunk := make([]byte, chunkSize)

	flush := func() error {
		if !committed {
			begin()
			committed = true
		}
		if len(pending) == 0 {
			return nil
		}
		if _, wErr := dst.Write(pending); wErr != nil {
			return wErr
		}
		if overlap > 0 {
			from := len(pending) - overlap
			if from < 0 {
				from = 0
			}
			tail = append(tail[:0], pending[from:]...)
		}
		pending = pending[:0]
		return nil
	}

	for {
		n, rErr := src.Read(chunk)
		if n > 0 {
			start := len(pending)
			pending = append(pending, chunk[:n]...)

			// Scan the new bytes plus enough of what came before them that a
			// needle spanning the seam is still found. When the preceding bytes
			// are already gone (flushed), the carried tail supplies them.
			from := start - overlap
			if from < 0 {
				from = 0
			}
			window = window[:0]
			if from == 0 {
				window = append(window, tail...)
			}
			window = append(window, pending[from:]...)
			if enc, hit := s.Scan(window); hit {
				return committed, &ReflectedError{Encoding: enc, Where: "body"}
			}

			if len(pending) >= holdBack {
				if fErr := flush(); fErr != nil {
					return committed, fErr
				}
			}
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			// Deliberately do NOT flush what is pending. A body we could not
			// finish reading is a body we could not finish scanning.
			return committed, rErr
		}
	}
	if fErr := flush(); fErr != nil {
		return committed, fErr
	}
	return committed, nil
}

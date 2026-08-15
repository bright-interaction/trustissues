package reflectguard

import (
	"unicode/utf16"
	"unicode/utf8"
)

// THE ENCODER-DIALECT PROBLEM, AND WHY THIS FILE DECODES INSTEAD OF ENCODING
//
// The needle set in New() is built by asking GO to escape the secret:
// url.QueryEscape, json.Marshal, html.EscapeString. Then Scan demands a
// byte-exact match. That silently made the guard specific to upstreams written
// in Go, which is a strange thing for a proxy whose entire job is talking to
// other people's servers. Every one of these is a standard library doing an
// ordinary thing, and every one of them defeated it:
//
//	php     json_encode("a/b")     -> "a\/b"          Go does not escape '/'
//	python  json.dumps("café")     -> "café"     Go emits the UTF-8 bytes
//	python  html.escape("'")       -> "&#x27;"        Go emits "&#39;"
//	php     htmlspecialchars("'")  -> "&#039;"        ditto, third spelling
//	xml     any serializer         -> "&apos;"        ditto, fourth spelling
//	various percent-encoders       -> "%2f"           Go emits "%2F"
//
// Adding those spellings to the needle set was the obvious fix and it is the
// wrong one: it fixes the six dialects somebody thought of and leaves the class
// alive, so the same finding comes back next time an upstream is written in a
// language nobody enumerated. The needle set cannot be completed, because it is
// a claim about every escaper that exists.
//
// So this file works the other way round. Decoders are near-universal where
// encoders are not: every dialect above produces something a permissive
// percent/JSON/HTML decoder turns back into the ORIGINAL bytes. Scan therefore
// searches the window as it arrived AND the small set of readings these
// decoders produce, so a hit needs only the secret to survive a round trip
// through one of the three escapings -- in ANY dialect, including ones written
// after this file.
//
// This composes with the existing needles rather than replacing them: the hex
// and base64 forms are re-scanned in each decoded reading too, so a base64
// blob that was then JSON-escaped (PHP turns its '/' into '\/') is caught by
// the base64 needle after the JSON reading undoes the escape.
//
// The decoders are deliberately PERMISSIVE. A malformed escape is emitted
// literally rather than rejected: this is a security scan, not a parser, and
// refusing to decode a body because one escape is malformed is how a scan gets
// skipped on exactly the input somebody crafted to skip it.

// unescaper is one reading of a window: a label for the audit row, a cheap
// applies() test so the pass is skipped when the window cannot contain that
// escaping at all, and the decoder itself.
type unescaper struct {
	label   string
	trigger byte
	fn      func(dst, src []byte) []byte
}

// The readings, in the order they are tried. Order only decides which label an
// operator sees when a body is escaped two ways at once.
var unescapers = []unescaper{
	{"percent-decoded", '%', func(dst, src []byte) []byte { return appendPercentDecoded(dst, src, false) }},
	// The second percent reading exists because '+' means space in a query and
	// means '+' everywhere else, and '+' is in the base64 alphabet. Decoding it
	// to a space is right for a form body and would destroy a base64 needle, so
	// both readings are taken rather than one being guessed at.
	{"percent-decoded (form)", '+', func(dst, src []byte) []byte { return appendPercentDecoded(dst, src, true) }},
	{"json-unescaped", '\\', appendJSONUnescaped},
	{"entity-unescaped", '&', appendEntityUnescaped},
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// appendPercentDecoded turns %XX (either hex case, which is the whole point)
// back into the byte it names. plusIsSpace selects the form-encoded reading.
func appendPercentDecoded(dst, src []byte, plusIsSpace bool) []byte {
	for i := 0; i < len(src); {
		if src[i] == '%' && i+2 < len(src) {
			if h, ok := unhex(src[i+1]); ok {
				if l, ok2 := unhex(src[i+2]); ok2 {
					dst = append(dst, h<<4|l)
					i += 3
					continue
				}
			}
		}
		if plusIsSpace && src[i] == '+' {
			dst = append(dst, ' ')
			i++
			continue
		}
		dst = append(dst, src[i])
		i++
	}
	return dst
}

// appendJSONUnescaped undoes the backslash escapes of the JSON family. It is
// looser than encoding/json on purpose: \/ is not something Go ever writes but
// is what PHP writes by default, \' is not JSON at all but is what a
// single-quoted JavaScript string carries, and an unknown \X yields X because
// that is what every dialect that invents an escape means by it.
func appendJSONUnescaped(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		if src[i] != '\\' || i+1 >= len(src) {
			dst = append(dst, src[i])
			i++
			continue
		}
		switch src[i+1] {
		case 'b':
			dst = append(dst, '\b')
			i += 2
		case 'f':
			dst = append(dst, '\f')
			i += 2
		case 'n':
			dst = append(dst, '\n')
			i += 2
		case 'r':
			dst = append(dst, '\r')
			i += 2
		case 't':
			dst = append(dst, '\t')
			i += 2
		case 'u':
			r, size, ok := decodeUnicodeEscape(src[i:])
			if !ok {
				dst = append(dst, src[i])
				i++
				continue
			}
			dst = utf8.AppendRune(dst, r)
			i += size
		default:
			// Covers \" \\ \/ \' and anything else: the backslash goes, the
			// character stays.
			dst = append(dst, src[i+1])
			i += 2
		}
	}
	return dst
}

// decodeUnicodeEscape reads one \uXXXX at the head of b, joining a surrogate
// PAIR when it finds one. Python's json.dumps and PHP's json_encode both emit
// \uXXXX for every non-ASCII character by default, and both spell an astral
// character as two escapes, so a secret with an emoji in it is a surrogate pair
// or it is nothing.
func decodeUnicodeEscape(b []byte) (r rune, size int, ok bool) {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return 0, 0, false
	}
	v := 0
	for i := 2; i < 6; i++ {
		h, valid := unhex(b[i])
		if !valid {
			return 0, 0, false
		}
		v = v<<4 | int(h)
	}
	r = rune(v)
	if utf16.IsSurrogate(r) {
		if len(b) >= 12 && b[6] == '\\' && b[7] == 'u' {
			lo := 0
			good := true
			for i := 8; i < 12; i++ {
				h, valid := unhex(b[i])
				if !valid {
					good = false
					break
				}
				lo = lo<<4 | int(h)
			}
			if good {
				if joined := utf16.DecodeRune(r, rune(lo)); joined != utf8.RuneError {
					return joined, 12, true
				}
			}
		}
		// A lone surrogate is not a character. Emitting U+FFFD here would let a
		// needle match across it, so it is reported as undecodable and the raw
		// bytes are kept.
		return 0, 0, false
	}
	return r, 6, true
}

// appendEntityUnescaped undoes the HTML/XML entity escapes.
//
// Only the numeric forms and the five named entities an ESCAPER produces are
// handled, which is the whole surface that matters here: html.EscapeString,
// htmlspecialchars, html.escape and every XML serializer emit some spelling of
// &amp; &lt; &gt; &quot; &apos; and nothing else. A secret byte never comes back
// as &hellip;. Keeping the table to five entries means it can be read and
// checked, rather than being a 2,000-entry map whose correctness nobody
// verifies.
//
// Go's html.UnescapeString would cover the same ground in one line and is not
// used: it takes a string, so it would copy the response body into an immutable
// allocation this package cannot Wipe, in a file whose whole subject is
// response bodies that may contain a decrypted credential.
func appendEntityUnescaped(dst, src []byte) []byte {
	named := [...]struct {
		name []byte
		ch   byte
	}{
		{[]byte("amp;"), '&'},
		{[]byte("lt;"), '<'},
		{[]byte("gt;"), '>'},
		{[]byte("quot;"), '"'},
		{[]byte("apos;"), '\''},
	}
	for i := 0; i < len(src); {
		if src[i] != '&' {
			dst = append(dst, src[i])
			i++
			continue
		}
		if r, size, ok := decodeNumericEntity(src[i:]); ok {
			dst = utf8.AppendRune(dst, r)
			i += size
			continue
		}
		matched := false
		for _, n := range named {
			if len(src)-i-1 >= len(n.name) && equalFoldASCII(src[i+1:i+1+len(n.name)], n.name) {
				dst = append(dst, n.ch)
				i += 1 + len(n.name)
				matched = true
				break
			}
		}
		if !matched {
			dst = append(dst, src[i])
			i++
		}
	}
	return dst
}

// decodeNumericEntity reads &#NN; or &#xHH; (either hex case, and either case
// of the 'x'), which is where the dialects actually differ: Go writes &#39;,
// PHP writes &#039;, Python writes &#x27;, all for one apostrophe. A leading
// zero is just a digit here, so &#039; and &#39; decode identically without
// needing to be listed separately.
func decodeNumericEntity(b []byte) (r rune, size int, ok bool) {
	if len(b) < 4 || b[0] != '&' || b[1] != '#' {
		return 0, 0, false
	}
	i := 2
	base, v := 10, 0
	if b[i] == 'x' || b[i] == 'X' {
		base = 16
		i++
	}
	digits := 0
	for ; i < len(b) && b[i] != ';'; i++ {
		var d byte
		var valid bool
		if base == 16 {
			d, valid = unhex(b[i])
		} else if b[i] >= '0' && b[i] <= '9' {
			d, valid = b[i]-'0', true
		}
		if !valid {
			return 0, 0, false
		}
		v = v*base + int(d)
		digits++
		// A code point cannot exceed U+10FFFF, and without this an entity of a
		// thousand digits would spin here overflowing an int.
		if v > 0x10FFFF {
			return 0, 0, false
		}
	}
	if digits == 0 || i >= len(b) || b[i] != ';' {
		return 0, 0, false
	}
	r = rune(v)
	if !utf8.ValidRune(r) {
		return 0, 0, false
	}
	return r, i + 1, true
}

// equalFoldASCII compares two byte slices ignoring ASCII case. Entity names are
// matched case-insensitively because &AMP; and &amp; are the same entity, and
// unlike strings.EqualFold this does not allocate or consider Unicode folding,
// neither of which applies to a five-entry table of ASCII names.
func equalFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

package shield

import (
	"context"
	"regexp"
	"strings"
)

// redactPattern is one regex + the kind it produces. Order in
// redactPatterns matters: more specific patterns must come before more
// general ones (e.g. personnummer before generic digit runs).
type redactPattern struct {
	kind Kind
	re   *regexp.Regexp
	hint []string // hint keys to extract on match
}

var redactPatterns = []redactPattern{
	{
		kind: KindPersonnummer,
		// Swedish personnummer: YYYYMMDD-XXXX or YYMMDD-XXXX, optional
		// dash. 10 or 12 digits with optional dash separator.
		re:   regexp.MustCompile(`\b(?:19|20)?\d{6}[-\s]?\d{4}\b`),
		hint: []string{"century"},
	},
	{
		kind: KindIBAN,
		// IBAN: 2 letters + 2 digits + 11..30 alnum. Loosely matched;
		// detail validation happens at the application layer.
		re:   regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`),
		hint: []string{"country"},
	},
	{
		kind: KindEmail,
		re:   regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		hint: []string{"domain", "len"},
	},
	{
		kind: KindPhone,
		// Loose international + Swedish formats. Matches +CC followed
		// by 7..14 digits with optional spaces/dashes/parentheses.
		re:   regexp.MustCompile(`\+\d{1,3}[\s\-().]*\d{1,4}[\s\-().]*\d{1,4}[\s\-().]*\d{1,9}`),
		hint: []string{"country", "len"},
	},
	{
		// SSH key fingerprints: SHA256:<base64> or (MD5:)?aa:bb:..:zz hex pairs.
		// Placed before the IP patterns so an MD5 fingerprint is not mistaken
		// for an IPv6 address.
		kind: KindSSHFingerprint,
		re:   regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}=*|(?:MD5:)?(?:[0-9a-f]{2}:){15}[0-9a-f]{2}`),
	},
	{
		// Known-prefix API keys / tokens and PEM private-key headers. NOTE: does
		// NOT include the "tok_" prefix, which is the shield marker token-id form
		// (see MarkerPattern) and would corrupt emitted markers on a second pass.
		kind: KindSecret,
		// The `(?:live|test)_` alternative has to come FIRST for each prefix and
		// has to exist for BOTH. It was present for ak_ and missing for sk_,
		// so every real Stripe secret key egressed verbatim: the underscore in
		// sk_live_... is outside [A-Za-z0-9], so `sk_[A-Za-z0-9]{8,}` sees only
		// the four characters of "live" and never matches at all. The generic
		// alternative is what made it silent, because it looks like it covers
		// the prefix.
		re:   regexp.MustCompile(`ak_(?:live|test)_[A-Za-z0-9]{4,}|ak_[A-Za-z0-9]{8,}|sk_(?:live|test)_[A-Za-z0-9]{4,}|sk_[A-Za-z0-9]{8,}|rk_(?:live|test)_[A-Za-z0-9]{4,}|pk_(?:live|test)_[A-Za-z0-9]{4,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]+PRIVATE KEY-----`),
	},
	{
		// IPv4 addresses with valid 0-255 octets (e.g. server IPs from
		// servers/list, dns/records). Valid octets reject 256.x and most
		// dotted version strings.
		kind: KindIPAddress,
		re:   regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b`),
	},
	{
		// Full-form IPv6 (8 hex groups). Runs after the SSH-fingerprint pattern
		// so hex-pair fingerprints are claimed first.
		kind: KindIPAddress,
		re:   regexp.MustCompile(`\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b`),
	},
	{
		// Compressed IPv6 (contains "::"): 2001:db8::1, fe80::1, ::1. Requiring
		// "::" keeps it from matching clock times like 12:34:56.
		kind: KindIPAddress,
		re:   regexp.MustCompile(`(?:[A-Fa-f0-9]{1,4}:){1,7}:|:(?::[A-Fa-f0-9]{1,4}){1,7}|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}`),
	},
	{
		// Hostnames / FQDNs (crm.example.com, host.internal). Most general,
		// so it runs LAST; emails are already tokenized above, and shield
		// markers contain no dotted FQDN so they are not re-matched.
		kind: KindHostname,
		re:   regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b`),
	},
}

// RedactString runs the regex bank over in and replaces every match
// with a marker. Used for free-form text fields (note bodies, message
// content, comments) where struct-tag-based shielding does not apply
// because the PII is embedded inside narrative text.
func (s *Session) RedactString(ctx context.Context, in string) (string, error) {
	if in == "" {
		return in, nil
	}
	// Never tokenize inside an encoded binary blob. ShieldJSON recurses into
	// every string leaf, so an image attachment (Anthropic's
	// messages[].content[].source.data, OpenAI's data: URI) was scanned by the
	// PII regexes. Base64 is a dense run of digits and letters, so the phone and
	// personnummer patterns match by chance and a marker gets spliced into the
	// payload: the provider then receives a corrupt image, and unshielding on the
	// way back cannot restore it because the surrounding bytes shifted.
	//
	// Verified with a random 4000-byte blob: one run came back with a
	// [shield:phone:...] marker at offset 4392. It is probabilistic, which is
	// worse than deterministic, because it corrupts a fraction of uploads.
	//
	// Skipping loses nothing: base64 is opaque to the model as text, so any PII
	// inside it was never legible to tokenize in the first place.
	if looksLikeEncodedBlob(in) {
		return in, nil
	}
	out := in
	for _, p := range redactPatterns {
		var firstErr error
		// Apply each pattern only OUTSIDE existing [shield:...] markers. Earlier
		// patterns (email etc.) emit markers whose hint can contain values a
		// later, more general pattern (hostname/IP) would otherwise re-match and
		// corrupt, breaking the unshield round-trip.
		out = replaceOutsideMarkers(out, p.re, func(match string) string {
			// The hostname pattern is broad; don't tokenize things that are
			// really filenames or code identifiers (config.json, main.go,
			// docker-compose.yml, strings.HasPrefix) which show up heavily in
			// compose/file content and in any question about code.
			//
			// looksLikeHostname is the positive test and subsumes the filename
			// case (no file extension is a TLD), but both run: the extension list
			// is the explicit statement of intent for compose/file content, so
			// adding a suffix to knownSuffixes can never silently start
			// tokenizing main.go.
			if p.kind == KindHostname && (looksLikeFilename(match) || !looksLikeHostname(match)) {
				return match
			}
			// Honour the session's configured level. This used to call
			// buildHint, which hardcodes HintFull, so
			// TRUSTISSUES_SHIELD_HINT_LEVEL was inert on the ONLY production
			// tokenization path (the AI gateway): setting bucketed, minimal or
			// none still egressed full value-derived metadata (email domain,
			// exact length, personnummer century) to the LLM provider. The
			// struct-tag path already did this correctly, which is how the two
			// diverged unnoticed.
			hint := buildHintAtLevel(p.kind, match, p.hint, s.hintLevel)
			marker, err := s.Tokenize(ctx, p.kind, match, hint)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return match
			}
			return marker
		})
		if firstErr != nil {
			return out, firstErr
		}
	}
	return out, nil
}

// fileExtensions are dotted suffixes that mean a dotted token is a filename or
// code identifier, not a hostname worth tokenizing.
var fileExtensions = map[string]bool{
	"go": true, "ts": true, "tsx": true, "js": true, "jsx": true, "json": true,
	"yml": true, "yaml": true, "md": true, "html": true, "htm": true, "css": true,
	"scss": true, "txt": true, "sh": true, "sql": true, "toml": true, "env": true,
	"lock": true, "mod": true, "sum": true, "xml": true, "csv": true, "ini": true,
	"conf": true, "log": true, "png": true, "jpg": true, "jpeg": true, "svg": true,
	"gif": true, "ico": true, "webp": true, "woff": true, "woff2": true, "ttf": true,
	"pdf": true, "zip": true, "tar": true, "gz": true, "tgz": true, "py": true,
	"rb": true, "rs": true, "java": true, "php": true, "tf": true, "proto": true,
}

// looksLikeFilename reports whether a dotted token's final segment is a known
// file extension (config.json, main.go, docker-compose.yml).
func looksLikeFilename(s string) bool {
	i := strings.LastIndex(s, ".")
	if i < 0 || i == len(s)-1 {
		return false
	}
	return fileExtensions[strings.ToLower(s[i+1:])]
}

// knownSuffixes are the final labels that make a dotted token a hostname.
//
// The hostname regex only requires the last label to be 2..63 LETTERS, which is
// also the shape of nearly every dotted code identifier: strings.HasPrefix,
// console.error, json.Unmarshal, np.array, React.useEffect, res.json. Those were
// all tokenized, so a developer using the AI gateway (its documented purpose)
// shipped the provider an unreadable prompt full of [shield:hostname:tok_...]
// and got back a confident answer about nothing. The response path does not
// repair it either: the model writes the real name back, UnshieldJSON passes it
// through, and nothing tells the caller their prompt was rewritten.
//
// An allowlist is the deliberate trade-off. The alternative, "anything dotted is
// a hostname", is what caused this. A host under a TLD missing from this list is
// not tokenized, so keep the internal suffixes at the end in sync with whatever
// the deployment actually uses; a hostname is also the least sensitive kind here
// (personnummer, email, IBAN and key patterns are matched by their own shape and
// are unaffected by this list).
var knownSuffixes = map[string]bool{
	// Common gTLDs.
	"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true,
	"int": true, "info": true, "biz": true, "name": true, "pro": true, "mobi": true,
	"app": true, "dev": true, "io": true, "ai": true, "co": true, "me": true,
	"tv": true, "cc": true, "xyz": true, "online": true, "site": true, "tech": true,
	"store": true, "cloud": true, "digital": true, "agency": true, "studio": true,
	"design": true, "media": true, "news": true, "blog": true, "wiki": true,
	"email": true, "systems": true, "solutions": true, "services": true,
	"software": true, "network": true, "host": true, "space": true, "zone": true,
	"link": true, "click": true, "live": true, "life": true, "world": true,
	"today": true, "group": true, "team": true, "works": true, "energy": true,
	"finance": true, "capital": true, "consulting": true, "legal": true,
	"security": true, "cyber": true, "data": true,
	// European ccTLDs, Nordics first (the deployment's own market).
	"se": true, "no": true, "dk": true, "fi": true, "is": true, "ee": true,
	"lv": true, "lt": true, "de": true, "at": true, "ch": true, "nl": true,
	"be": true, "lu": true, "fr": true, "es": true, "pt": true, "it": true,
	"ie": true, "uk": true, "eu": true, "pl": true, "cz": true, "sk": true,
	"hu": true, "ro": true, "bg": true, "gr": true, "hr": true, "si": true,
	"rs": true, "ua": true, "tr": true, "ru": true,
	// Rest of world, common ones.
	"us": true, "ca": true, "mx": true, "br": true, "ar": true, "cl": true,
	"au": true, "nz": true, "jp": true, "cn": true, "kr": true, "in": true,
	"sg": true, "hk": true, "tw": true, "il": true, "ae": true, "sa": true,
	"za": true, "ng": true, "ke": true,
	// Internal / non-public suffixes: the case the hostname pattern's own
	// comment calls out (host.internal).
	"internal": true, "local": true, "lan": true, "home": true, "corp": true,
	"intranet": true, "private": true, "arpa": true, "test": true,
	"localhost": true, "onion": true,
}

// looksLikeHostname reports whether a dotted token's final label is a plausible
// TLD or internal suffix, i.e. whether it is a hostname at all rather than a
// code identifier that merely has the same shape.
func looksLikeHostname(s string) bool {
	i := strings.LastIndex(s, ".")
	if i < 0 || i == len(s)-1 {
		return false
	}
	return knownSuffixes[strings.ToLower(s[i+1:])]
}

// replaceOutsideMarkers runs re.ReplaceAllStringFunc over every part of s that
// is NOT inside an existing [shield:...] marker, leaving markers verbatim.
func replaceOutsideMarkers(s string, re *regexp.Regexp, repl func(string) string) string {
	spans := MarkerPattern.FindAllStringIndex(s, -1)
	if len(spans) == 0 {
		return re.ReplaceAllStringFunc(s, repl)
	}
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(re.ReplaceAllStringFunc(s[last:sp[0]], repl))
		b.WriteString(s[sp[0]:sp[1]]) // keep the marker untouched
		last = sp[1]
	}
	b.WriteString(re.ReplaceAllStringFunc(s[last:], repl))
	return b.String()
}

// encodedBlobMinLen is the shortest string treated as an encoded binary blob.
//
// It has to sit well above any realistic PII value (the longest thing the
// patterns match is an IBAN at ~34 characters) and well below a real attachment
// (a 1x1 PNG is already ~100 bytes of base64, a real screenshot is tens of
// kilobytes). 512 leaves a wide margin on both sides.
const encodedBlobMinLen = 512

// looksLikeEncodedBlob reports whether a string is an encoded binary payload
// rather than human text, so RedactString can leave it alone.
//
// Deliberately conservative: it requires the string to be long AND to consist
// entirely of the base64 alphabet (optionally behind a data: URI prefix). Prose
// fails immediately on the first space or comma, so this cannot silently exempt
// a paragraph that happens to contain an email address.
func looksLikeEncodedBlob(s string) bool {
	// A data: URI carries its payload after the comma; judge the payload.
	if strings.HasPrefix(s, "data:") {
		if i := strings.IndexByte(s, ','); i >= 0 && i+1 < len(s) {
			s = s[i+1:]
		}
	}
	if len(s) < encodedBlobMinLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '-', c == '_':
			// '-' and '_' cover base64url.
		default:
			return false
		}
	}
	return true
}

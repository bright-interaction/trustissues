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
	// KindSecret runs FIRST, before personnummer.
	//
	// Pattern order is match priority, and the personnummer pattern
	// \b(?:19|20)?\d{6}[-\s]?\d{4}\b claims any 10-digit run. A Slack token
	// (xoxb-1234567890-ABCDEF) contains one, so the token was cut in half and
	// re-emitted as xoxb-[shield:personnummer:...]-ABCDEF: it round-trips, but
	// the kind is wrong, the hint leaks a fake "century", and the operator
	// reading the audit sees a personnummer where a credential was. Anything
	// with a known credential prefix is a secret first.
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
		re: regexp.MustCompile(
			// Underscore families (Stripe, GitHub).
			`ak_(?:live|test)_[A-Za-z0-9]{4,}|ak_[A-Za-z0-9]{8,}` +
				`|sk_(?:live|test)_[A-Za-z0-9]{4,}|sk_[A-Za-z0-9]{8,}` +
				`|rk_(?:live|test)_[A-Za-z0-9]{4,}|pk_(?:live|test)_[A-Za-z0-9]{4,}` +
				`|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}` +
				`|github_pat_[A-Za-z0-9_]{20,}` +
				// Trustissues' OWN API key: "ti_" + 64 hex. The bank knew every
				// third-party vendor's format and not the one this product
				// mints, so a user pasting their own key into a prompt sent it
				// verbatim to Anthropic or OpenAI through this product's own
				// gateway. Look at what you issue, not only what you consume.
				`|ti_[0-9a-f]{64}` +
				// HYPHENATED families. These were entirely absent, including the
				// two providers this product's own AI gateway proxies to: an
				// Anthropic or OpenAI key pasted into a prompt egressed verbatim
				// to that same provider. The underscore alternatives above look
				// like they cover "sk", which is what made the gap invisible.
				`|sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,}` +
				`|sk-proj-[A-Za-z0-9_\-]{20,}|sk-svcacct-[A-Za-z0-9_\-]{20,}` +
				`|sk-[A-Za-z0-9]{20,}` +
				`|xox[baprs]-[A-Za-z0-9-]{10,}` +
				// Cloud provider keys.
				`|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}` +
				`|AIza[0-9A-Za-z_\-]{35}` +
				// A PEM private key: the whole body, not just the banner. Matching
				// only the BEGIN line left the actual key material in the prompt.
				`|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----` +
				`|-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	},

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
		// The local part accepts any non-ASCII letter, and the leading \b is
		// gone.
		//
		// Both classes were ASCII-only and Go's \b is an ASCII word boundary, so
		// a UTF-8 lead byte terminated the local part and the engine simply
		// restarted after it: "Åsa.Öberg@example.se" tokenized as
		// "Åsa.Ö[shield:email:...:domain=example.se]". The name fragment egressed
		// in cleartext directly beside a marker whose hint supplied the domain,
		// which is worse than not redacting at all.
		//
		// This product's market is Swedish, where Å, Ä and Ö in a name are the
		// common case rather than an edge case, so the ASCII-only class made the
		// email detector unreliable for most of the names it exists to protect.
		//
		// \p{L} covers accented and non-Latin scripts. The leading boundary is
		// replaced by an explicit "not already part of an address" check in the
		// character class itself: \b would not fire before "Å" anyway, because
		// the byte before it is not an ASCII word character.
		// \p{M} (combining marks) is as load-bearing as \p{L}.
		//
		// The first fix swapped the ASCII class for \p{L} and I treated the class
		// as closed. It was not: it only moved the boundary from "ASCII letter" to
		// "composed letter". In NFD, "Å" is A + U+030A COMBINING RING ABOVE, and
		// that mark is \p{M}, so a decomposed Swedish name leaks EXACTLY as the
		// ASCII class did, on text that renders identically on screen. Devanagari
		// matras (राहुल) and Vietnamese NFD (nguyễn) have the same shape and are
		// not edge cases in either script.
		//
		// Third iteration on this one pattern. The lesson: widening a character
		// class is not the same as covering a class of input.
		re:   regexp.MustCompile(`[\p{L}\p{M}0-9._%+\-]+@[\p{L}\p{M}0-9.\-]+\.[\p{L}\p{M}]{2,}`),
		hint: []string{"domain", "len"},
	},
	{
		kind: KindPhone,
		// Loose international + Swedish formats. Matches +CC followed
		// by 7..14 digits with optional spaces/dashes/parentheses.
		// The leading + used to be REQUIRED, so only E.164 matched and every
		// national format egressed verbatim: Swedish 070-123 45 67 and 08-123
		// 456, US (415) 555-0199. Those are the forms a Swedish team actually
		// writes, which made the phone tokenizer close to useless in practice.
		//
		// Now: an optional +, then a 7..15 digit number allowing spaces, dashes
		// and parentheses as separators. Anchored on a word boundary and
		// requiring at least 7 digits so it does not eat ordinary integers,
		// years or short IDs.
		// No "." in the separator class: it collides with IPv4 (192.168.1.10) and
		// version strings, and the phone pattern runs BEFORE the IP patterns, so
		// including it made every server address tokenize as a phone number.
		// Three explicit shapes rather than "a long run of digits and separators".
		// The loose version ate ISO dates (2026-07-29 inside a timestamp),
		// 18-digit trace ids, card numbers and build stamps: dates in particular
		// appear in almost every prompt, and mangling one corrupts the text the
		// model sees for no gain.
		//
		//   +CC...        international
		//   0N...         national trunk prefix (Swedish 070-, 08-)
		//   NNN-NNN-NNNN  the common US grouping
		re: regexp.MustCompile(
			`\+\d[\d\s\-()]{6,18}\d` +
				`|\b0\d[\d\s\-()]{5,17}\d` +
				`|\b\d{3}[-\s]\d{3}[-\s]\d{4}\b`),
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
		// Non-ASCII labels included, for the same reason as the email pattern:
		// an ASCII-only class stops at the first UTF-8 lead byte and the engine
		// restarts after it, so "skåne-db.example.se" tokenized as
		// "skå[shield:hostname:...]" and leaked the fragment. Internationalised
		// hostnames are ordinary in this product's market.
		//
		// The final label stays ASCII-ish because looksLikeHostname matches it
		// against knownSuffixes, which lists ASCII TLDs. A fully non-ASCII TLD
		// therefore still will not tokenize; that is a recall gap, not a partial
		// leak, and partial leaks are the failure worth removing first.
		re: regexp.MustCompile(`(?:[\p{L}\p{M}0-9](?:[\p{L}\p{M}0-9-]{0,61}[\p{L}\p{M}0-9])?\.)+[a-zA-Z]{2,63}\b`),
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
			// Same shape as the hostname guard: the regex finds candidates, a
			// validator decides. See looksLikePhone / plausiblePersonnummer for
			// why each rejection exists, and testdata/noise.corpus for proof.
			if p.kind == KindPhone && !looksLikePhone(match) {
				return match
			}
			if p.kind == KindPersonnummer && !plausiblePersonnummer(match) {
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
// unambiguousSuffixes are final labels that make a dotted token a hostname on
// their own, because they essentially never appear as a property or method name.
//
// The previous version of this list was one flat set that included .data, .name,
// .email, .info, .host, .link, .is and .at. Those are real TLDs AND some of the
// most common identifiers in every language: res.data, user.name, user.email,
// console.info, config.host, Object.is, arr.at. So the fix for "strings.HasPrefix
// gets tokenized" shipped with a list that still mangled most real code. Splitting
// the set is the point: an ambiguous suffix now has to prove it is a host.
var unambiguousSuffixes = map[string]bool{
	// Classic gTLDs. None of these is a plausible property name.
	"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true,
	"int": true, "biz": true, "xyz": true,
	// ccTLDs, minus every two-letter code that collides with a common member
	// name (at, is, to, do, so, sh, me, my, in, it, no, us, be, co).
	"se": true, "dk": true, "fi": true, "ee": true, "lv": true, "lt": true,
	"de": true, "ch": true, "nl": true, "lu": true, "fr": true, "es": true,
	"pt": true, "ie": true, "uk": true, "eu": true, "pl": true, "cz": true,
	"sk": true, "hu": true, "ro": true, "bg": true, "gr": true, "hr": true,
	"si": true, "rs": true, "ua": true, "tr": true, "ru": true,
	"ca": true, "mx": true, "br": true, "ar": true, "cl": true,
	"au": true, "nz": true, "jp": true, "cn": true, "kr": true,
	"sg": true, "hk": true, "tw": true, "il": true, "ae": true, "sa": true,
	"za": true, "ng": true, "ke": true,
	// Internal / non-public suffixes: the case the hostname pattern's own
	// comment calls out (host.internal).
	"internal": true, "local": true, "lan": true, "corp": true,
	"intranet": true, "arpa": true, "localhost": true, "onion": true,
}

// ambiguousSuffixes are real TLDs that are ALSO ordinary words or short
// identifiers, so seeing one at the end of a dotted token proves nothing. They
// tokenize only with a positive host signal (see hostSignal).
var ambiguousSuffixes = map[string]bool{
	"io": true, "ai": true, "co": true, "me": true, "app": true, "dev": true,
	"tv": true, "cc": true, "info": true, "name": true, "email": true,
	"host": true, "link": true, "click": true, "live": true, "life": true,
	"works": true, "data": true, "today": true, "world": true, "group": true,
	"team": true, "news": true, "media": true, "design": true, "store": true,
	"space": true, "zone": true, "cloud": true, "digital": true, "online": true,
	"site": true, "tech": true, "studio": true, "agency": true, "solutions": true,
	"services": true, "software": true, "network": true, "systems": true,
	"security": true, "legal": true, "finance": true, "capital": true,
	"consulting": true, "energy": true, "blog": true, "wiki": true, "is": true,
	"at": true, "in": true, "it": true, "no": true, "us": true, "be": true,
	"to": true, "sh": true, "so": true, "home": true, "private": true,
	"test": true, "pro": true, "mobi": true, "cyber": true,
}

// looksLikeHostname reports whether a dotted token is a hostname rather than a
// code identifier that merely has the same shape.
//
// An unambiguous TLD decides it alone. An ambiguous one (a real TLD that is also
// an ordinary word, like .data or .name) additionally requires a positive host
// signal, because "ends in a word that happens to be a TLD" describes most
// property accesses ever written.
func looksLikeHostname(s string) bool {
	i := strings.LastIndex(s, ".")
	if i < 0 || i == len(s)-1 {
		return false
	}
	last := strings.ToLower(s[i+1:])
	if unambiguousSuffixes[last] {
		return true
	}
	if !ambiguousSuffixes[last] {
		return false
	}
	return hostSignal(s)
}

// hostSignal looks for structure that a member-access expression does not have:
// three or more labels (api.eu.example.io), or a hyphen or digit inside a label
// (host.local, db01.host). Identifiers are overwhelmingly two bare
// alphabetic labels, which is exactly what this refuses.
func hostSignal(s string) bool {
	labels := strings.Split(s, ".")
	if len(labels) >= 3 {
		return true
	}
	for _, l := range labels {
		for i := 0; i < len(l); i++ {
			if l[i] == '-' || (l[i] >= '0' && l[i] <= '9') {
				return true
			}
		}
	}
	return false
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

// looksLikePhone rejects candidates that matched the phone shape but are
// something else. RE2 has no lookbehind, so the pattern alone cannot tell that
// "07-29 13:06" is the tail of a timestamp rather than a Swedish number.
//
// Rejecting here rather than tightening the regex keeps the pattern readable and
// puts the reasoning where it can be explained. The corpus is what proves it.
func looksLikePhone(s string) bool {
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	// A real phone number is 7 to 15 digits (E.164 caps at 15).
	if digits < 7 || digits > 15 {
		return false
	}
	// A colon means a clock time got swept in: "13:06:04", "08:00-09:30".
	if strings.ContainsRune(s, ':') {
		return false
	}
	// Date-shaped: NN-NN followed by a space and more digits is a timestamp
	// tail, not a subscriber number.
	if dateTail.MatchString(s) {
		return false
	}
	return true
}

// dateTail matches the "07-29 13" shape that a national-prefix phone pattern
// picks up out of "2026-07-29 13:06:04".
var dateTail = regexp.MustCompile(`^\d{2}-\d{2}\s`)

// plausiblePersonnummer rejects a bare digit run whose date fields are nonsense.
//
// The pattern claims any 10 or 12 digit run, so order ids and epoch timestamps
// became [shield:personnummer:...] complete with a fabricated century hint. This
// checks only that the month and day COULD be a date; it deliberately does not
// verify the Luhn check digit or reject a real-but-odd date, because a false
// negative here sends a personnummer to the LLM provider while a false positive
// only mangles prose. Samordningsnummer (day + 60) stay accepted for the same
// reason.
func plausiblePersonnummer(s string) bool {
	var d []rune
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d = append(d, r)
		}
	}
	// Take the YYMMDD part: last 10 digits are YYMMDD+4, 12 are YYYYMMDD+4.
	switch len(d) {
	case 10:
	case 12:
		d = d[2:]
	default:
		return false
	}
	month := int(d[2]-'0')*10 + int(d[3]-'0')
	day := int(d[4]-'0')*10 + int(d[5]-'0')
	if month < 1 || month > 12 {
		return false
	}
	// Day may carry +60 (samordningsnummer), a real Skatteverket identifier.
	if day > 60 {
		day -= 60
	}
	return day >= 1 && day <= 31
}

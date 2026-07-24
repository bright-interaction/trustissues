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
		re:   regexp.MustCompile(`ak_(?:live|test)_[A-Za-z0-9]{4,}|ak_[A-Za-z0-9]{8,}|sk_[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]+PRIVATE KEY-----`),
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
			// docker-compose.yml) which show up heavily in compose/file content.
			if p.kind == KindHostname && looksLikeFilename(match) {
				return match
			}
			hint := buildHint(p.kind, match, p.hint)
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

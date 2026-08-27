// Package emailidentity owns the canonical representation used wherever an
// email address identifies a Trustissues account or a pending collection seat.
package emailidentity

import (
	"fmt"
	"net/mail"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

var lookupDomain = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

// CanonicalStrict reduces exactly one net/mail address to the stable addr-spec
// used as an account identity. Local-parts are normalized to NFC and folded to
// lower case according to Trustissues' existing identity rule. Domains are
// validated using the IDNA lookup profile and stored as lower-case A-labels, so
// U-label and punycode spellings cannot create separate accounts.
//
// net/mail exposes a quoted local-part in decoded form. Re-serializing through
// mail.Address.String is therefore security-significant: it preserves valid
// spaces, embedded @ signs, quotes, and backslashes instead of storing an
// ambiguous or syntactically invalid addr-spec.
func CanonicalStrict(raw string) (string, error) {
	prepared := norm.NFC.String(strings.TrimSpace(raw))
	if prepared == "" {
		return "", fmt.Errorf("email address is empty")
	}
	prepared = stripTerminalDomainRoot(prepared)

	address, err := mail.ParseAddress(prepared)
	if err != nil {
		return "", fmt.Errorf("parse email address: %w", err)
	}

	addrSpec := norm.NFC.String(strings.TrimSpace(address.Address))
	at := strings.LastIndexByte(addrSpec, '@')
	if at <= 0 || at == len(addrSpec)-1 {
		return "", fmt.Errorf("email address must contain a local-part and domain")
	}

	local := strings.ToLower(norm.NFC.String(addrSpec[:at]))
	domain := norm.NFC.String(addrSpec[at+1:])
	if strings.HasPrefix(domain, "[") || strings.HasSuffix(domain, "]") {
		return "", fmt.Errorf("email domain literals are not supported")
	}
	if err := rejectIDNACompatibilityAliases(domain); err != nil {
		return "", err
	}

	asciiDomain, err := lookupDomain.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("invalid IDNA email domain: %w", err)
	}
	asciiDomain = strings.ToLower(asciiDomain)
	// A fully-qualified DNS name may contain one terminal root dot. IDNA also
	// maps Unicode dot-equivalents, so perform this step after ToASCII as well
	// as the pre-parse ASCII-dot accommodation above.
	asciiDomain = strings.TrimSuffix(asciiDomain, ".")
	if asciiDomain == "" || strings.HasSuffix(asciiDomain, ".") {
		return "", fmt.Errorf("email domain is empty or has more than one terminal root dot")
	}

	semanticAddrSpec := local + "@" + asciiDomain
	rendered := (&mail.Address{Address: semanticAddrSpec}).String()
	if len(rendered) < 2 || rendered[0] != '<' || rendered[len(rendered)-1] != '>' {
		return "", fmt.Errorf("serialize canonical email address")
	}
	canonical := rendered[1 : len(rendered)-1]
	reparsed, err := mail.ParseAddress(canonical)
	if err != nil || reparsed.Address != semanticAddrSpec {
		if err != nil {
			return "", fmt.Errorf("validate canonical email address: %w", err)
		}
		return "", fmt.Errorf("canonical email address did not round-trip")
	}
	return canonical, nil
}

// rejectIDNACompatibilityAliases preserves a strict one-spelling-to-one-
// identity invariant around UTS #46 mappings. In particular, GO-2026-5026
// showed that some x/net/Go combinations can accept an xn-- label which
// decodes entirely to ASCII (for example xn--example- -> example). Depending
// only on the library error would let that alternate spelling log in as the
// ordinary domain even when the dependency scanner reports a fixed version.
//
// A real non-ASCII IDN label has an xn-- A-label after ToASCII. Conversely, an
// input that is already an A-label must remain that exact label apart from
// ASCII case. Rejecting any other compatibility-only rewrite also blocks
// full-width or ignored characters from becoming an ASCII account alias.
func rejectIDNACompatibilityAliases(domain string) error {
	domain = strings.Map(func(r rune) rune {
		switch r {
		case '\u3002', '\uff0e', '\uff61':
			return '.'
		default:
			return r
		}
	}, domain)
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			// Empty/interior/root labels are diagnosed by the full-domain
			// conversion and terminal-root handling below.
			continue
		}
		mapped, err := lookupDomain.ToASCII(label)
		if err != nil {
			return fmt.Errorf("invalid IDNA email domain: %w", err)
		}
		foldedLabel := strings.ToLower(label)
		foldedMapped := strings.ToLower(mapped)
		sourceASCII := isASCII(label)
		if sourceASCII && strings.HasPrefix(foldedLabel, "xn--") && foldedMapped != foldedLabel {
			return fmt.Errorf("invalid IDNA email domain: A-label aliases an ASCII label")
		}
		if !sourceASCII && isASCII(mapped) && !strings.HasPrefix(foldedMapped, "xn--") {
			return fmt.Errorf("invalid IDNA email domain: compatibility mapping aliases an ASCII label")
		}
	}
	return nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

// stripTerminalDomainRoot lets net/mail parse the conventional trailing root
// dot that it otherwise rejects. It only strips a dot in the domain position
// of a bare addr-spec or the usual display-name <addr-spec> form.
func stripTerminalDomainRoot(raw string) string {
	if strings.HasSuffix(raw, ".>") {
		addrEnd := len(raw) - 2
		if strings.LastIndexByte(raw[:addrEnd], '@') > strings.LastIndexByte(raw[:addrEnd], '<') {
			return raw[:addrEnd] + ">"
		}
	}
	if strings.HasSuffix(raw, ".") && strings.LastIndexByte(raw[:len(raw)-1], '@') >= 0 {
		return raw[:len(raw)-1]
	}
	return raw
}

// Canonical is the request-path convenience wrapper. Valid identities use the
// strict representation above. Invalid input remains invalid after only the
// legacy trim/NFC/lower transform, allowing the caller's ValidateEmail check
// to return its ordinary validation response.
//
// net/mail accepts RFC 6532 UTF-8 addresses, so using ASCII-only lower-casing
// here would make internationalized accounts behave differently from ordinary
// ones. The same function is used by the data migration and every request path
// that writes or looks up an account identity.
func Canonical(raw string) string {
	if canonical, err := CanonicalStrict(raw); err == nil {
		return canonical
	}
	return strings.ToLower(norm.NFC.String(strings.TrimSpace(raw)))
}

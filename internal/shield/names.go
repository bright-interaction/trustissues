package shield

import "strings"

// Person and organisation names have no lexical shape, so no regex in
// redact.go can find one. KindName and KindCompany have existed in the Kind
// enum since the beginning, with hint rules declared for both, and until now
// nothing ever produced one: every pattern-based kind (email, personnummer,
// IBAN, phone, hostname, secret) is a SHAPE, and a name is not. So a prompt
// carrying "Anna Svensson" or "Sofos Card AB" went to Anthropic or OpenAI
// verbatim through this product's own gateway, which is the one thing the
// product's sovereignty claim says cannot happen.
//
// What CAN be recognised without a model is the KEY a value arrives under. A
// JSON field literally called customer_name holds a customer's name whatever
// the value looks like, and shieldAnyUnderKey already carries the enclosing key
// for exactly this class of reasoning (see dereferencedURLKeys). That makes the
// structured case - the dominant real one, where an agent passes records into a
// model - closable exactly, with no gazetteer, no name list, no model, and no
// false positives from guessing at capitalised words in prose.
//
// WHAT THIS DOES NOT CLOSE, stated plainly so nobody reads it as more than it
// is: a bare name inside free-form prose ("please email Anna Svensson about
// the invoice") is still not detected. That needs real NER, which is a model
// dependency and a separate decision. This closes the structured half and
// leaves the prose half open.
//
// The keys below are deliberately UNAMBIGUOUS ones. Bare "name" is excluded and
// must stay excluded: in both provider APIs this gateway proxies to, "name" is
// a STRUCTURAL field. Anthropic tool definitions and OpenAI function definitions
// both carry {"name": "get_weather"}, and tool_use blocks echo that name back so
// the caller can dispatch on it. Tokenizing it would rewrite the tool's name to
// a marker, the model would answer with the marker, and tool calling would break
// outright for every caller with Shield on. The same reasoning excludes bare
// "company", "contact", "owner" and "author", any of which is as likely to be a
// structural or non-person field as a person.
var nameBearingKeys = map[string]Kind{
	// Person names. Normalised form: lowercase, separators stripped, so
	// full_name, fullName, Full-Name and FULLNAME all arrive here as "fullname".
	"fullname":        KindName,
	"firstname":       KindName,
	"lastname":        KindName,
	"givenname":       KindName,
	"familyname":      KindName,
	"middlename":      KindName,
	"surname":         KindName,
	"personname":      KindName,
	"customername":    KindName,
	"clientname":      KindName,
	"contactname":     KindName,
	"contactperson":   KindName,
	"patientname":     KindName,
	"employeename":    KindName,
	"membername":      KindName,
	"ownername":       KindName,
	"authorname":      KindName,
	"recipientname":   KindName,
	"sendername":      KindName,
	"attendeename":    KindName,
	"accountholder":   KindName,
	"beneficiaryname": KindName,
	"legalname":       KindName,

	// Swedish, because this product's users and their records are Swedish and a
	// Swedish-language integration names its fields in Swedish. Bare "namn" is
	// included where bare "name" is not: it carries none of the structural
	// meaning "name" has in the two provider APIs, so it cannot collide with a
	// tool definition.
	"namn":             KindName,
	"fornamn":          KindName,
	"efternamn":        KindName,
	"fullstandigtnamn": KindName,
	"kontaktperson":    KindName,
	"mottagarnamn":     KindName,
	"avsandarnamn":     KindName,

	// Organisations.
	"companyname":       KindCompany,
	"organisationname":  KindCompany,
	"organizationname":  KindCompany,
	"orgname":           KindCompany,
	"employername":      KindCompany,
	"vendorname":        KindCompany,
	"suppliername":      KindCompany,
	"foretagsnamn":      KindCompany,
	"organisationsnamn": KindCompany,
}

// normalizeNameKey folds the spelling variants a JSON key arrives in down to
// one form: lowercase, with every separator removed, so full_name, fullName,
// Full-Name and "full name" are the same key.
//
// Swedish diacritics are folded too (a-ring, a-umlaut, o-umlaut to a/a/o),
// because an integration may or may not have normalised them and "förnamn"
// and "fornamn" are the same field. The folded forms are what the map above
// stores.
func normalizeNameKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range strings.ToLower(key) {
		switch r {
		case '_', '-', ' ', '.', '\t':
			continue
		case 'å', 'ä':
			b.WriteRune('a')
		case 'ö':
			b.WriteRune('o')
		case 'é', 'è':
			b.WriteRune('e')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// nameKindForKey reports the Kind a value under this JSON key should be
// tokenized as, and whether the key is name-bearing at all.
//
// A plural key is checked by falling back to its singular. An array of names is
// idiomatically written {"attendee_names":[...]}, and shieldAnyUnderKey passes
// the parent key down to every element, so without this the plural spelling -
// the one an integration actually uses for a list of people - matched nothing
// and every name in the list egressed. That was not hypothetical: it is what
// this package's own test caught on the first run.
//
// The fallbacks cannot widen the map into ambiguity, because they only ever
// reach entries that are already in it. "names" singularises to "name", which
// is deliberately absent (see above), so it stays absent.
func nameKindForKey(key string) (Kind, bool) {
	if key == "" {
		return "", false
	}
	norm := normalizeNameKey(key)
	if k, ok := nameBearingKeys[norm]; ok {
		return k, true
	}
	// English plural, then Swedish (-er, as in kontaktperson/kontaktpersoner).
	for _, suffix := range []string{"s", "er"} {
		if stem := strings.TrimSuffix(norm, suffix); stem != norm {
			if k, ok := nameBearingKeys[stem]; ok {
				return k, true
			}
		}
	}
	return "", false
}

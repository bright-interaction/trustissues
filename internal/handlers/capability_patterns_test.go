package handlers

import (
	"strings"
	"testing"
)

// TestDestinationPatternValidationRejectsFakeRestrictions locks the validation
// on the capability ceiling.
//
// Until this shipped the column had exactly ONE writer, the provider preset
// seed, so a secret created without a recognised provider could never mint a
// capability token and the whole "let an agent use a secret it never sees"
// feature was unreachable for it. Now that operators can set it, the list is the
// only thing between a minted token and an arbitrary destination, so every
// pattern that LOOKS like a restriction without being one has to be refused.
func TestDestinationPatternValidationRejectsFakeRestrictions(t *testing.T) {
	bad := map[string]string{
		"bare star":         "*",
		"star with path":    "*/v1/*",
		"host wildcard":     "*.supabase.co/*",
		"mid-host wildcard": "api.*.com/*",
		"scheme":            "https://api.example.com/*",
		"credentials":       "user:pass@api.example.com/*",
		"loopback name":     "localhost/*",
		"loopback ip":       "127.0.0.1/*",
		"private ip":        "10.0.0.5/*",
		"private ip 192":    "192.168.1.10/*",
		"link local":        "169.254.169.254/*",
		"unspecified":       "0.0.0.0/*",
		"not fqdn":          "internal/*",
		"space":             "api.example.com /*",
		"backslash":         `api.example.com\*`,
		"empty":             "",
	}
	for name, p := range bad {
		if err := ValidateDestinationPatterns([]string{p}); err == nil {
			t.Errorf("%s: %q was ACCEPTED as a ceiling; it does not restrict anything", name, p)
		}
	}

	good := []string{
		"api.openai.com/*",
		"api.example.com/v1/chat/*",
		"abcdefgh.supabase.co/*",
		"api.example.com:8443/v1/*",
		"sentry.io/api/*",
	}
	for _, p := range good {
		if err := ValidateDestinationPatterns([]string{p}); err != nil {
			t.Errorf("legitimate pattern %q was rejected: %v", p, err)
		}
	}

	// The list is bounded, so a ceiling cannot become allow-everything by
	// accretion.
	many := make([]string, maxDestinationPatterns+1)
	for i := range many {
		many[i] = "api.example.com/*"
	}
	if err := ValidateDestinationPatterns(many); err == nil {
		t.Fatalf("more than %d patterns was accepted", maxDestinationPatterns)
	}
}

// TestDestinationPatternErrorsTellYouWhatToDo guards the operator experience.
// A ceiling that rejects input without saying why is a feature nobody can use,
// which is how the previous "pass dests explicitly" / "cannot be honored" pair
// ended up telling callers to do two opposite impossible things.
func TestDestinationPatternErrorsTellYouWhatToDo(t *testing.T) {
	err := ValidateDestinationPatterns([]string{"*.supabase.co/*"})
	if err == nil {
		t.Fatal("host wildcard accepted")
	}
	if !strings.Contains(err.Error(), "path glob") && !strings.Contains(err.Error(), "exact host") {
		t.Fatalf("wildcard error does not suggest the fix: %q", err)
	}

	err = ValidateDestinationPatterns([]string{"https://api.example.com/*"})
	if err == nil {
		t.Fatal("URL accepted")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("URL error does not name the problem: %q", err)
	}
}

// TestNormalizeDestinationPatterns pins de-duplication and trimming, so an
// operator pasting a list with stray whitespace gets what they meant.
func TestNormalizeDestinationPatterns(t *testing.T) {
	got := NormalizeDestinationPatterns([]string{
		" api.example.com/* ", "api.example.com/*", "", "   ", "other.example.com/*",
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 unique patterns, got %d: %v", len(got), got)
	}
	if got[0] != "api.example.com/*" || got[1] != "other.example.com/*" {
		t.Fatalf("normalization changed meaning or order: %v", got)
	}
}

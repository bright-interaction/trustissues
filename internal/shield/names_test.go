package shield

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestNamesUnderNameBearingKeysDoNotEgress is the gap this file closes.
//
// Every kind in redact.go is a SHAPE. A person's name has none, so no pattern
// could ever match one and "Anna Svensson" travelled to Anthropic or OpenAI
// verbatim through this product's own gateway. The key a value arrives under is
// the signal that is available without a model.
func TestNamesUnderNameBearingKeysDoNotEgress(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // the plaintext that must NOT appear in the shielded body
		kind Kind
	}{
		{"snake_case", `{"customer_name":"Anna Svensson"}`, "Anna Svensson", KindName},
		{"camelCase", `{"customerName":"Anna Svensson"}`, "Anna Svensson", KindName},
		{"kebab-case", `{"customer-name":"Anna Svensson"}`, "Anna Svensson", KindName},
		{"swedish namn", `{"namn":"Anna Svensson"}`, "Anna Svensson", KindName},
		{"swedish diacritic key", `{"förnamn":"Anna"}`, "Anna", KindName},
		{"swedish efternamn", `{"efternamn":"Svensson"}`, "Svensson", KindName},
		{"kontaktperson", `{"kontaktperson":"Björn Ek"}`, "Björn Ek", KindName},
		{"company", `{"company_name":"Sofos Card AB"}`, "Sofos Card AB", KindCompany},
		{"foretagsnamn", `{"företagsnamn":"Sofos Card AB"}`, "Sofos Card AB", KindCompany},
		{"nested in array", `{"attendee_names":["Anna Svensson","Björn Ek"]}`, "Björn Ek", KindName},
		{"deep in message content", `{"messages":[{"role":"user","content":{"patient_name":"Anna Svensson"}}]}`,
			"Anna Svensson", KindName},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, err := NewSession(ctx, NewMemoryStore(), "names-"+tc.name, testKey(), time.Minute, HintFull)
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			out, err := s.ShieldJSON(ctx, []byte(tc.body))
			if err != nil {
				t.Fatalf("shield: %v", err)
			}
			if strings.Contains(string(out), tc.want) {
				t.Fatalf("THE NAME EGRESSED VERBATIM: %q is still present in %s", tc.want, out)
			}
			if !strings.Contains(string(out), "[shield:"+string(tc.kind)+":") {
				t.Errorf("expected a %s marker, got %s", tc.kind, out)
			}

			// AND IT COMES BACK. A redaction that does not round-trip is a
			// corruption, not a privacy control.
			back, err := s.UnshieldJSON(ctx, out)
			if err != nil {
				t.Fatalf("unshield: %v", err)
			}
			var got, want any
			_ = json.Unmarshal(back, &got)
			_ = json.Unmarshal([]byte(tc.body), &want)
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("round trip lost the original:\n got %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
}

// TestToolNamesSurviveShield is the regression this design is shaped around.
//
// Both provider APIs the gateway proxies to use "name" as a STRUCTURAL field:
// Anthropic tool definitions and OpenAI function definitions carry
// {"name":"get_weather"}, and tool_use blocks echo it back so the caller can
// dispatch on it. Tokenizing bare "name" would rewrite the tool's identity to a
// marker and break tool calling for every caller with Shield on, which is why
// nameBearingKeys excludes it and must keep excluding it.
func TestToolNamesSurviveShield(t *testing.T) {
	ctx := context.Background()
	s, err := NewSession(ctx, NewMemoryStore(), "tools", testKey(), time.Minute, HintFull)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	body := `{"tools":[{"name":"get_weather","description":"Look up weather"}],` +
		`"messages":[{"role":"user","content":[{"type":"tool_use","name":"get_weather","id":"tu_1"}]}]}`
	out, err := s.ShieldJSON(ctx, []byte(body))
	if err != nil {
		t.Fatalf("shield: %v", err)
	}
	if strings.Count(string(out), "get_weather") != 2 {
		t.Fatalf("A TOOL NAME WAS TOKENIZED, so the model cannot be dispatched on it and tool "+
			"calling breaks whenever Shield is on: %s", out)
	}
	for _, structural := range []string{"tools", "description", "role", "type", "id"} {
		if !strings.Contains(string(out), `"`+structural+`"`) {
			t.Errorf("structural key %q did not survive: %s", structural, out)
		}
	}
}

// TestAlreadyShieldedNamesAreNotNested. Conversation history is replayed into
// the next request, so a second pass sees markers where names were. Nesting a
// marker inside a marker makes the outer resolve hand back the inner marker
// instead of the name, so the round trip silently stops returning the original.
func TestAlreadyShieldedNamesAreNotNested(t *testing.T) {
	ctx := context.Background()
	s, err := NewSession(ctx, NewMemoryStore(), "replay", testKey(), time.Minute, HintFull)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	first, err := s.ShieldJSON(ctx, []byte(`{"customer_name":"Anna Svensson"}`))
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	second, err := s.ShieldJSON(ctx, first)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if string(second) != string(first) {
		t.Errorf("a second pass changed an already-shielded document:\nfirst  %s\nsecond %s", first, second)
	}
	back, err := s.UnshieldJSON(ctx, second)
	if err != nil {
		t.Fatalf("unshield: %v", err)
	}
	if !strings.Contains(string(back), "Anna Svensson") {
		t.Errorf("the name did not survive a shield-shield-unshield cycle: %s", back)
	}
}

// TestNormalizeNameKeyFoldsSpellings pins the folding the map depends on.
func TestNormalizeNameKeyFoldsSpellings(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"full_name", "fullname"},
		{"fullName", "fullname"},
		{"Full-Name", "fullname"},
		{"FULL NAME", "fullname"},
		{"förnamn", "fornamn"},
		{"Efternamn", "efternamn"},
		{"företagsnamn", "foretagsnamn"},
	} {
		if got := normalizeNameKey(tc.in); got != tc.want {
			t.Errorf("normalizeNameKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPluralNameKeysAreCovered. An array of people is idiomatically written
// under a plural key, and the walker passes the parent key to every element, so
// a map holding only singulars protected none of them.
func TestPluralNameKeysAreCovered(t *testing.T) {
	for _, key := range []string{"attendee_names", "customer_names", "contact_names", "kontaktpersoner"} {
		if _, ok := nameKindForKey(key); !ok {
			t.Errorf("plural key %q is not name-bearing, so every element of that list egresses", key)
		}
	}
	// The exclusion must survive singularisation: "names" must not become "name".
	if _, ok := nameKindForKey("names"); ok {
		t.Errorf(`"names" became name-bearing, which reintroduces the tool-name collision through the plural fallback`)
	}
}

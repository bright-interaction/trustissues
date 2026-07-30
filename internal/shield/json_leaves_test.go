package shield

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ShieldJSON must redact every string in the document, including object KEYS and
// every leaf under a url-ish key that is not actually a URL.
//
// Two holes, both found by executing the real package rather than reading it:
//
//	{"anna@example.se":"note"}               -> unchanged, keys were never walked
//	{"url":["anna@example.se","+46 70..."]}  -> unchanged, the exemption was keyed
//	                                            on the NAME and inherited into arrays
//
// The second is the more dangerous of the pair, because it is silent and wide: an
// array inherits its parent key, so every string leaf at any depth beneath url,
// image_url, audio_url, video_url, document_url, file_url, source_url or
// server_url escaped redaction entirely. A caller putting a customer list under
// "source_url" got none at all.
func TestShieldJSONRedactsKeysAndNonURLLeaves(t *testing.T) {
	const (
		email = "anna.svensson@example.se"
		phone = "+46 70 123 45 67"
		pnr   = "19850101-1234"
	)

	cases := []struct {
		name string
		doc  string
		// raw values that must NOT survive anywhere in the output
		mustNotSurvive []string
	}{
		{"PII as an object key", `{"` + email + `":"note about the client"}`, []string{email}},
		{"PII as a nested key", `{"outer":{"` + email + `":1}}`, []string{email}},
		{"PII key and value", `{"` + email + `":"` + phone + `"}`, []string{email, phone}},
		{"non-URL under url", `{"url":"` + email + `"}`, []string{email}},
		{"array under url", `{"url":["` + email + `","` + phone + `"]}`, []string{email, phone}},
		{"array of arrays under image_url", `{"image_url":[["` + email + `"]]}`, []string{email}},
		{"nested object under source_url", `{"source_url":{"a":"` + pnr + `"}}`, []string{pnr}},
		{"PII beside a real URL under url", `{"url":["https://ok.test/x","` + email + `"]}`, []string{email}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			s, err := NewSession(ctx, NewMemoryStore(), "js", testKey(), time.Minute, HintFull)
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			out, err := s.ShieldJSON(ctx, []byte(c.doc))
			if err != nil {
				t.Fatalf("ShieldJSON: %v", err)
			}
			got := string(out)
			for _, raw := range c.mustNotSurvive {
				if strings.Contains(got, raw) {
					t.Errorf("%q egressed verbatim:\n  in:  %s\n  out: %s", raw, c.doc, got)
				}
			}
		})
	}
}

// TestShieldJSONStillExemptsRealURLs is the half that keeps the fix honest.
//
// The exemption exists so Shield does not corrupt a link or an inline attachment
// the provider has to dereference. A fix that redacted everything would "pass" the
// test above and break image and document handling, so this asserts a genuine URL
// under a url-ish key is still left alone, and that the whole document round-trips.
func TestShieldJSONStillExemptsRealURLs(t *testing.T) {
	ctx := context.Background()
	s, err := NewSession(ctx, NewMemoryStore(), "js2", testKey(), time.Minute, HintFull)
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	const link = "https://cdn.example.test/a/b.png?token=abc"
	doc := `{"image_url":"` + link + `","note":"mail anna.svensson@example.se"}`

	out, err := s.ShieldJSON(ctx, []byte(doc))
	if err != nil {
		t.Fatalf("ShieldJSON: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, link) {
		t.Errorf("a real URL under image_url was redacted, which corrupts what the provider must "+
			"fetch:\n  in:  %s\n  out: %s", doc, got)
	}
	if strings.Contains(got, "anna.svensson@example.se") {
		t.Errorf("the address beside it was NOT redacted:\n  out: %s", got)
	}

	// Round-trip: keys are shielded now, so unshield has to restore them too.
	back, err := s.UnshieldJSON(ctx, out)
	if err != nil {
		t.Fatalf("UnshieldJSON: %v", err)
	}
	var a, b any
	if err := json.Unmarshal([]byte(doc), &a); err != nil {
		t.Fatalf("unmarshal original: %v", err)
	}
	if err := json.Unmarshal(back, &b); err != nil {
		t.Fatalf("unmarshal restored: %v", err)
	}
	oa, _ := json.Marshal(a)
	ob, _ := json.Marshal(b)
	if string(oa) != string(ob) {
		t.Errorf("the document did not round-trip:\n  want: %s\n  got:  %s", oa, ob)
	}
}

// TestShieldJSONRoundTripsAPIIKey is the round-trip for the KEY path specifically,
// since redacting keys without restoring them would hand the caller back a
// document whose keys are markers.
func TestShieldJSONRoundTripsAPIIKey(t *testing.T) {
	ctx := context.Background()
	s, err := NewSession(ctx, NewMemoryStore(), "js3", testKey(), time.Minute, HintFull)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	const doc = `{"anna.svensson@example.se":{"note":"x"},"plain":"y"}`

	shielded, err := s.ShieldJSON(ctx, []byte(doc))
	if err != nil {
		t.Fatalf("ShieldJSON: %v", err)
	}
	if strings.Contains(string(shielded), "anna.svensson@example.se") {
		t.Fatalf("ABORT: the key was not redacted, so this test is not exercising the key path: %s", shielded)
	}

	back, err := s.UnshieldJSON(ctx, shielded)
	if err != nil {
		t.Fatalf("UnshieldJSON: %v", err)
	}
	var a, b any
	_ = json.Unmarshal([]byte(doc), &a)
	if err := json.Unmarshal(back, &b); err != nil {
		t.Fatalf("unmarshal restored: %v", err)
	}
	oa, _ := json.Marshal(a)
	ob, _ := json.Marshal(b)
	if string(oa) != string(ob) {
		t.Errorf("a document with a PII key did not round-trip:\n  want: %s\n  got:  %s", oa, ob)
	}
}

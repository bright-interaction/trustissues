package shield

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestUnshieldKeepsPartialResult locks the fix for an all-or-nothing walk.
//
// unshieldAny returned (nil, err) on the first marker it could not resolve, and
// the gateway only used the result when err was nil, so ONE bad marker anywhere
// in a provider response discarded resolution of the whole body. The caller got
// [shield:email:tok_...] instead of every address in the document, with a 200
// and nothing explaining why.
//
// It is easy to hit without an attacker: the model is free to reformat, so
// quoting a marker with a digit changed or abbreviating it is enough. Untrusted
// text being summarised can also contain a marker-shaped string.
//
// UnshieldString already kept going and left unresolvable text in place; the
// walk was the only piece that disagreed with that contract.
func TestUnshieldKeepsPartialResult(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)

		shielded, err := s.RedactString(ctx, "mail anna@klientfirman.se about it")
		if err != nil {
			t.Fatalf("redact: %v", err)
		}
		if !strings.Contains(shielded, "[shield:email:") {
			t.Fatalf("ABORT: nothing was tokenized, the test would be vacuous: %q", shielded)
		}

		// A real marker beside one this session can never resolve.
		doc, err := json.Marshal(map[string]any{
			"good": shielded,
			"bad":  "[shield:email:tok_000000000000:domain=x.com,len=5]",
			"nested": map[string]any{
				"also_good": shielded,
			},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		out, uErr := s.UnshieldJSON(ctx, doc)
		if len(out) == 0 {
			t.Fatal("the whole body was discarded because of one unresolvable marker")
		}
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("result is not valid JSON: %v", err)
		}
		if g, _ := got["good"].(string); !strings.Contains(g, "anna@klientfirman.se") {
			t.Errorf("a resolvable marker was left unresolved: %q", g)
		}
		nested, _ := got["nested"].(map[string]any)
		if n, _ := nested["also_good"].(string); !strings.Contains(n, "anna@klientfirman.se") {
			t.Errorf("a resolvable marker nested in a map was left unresolved: %q", n)
		}
		// The unresolvable one stays verbatim rather than becoming an error or "".
		if b, _ := got["bad"].(string); !strings.Contains(b, "tok_000000000000") {
			t.Errorf("the unresolvable marker was mangled instead of left in place: %q", b)
		}
		// The failure must still be reported, or it becomes invisible.
		if uErr == nil {
			t.Error("an unresolvable marker was silent; nothing would ever surface a broken round-trip")
		}
	})
}

// TestUnshieldCleanDocumentReportsNoError guards the common path: a document
// whose markers all resolve must return a nil error, so the new partial-result
// contract does not make every response look degraded.
func TestUnshieldCleanDocumentReportsNoError(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)

		shielded, err := s.RedactString(ctx, "mail anna@klientfirman.se about it")
		if err != nil {
			t.Fatalf("redact: %v", err)
		}
		doc, _ := json.Marshal(map[string]any{"a": shielded, "b": []any{shielded, "plain text"}})

		out, uErr := s.UnshieldJSON(ctx, doc)
		if uErr != nil {
			t.Errorf("a fully resolvable document reported an error: %v", uErr)
		}
		if !strings.Contains(string(out), "anna@klientfirman.se") {
			t.Errorf("clean document did not resolve: %s", out)
		}
	})
}

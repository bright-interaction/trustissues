package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// TestNeonRotateWithoutAnIDLeavesThePredecessorLive is the unrevokable-forever
// state, driven end to end.
//
// Neon's mint returns {id, key}. Rotate queued the predecessor's DELETE before
// checking whether an id came back, and then wrote meta["key_id"] only when it
// did. So a response carrying a usable key and no id destroyed the old key while
// meta["key_id"] still named it: the successor's id existed nowhere, no future
// rotation could revoke it, and the entry was recorded as a clean success.
//
// The recoverable choice is both keys live plus a warning, because Neon
// authenticates with the key itself and the id is only needed to revoke, so
// refusing outright would throw away a working credential.
func TestNeonRotateWithoutAnIDLeavesThePredecessorLive(t *testing.T) {
	var revokeHits int
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			revokeHits++
			w.WriteHeader(http.StatusOK)
			return
		}
		// A key, but no "id" field at all.
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"neon_successor_value"}`))
	})

	p := &NeonProvider{}
	meta := map[string]string{"key_id": "111"}
	key, err := p.Rotate(providerCtx(p, meta), "neon_current_value", meta)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if key != "neon_successor_value" {
		t.Fatalf("the minted key was not returned: %q", key)
	}

	// THE PREDECESSOR MUST NOT BE QUEUED FOR DELETION. Nothing can revoke the
	// successor, so killing the old key strands the entry with an immortal
	// credential.
	if _, queued := meta[pendingRevokeURL]; queued {
		t.Errorf("A REVOKE OF THE PREDECESSOR WAS QUEUED while the successor has no recorded id: "+
			"the old key dies and the new one can never be revoked by any future rotation (url=%q)",
			meta[pendingRevokeURL])
	}
	if meta["key_id"] != "111" {
		t.Errorf("key_id should still name the surviving predecessor, got %q", meta["key_id"])
	}
	// And the operator is told, rather than the rotation reading as clean.
	if meta["last_revoke_error"] == "" {
		t.Errorf("the rotation recorded no warning, so it surfaces as a clean success while both " +
			"keys are live at Neon")
	}

	// performPendingRevoke is what production calls next; it must not fire.
	performPendingRevoke(providerCtx(p, meta), meta, "neon",
		secretexit.Minted([]byte(key), secretexit.Origin{EntryID: "entry-neon", Name: "neon"},
			allowAllExitAuthority{}))
	if revokeHits != 0 {
		t.Errorf("the predecessor was deleted upstream anyway (%d DELETE calls)", revokeHits)
	}
}

// TestNeonRotateWithAnIDStillRevokesThePredecessor is the other half: the guard
// above must not have turned the normal path off.
func TestNeonRotateWithAnIDStillRevokesThePredecessor(t *testing.T) {
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":222,"key":"neon_successor_value"}`))
	})

	p := &NeonProvider{}
	meta := map[string]string{"key_id": "111"}
	if _, err := p.Rotate(providerCtx(p, meta), "neon_current_value", meta); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if meta[pendingRevokeURL] == "" {
		t.Fatalf("no revoke was queued for the predecessor, so the old Neon key stays live forever")
	}
	if got, want := meta["key_id"], "222"; got != want {
		t.Errorf("key_id did not advance to the successor: got %q want %q", got, want)
	}
	if meta["last_revoke_error"] != "" {
		t.Errorf("a healthy rotation recorded a revoke warning: %q", meta["last_revoke_error"])
	}
}

// TestAuth0ValidateSendsWellFormedJSONForAnySecret locks the interpolation bug.
//
// Validate built its request body with fmt.Sprintf into a JSON literal, so a
// client secret containing a double quote or a backslash - both legal in an
// Auth0 client secret - produced malformed JSON. Auth0 answered 400 and Validate
// reported valid:false, which marks a working credential dead and alarms on it.
// The same hole let an operator-controlled provider_meta value close the string
// and append fields of its own.
func TestAuth0ValidateSendsWellFormedJSONForAnySecret(t *testing.T) {
	hostile := []struct {
		name   string
		secret string
	}{
		{"double quote", `abc"def`},
		{"backslash", `abc\def`},
		{"quote and brace", `a"},"audience":"https://evil.example.com/`},
		{"newline", "abc\ndef"},
	}

	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]any
			var decodeErr error
			withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				decodeErr = json.Unmarshal(raw, &got)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"ok"}`))
			})

			p := &Auth0Provider{}
			meta := map[string]string{"tenant": "acme", "client_id": "cid-1"}
			valid, err := p.Validate(providerCtx(p, meta), tc.secret, meta)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}

			// THE BODY MUST PARSE. This is what used to fail.
			if decodeErr != nil {
				t.Fatalf("AUTH0 RECEIVED MALFORMED JSON for a legal secret, so a healthy credential "+
					"is reported invalid: %v", decodeErr)
			}
			// AND THE SECRET MUST ARRIVE VERBATIM, not truncated at the quote.
			if got["client_secret"] != tc.secret {
				t.Errorf("the secret did not survive encoding: got %q want %q", got["client_secret"], tc.secret)
			}
			// AND NOTHING WAS INJECTED: audience is still the tenant's own.
			if want := "https://acme.auth0.com/api/v2/"; got["audience"] != want {
				t.Errorf("the audience was overridden through the secret: got %q want %q", got["audience"], want)
			}
			if !valid {
				t.Errorf("upstream answered 200 but Validate reported invalid")
			}
		})
	}
}

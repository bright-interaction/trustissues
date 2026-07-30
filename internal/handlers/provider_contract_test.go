package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Real provider adapters, driven against a fake upstream.
//
// vault_providers.go is 1653 lines, 34 registered providers, 14 of them auto-rotating,
// and until now not ONE real adapter had a test. rotation_contract_test.go exercises the
// orchestration wrapper against synthetic fakes (shared-secret, generated-key-32) and
// never touches a provider that speaks HTTP. Round 15 found four defects in this file,
// including both of its highs, which is what an untested 1653-line file predicts.
//
// The reason it stayed untested is worth recording, because it is not a real obstacle:
// providerHTTP is alerts.GuardedWebhookClient, which blocks loopback at DIAL time, so an
// httptest server is unreachable through it. But providerHTTP is a package var precisely
// so a test can swap it, which the rotation matrix already does. There was never a
// barrier, only the belief in one.
//
// withFakeUpstream points a provider at a local server and restores everything after.
func withFakeUpstream(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	prev := providerHTTP
	// A plain client (the guarded one refuses loopback) plus a redirect-free transport
	// that rewrites the provider's hard-coded absolute URL to the fake server.
	providerHTTP = &http.Client{Transport: rewriteTo(srv.URL)}
	t.Cleanup(func() { providerHTTP = prev })
	return srv
}

// rewriteTo sends every request to base, preserving path and query, so a provider's
// hard-coded https://api.vendor.com/... reaches the fake upstream unchanged.
type rewriteTransport struct{ base string }

func rewriteTo(base string) http.RoundTripper { return &rewriteTransport{base: base} }

func (rt *rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	u := *r.URL
	baseURL := strings.TrimPrefix(strings.TrimPrefix(rt.base, "http://"), "https://")
	u.Scheme = "http"
	u.Host = baseURL
	r2 := r.Clone(r.Context())
	r2.URL = &u
	r2.Host = ""
	return http.DefaultTransport.RoundTrip(r2)
}

// TestTwilioRotatePairsTheNewSecretWithItsOwnSid locks the round-15 high.
//
// Twilio Basic auth is (AccountSid, AuthToken) OR (ApiKeySid, ApiKeySecret) and never
// (AccountSid, ApiKeySecret). Rotate parsed the new key's sid and threw it away, so the
// vault stored a secret whose sid existed nowhere in the product:
//
//	Validate answered valid:false on a freshly-rotated entry
//	the NEXT rotation's own mint call 401'd, recorded rotFailProvider on every pass
//	every consumer the value was delivered to started failing auth
//
// and all of it was recorded as status "success" with last_rotation_error NULL and no
// alert, because Twilio queues no revoke so revokeWarn was empty. The flagship feature
// silently stored a credential that authenticates nowhere.
func TestTwilioRotatePairsTheNewSecretWithItsOwnSid(t *testing.T) {
	var gotUser, gotPass string
	// A DIFFERENT sid per mint, because a real upstream never returns the same key
	// twice and the revoke is only queued when the predecessor differs. Returning a
	// constant would have made the revoke assertion pass vacuously.
	mint := 0
	sids := []string{"SKnew123", "SKnew789"}
	secrets := []string{"newsecret456", "newsecret999"}
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		i := mint
		if i >= len(sids) {
			i = len(sids) - 1
		}
		mint++
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"sid": sids[i], "secret": secrets[i]})
	})

	p := &TwilioProvider{}
	meta := map[string]string{"account_sid": "ACaccount"}

	// FIRST rotation: the stored value is the account Auth Token, so the mint
	// authenticates as the account.
	got, err := p.Rotate(context.Background(), "the-auth-token", meta)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got != "newsecret456" {
		t.Errorf("returned %q, want the new secret", got)
	}
	if gotUser != "ACaccount" || gotPass != "the-auth-token" {
		t.Errorf("first mint authenticated as (%q,%q), want the ACCOUNT sid + auth token", gotUser, gotPass)
	}

	// THE FIX: the new key's sid must be recorded, or the secret can never be paired.
	if meta["key_sid"] != "SKnew123" {
		t.Fatalf("key_sid = %q, want SKnew123.\n"+
			"Without it the vault holds an API Key secret whose sid exists nowhere, so Validate "+
			"and the next Rotate both 401 forever while the rotation is recorded as a success.",
			meta["key_sid"])
	}

	// SECOND rotation: now it must authenticate with the KEY sid, not the account.
	if _, err := p.Rotate(context.Background(), "newsecret456", meta); err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if gotUser != "SKnew123" {
		t.Errorf("second mint authenticated as %q, want the previous KEY sid SKnew123; pairing an "+
			"API Key secret with the account sid is a hard 401", gotUser)
	}
	if meta["key_sid"] != "SKnew789" {
		t.Errorf("key_sid = %q after the second rotation, want the NEWEST sid SKnew789; a stale id "+
			"pairs the old sid with the new secret, which is the same 401", meta["key_sid"])
	}

	// And the predecessor must be queued for deletion, which it never was.
	if meta[pendingRevokeURL] == "" {
		t.Error("no revoke was queued for the previous API key, so it stays live at Twilio " +
			"indefinitely while the rotation reports success")
	} else if !strings.Contains(meta[pendingRevokeURL], "SKnew123") {
		t.Errorf("the queued revoke does not target the PREVIOUS key: %s", meta[pendingRevokeURL])
	}
}

// TestTwilioValidateUsesTheSameIdentityAsRotate is the other half.
//
// Rotate and Validate disagreeing about what the stored value IS was the whole defect,
// so they are asserted together. A fix that changed only one of them would leave the
// product answering "this key is invalid" about a key it had just minted.
func TestTwilioValidateUsesTheSameIdentityAsRotate(t *testing.T) {
	var gotUser string
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotUser, _, _ = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	p := &TwilioProvider{}

	// Pre-rotation: the value is the Auth Token, paired with the account sid.
	if _, err := p.Validate(context.Background(), "auth-token", map[string]string{"account_sid": "ACaccount"}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if gotUser != "ACaccount" {
		t.Errorf("pre-rotation Validate used %q, want the account sid", gotUser)
	}

	// Post-rotation: the value is an API Key secret, paired with its own sid.
	if _, err := p.Validate(context.Background(), "keysecret",
		map[string]string{"account_sid": "ACaccount", "key_sid": "SKnew123"}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if gotUser != "SKnew123" {
		t.Errorf("post-rotation Validate used %q, want the KEY sid; otherwise the product reports "+
			"a freshly rotated key as invalid", gotUser)
	}
}

// TestTwilioRefusesAKeyItCannotPair guards the fail-closed direction.
//
// If Twilio ever returns a key with no sid, storing the secret would recreate the exact
// unusable state this fix removes. The provider-failure path leaves the stored secret
// untouched, so erroring is strictly better than storing something that authenticates
// nowhere.
func TestTwilioRefusesAKeyItCannotPair(t *testing.T) {
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"secret":"orphan"}`)) // no sid
	})
	p := &TwilioProvider{}
	meta := map[string]string{"account_sid": "ACaccount"}
	got, err := p.Rotate(context.Background(), "tok", meta)
	if err == nil {
		t.Errorf("a sid-less key was accepted and %q would be stored; it can never be paired "+
			"and every later call 401s", got)
	}
	if meta["key_sid"] != "" {
		t.Errorf("key_sid was set to %q from a response that had none", meta["key_sid"])
	}
}

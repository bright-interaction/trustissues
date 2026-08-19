package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestDeferredRevokeAuthenticatesThewayEachProviderRequires is finding B's
// proof (and, for Backblaze, ties finding A's fix to the authentication it
// depends on).
//
// performPendingRevoke used to send every deferred revoke as
// "Authorization: Bearer <the new secret>", unconditionally. Twilio's own Basic
// auth is (ApiKeySid, ApiKeySecret) and NEVER a bearer token - the adapter's own
// Rotate says so twice and uses req.SetBasicAuth for the mint - so every Twilio
// deferred revoke went out mismatched, 401'd, and because meta["key_sid"] had
// already advanced to the successor by the time it ran, the orphaned key was
// never a revoke candidate again: a compromised Twilio credential had no
// remaining path to be killed. Backblaze's revoke needs a different shape
// again: no single header at all, but a b2_authorize_account round trip
// (Basic base64(newKeyId:newSecret)) to obtain a token before b2_delete_key.
//
// This drives performPendingRevoke against a REAL httptest server per scheme
// (through the same providerHTTP-swap + host-rewrite withFakeUpstream uses for
// the adapter contract tests) and asserts the Authorization the wire actually
// saw, not just that a revoke was queued.
func TestDeferredRevokeAuthenticatesThewayEachProviderRequires(t *testing.T) {
	t.Run("bearer: resend/sendgrid/neon shape", func(t *testing.T) {
		var gotAuth string
		var hits int
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			hits++
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		})

		meta := map[string]string{}
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/old-id", revokeAuthBearer, "old-id")

		performPendingRevoke(context.Background(), meta, "resend", testPlaintext("NEW-SECRET-VALUE"))

		if hits != 1 {
			t.Fatalf("ABORT: the fake upstream saw %d requests, want 1; this is not exercising the "+
				"revoke at all", hits)
		}
		if gotAuth != "Bearer NEW-SECRET-VALUE" {
			t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer NEW-SECRET-VALUE")
		}
		if meta["last_revoke_error"] != "" {
			t.Errorf("revoke recorded an error: %q", meta["last_revoke_error"])
		}
	})

	t.Run("basic: twilio shape, (ApiKeySid, ApiKeySecret) and never the account sid", func(t *testing.T) {
		var gotUser, gotPass string
		var sawBasic bool
		var hits int
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			hits++
			gotUser, gotPass, sawBasic = r.BasicAuth()
			w.WriteHeader(http.StatusNoContent)
		})

		// key_sid is what Twilio's Rotate has already written into meta (the NEW
		// key's sid) by the time a defer runs; performPendingRevoke's basic-auth
		// arm reads it back to build the username half of the pair.
		meta := map[string]string{"key_sid": "SKnew123"}
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.twilio.com/2010-04-01/Accounts/ACaccount/Keys/SKold.json", revokeAuthBasic, "SKold.json")

		performPendingRevoke(context.Background(), meta, "twilio", testPlaintext("newsecret456"))

		if hits != 1 {
			t.Fatalf("ABORT: the fake upstream saw %d requests, want 1", hits)
		}
		if !sawBasic {
			t.Fatal("no Basic auth header was sent at all; Twilio requires Basic and refuses everything " +
				"else, so a bearer token (or nothing) 401s and the predecessor stays live forever")
		}
		if gotUser != "SKnew123" || gotPass != "newsecret456" {
			t.Errorf("Basic auth = (%q, %q), want (%q, %q) - the KEY sid paired with the NEW secret, "+
				"never the account sid", gotUser, gotPass, "SKnew123", "newsecret456")
		}
		if meta["last_revoke_error"] != "" {
			t.Errorf("revoke recorded an error: %q", meta["last_revoke_error"])
		}
	})

	t.Run("basic: refuses rather than sends a malformed header when no username is recorded", func(t *testing.T) {
		var hits int
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.WriteHeader(http.StatusOK)
		})

		// No key_sid recorded: a row that somehow reached this state (a bug
		// upstream, a hand-edited fixture, an older schema) must not send
		// "Basic <base64 of ':secret'>" as if that were a real credential pair.
		meta := map[string]string{}
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.twilio.com/2010-04-01/Accounts/ACaccount/Keys/SKold.json", revokeAuthBasic, "SKold.json")

		performPendingRevoke(context.Background(), meta, "twilio", testPlaintext("newsecret456"))

		if hits != 0 {
			t.Errorf("a basic-auth revoke with no recorded username still dialled the provider (%d "+
				"requests); it should refuse before making the request", hits)
		}
		if meta["last_revoke_error"] == "" {
			t.Error("the refusal was silent: no last_revoke_error means nothing tells an operator the " +
				"old key was never revoked")
		}
	})

	t.Run("b2: backblaze shape, authorize-then-delete authenticated as the NEW key pair", func(t *testing.T) {
		var authorizeAuth, deleteAuth, deletePath string
		var authorizeHits, deleteHits int
		var deleteBody string
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "b2_authorize_account"):
				authorizeHits++
				authorizeAuth = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"authorizationToken": "tok-xyz",
					"apiInfo": map[string]any{
						// Has to resolve under the ".backblazeb2.com" suffix
						// declared for backblaze in egress_authority.go, or
						// CheckHost refuses the delete call before it is ever
						// sent (which is the correct behaviour, and is exactly
						// what this test would otherwise fail to notice). rewriteTo
						// still forces the actual TCP connection back to this same
						// fake server regardless of the hostname named here.
						// Carries b2MintBase so the DESTINATION is observable.
						// rewriteTo rewrites scheme+host on every outbound
						// request and keeps only path+query, so no fixture using
						// this harness can see which host the code chose. The
						// path survives, and only a request built from the
						// apiUrl this response returns arrives carrying it.
						"storageApi": map[string]any{"apiUrl": "https://storage001.backblazeb2.com" + b2MintBase},
					},
				})
			case strings.Contains(r.URL.Path, "b2_delete_key"):
				deleteHits++
				deleteAuth = r.Header.Get("Authorization")
				deletePath = r.URL.Path
				b, _ := io.ReadAll(r.Body)
				deleteBody = string(b)
				w.WriteHeader(http.StatusOK)
			default:
				t.Errorf("unexpected request to %s", r.URL.Path)
				w.WriteHeader(http.StatusOK)
			}
		})

		// meta["key_id"] already holds the NEW key id: Backblaze's Rotate writes
		// it before deferring, precisely so this authorize step can use it.
		meta := map[string]string{"key_id": "0021new"}
		// url carries the OLD key id (see deferRevokeOldProviderKey's doc), not a
		// URL: b2_delete_key's real URL is only known after the authorize round
		// trip below.
		deferRevokeOldProviderKey(meta, "DELETE", "0021old", revokeAuthB2, "0021old")

		performPendingRevoke(context.Background(), meta, "backblaze", testPlaintext("K0newSecret"))

		if authorizeHits != 1 {
			t.Fatalf("ABORT: b2_authorize_account was hit %d times, want 1", authorizeHits)
		}
		if deleteHits != 1 {
			t.Fatalf("b2_delete_key was never called (%d hits): the old key was authorized against but "+
				"never actually deleted, so it is still live at Backblaze", deleteHits)
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("0021new:K0newSecret"))
		if authorizeAuth != wantAuth {
			t.Errorf("b2_authorize_account Authorization = %q, want %q (base64 of the NEW keyId:secret "+
				"pair, per Backblaze's own Basic-auth contract)", authorizeAuth, wantAuth)
		}
		// The DELETE leg's own header, which nothing asserted until now. The
		// authorize assertion above is a different value from the same helper
		// (Basic keyId:secret, not the token), so it does not cover this: with
		// only that one in place, `"Bearer "+token` on delReq was green
		// everywhere. Half a two-part contract asserted reads exactly like all
		// of it.
		// The delete leg's DESTINATION, which nothing asserted until now.
		// b2_delete_key's base URL is the apiUrl b2_authorize_account returned,
		// not the fixed host -- the same contract the mint leg had wrong until
		// eda98b431. Measured before this assertion existed: rebuilding delReq
		// against "https://api.backblazeb2.com" was GREEN across all 21
		// packages, and providerDo does not catch it either, because the fixed
		// host is itself inside backblaze's declared ".backblazeb2.com" suffix.
		//
		// This is the same half-asserted-contract shape 19184afda fixed for the
		// mint and for THIS leg's header, and then missed for this leg's
		// destination, one file over from where the pattern already lived.
		//
		// KNOWN LIMIT, stated rather than left to be rediscovered: this pins the
		// PATH, not the HOST, because rewriteTo erases the host before any
		// fixture sees it. A mutation that keeps the returned path and swaps
		// only the host is still green here. And B2's real apiUrl is host-only,
		// so against a production-shaped response b2MintBase would be "" and
		// strings.HasPrefix would be vacuously true. What this DOES catch is the
		// regression that actually happened twice in this file -- ignoring the
		// returned base URL altogether -- and CheckHost still bounds the damage
		// to some host inside .backblazeb2.com. The durable fix is to make
		// rewriteTransport record the original host so fixtures can assert it
		// directly, which closes this for all nine provider adapters at once.
		if !strings.HasPrefix(deletePath, b2MintBase) {
			t.Errorf("b2_delete_key was sent to %q, which does not start with %q, the base URL "+
				"b2_authorize_account returned. The fixed api.backblazeb2.com host is only correct "+
				"for b2_authorize_account itself.", deletePath, b2MintBase)
		}
		if deleteAuth != "tok-xyz" {
			t.Errorf("b2_delete_key Authorization = %q, want the raw account authorization token "+
				"%q. B2 takes the token as the entire header value; \"Bearer \"+token is a "+
				"different, wrong header.", deleteAuth, "tok-xyz")
		}
		if !strings.Contains(deleteBody, "0021old") {
			t.Errorf("b2_delete_key body = %q, want it to target the OLD key id 0021old, not the new one",
				deleteBody)
		}
		if meta["last_revoke_error"] != "" {
			t.Errorf("revoke recorded an error: %q", meta["last_revoke_error"])
		}
	})

	t.Run("b2: refuses rather than authenticates with an empty key id when meta lost key_id", func(t *testing.T) {
		var hits int
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.WriteHeader(http.StatusOK)
		})

		meta := map[string]string{} // no key_id
		deferRevokeOldProviderKey(meta, "DELETE", "0021old", revokeAuthB2, "0021old")

		performPendingRevoke(context.Background(), meta, "backblaze", testPlaintext("K0newSecret"))

		if hits != 0 {
			t.Errorf("a b2 revoke with no recorded new key id still dialled Backblaze (%d requests); it "+
				"should refuse before authenticating with an empty id", hits)
		}
		if meta["last_revoke_error"] == "" {
			t.Error("the refusal was silent")
		}
	})
}

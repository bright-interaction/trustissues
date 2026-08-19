package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestBackblazeCASConflictLeavesThePredecessorLive is finding A's proof, driven
// through the REAL manual-rotate HTTP handler against a REAL SQLite-backed
// VaultHandler, not a unit test of the revoke machinery in isolation.
//
// Backblaze's Rotate used to call backblazeRevokeOldKey INLINE, immediately
// after minting the successor and before returning, commented as "best-effort,
// because b2_delete_key needs an authorize step first". That ran BEFORE the
// caller (vault.go's Rotate handler) had encrypted the new value, before it had
// even attempted its compare-and-swap. So a concurrent edit landing in that
// window - another request saving the entry, a second rotation racing the
// first - made the CAS reject the write, the handler discard the freshly
// minted key and answer 409 rotation_conflict, while the OLD key had ALREADY
// been deleted at Backblaze moments earlier. The 409 body claims "the old key
// is still live and the new one is stranded upstream"; for Backblaze that was
// false, and nobody was left holding a working credential.
//
// This test races exactly that window without needing real concurrency: the
// fake B2 upstream itself performs the conflicting write the instant it serves
// the mint (b2_create_key) response, which is precisely the moment production
// sits between "the provider minted a successor" and "the caller's CAS
// commits it". It then asserts two things: the request reports the conflict,
// and Backblaze was NEVER asked to authorize or delete the old key. The second
// assertion is the one that matters: it is the difference between "the old key
// is safe" and "the old key is already gone".
//
// Must fail before the ordering fix (the inline revoke fires regardless of
// what the CAS later does) and pass after it (the revoke is only ever queued,
// and performPendingRevoke - the sole place that can run it - is never reached
// because the CAS conflict makes the handler return first).
func TestBackblazeCASConflictLeavesThePredecessorLive(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const password = "CorrectHorseBatteryStaple1!"
	owner := mustUser(t, queries, "b2cas@example.com", "user", password)
	const entryID = "b2-cas-1"
	mustEntry(t, h, queries, entryID, owner, "Backblaze key", "K0old")

	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider:     toNullString("backblaze"),
		ProviderMeta: toNullString(`{"key_id":"0021old","account_id":"acct"}`),
		ID:           entryID,
	}); err != nil {
		t.Fatalf("set provider: %v", err)
	}

	before, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	if before.UpdatedAtText == "" {
		t.Fatal("ABORT: the row carries no updated_at text, so the CAS has nothing to bind and this " +
			"test cannot force a conflict")
	}

	var revokeAttempts int
	// The account authorization token b2_authorize_account hands out. The mint
	// has to present THIS, raw, or the fixture 401s it: dispatching on the URL
	// path alone is what let Rotate send `Basic keyId:secret` to the wrong host
	// for the whole life of the b2 adapter with every B2 test still green.
	const accountToken = "b2-account-authorization-token"
	var authorized bool
	var mintAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "b2_authorize_account"):
			// Reached by the MINT now, which is correct and is the fix:
			// b2_create_key needs a token from here and a base URL from here.
			// The revoke leg is no longer detected by this branch -- it is
			// detected by b2_delete_key below, which is the call that actually
			// destroys the predecessor and the only one this test forbids.
			authorized = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorizationToken": accountToken,
				// Must resolve under the ".backblazeb2.com" suffix declared for
				// backblaze in egress_authority.go or CheckHost refuses the mint
				// before it is sent. rewriteTo still forces the connection back
				// to this same fake server.
				"apiInfo": map[string]any{"storageApi": map[string]any{"apiUrl": "https://storage001.backblazeb2.com"}},
			})
		case strings.Contains(r.URL.Path, "b2_create_key"):
			mintAuth = r.Header.Get("Authorization")
			if !authorized {
				t.Errorf("b2_create_key was called without a preceding b2_authorize_account; " +
					"its token and its base URL both come from that call")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if mintAuth != accountToken {
				t.Errorf("b2_create_key Authorization = %q, want the raw account authorization "+
					"token %q", mintAuth, accountToken)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// THE RACE. This is the fake upstream standing in for the real
			// b2_create_key call, at the exact moment the real one would return
			// to Rotate with a freshly minted successor key. A concurrent save
			// lands here, in production driven by an unrelated request or a
			// second rotation; here, driven by the upstream itself so the test
			// needs no goroutines to force the window.
			// A REAL conflict now means the VALUE moved: updated_at alone is no
			// longer part of the CAS predicate, because comparing it made every
			// unrelated column write fail a rotation that had already minted
			// upstream. So this writes a genuinely different, genuinely
			// decryptable value, which is the lost-update the guard exists for.
			concCipher, concNonce, encErr := h.encrypt([]byte("K0concurrent"))
			if encErr != nil {
				t.Errorf("encrypt concurrent value: %v", encErr)
			}
			if _, execErr := h.db.Exec(
				`UPDATE vault_entries SET updated_at = datetime('now','+1 second'), encrypted_value = ?, nonce = ? WHERE id = ?`,
				concCipher, concNonce, entryID); execErr != nil {
				t.Errorf("concurrent edit: %v", execErr)
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"applicationKey": "K0new", "applicationKeyId": "0021new",
			})
		case strings.Contains(r.URL.Path, "b2_delete_key"):
			// THE ASSERTION, made live. If the fix holds, this branch is never
			// reached at all: the handler returns 409 before
			// revokeOldKeyAndPersistMeta -> performPendingRevoke ever runs.
			revokeAttempts++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	prev := providerHTTP
	providerHTTP = &http.Client{Transport: rewriteTo(srv.URL)}
	defer func() { providerHTTP = prev }()

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest("POST", "/api/vault/"+entryID+"/rotate", owner, "user", entryID,
		`{"password":"`+password+`"}`))

	if rec.Code != http.StatusConflict {
		t.Fatalf("rotate returned %d, want 409 rotation_conflict: %s\n"+
			"ABORT if this is not a conflict: the rest of this test's assertions would not be "+
			"exercising the CAS-miss path at all", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rotation_conflict") {
		t.Errorf("409 body does not report rotation_conflict: %s", rec.Body.String())
	}
	// The mint reached the fixture at all, and reached it holding the account
	// authorization token. Without this the 409 above is satisfied just as well
	// by a mint that never authenticated correctly in the first place.
	if mintAuth != accountToken {
		t.Errorf("b2_create_key presented Authorization %q, want the raw account authorization token %q",
			mintAuth, accountToken)
	}

	// THE WHOLE POINT. A CAS conflict must not have destroyed the predecessor
	// upstream: Backblaze must never have been asked to authorize or delete it.
	if revokeAttempts != 0 {
		t.Fatalf("Backblaze was asked to revoke the old key %d time(s) even though the compare-and-"+
			"swap rejected the new value.\n"+
			"The old key is now dead at Backblaze AND the newly minted successor was discarded, so "+
			"nobody holds a working credential. This is exactly the unrecoverable state "+
			"deferRevokeOldProviderKey exists to prevent: revoking must never happen before the "+
			"caller's compare-and-swap has durably stored the new value.", revokeAttempts)
	}

	// And, on top of nothing being revoked, nothing should have been stored:
	// the CAS conflict means the write did not apply.
	after, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	plain, err := h.openForTest(after.EncryptedValue, after.Nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	// The CONCURRENT save's value is what must survive: the rotation lost its
	// CAS, so its freshly minted "K0new" must not have landed. (Before the
	// updated_at predicate was dropped this read "K0old", because the simulated
	// conflict only bumped a timestamp and never actually saved anything.)
	if !plain.EqualsString("K0concurrent") {
		t.Error("the rotation's value landed even though the rotate request reported a conflict, so " +
			"it overwrote the value the concurrent save had just stored; the entry now holds neither " +
			"what the saver wrote nor a value anyone was told about")
	}
}

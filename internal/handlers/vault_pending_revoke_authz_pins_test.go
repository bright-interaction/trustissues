package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestRetryRefusesAWrongPassword pins the password re-auth on the retry
// endpoint.
//
// The check at vault_pending_revoke.go's reauthOrRefuse is CORRECT. Nothing
// held it there: deleting those three lines left the entire Go suite green,
// and a wrong password then reached the upstream spend and returned
// {"revoked":true}. That is the difference between "this endpoint spends a
// live credential" and "a stolen session spends a live credential", and it was
// resting on nobody editing that function.
//
// The assertion that matters is the second one. A 4xx alone would still pass
// if the refusal happened AFTER the upstream call.
func TestRetryRefusesAWrongPassword(t *testing.T) {
	h, _, owner, entryID, sink := failingRevokeEnv(t, http.StatusOK)

	rec := httptest.NewRecorder()
	h.RetryPendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+entryID+"/pending-revoke/retry", owner, "user", entryID,
		`{"password":"not-the-right-password"}`))

	if rec.Code < 400 {
		t.Errorf("a WRONG password was accepted (HTTP %d): %s", rec.Code, rec.Body.String())
	}
	if sink.sawStale() {
		t.Errorf("a WRONG password reached the upstream revoke and spent the entry's live credential: %v. "+
			"Refusing after the network call is not refusing.", sink.all())
	}

	t.Run("positive control: the RIGHT password does reach the upstream", func(t *testing.T) {
		// Without this the assertions above pass against an endpoint that
		// refuses everybody, or one whose fixture never had a marker to spend.
		h2, _, owner2, entry2, sink2 := failingRevokeEnv(t, http.StatusOK)
		rec2 := httptest.NewRecorder()
		h2.RetryPendingRevoke(rec2, vaultAuthzRequest(http.MethodPost,
			"/api/vault/"+entry2+"/pending-revoke/retry", owner2, "user", entry2,
			`{"password":"`+rotationTestPassword+`"}`))
		if rec2.Code != http.StatusOK {
			t.Fatalf("ABORT: the right password returned %d: %s", rec2.Code, rec2.Body.String())
		}
		if !sink2.sawStale() {
			t.Fatalf("ABORT: even the right password never reached the upstream, so the negative case above proves nothing")
		}
	})
}

// TestPendingRevokeTakesTheEntryIDFromTheURLOnly pins a rule both handlers
// state in prose and neither enforces with a test: "the entry id comes from the
// chi URL param only, never from the request body."
//
// Nothing held it. An ablation that ran authz against the URL id and then let a
// body field steer the OPERATION erased a different tenant's stranded-key
// coordinates and returned 200, with the whole suite green. That is a
// cross-tenant destruction of the only record that a live orphaned credential
// exists.
//
// This test sends the body field a future refactor would plausibly add. Today
// those fields are ignored because nothing decodes them, which is exactly the
// property being pinned: the victim entry must be untouched no matter what the
// body says.
func TestPendingRevokeTakesTheEntryIDFromTheURLOnly(t *testing.T) {
	h, queries, owner, callerEntry, _ := failingRevokeEnv(t, http.StatusOK)

	// A second entry, owned by somebody else, carrying its own live marker.
	victimOwner := mustUser(t, queries, "victim-"+randomHex(6)+"@example.com", "user", rotationTestPassword)
	victim := "victim-" + randomHex(6)
	mustEntry(t, h, queries, victim, victimOwner, "Victim "+victim, "V")
	const victimURL = "https://api.resend.com/api-keys/victim_key_1"
	enc, err := h.encryptColumn(`{"key_id":"vk","pending_revoke_url":"` + victimURL +
		`","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider:     toNullString(revokeFailProvider),
		ProviderMeta: toNullString(enc),
		AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
		ID:           victim,
	}); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	if got := entryMetaMap(t, h, queries, victim); got[pendingRevokeURL] != victimURL {
		t.Fatalf("ABORT: the victim fixture did not land: %+v", got)
	}

	for _, body := range []string{
		`{"password":"` + rotationTestPassword + `","entry_id":"` + victim + `"}`,
		`{"password":"` + rotationTestPassword + `","id":"` + victim + `"}`,
	} {
		rec := httptest.NewRecorder()
		h.RetryPendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
			"/api/vault/"+callerEntry+"/pending-revoke/retry", owner, "user", callerEntry, body))
		_ = rec
	}

	rec := httptest.NewRecorder()
	h.ResolvePendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+callerEntry+"/pending-revoke/resolve", owner, "user", callerEntry,
		`{"acknowledged_key_id":"victim_key_1","entry_id":"`+victim+`","id":"`+victim+`"}`))

	if got := entryMetaMap(t, h, queries, victim); got[pendingRevokeURL] != victimURL {
		t.Errorf("a request body steered a pending-revoke operation onto ANOTHER entry: the victim's "+
			"stranded-key coordinates are now %+v, want %q still present. The caller had no rights to "+
			"that entry, and the erased marker is the only record that a live key is orphaned upstream.",
			got, victimURL)
	}

	var resolveBody map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resolveBody)
	if rec.Code == http.StatusOK {
		t.Errorf("resolve returned 200 while acknowledging a key id that belongs to a DIFFERENT entry: %v",
			resolveBody)
	}
}

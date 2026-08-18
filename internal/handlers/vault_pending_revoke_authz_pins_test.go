package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
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

// TestProviderChangeRecordsTheDiscardedPredecessor pins the audit and the
// reconciliation on the silent discharge path.
//
// ResolvePendingRevoke demands the operator type the predecessor key id back
// and writes an activity row naming it. Changing the provider on a PUT dropped
// the same markers with neither, and left last_rotation_error still saying
// "old key not revoked (still live at provider)" after the marker that
// explained it and the affordance that could act on it were both gone: an
// alarm nothing in the product could clear or explain.
func TestProviderChangeRecordsTheDiscardedPredecessor(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "discard-"+randomHex(6)+"@example.com", "user", "")
	entryID := "discard-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
	forceProviderConfig(t, h, entryID, "resend",
		`{"key_id":"k2","pending_revoke_method":"DELETE","pending_revoke_key_id":"key_old_1",`+
			`"pending_revoke_url":"https://api.resend.com/api-keys/key_old_1","pending_revoke_auth":"bearer"}`)
	if err := queries.UpdateVaultEntryRotationError(context.Background(), db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString("webhook delivery failed: HTTP 500; " + revokeStillLiveMsg),
		ID:                entryID,
	}); err != nil {
		t.Fatalf("seed error: %v", err)
	}

	rec := putVault(t, h, owner, "user", entryID, map[string]any{
		"name": "Entry " + entryID, "provider": "sendgrid",
	})
	if rec.Code >= 400 {
		t.Fatalf("ABORT: the provider change was refused (HTTP %d): %s", rec.Code, rec.Body.String())
	}
	if got := entryMetaMap(t, h, queries, entryID); got[pendingRevokeURL] != "" {
		t.Fatalf("ABORT: the provider change did not drop the markers, so this test proves nothing: %+v", got)
	}

	// The audit trail must name what was abandoned.
	var found int
	if err := h.db.QueryRow(
		`SELECT COUNT(*) FROM activity_log WHERE action = 'vault.pending_revoke_discarded'`).
		Scan(&found); err != nil {
		t.Fatalf("activity query: %v", err)
	}
	if found == 0 {
		t.Errorf("a provider change discarded a stranded key's only record and wrote no activity row. " +
			"The resolve endpoint demands a typed acknowledgement for exactly this decision; the silent " +
			"path must at least leave a trail.")
	}

	// And the row must not contradict itself afterwards.
	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if strings.Contains(row.LastRotationError.String, revokeStillLiveMsg) {
		t.Errorf("last_rotation_error still says the old key is live (%q) after the marker that "+
			"explained it was discarded, and nothing in the product can clear it now",
			row.LastRotationError.String)
	}
	if !strings.Contains(row.LastRotationError.String, "webhook delivery failed") {
		t.Errorf("clearing the revoke half also erased an unrelated delivery failure: %q",
			row.LastRotationError.String)
	}
}

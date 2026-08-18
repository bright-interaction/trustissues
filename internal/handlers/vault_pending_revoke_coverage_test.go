package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// ---------------------------------------------------------------------------
// MISSING TEST 1: the retry endpoint's FAILURE path, handler-level.
// ---------------------------------------------------------------------------

// failingRevokeEnv is staleRevokeEnv with an upstream that REFUSES the revoke,
// and with last_rotation_error already carrying revokeStillLiveMsg the way a
// previous partial rotation leaves it.
func failingRevokeEnv(t *testing.T, revokeStatus int) (*VaultHandler, *db.Queries, string, string, *revokeSink) {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	installRotationFakes(t)

	sink := &revokeSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			sink.record(r.URL.Path)
			w.WriteHeader(revokeStatus)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	revokeTargetURL = srv.URL + "/keys/fresh"
	prevHTTP := providerHTTP
	providerHTTP = &http.Client{}
	t.Cleanup(func() { providerHTTP = prevHTTP })

	owner := mustUser(t, queries, fmt.Sprintf("failrevoke-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	entryID := "failrevoke-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "ORIGINAL-VALUE")

	staleMeta := fmt.Sprintf(
		`{"key_id":"key-2","unrelated":"keep-me","pending_revoke_method":"DELETE","pending_revoke_url":%q,"pending_revoke_auth":"bearer","last_revoke_error":"revoke old key: HTTP 503"}`,
		srv.URL+"/keys/stranded-key")
	enc, err := h.encryptColumn(staleMeta)
	if err != nil {
		t.Fatalf("encrypt provider_meta: %v", err)
	}
	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider:     toNullString(revokeFailProvider),
		ProviderMeta: toNullString(enc),
		AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
		ID:           entryID,
	}); err != nil {
		t.Fatalf("set provider: %v", err)
	}
	if err := queries.UpdateVaultEntryRotationError(context.Background(), db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString(revokeStillLiveMsg),
		ID:                entryID,
	}); err != nil {
		t.Fatalf("seed last_rotation_error: %v", err)
	}
	return h, queries, owner, entryID, sink
}

func entryMetaMap(t *testing.T, h *VaultHandler, queries *db.Queries, entryID string) map[string]string {
	t.Helper()
	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload entry: %v", err)
	}
	return ParseProviderMeta(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta))
}

// TestZZRetryEndpointFailedRevokeChangesNothing is the handler-level twin of
// TestRevokeTreats404ByWhereTheKeyIdTravels. That test proves the HELPER records
// the failure; nothing proved the ENDPOINT respects it. A retry whose upstream
// refuses must report revoked:false, keep all three coordinates, keep the
// revoke half of last_rotation_error, and keep reporting the stranded key on
// the derived status it hands back.
func TestZZRetryEndpointFailedRevokeChangesNothing(t *testing.T) {
	h, queries, owner, entryID, sink := failingRevokeEnv(t, http.StatusServiceUnavailable)

	rec := httptest.NewRecorder()
	h.RetryPendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+entryID+"/pending-revoke/retry", owner, "user", entryID,
		`{"password":"`+rotationTestPassword+`"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: retry returned %d, so nothing below is being tested: %s", rec.Code, rec.Body.String())
	}
	if !sink.sawStale() {
		t.Fatalf("ABORT: the upstream revoke was never attempted (%v); this test proves nothing", sink.all())
	}

	var resp pendingRevokeRetryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Revoked {
		t.Errorf("a REFUSED upstream revoke was reported to the operator as revoked:true. The " +
			"predecessor key is still live at the provider.")
	}
	if resp.Detail != revokeStillLiveMsg {
		t.Errorf("detail = %q, want the static revokeStillLiveMsg", resp.Detail)
	}
	if resp.PendingRevoke == nil || !resp.PendingRevoke.Outstanding {
		t.Errorf("a failed retry reported no outstanding pending revoke: %+v", resp.PendingRevoke)
	}

	meta := entryMetaMap(t, h, queries, entryID)
	if !strings.Contains(meta[pendingRevokeURL], "stranded-key") {
		t.Errorf("a FAILED retry deleted the stranded key's coordinates: %+v. That erases the only "+
			"record of a key that is still live upstream -- the 2026-08-17 b2 shape.", meta)
	}
	if meta[pendingRevokeMethod] == "" || meta[pendingRevokeAuth] == "" {
		t.Errorf("a FAILED retry deleted part of the retry coordinates: %+v", meta)
	}
	if meta["unrelated"] != "keep-me" {
		t.Errorf("the retry clobbered an unrelated provider_meta key: %+v", meta)
	}

	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if row.LastRotationError.String != revokeStillLiveMsg {
		t.Errorf("a FAILED retry cleared last_rotation_error (now %q): the entry now reports clean "+
			"while an orphaned key is live upstream", row.LastRotationError.String)
	}
}

// TestZZRetryEndpointB2404IsAFailure is the handler-level b2 404 test. The
// helper-level one exists; this one proves the ENDPOINT does not launder that
// 404 into a success on its way out.
func TestZZRetryEndpointB2404IsAFailure(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	installRotationFakes(t)

	var deleteHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "b2_delete_key") {
			deleteHits++
			w.WriteHeader(http.StatusNotFound) // names the PATH, not the key
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorizationToken":"tok","apiInfo":{"storageApi":{"apiUrl":"https://api.backblazeb2.com"}}}`))
	}))
	t.Cleanup(srv.Close)

	// revokeTargetURL drives revokeFailProvider's declared egress, so pointing it
	// at api.backblazeb2.com is what lets the b2 arm's hard-coded host through
	// the exit declaration; rewriteTo then delivers it to the local sink.
	revokeTargetURL = "https://api.backblazeb2.com/keys/fresh"
	prevHTTP := providerHTTP
	providerHTTP = &http.Client{Transport: rewriteTo(srv.URL)}
	t.Cleanup(func() { providerHTTP = prevHTTP })

	owner := mustUser(t, queries, fmt.Sprintf("b2h-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	entryID := "b2h-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "K0newSecret")

	staleMeta := `{"key_id":"0021new","pending_revoke_method":"DELETE","pending_revoke_url":"0021STILLLIVE","pending_revoke_auth":"b2"}`
	enc, err := h.encryptColumn(staleMeta)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider:     toNullString(revokeFailProvider),
		ProviderMeta: toNullString(enc),
		AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
		ID:           entryID,
	}); err != nil {
		t.Fatalf("set provider: %v", err)
	}

	rec := httptest.NewRecorder()
	h.RetryPendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+entryID+"/pending-revoke/retry", owner, "user", entryID,
		`{"password":"`+rotationTestPassword+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: retry returned %d: %s", rec.Code, rec.Body.String())
	}
	if deleteHits == 0 {
		t.Fatalf("ABORT: b2_delete_key was never called, so the 404 rule is not under test")
	}

	var resp pendingRevokeRetryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Revoked {
		t.Error("a b2 endpoint 404 was reported to the operator as a successful revoke. The key id " +
			"travels in the BODY, so a 404 cannot mean the key is gone.")
	}
	meta := entryMetaMap(t, h, queries, entryID)
	if meta[pendingRevokeURL] != "0021STILLLIVE" {
		t.Errorf("a b2 endpoint 404 discarded the coordinates of a live key: %+v", meta)
	}
	if resp.PendingRevoke == nil || resp.PendingRevoke.PredecessorKeyID != "0021STILLLIVE" {
		t.Errorf("the derived status lost the predecessor id: %+v", resp.PendingRevoke)
	}
}

// ---------------------------------------------------------------------------
// MISSING TEST 2: casEditProviderMeta -- there is no CAS test at all today.
// ---------------------------------------------------------------------------

func TestZZCasEditProviderMetaRace(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	installRotationFakes(t)
	ctx := context.Background()

	seed := func(t *testing.T, entryID, metaJSON string) sql.NullString {
		t.Helper()
		enc, err := h.encryptColumn(metaJSON)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
			Provider:     toNullString(revokeFailProvider),
			ProviderMeta: toNullString(enc),
			AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
			ID:           entryID,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		row, err := queries.GetVaultEntryMeta(ctx, entryID)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		return row.ProviderMeta
	}
	deleteMarkers := func(m map[string]string) {
		delete(m, pendingRevokeMethod)
		delete(m, pendingRevokeURL)
		delete(m, pendingRevokeAuth)
	}
	const targetURL = "https://vendor.example/keys/old"

	t.Run("positive control: an uncontended edit applies", func(t *testing.T) {
		owner := mustUser(t, queries, fmt.Sprintf("cas1-%s@example.com", randomHex(6)), "user", "")
		entryID := "cas1-" + randomHex(6)
		mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
		tok := seed(t, entryID, `{"key_id":"k2","pending_revoke_url":"`+targetURL+`","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)

		raw := h.decryptColumnOrLog(tok.String, "{}", vaultFieldProviderMeta)
		got, applied, midFlight, err := h.casEditProviderMeta(ctx, entryID, revokeFailProvider, targetURL,
			raw, ParseProviderMeta(raw), tok, deleteMarkers)
		if err != nil || !applied || midFlight {
			t.Fatalf("uncontended edit: applied=%t midFlight=%t err=%v", applied, midFlight, err)
		}
		if _, ok := got[pendingRevokeURL]; ok {
			t.Errorf("the transform did not apply: %+v", got)
		}
		if stored := entryMetaMap(t, h, queries, entryID); stored[pendingRevokeURL] != "" {
			t.Errorf("the row still carries the marker: %+v", stored)
		}
	})

	t.Run("a stale token re-reads and preserves the concurrent edit", func(t *testing.T) {
		owner := mustUser(t, queries, fmt.Sprintf("cas2-%s@example.com", randomHex(6)), "user", "")
		entryID := "cas2-" + randomHex(6)
		mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
		staleTok := seed(t, entryID, `{"key_id":"k2","pending_revoke_url":"`+targetURL+`","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)
		staleRaw := h.decryptColumnOrLog(staleTok.String, "{}", vaultFieldProviderMeta)
		staleMap := ParseProviderMeta(staleRaw)

		// SOMEBODY ELSE WRITES between our read and our write, adding an
		// unrelated key and leaving the coordinates alone.
		seed(t, entryID, `{"key_id":"k2","added_by_someone_else":"survive","pending_revoke_url":"`+targetURL+`","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)

		got, applied, midFlight, err := h.casEditProviderMeta(ctx, entryID, revokeFailProvider, targetURL,
			staleRaw, staleMap, staleTok, deleteMarkers)
		if err != nil {
			t.Fatalf("a CAS miss must be retried, not errored: %v", err)
		}
		if midFlight {
			t.Fatalf("the coordinates did not move, so this is not mid-flight")
		}
		if !applied {
			t.Fatalf("the CAS never landed after a re-read")
		}
		if _, ok := got[pendingRevokeURL]; ok {
			t.Errorf("the transform did not apply to the fresh map: %+v", got)
		}
		stored := entryMetaMap(t, h, queries, entryID)
		if stored["added_by_someone_else"] != "survive" {
			t.Errorf("the retry re-applied its transform to the STALE map and CLOBBERED the "+
				"concurrent edit: %+v", stored)
		}
		if stored[pendingRevokeURL] != "" {
			t.Errorf("the marker survived a landed CAS: %+v", stored)
		}
	})

	t.Run("coordinates moved mid-flight: refuse and report", func(t *testing.T) {
		owner := mustUser(t, queries, fmt.Sprintf("cas3-%s@example.com", randomHex(6)), "user", "")
		entryID := "cas3-" + randomHex(6)
		mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
		staleTok := seed(t, entryID, `{"key_id":"k2","pending_revoke_url":"`+targetURL+`","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)
		staleRaw := h.decryptColumnOrLog(staleTok.String, "{}", vaultFieldProviderMeta)
		staleMap := ParseProviderMeta(staleRaw)

		// A rotation completes concurrently: NEW coordinates, naming a DIFFERENT
		// predecessor. This attempt's deletion must not touch them.
		const newURL = "https://vendor.example/keys/k2"
		seed(t, entryID, `{"key_id":"k3","pending_revoke_url":"`+newURL+`","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)

		_, applied, midFlight, err := h.casEditProviderMeta(ctx, entryID, revokeFailProvider, targetURL,
			staleRaw, staleMap, staleTok, deleteMarkers)
		if err != nil {
			t.Fatalf("mid-flight is not an error: %v", err)
		}
		if applied {
			t.Errorf("the edit was applied to coordinates it was never about")
		}
		if !midFlight {
			t.Errorf("a moved pending_revoke_url was not reported as mid-flight")
		}
		if stored := entryMetaMap(t, h, queries, entryID); stored[pendingRevokeURL] != newURL {
			t.Errorf("a mid-flight bailout wrote anyway, erasing the NEW predecessor's coordinates: %+v", stored)
		}
	})
}

// ---------------------------------------------------------------------------
// MISSING TEST 3: withoutRevokeStillLive table test.
// ---------------------------------------------------------------------------

func TestZZWithoutRevokeStillLive(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"the message alone clears the field", revokeStillLiveMsg, ""},
		{"joined suffix keeps the delivery failure", "webhook delivery failed: HTTP 500; " + revokeStillLiveMsg, "webhook delivery failed: HTTP 500"},
		{"an unrelated error survives untouched", "webhook delivery failed: HTTP 500", "webhook delivery failed: HTTP 500"},
		{"the message as a PREFIX is not the join shape and must not be trimmed", revokeStillLiveMsg + "; webhook delivery failed", revokeStillLiveMsg + "; webhook delivery failed"},
		{"a bare substring in the middle is not the join shape", "before " + revokeStillLiveMsg + " after", "before " + revokeStillLiveMsg + " after"},
		{"trailing whitespace defeats the suffix match (documented shape only)", revokeStillLiveMsg + " ", revokeStillLiveMsg + " "},
		{"doubled suffix removes exactly one", "x; " + revokeStillLiveMsg + "; " + revokeStillLiveMsg, "x; " + revokeStillLiveMsg},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := withoutRevokeStillLive(c.in); got != c.want {
				t.Errorf("withoutRevokeStillLive(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MISSING TEST 4 (not on the brief's list, found by mutation): the derived
// status has NO test at all. Nilling all seven vault.go call sites, or echoing
// the raw pending_revoke_url back, leaves the whole Go suite green today.
// ---------------------------------------------------------------------------

func TestZZPendingRevokeStatusFromRedacts(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantNil     bool
		wantKeyID   string
		mustNotHave []string
	}{
		{name: "no marker at all", raw: `{"key_id":"k2"}`, wantNil: true},
		{name: "empty object", raw: `{}`, wantNil: true},
		{
			name:        "a real URL is reduced to the last path segment",
			raw:         `{"pending_revoke_url":"https://api.resend.com/api-keys/key_old_1?token=SUPERSECRET#frag"}`,
			wantKeyID:   "key_old_1",
			mustNotHave: []string{"api.resend.com", "https", "SUPERSECRET", "/api-keys/"},
		},
		{
			// path.Base("/") is "/" and path.Base("") is "." -- punctuation, not
			// a key id. Both are withheld (outstanding stays true), because
			// echoing them would put a "." in front of the operator AS the key
			// id and then demand they type it back to resolve. The host never
			// appears either way, which is the other half of this row.
			name:        "a bare root path yields no id, and never the host",
			raw:         `{"pending_revoke_url":"https://internal-vault.corp.example/"}`,
			wantKeyID:   "",
			mustNotHave: []string{"internal-vault.corp.example"},
		},
		{
			name:        "no path at all yields no id, and never the host",
			raw:         `{"pending_revoke_url":"https://internal-vault.corp.example"}`,
			wantKeyID:   "",
			mustNotHave: []string{"internal-vault.corp.example"},
		},
		{
			name:        "a trailing slash still yields the last real segment",
			raw:         `{"pending_revoke_url":"https://api.resend.com/api-keys/key_old_9/"}`,
			wantKeyID:   "key_old_9",
			mustNotHave: []string{"api.resend.com"},
		},
		{
			name:      "the b2 scheme carries a bare key id and is returned as-is",
			raw:       `{"pending_revoke_url":"0021abcDEF_-"}`,
			wantKeyID: "0021abcDEF_-",
		},
		{
			name:        "junk that fails the charset check is WITHHELD, outstanding stays true",
			raw:         `{"pending_revoke_url":"not a key id; drop table\"<script>"}`,
			wantKeyID:   "",
			mustNotHave: []string{"script", "drop table"},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := pendingRevokeStatusFrom(c.raw)
			if c.wantNil {
				if got != nil {
					t.Fatalf("want nil for a row with no marker, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("a row carrying a marker derived no status at all")
			}
			if !got.Outstanding {
				t.Errorf("Outstanding=false while a marker is on the row")
			}
			if got.PredecessorKeyID != c.wantKeyID {
				t.Errorf("PredecessorKeyID = %q, want %q", got.PredecessorKeyID, c.wantKeyID)
			}
			for _, bad := range c.mustNotHave {
				if strings.Contains(got.PredecessorKeyID, bad) {
					t.Errorf("the derived status leaked %q to the client: %q", bad, got.PredecessorKeyID)
				}
			}
		})
	}
}

// TestZZPendingRevokeStatusReachesTheReadPath pins that the derived status is
// actually attached on the read surfaces, not merely derivable. Every one of
// the seven vault.go call sites can be replaced with `nil` today and the whole
// Go suite stays green.
func TestZZPendingRevokeStatusReachesTheReadPath(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	installRotationFakes(t)
	ctx := context.Background()

	owner := mustUser(t, queries, fmt.Sprintf("readpath-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	entryID := "readpath-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
	enc, err := h.encryptColumn(`{"key_id":"k2","pending_revoke_url":"https://api.resend.com/api-keys/key_old_1","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider:     toNullString(revokeFailProvider),
		ProviderMeta: toNullString(enc),
		AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
		ID:           entryID,
	}); err != nil {
		t.Fatalf("set provider: %v", err)
	}

	row, err := queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	meta := h.vaultMetaFromGetRow(ctx, row, owner)
	if meta.PendingRevoke == nil || !meta.PendingRevoke.Outstanding ||
		meta.PendingRevoke.PredecessorKeyID != "key_old_1" {
		t.Errorf("the single-entry read surface dropped the derived pending_revoke: %+v", meta.PendingRevoke)
	}

	all, err := queries.ListAllVaultEntries(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := false
	for _, r := range all {
		if r.ID != entryID {
			continue
		}
		seen = true
		m := h.vaultMetaFromListAllRow(r)
		if m.PendingRevoke == nil || !m.PendingRevoke.Outstanding {
			t.Errorf("the LIST surface dropped the derived pending_revoke, so the locked table's "+
				"chip -- the only signal an on-demand entry has -- can never render: %+v", m.PendingRevoke)
		}
	}
	if !seen {
		t.Fatalf("ABORT: the seeded entry was not in the list result")
	}
}

// ---------------------------------------------------------------------------
// MISSING TEST 5 (found by mutation): ResolvePendingRevoke's success path and
// its acknowledged_key_id equality check have NO handler-level test. Deleting
// `req.AcknowledgedKeyID != status.PredecessorKeyID` leaves the suite green.
// ---------------------------------------------------------------------------

func TestZZResolvePendingRevokeMatchesTheAcknowledgedKey(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	installRotationFakes(t)
	ctx := context.Background()

	newEntry := func(t *testing.T) (string, string) {
		t.Helper()
		owner := mustUser(t, queries, fmt.Sprintf("res-%s@example.com", randomHex(6)), "user", rotationTestPassword)
		entryID := "res-" + randomHex(6)
		mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
		enc, err := h.encryptColumn(`{"key_id":"k2","keep":"me","pending_revoke_url":"https://api.resend.com/api-keys/key_old_1","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
			Provider:     toNullString(revokeFailProvider),
			ProviderMeta: toNullString(enc),
			AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
			ID:           entryID,
		}); err != nil {
			t.Fatalf("set provider: %v", err)
		}
		if err := queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
			LastRotationError: toNullString("webhook delivery failed: HTTP 500; " + revokeStillLiveMsg),
			ID:                entryID,
		}); err != nil {
			t.Fatalf("seed error: %v", err)
		}
		return owner, entryID
	}

	t.Run("a WRONG key id is refused and nothing is discarded", func(t *testing.T) {
		owner, entryID := newEntry(t)
		rec := httptest.NewRecorder()
		h.ResolvePendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
			"/api/vault/"+entryID+"/pending-revoke/resolve", owner, "user", entryID,
			`{"acknowledged_key_id":"key_old_2"}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("a mismatched acknowledgement returned %d, want 400: %s", rec.Code, rec.Body.String())
		}
		if got := entryMetaMap(t, h, queries, entryID); got[pendingRevokeURL] == "" {
			t.Errorf("a REFUSED resolve discarded the stranded key's coordinates anyway: %+v", got)
		}
	})

	t.Run("the RAW url is not accepted as the acknowledgement", func(t *testing.T) {
		owner, entryID := newEntry(t)
		rec := httptest.NewRecorder()
		h.ResolvePendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
			"/api/vault/"+entryID+"/pending-revoke/resolve", owner, "user", entryID,
			`{"acknowledged_key_id":"https://api.resend.com/api-keys/key_old_1"}`))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("the raw marker URL was accepted as an acknowledgement (%d); the caller must "+
				"echo the DERIVED id they were shown: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("positive control: the RIGHT key id clears the markers and the revoke half only", func(t *testing.T) {
		owner, entryID := newEntry(t)
		rec := httptest.NewRecorder()
		h.ResolvePendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
			"/api/vault/"+entryID+"/pending-revoke/resolve", owner, "user", entryID,
			`{"acknowledged_key_id":"key_old_1"}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("a matching acknowledgement returned %d: %s", rec.Code, rec.Body.String())
		}
		var resp pendingRevokeResolveResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !resp.Resolved || resp.PendingRevoke != nil {
			t.Errorf("resolve response = %+v", resp)
		}
		got := entryMetaMap(t, h, queries, entryID)
		if got[pendingRevokeURL] != "" || got[pendingRevokeMethod] != "" || got[pendingRevokeAuth] != "" {
			t.Errorf("resolve left markers behind: %+v", got)
		}
		if got["keep"] != "me" || got["key_id"] != "k2" {
			t.Errorf("resolve clobbered unrelated provider_meta keys: %+v", got)
		}
		row, err := queries.GetVaultEntryMeta(ctx, entryID)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if row.LastRotationError.String != "webhook delivery failed: HTTP 500" {
			t.Errorf("last_rotation_error = %q; resolve must clear only the revoke half",
				row.LastRotationError.String)
		}
	})
}

// ---------------------------------------------------------------------------
// MISSING TEST 6: CAS EXHAUSTION. casEditProviderMeta's "gave up after N
// concurrent writes" arm, and the handler's refusal to clear
// last_rotation_error when the marker deletion never landed, are both
// unreachable from any test today.
//
// A BEFORE UPDATE trigger with RAISE(IGNORE) makes every provider_meta write to
// ONE row a no-op with RowsAffected 0, which is exactly what CASProviderMeta
// reports as "somebody else won the race" -- deterministically, forever, with
// no goroutines and no flake.
// ---------------------------------------------------------------------------

func blockProviderMetaWrites(t *testing.T, h *VaultHandler, entryID string) {
	t.Helper()
	name := "zz_block_" + strings.ReplaceAll(entryID, "-", "_")
	if _, err := h.db.Exec(fmt.Sprintf(
		`CREATE TRIGGER %s BEFORE UPDATE OF provider_meta ON vault_entries
		 WHEN NEW.id = '%s' BEGIN SELECT RAISE(IGNORE); END;`, name, entryID)); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	t.Cleanup(func() { _, _ = h.db.Exec("DROP TRIGGER IF EXISTS " + name) })
}

func TestZZCasEditProviderMetaGivesUpLoudly(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	installRotationFakes(t)
	ctx := context.Background()

	owner := mustUser(t, queries, fmt.Sprintf("exh-%s@example.com", randomHex(6)), "user", "")
	entryID := "exh-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
	const targetURL = "https://vendor.example/keys/old"
	enc, err := h.encryptColumn(`{"key_id":"k2","pending_revoke_url":"` + targetURL + `","pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider: toNullString(revokeFailProvider), ProviderMeta: toNullString(enc),
		AutoRotate: sql.NullInt64{Int64: 0, Valid: true}, ID: entryID,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	row, err := queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tok := row.ProviderMeta
	before := entryMetaMap(t, h, queries, entryID)
	if before[pendingRevokeURL] != targetURL {
		t.Fatalf("ABORT: seed did not land: %+v", before)
	}

	blockProviderMetaWrites(t, h, entryID)

	rawMeta := h.decryptColumnOrLog(tok.String, "{}", vaultFieldProviderMeta)
	got, applied, midFlight, err := h.casEditProviderMeta(ctx, entryID, revokeFailProvider, targetURL,
		rawMeta, ParseProviderMeta(rawMeta), tok,
		func(m map[string]string) {
			delete(m, pendingRevokeMethod)
			delete(m, pendingRevokeURL)
			delete(m, pendingRevokeAuth)
		})

	if applied {
		t.Errorf("casEditProviderMeta reported applied=true after exhausting its attempts without " +
			"ever landing a write. Every caller then treats a marker deletion that never reached " +
			"the row as done, and clears last_rotation_error on an entry whose predecessor key is " +
			"still live upstream.")
	}
	if err == nil {
		t.Errorf("exhaustion returned no error (applied=%t midFlight=%t result=%+v)", applied, midFlight, got)
	}
	if after := entryMetaMap(t, h, queries, entryID); after[pendingRevokeURL] != targetURL {
		t.Errorf("ABORT: the trigger did not actually block the write, so this test proves nothing: %+v", after)
	}
}

// TestZZRetryDoesNotReportCleanWhenThePersistNeverLanded is the handler-level
// consequence: a revoke that genuinely SUCCEEDED upstream, whose marker
// deletion could not be persisted, must not clear last_rotation_error. The
// entry would otherwise report clean while its row still carries coordinates
// for a key that is now gone -- and, in the mirror case, report clean while a
// key is still live.
func TestZZRetryDoesNotReportCleanWhenThePersistNeverLanded(t *testing.T) {
	h, queries, owner, entryID, sink := failingRevokeEnv(t, http.StatusOK) // 200 == revoke SUCCEEDS
	blockProviderMetaWrites(t, h, entryID)

	rec := httptest.NewRecorder()
	h.RetryPendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+entryID+"/pending-revoke/retry", owner, "user", entryID,
		`{"password":"`+rotationTestPassword+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: retry returned %d: %s", rec.Code, rec.Body.String())
	}
	if !sink.sawStale() {
		t.Fatalf("ABORT: the upstream revoke never happened (%v)", sink.all())
	}

	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if row.LastRotationError.String != revokeStillLiveMsg {
		t.Errorf("last_rotation_error was cleared (now %q) even though the marker deletion never "+
			"reached the row. The entry reports clean while its row still says a key is stranded.",
			row.LastRotationError.String)
	}
	if got := entryMetaMap(t, h, queries, entryID); got[pendingRevokeURL] == "" {
		t.Errorf("ABORT: the trigger did not block the write: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// MISSING TEST 7: the tripwire the spend-gate test needs to be worth anything.
//
// RetryPendingRevoke's entryCurrentlyUsableBy check is BEHAVIOURALLY DEAD
// today: grantFor has no row with manage=true and use=false, so the canWrite
// gate immediately after it refuses every identity the spend gate would have.
// Deleting the spend gate entirely leaves the whole handlers suite green.
// That is fine as defence in depth, but it means the moment somebody adds a
// manage-without-use role the endpoint silently loses its spend check with no
// test to say so. This is that alarm.
// ---------------------------------------------------------------------------

func TestZZNoGrantRowHasManageWithoutUse(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, fmt.Sprintf("g-creator-%s@example.com", randomHex(4)), "user", "")
	manager := mustUser(t, queries, fmt.Sprintf("g-manager-%s@example.com", randomHex(4)), "user", "")
	editor := mustUser(t, queries, fmt.Sprintf("g-editor-%s@example.com", randomHex(4)), "user", "")
	viewer := mustUser(t, queries, fmt.Sprintf("g-viewer-%s@example.com", randomHex(4)), "user", "")
	stranger := mustUser(t, queries, fmt.Sprintf("g-stranger-%s@example.com", randomHex(4)), "user", "")
	admin := mustUser(t, queries, fmt.Sprintf("g-admin-%s@example.com", randomHex(4)), "admin", "")

	personal := "g-personal-" + randomHex(4)
	mustEntry(t, h, queries, personal, creator, "Personal", "V")

	collID := "g-coll-" + randomHex(4)
	mustCollection(t, queries, collID, manager, map[string]string{
		manager: collRoleManager, editor: collRoleEditor, viewer: collRoleViewer, creator: collRoleEditor,
	})
	shared := "g-shared-" + randomHex(4)
	mustEntry(t, h, queries, shared, creator, "Shared", "V")
	placeInCollection(t, queries, shared, collID)

	rows := []struct {
		name    string
		entry   string
		user    string
		isAdmin bool
	}{
		{"personal owner", personal, creator, false},
		{"personal non-owner", personal, stranger, false},
		{"admin", shared, admin, true},
		{"accepted manager", shared, manager, false},
		{"accepted editor", shared, editor, false},
		{"accepted viewer", shared, viewer, false},
		{"stranger", shared, stranger, false},
		{"missing entry", "no-such-entry", creator, false},
	}
	check := func(t *testing.T, name, entry, user string, isAdmin bool) {
		t.Helper()
		g := h.grantFor(ctx, user, isAdmin, entry)
		if g.manage && !g.use {
			t.Errorf("%s: grantFor now returns manage WITHOUT use. RetryPendingRevoke's "+
				"entryCurrentlyUsableBy gate stops being redundant the moment this happens, and "+
				"nothing else in the suite can tell whether that gate is still there. Add a "+
				"handler-level row for this identity to TestPendingRevokeAuthz before shipping.", name)
		}
	}
	for _, c := range rows {
		check(t, c.name, c.entry, c.user, c.isAdmin)
	}
	// And the removed creator, which is the row the endpoint's doc is about.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: collID, UserID: creator,
	}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	check(t, "removed creator (residual read)", shared, creator, false)
	if g := h.grantFor(ctx, creator, false, shared); !g.read || g.use || g.manage {
		t.Errorf("removed creator grant = %+v, want read-only residual", g)
	}
}

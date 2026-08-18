package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE RETRY HAS TO BE WIRED IN, NOT MERELY WRITTEN.
//
// vault_pending_revoke_retry_test.go proves retryOutstandingRevoke
// behaves; it says nothing about whether either rotation path calls it, and a
// helper nobody calls is exactly the shape of "a preserved record nothing
// reads" that this work exists to close. Deleting the call from either path
// leaves that file green.
//
// So this drives BOTH real rotation paths, through the real handlers, against a
// real upstream, on an entry whose row already carries a failed revoke's
// coordinates, and asserts the predecessor was actually revoked. A source-order
// check would be cheaper and would prove nothing: the estate has four guards
// this week that passed while the bug they named was live.

// revokeSink records every revoke the rotation actually issued.
type revokeSink struct {
	mu   sync.Mutex
	hits []string
}

func (s *revokeSink) record(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, path)
}

func (s *revokeSink) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

func (s *revokeSink) sawStale() bool {
	for _, h := range s.all() {
		if strings.Contains(h, "stranded-key") {
			return true
		}
	}
	return false
}

// staleRevokeEnv seeds an entry mid-partial-rotation: a previous rotation minted
// key-2 and its revoke of key-1 failed, so the coordinates are on the row.
func staleRevokeEnv(t *testing.T, autoRotate int64) (*VaultHandler, *db.Queries, string, string, *revokeSink) {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	installRotationFakes(t)

	sink := &revokeSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			sink.record(r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// revokeTargetURL drives BOTH the test provider's egress declaration and the
	// coordinates its Rotate defers, so pointing it at the sink is what lets a
	// real revoke reach a real server.
	revokeTargetURL = srv.URL + "/keys/fresh"
	// The guarded client refuses loopback at dial time, correct in production
	// and useless for reaching a test server.
	prevHTTP := providerHTTP
	providerHTTP = &http.Client{}
	t.Cleanup(func() { providerHTTP = prevHTTP })

	owner := mustUser(t, queries, fmt.Sprintf("stale-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	entryID := "stale-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "ORIGINAL-VALUE")

	// The row as a failed revoke leaves it: key-2 is current, key-1 is stranded
	// upstream, and its coordinates are the only record of how to kill it.
	staleMeta := fmt.Sprintf(
		`{"key_id":"key-2","pending_revoke_method":"DELETE","pending_revoke_url":%q,"pending_revoke_auth":"bearer","last_revoke_error":"revoke old key: HTTP 503"}`,
		srv.URL+"/keys/stranded-key")
	enc, err := h.encryptColumn(staleMeta)
	if err != nil {
		t.Fatalf("encrypt provider_meta: %v", err)
	}
	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider:     toNullString(revokeFailProvider),
		ProviderMeta: toNullString(enc),
		AutoRotate:   sql.NullInt64{Int64: autoRotate, Valid: true},
		ID:           entryID,
	}); err != nil {
		t.Fatalf("set provider: %v", err)
	}
	if err := queries.UpdateVaultEntryRotationInterval(context.Background(),
		db.UpdateVaultEntryRotationIntervalParams{
			RotationIntervalDays: sql.NullInt64{Int64: 1, Valid: true}, ID: entryID,
		}); err != nil {
		t.Fatalf("set interval: %v", err)
	}
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET last_rotated_at = datetime('now','-30 days'),
		 updated_at = datetime('now','-1 hour') WHERE id = ?`, entryID); err != nil {
		t.Fatalf("age entry: %v", err)
	}
	return h, queries, owner, entryID, sink
}

func TestStrandedKeyIsRevokedByTheNextManualRotation(t *testing.T) {
	h, queries, owner, entryID, sink := staleRevokeEnv(t, 1)

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/rotate",
		owner, "user", entryID, `{"password":"`+rotationTestPassword+`"}`))
	h.WaitForDelivery(5 * 1e9)

	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the rotation itself failed with %d, so nothing below is being tested (body: %s)",
			rec.Code, rec.Body.String())
	}
	if !sink.sawStale() {
		t.Fatalf("the stranded predecessor was never revoked; the rotation only issued %v. "+
			"Its coordinates have now been overwritten by this rotation's mint, so the key is live "+
			"upstream forever with nothing left recording where to kill it", sink.all())
	}
	assertStaleMarkerGone(t, h, queries, entryID)
}

func TestStrandedKeyIsRevokedByTheNextSweepRotation(t *testing.T) {
	h, queries, _, entryID, sink := staleRevokeEnv(t, 1)

	due, err := queries.ListVaultEntriesNeedingRotation(context.Background())
	if err != nil {
		t.Fatalf("due list: %v", err)
	}
	var row *db.ListVaultEntriesNeedingRotationRow
	for i := range due {
		if due[i].ID == entryID {
			row = &due[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("ABORT: entry %s is not due (%d due), so the sweep is a no-op and this asserts nothing",
			entryID, len(due))
	}
	rotateOneEntry(context.Background(), queries, h, *row)

	if !sink.sawStale() {
		t.Fatalf("the sweep never revoked the stranded predecessor; it only issued %v", sink.all())
	}
	assertStaleMarkerGone(t, h, queries, entryID)
}

// assertStaleMarkerGone checks the row afterwards. A successful retry clears the
// old coordinates, and this rotation's own defer then records the NEW ones, so
// what must never survive is the stranded key's URL specifically.
func assertStaleMarkerGone(t *testing.T, h *VaultHandler, queries *db.Queries, entryID string) {
	t.Helper()
	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload entry: %v", err)
	}
	meta := ParseProviderMeta(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta))
	if strings.Contains(meta[pendingRevokeURL], "stranded-key") {
		t.Errorf("the stranded key's coordinates survived a successful retry: %+v", meta)
	}
}

// TestStrandedKeyIsRevokedByTheRetryEndpointOnAnOnDemandEntry is the
// operator-visible closure of retryOutstandingRevoke's KNOWN COVERAGE HOLE
// (vault_rotation_core.go): an on-demand entry (auto_rotate = 0) that the
// scheduled sweep will never pick up again, and that nobody has clicked Rotate
// on, still had its stranded predecessor key sitting there forever before this
// endpoint existed. This drives the REAL handler, against a real (test) upstream,
// on exactly that shape of entry.
func TestStrandedKeyIsRevokedByTheRetryEndpointOnAnOnDemandEntry(t *testing.T) {
	h, queries, owner, entryID, sink := staleRevokeEnv(t, 0) // auto_rotate = 0: on-demand

	// ABORT if the scheduled sweep's own due query would select this entry: that
	// would prove the sweep can reach it after all, and this test would show
	// nothing about the endpoint it exists to cover.
	due, err := queries.ListVaultEntriesNeedingRotation(context.Background())
	if err != nil {
		t.Fatalf("due list: %v", err)
	}
	for _, row := range due {
		if row.ID == entryID {
			t.Fatalf("ABORT: entry %s is due for the scheduled sweep even with auto_rotate=0; this "+
				"test cannot prove the sweep genuinely cannot reach it", entryID)
		}
	}

	rec := httptest.NewRecorder()
	h.RetryPendingRevoke(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/pending-revoke/retry",
		owner, "user", entryID, `{"password":"`+rotationTestPassword+`"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the retry endpoint itself failed with %d, so nothing below is being tested (body: %s)",
			rec.Code, rec.Body.String())
	}
	var resp struct {
		Revoked bool `json:"revoked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode retry response: %v", err)
	}
	if !resp.Revoked {
		t.Fatalf("the retry endpoint reported revoked=false: %s", rec.Body.String())
	}
	if !sink.sawStale() {
		t.Fatalf("the stranded predecessor was never revoked through the retry endpoint; it only issued %v. "+
			"An on-demand entry that nobody rotates again would have carried this marker forever",
			sink.all())
	}
	assertStaleMarkerGone(t, h, queries, entryID)
}

// TestPendingRevokeRetryRefusesAPinnedEntry proves the retry endpoint asks
// spendProviderSecret, not just an ad-hoc host check: the entry is wired into
// the AI gateway as a DIFFERENT provider's key (openai, api.openai.com), while
// its own declared provider egress resolves to the test sink instead. That
// mismatch is refused only if spendProviderSecret's PIN check actually runs.
//
// This is the ablation the brief calls out by name: performPendingRevoke mints
// its OWN secretexit receipt, so providerDo alone would let the revoke through
// even with spendProviderSecret removed. Only the pin check, which lives
// exclusively in spendProviderSecret, catches this. Dropping that call is
// exactly the mutation proven below to flip this test red.
func TestPendingRevokeRetryRefusesAPinnedEntry(t *testing.T) {
	h, queries, owner, entryID, sink := staleRevokeEnv(t, 1)

	// PUT /api/settings/ai is AdminOnly; this is that write, wiring the gateway
	// to a provider the entry itself is NOT configured for.
	if err := queries.UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: "ai_key_openai", Value: entryID,
	}); err != nil {
		t.Fatalf("wire the gateway: %v", err)
	}

	rec := httptest.NewRecorder()
	h.RetryPendingRevoke(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/pending-revoke/retry",
		owner, "user", entryID, `{"password":"`+rotationTestPassword+`"}`))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a pinned entry's retry returned %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if sink.sawStale() {
		t.Fatalf("a pinned entry's retry reached the upstream revoke anyway: %v", sink.all())
	}
	assertStaleMarkerStillPresent(t, h, queries, entryID)
}

// assertStaleMarkerStillPresent is assertStaleMarkerGone's negation, for a
// refused retry: the marker must survive a refusal exactly as it must not
// survive a success.
func assertStaleMarkerStillPresent(t *testing.T, h *VaultHandler, queries *db.Queries, entryID string) {
	t.Helper()
	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload entry: %v", err)
	}
	meta := ParseProviderMeta(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta))
	if !strings.Contains(meta[pendingRevokeURL], "stranded-key") {
		t.Errorf("a refused retry discarded the stranded key's coordinates anyway: %+v", meta)
	}
}

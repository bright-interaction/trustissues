package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE P0-1 REGRESSION SUITE. Adapted from the 2026-08-19 audit crew's
// TestProbeA_TwoStillLiveKeysShareOneAlarmAndOneRetryClearsBoth, which FAILED
// against a6558e065 and is preserved at
// ops/audits/trustissues-2026-08-19-probes/.
//
// The defect: two stranded keys shared ONE identity-free alarm and ONE marker
// slot, so rotation N+1 evicted rotation N's coordinates and settling the
// surviving key cleared the alarm for both. Measured on the real handlers as
// sink [503 /keys/K1, 503 /keys/K2, 200 /keys/K2] with last_rotation_error
// empty afterwards: K1 valid at the vendor, the product reporting clean.
//
// Everything below drives real h.Rotate, real retryOutstandingRevoke, real
// deferRevokeOldProviderKey and the real retry/resolve endpoints. Only the
// starting fixture and the provider adapter are test-authored.

const historyProvider = "test-revoke-history"

// historySink is a fake upstream that records every revoke and can be flipped
// between "the provider is down" and "the provider works".
type historySink struct {
	mu   sync.Mutex
	hits []string
	code int
}

func (s *historySink) setCode(c int) { s.mu.Lock(); s.code = c; s.mu.Unlock() }

func (s *historySink) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	code := s.code
	if r.Method == http.MethodDelete {
		s.hits = append(s.hits, fmt.Sprintf("%d %s", code, r.URL.Path))
	}
	s.mu.Unlock()
	w.WriteHeader(code)
}

func (s *historySink) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

// revokedOK reports whether the sink ever ACCEPTED a delete of the named key.
func (s *historySink) revokedOK(key string) bool {
	for _, h := range s.all() {
		if strings.HasPrefix(h, "200 ") && strings.HasSuffix(h, "/keys/"+key) {
			return true
		}
	}
	return false
}

var (
	historyBaseURL   string
	historyNextKeyID = "K3"
)

type historyProviderImpl struct{}

func (p *historyProviderImpl) Name() string                            { return historyProvider }
func (p *historyProviderImpl) CanAutoRotate() bool                     { return true }
func (p *historyProviderImpl) DashboardURL(_ map[string]string) string { return "" }
func (p *historyProviderImpl) Validate(_ context.Context, _ string, _ map[string]string) (bool, error) {
	return true, nil
}

// Rotate mints a successor and defers the revoke of THIS entry's current key,
// exactly the way resend/sendgrid/neon do.
func (p *historyProviderImpl) Rotate(_ context.Context, _ string, meta map[string]string) (string, error) {
	old := meta["key_id"]
	meta["key_id"] = historyNextKeyID
	if old != "" && old != historyNextKeyID {
		deferRevokeOldProviderKey(meta, "DELETE", historyBaseURL+"/keys/"+old, revokeAuthBearer, old)
	}
	return "ROTATED-" + historyNextKeyID, nil
}

// revokeHistoryEnv seeds one entry that is already mid-partial-rotation: an
// EARLIER rotation minted K2 and its revoke of K1 failed, so K1's coordinates
// are the only record of how to kill it.
//
// providerMetaJSON is the stored column, so a caller can seed the OLD (pre-queue)
// shape verbatim.
func revokeHistoryEnv(t *testing.T, providerMetaJSON func(base string) string) (
	*VaultHandler, *db.Queries, string, string, *historySink) {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	installRotationFakes(t)

	sink := &historySink{code: http.StatusServiceUnavailable}
	srv := httptest.NewServer(http.HandlerFunc(sink.serve))
	t.Cleanup(srv.Close)
	historyBaseURL = srv.URL

	prevHTTP := providerHTTP
	providerHTTP = &http.Client{}
	t.Cleanup(func() { providerHTTP = prevHTTP })

	ProviderRegistry[historyProvider] = &historyProviderImpl{}
	providerLabels[historyProvider] = "Revoke-history regression provider"
	providerEgress[historyProvider] = providerEgressDecl{
		hosts: func(map[string]string) []string {
			u, err := url.Parse(historyBaseURL)
			if err != nil || u.Hostname() == "" {
				return nil
			}
			return []string{u.Hostname()}
		},
		why: "revoke-history regression provider",
	}
	t.Cleanup(func() {
		delete(ProviderRegistry, historyProvider)
		delete(providerLabels, historyProvider)
		delete(providerEgress, historyProvider)
	})

	owner := mustUser(t, queries, fmt.Sprintf("revhist-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	entryID := "revhist-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "SECRET-FOR-K2")

	enc, err := h.encryptColumn(providerMetaJSON(srv.URL))
	if err != nil {
		t.Fatalf("encrypt provider_meta: %v", err)
	}
	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider:     toNullString(historyProvider),
		ProviderMeta: toNullString(enc),
		AutoRotate:   sql.NullInt64{Int64: 1, Valid: true},
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

// oldShapeStrandedMeta is the pre-queue provider_meta a production row written
// before this change actually holds: four scalar markers and nothing else.
func oldShapeStrandedMeta(base string) string {
	return fmt.Sprintf(
		`{"key_id":"K2","pending_revoke_method":"DELETE","pending_revoke_url":%q,`+
			`"pending_revoke_auth":"bearer","pending_revoke_key_id":"K1",`+
			`"last_revoke_error":"revoke old key: HTTP 503"}`,
		base+"/keys/K1")
}

func revokeHistoryMeta(t *testing.T, h *VaultHandler, queries *db.Queries, entryID string) (map[string]string, string) {
	t.Helper()
	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload entry: %v", err)
	}
	return ParseProviderMeta(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)),
		row.LastRotationError.String
}

// TestTwoStillLiveKeysKeepSeparateIdentitiesAndOneRetryClearsOnlyItsOwn is the
// permanent form of the crew's ProbeA.
//
// IT IS ALSO THE OLD-SHAPE PROOF. The fixture is seeded in the pre-queue scalar
// shape that every existing production row carries -- no pending_revoke_stranded
// key at all -- so the whole sequence below exercises a legacy row being read,
// rotated, queued and discharged by the new code.
func TestTwoStillLiveKeysKeepSeparateIdentitiesAndOneRetryClearsOnlyItsOwn(t *testing.T) {
	h, queries, owner, entryID, sink := revokeHistoryEnv(t, oldShapeStrandedMeta)

	// Phase 1: the provider is down. Both revokes fail.
	sink.setCode(http.StatusServiceUnavailable)

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/rotate",
		owner, "user", entryID, `{"password":"`+rotationTestPassword+`"}`))
	h.WaitForDelivery(5e9)
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the rotation itself failed with %d, nothing below is being tested: %s",
			rec.Code, rec.Body.String())
	}

	meta, lastErr := revokeHistoryMeta(t, h, queries, entryID)
	t.Logf("after rotation: last_rotation_error=%q head=%q/%q backlog=%q sink=%v",
		lastErr, meta[pendingRevokeKeyID], meta[pendingRevokeURL], meta[pendingRevokeStranded], sink.all())

	if meta[pendingRevokeKeyID] != "K2" {
		t.Fatalf("ABORT: the head marker names %q, want K2 (this rotation's own predecessor)",
			meta[pendingRevokeKeyID])
	}

	// 1. THE ALARM NAMES BOTH KEYS. It used to be one identity-free const.
	wantArmed := revokeStillLiveMsgFor([]string{"K1", "K2"})
	if lastErr != wantArmed {
		t.Fatalf("the alarm does not name both still-live keys.\n got: %q\nwant: %q\n"+
			"An alarm that carries no identity cannot be cleared safely: settling one key clears it for all.",
			lastErr, wantArmed)
	}

	// 2. K1's COORDINATES SURVIVED THE DEFER. They used to be overwritten.
	backlog, malformed := parseStrandedRevokes(meta)
	if malformed {
		t.Fatalf("the stranded backlog did not parse: %q", meta[pendingRevokeStranded])
	}
	if len(backlog) != 1 || backlog[0].KeyID != "K1" {
		t.Fatalf("K1's revoke coordinates were EVICTED by this rotation's defer; backlog is %+v.\n"+
			"That is the CRITICAL: nothing durable names K1 any more and it is still valid at the vendor.",
			backlog)
	}
	if !strings.HasSuffix(backlog[0].URL, "/keys/K1") {
		t.Errorf("the backlog entry does not carry K1's URL: %+v", backlog[0])
	}

	// Phase 2: the provider comes back. The operator retries the key the product
	// is currently showing them.
	sink.setCode(http.StatusOK)
	rec2 := httptest.NewRecorder()
	h.RetryPendingRevoke(rec2, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+entryID+"/pending-revoke/retry", owner, "user", entryID,
		`{"password":"`+rotationTestPassword+`"}`))
	if rec2.Code != http.StatusOK {
		t.Fatalf("ABORT: the retry endpoint failed with %d: %s", rec2.Code, rec2.Body.String())
	}
	var resp struct {
		Revoked bool `json:"revoked"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp)
	if !resp.Revoked {
		t.Fatalf("ABORT: the retry reported revoked=false: %s", rec2.Body.String())
	}

	meta2, lastErr2 := revokeHistoryMeta(t, h, queries, entryID)
	t.Logf("after retry:    last_rotation_error=%q head=%q/%q backlog=%q sink=%v",
		lastErr2, meta2[pendingRevokeKeyID], meta2[pendingRevokeURL], meta2[pendingRevokeStranded], sink.all())

	// The premise of the whole probe: K2 settled, K1 did not.
	if sink.revokedOK("K1") {
		t.Fatalf("ABORT: K1 was actually revoked; the probe's premise does not hold. sink=%v", sink.all())
	}
	if !sink.revokedOK("K2") {
		t.Fatalf("ABORT: K2 was not revoked either, so nothing settled. sink=%v", sink.all())
	}

	// 3. SETTLING ONE KEY MUST NOT CLEAR THE ALARM FOR THE OTHER. This is the
	//    assertion the crew's probe failed on: lastErr2 was "".
	wantRemaining := revokeStillLiveMsgFor([]string{"K1"})
	if lastErr2 != wantRemaining {
		t.Errorf("settling ONE still-live key changed the alarm to %q, want %q.\n"+
			"K1 is still authenticating at the provider (the sink only ever saw %v). "+
			"If this is empty, the entry now reports a completely clean rotation while a credential "+
			"the operator asked to retire is live at the vendor.",
			lastErr2, wantRemaining, sink.all())
	}

	// 4. K1 IS PROMOTED INTO THE HEAD, so the operator can act on it next.
	if got := meta2[pendingRevokeKeyID]; got != "K1" {
		t.Errorf("K1 was not promoted into the head marker after K2 was discharged: head names %q, "+
			"backlog is %q", got, meta2[pendingRevokeStranded])
	}
	if st := pendingRevokeStatusFromMeta(meta2); st == nil || !st.Outstanding || st.PredecessorKeyID != "K1" {
		t.Errorf("the entry no longer advertises an outstanding revoke for K1: %+v", st)
	}

	// 5. AND THE SECOND RETRY ACTUALLY KILLS K1. The affordance is real, not
	//    just a chip.
	rec3 := httptest.NewRecorder()
	h.RetryPendingRevoke(rec3, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+entryID+"/pending-revoke/retry", owner, "user", entryID,
		`{"password":"`+rotationTestPassword+`"}`))
	if rec3.Code != http.StatusOK {
		t.Fatalf("the second retry failed with %d: %s", rec3.Code, rec3.Body.String())
	}
	if !sink.revokedOK("K1") {
		t.Errorf("the second retry never reached K1 at the provider; sink=%v", sink.all())
	}
	meta3, lastErr3 := revokeHistoryMeta(t, h, queries, entryID)
	if lastErr3 != "" {
		t.Errorf("with BOTH keys settled the alarm should be gone, got %q", lastErr3)
	}
	if st := pendingRevokeStatusFromMeta(meta3); st != nil {
		t.Errorf("with both keys settled nothing should be outstanding, got %+v", st)
	}
	if _, still := meta3[pendingRevokeStranded]; still {
		t.Errorf("the backlog key survived a full discharge: %q", meta3[pendingRevokeStranded])
	}
}

// TestResolvingOneStrandedKeyDoesNotAcknowledgeTheOnesQueuedBehindIt is the
// resolve-endpoint twin of the retry case above.
//
// Resolve is the TERMINAL escape hatch: the operator asserts, out of band, that
// one named key is not a concern. That assertion is about ONE key. Before this
// change it discarded the whole marker set and cleared the whole alarm, so
// acknowledging K2 silently acknowledged K1 too.
func TestResolvingOneStrandedKeyDoesNotAcknowledgeTheOnesQueuedBehindIt(t *testing.T) {
	h, queries, owner, entryID, sink := revokeHistoryEnv(t, oldShapeStrandedMeta)
	sink.setCode(http.StatusServiceUnavailable)

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/rotate",
		owner, "user", entryID, `{"password":"`+rotationTestPassword+`"}`))
	h.WaitForDelivery(5e9)
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: rotation failed with %d: %s", rec.Code, rec.Body.String())
	}
	if meta, _ := revokeHistoryMeta(t, h, queries, entryID); meta[pendingRevokeKeyID] != "K2" {
		t.Fatalf("ABORT: head does not name K2: %+v", meta)
	}

	rec2 := httptest.NewRecorder()
	h.ResolvePendingRevoke(rec2, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+entryID+"/pending-revoke/resolve", owner, "user", entryID,
		`{"acknowledged_key_id":"K2"}`))
	if rec2.Code != http.StatusOK {
		t.Fatalf("resolve failed with %d: %s", rec2.Code, rec2.Body.String())
	}

	// The response must not claim there is nothing left.
	var resp pendingRevokeResolveResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode resolve response: %v (%s)", err, rec2.Body.String())
	}
	if resp.PendingRevoke == nil || resp.PendingRevoke.PredecessorKeyID != "K1" {
		t.Errorf("the resolve response reported %+v; acknowledging K2 must hand back K1 as the new "+
			"outstanding revoke, not nil. Reporting nil tells the client the entry is clean while "+
			"K1 is live at the vendor.", resp.PendingRevoke)
	}

	meta, lastErr := revokeHistoryMeta(t, h, queries, entryID)
	if want := revokeStillLiveMsgFor([]string{"K1"}); lastErr != want {
		t.Errorf("acknowledging K2 changed the alarm to %q, want %q", lastErr, want)
	}
	if meta[pendingRevokeKeyID] != "K1" {
		t.Errorf("K1 was not promoted into the head after K2 was acknowledged: %+v", meta)
	}
}

// TestOldShapeProviderMetaRowsStillReadAndDischargeCorrectly is the migration
// proof the queue change owes.
//
// provider_meta is an ENCRYPTED JSON column with live production rows in it, and
// this change adds a key none of them carry. The claim being tested is that the
// addition is purely additive: a row in the old scalar shape must read, report,
// discharge and clear exactly as it did before, with no backlog anywhere.
func TestOldShapeProviderMetaRowsStillReadAndDischargeCorrectly(t *testing.T) {
	t.Run("a single old-shape marker set reports and discharges with no backlog", func(t *testing.T) {
		m := map[string]string{
			"key_id":                "K2",
			pendingRevokeMethod:     "DELETE",
			pendingRevokeURL:        "https://api.resend.com/api-keys/K1",
			pendingRevokeAuth:       revokeAuthBearer,
			pendingRevokeKeyID:      "K1",
			"operator_setting":      "kept",
			"another_operator_knob": "also kept",
		}
		if _, present := m[pendingRevokeStranded]; present {
			t.Fatal("ABORT: the fixture is not in the old shape")
		}

		st := pendingRevokeStatusFromMeta(m)
		if st == nil || !st.Outstanding || st.PredecessorKeyID != "K1" {
			t.Fatalf("an old-shape row stopped reporting its outstanding revoke: %+v", st)
		}
		if got := outstandingRevokeKeyIDs(m); len(got) != 1 || got[0] != "K1" {
			t.Fatalf("outstandingRevokeKeyIDs on an old-shape row = %v, want [K1]", got)
		}

		dischargePendingRevokeHead(m)
		for _, k := range pendingRevokeMarkerKeys {
			if _, left := m[k]; left {
				t.Errorf("%s survived the discharge of an old-shape row: %+v", k, m)
			}
		}
		if _, invented := m[pendingRevokeStranded]; invented {
			t.Errorf("discharging an old-shape row INVENTED a backlog key: %q", m[pendingRevokeStranded])
		}
		if pendingRevokeStatusFromMeta(m) != nil {
			t.Errorf("an old-shape row still reports outstanding after a clean discharge: %+v", m)
		}
		if m["operator_setting"] != "kept" || m["another_operator_knob"] != "also kept" {
			t.Errorf("the discharge clobbered the operator's own keys: %+v", m)
		}
	})

	t.Run("an old-shape alarm with no key identity still clears wholesale", func(t *testing.T) {
		// The honest limit of the fix, pinned so nobody is surprised by it: a row
		// written before this change holds the bare const, which does not encode
		// which key it is about, so there is nothing better available than the
		// pre-change behaviour. New alarms carry identity; old ones cannot.
		if got := withoutRevokeStillLiveKeys(revokeStillLiveMsg, []string{"anything"}); got != "" {
			t.Errorf("an identity-free alarm no longer clears: got %q", got)
		}
	})

	t.Run("a defer over an old-shape head queues it instead of evicting it", func(t *testing.T) {
		m := map[string]string{
			"key_id":            "K2",
			pendingRevokeMethod: "DELETE",
			pendingRevokeURL:    "https://api.resend.com/api-keys/K1",
			pendingRevokeAuth:   revokeAuthBearer,
			pendingRevokeKeyID:  "K1",
		}
		deferRevokeOldProviderKey(m, "DELETE", "https://api.resend.com/api-keys/K2", revokeAuthBearer, "K2")

		if m[pendingRevokeKeyID] != "K2" {
			t.Errorf("the head did not advance to the new predecessor: %+v", m)
		}
		backlog, malformed := parseStrandedRevokes(m)
		if malformed {
			t.Fatalf("backlog did not parse: %q", m[pendingRevokeStranded])
		}
		if len(backlog) != 1 || backlog[0].KeyID != "K1" ||
			backlog[0].URL != "https://api.resend.com/api-keys/K1" {
			t.Fatalf("the old-shape head was EVICTED rather than queued: %+v", backlog)
		}
	})
}

// TestDeferOverTheSameKeyOverwritesInPlaceRatherThanQueueing pins the case that
// must NOT queue.
//
// deferRevokeOldProviderKey is routinely handed a surviving marker set for the
// SAME key: a failed revoke leaves all four in place and the same predecessor is
// deferred again. Queueing there would grow an unbounded pile of duplicates of
// one key and make the alarm name it twice.
func TestDeferOverTheSameKeyOverwritesInPlaceRatherThanQueueing(t *testing.T) {
	m := map[string]string{}
	deferRevokeOldProviderKey(m, "DELETE", "https://api.resend.com/api-keys/K1", revokeAuthBearer, "K1")
	deferRevokeOldProviderKey(m, "DELETE", "https://api.resend.com/api-keys/K1", revokeAuthBearer, "K1")

	if _, queued := m[pendingRevokeStranded]; queued {
		t.Errorf("re-deferring the SAME key queued a duplicate: %q", m[pendingRevokeStranded])
	}
	if got := outstandingRevokeKeyIDs(m); len(got) != 1 || got[0] != "K1" {
		t.Errorf("outstandingRevokeKeyIDs = %v, want exactly [K1]", got)
	}

	t.Run("and a key already on the backlog is not queued twice", func(t *testing.T) {
		// K1 -> backlog, head K2. Now discharge K2 (K1 promotes back to head) and
		// defer K3 over it: K1 must appear once, not twice.
		mm := map[string]string{}
		deferRevokeOldProviderKey(mm, "DELETE", "https://api.resend.com/api-keys/K1", revokeAuthBearer, "K1")
		deferRevokeOldProviderKey(mm, "DELETE", "https://api.resend.com/api-keys/K2", revokeAuthBearer, "K2")
		deferRevokeOldProviderKey(mm, "DELETE", "https://api.resend.com/api-keys/K3", revokeAuthBearer, "K3")
		// Defer K2 again over the head K3, when K2 is already on the backlog.
		deferRevokeOldProviderKey(mm, "DELETE", "https://api.resend.com/api-keys/K4", revokeAuthBearer, "K4")

		ids := outstandingRevokeKeyIDs(mm)
		seen := map[string]int{}
		for _, id := range ids {
			seen[id]++
		}
		for id, n := range seen {
			if n > 1 {
				t.Errorf("%s appears %d times in %v", id, n, ids)
			}
		}
		if len(ids) != 4 {
			t.Errorf("outstandingRevokeKeyIDs = %v, want K1..K4 once each", ids)
		}
	})
}

// TestTheStrandedBacklogIsBoundedAndKeepsTheOldest pins the overflow direction.
//
// The backlog lives in an encrypted column no operator can prune by hand, so it
// must be bounded. When it is full the OLDEST entries are kept and the newest is
// refused, because the oldest stranded key is the one that has survived the most
// rotations unretried and is closest to being forgotten. The refusal is loud:
// it goes out through last_revoke_error, which downgrades the rotation to
// partial and alarms.
func TestTheStrandedBacklogIsBoundedAndKeepsTheOldest(t *testing.T) {
	m := map[string]string{}
	for i := 0; i <= maxStrandedRevokes+3; i++ {
		id := fmt.Sprintf("K%03d", i)
		deferRevokeOldProviderKey(m, "DELETE", "https://api.resend.com/api-keys/"+id, revokeAuthBearer, id)
	}
	backlog, malformed := parseStrandedRevokes(m)
	if malformed {
		t.Fatalf("backlog did not parse: %q", m[pendingRevokeStranded])
	}
	if len(backlog) != maxStrandedRevokes {
		t.Fatalf("backlog length %d, want the cap %d", len(backlog), maxStrandedRevokes)
	}
	if backlog[0].KeyID != "K000" {
		t.Errorf("the OLDEST stranded key was evicted (backlog starts at %q, want K000). "+
			"Evicting the oldest is the defect this whole change exists to remove.", backlog[0].KeyID)
	}
	if m["last_revoke_error"] == "" {
		t.Errorf("overflowing the backlog was SILENT; it must alarm so the operator is told a " +
			"predecessor's coordinates could not be preserved")
	}
}

// TestTheAlarmNeverCarriesAnythingButABoundedKeyID is the disclosure pin.
//
// revokeStillLiveMsg is static on purpose: the raw revoke error can embed the
// provider URL and the upstream response body, and last_rotation_error is
// API-visible. Appending key identity is safe ONLY because the ids are filtered
// through conservativeKeyIDPattern, the identical filter the predecessor_key_id
// API field already passes to the same readers. If that filter is ever dropped,
// this fires.
func TestTheAlarmNeverCarriesAnythingButABoundedKeyID(t *testing.T) {
	hostile := []string{
		"https://api.resend.com/api-keys/K1",
		"K1 (HTTP 503: {\"token\":\"re_leaked\"})",
		"../../etc/passwd",
		"K1 K2",
		"K1\nK2",
		"",
		strings.Repeat("K", 129),
	}
	for _, id := range hostile {
		got := revokeStillLiveMsgFor([]string{id})
		if got != revokeStillLiveMsg {
			t.Errorf("revokeStillLiveMsgFor(%q) = %q; an id that fails conservativeKeyIDPattern must be "+
				"DROPPED, leaving the bare const, never rendered into an API-visible column", id, got)
		}
	}
	// The positive control, so the test above cannot pass by the renderer being broken.
	if got := revokeStillLiveMsgFor([]string{"K1"}); got == revokeStillLiveMsg {
		t.Fatalf("ABORT: a legitimate id was dropped too, so the checks above prove nothing")
	}
}

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
	mu         sync.Mutex
	hits       []string
	code       int
	failSuffix string
}

func (s *historySink) setCode(c int) { s.mu.Lock(); s.code = c; s.mu.Unlock() }

// setFailSuffix makes ONE key permanently unrevokable while every other key
// succeeds. That is the ordinary shape of a stranded predecessor: the key is
// gone from the vendor's side, or its own delete is rejected, while the account
// is otherwise healthy.
//
// It replaces a fail-the-first-delete-only switch, whose whole purpose was to
// manufacture the interleaving the deleted cap+1 fixture needed. Failing one
// key needs no timing trick, which is exactly what lets the saturation fixture
// below reach the cap the way production reaches it.
func (s *historySink) setFailSuffix(v string) { s.mu.Lock(); s.failSuffix = v; s.mu.Unlock() }

func (s *historySink) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	code := s.code
	if r.Method == http.MethodDelete {
		if s.failSuffix != "" && strings.HasSuffix(r.URL.Path, s.failSuffix) {
			code = http.StatusServiceUnavailable
		}
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

// capSaturatedBacklogMeta seeds the SATURATION STATE THE WRITERS ACTUALLY
// PRODUCE: a surviving head plus a backlog sitting exactly on the cap.
//
// A FIXTURE MUST BE REACHABLE BY THE SYSTEM'S OWN WRITERS, NOT MERELY TOLERATED
// BY ITS READERS. This replaces a fixture that seeded maxStrandedRevokes+1
// entries and defended itself on reader tolerance: parseStrandedRevokes and
// dischargePendingRevokeHead do accept any length, and that is true and beside
// the point. The discriminator is the writers, and there are exactly two. The
// append at pushDisplacedHeadOntoBacklog sits past a len(backlog) >=
// maxStrandedRevokes guard, so its output is never longer than the cap; the
// promotion in dischargePendingRevokeHead writes backlog[1:], which strictly
// shrinks. All six persistence doors write maps derived from those two, the key
// is refused on both client write doors and redacted on read, and the cap and
// the key were introduced in the same commit, so no legacy row can carry a
// longer list either. Driving the real sweep 40 times with every revoke failing
// saturates at 32 and holds there forever.
//
// So the true saturation state is HEAD + 32 BACKLOG = 33 KEYS OUTSTANDING on one
// entry, which is what this seeds. A 33-entry backlog is a state only a test can
// construct, and at the largest genuinely reachable length the old fixture
// failed against correct source: its seed was the only thing holding it up.
//
// The head is K1 with its own revoke permanently failing, so the rotation's
// opening retry cannot discharge it and the backlog is still full when the mint
// defers K2 over it. That is the cap refusal in its reachable form.
func capSaturatedBacklogMeta(base string) string {
	backlog := make([]strandedRevoke, 0, maxStrandedRevokes)
	for i := 0; i < maxStrandedRevokes; i++ {
		id := fmt.Sprintf("S%03d", i)
		backlog = append(backlog, strandedRevoke{
			KeyID:  id,
			Method: "DELETE",
			URL:    base + "/keys/" + id,
			Auth:   revokeAuthBearer,
		})
	}
	encBacklog, err := json.Marshal(backlog)
	if err != nil {
		panic(err)
	}
	out, err := json.Marshal(map[string]string{
		"key_id":              "K2",
		pendingRevokeMethod:   "DELETE",
		pendingRevokeURL:      base + "/keys/K1",
		pendingRevokeAuth:     revokeAuthBearer,
		pendingRevokeKeyID:    "K1",
		pendingRevokeStranded: string(encBacklog),
	})
	if err != nil {
		panic(err)
	}
	return string(out)
}

// TestAtBacklogSaturationTheCapRefusalVetoesTheDefer is HIGH-1 end to end in a
// state the writers can reach. It is the round-2 review's
// TestLens1NaturalCapRefusalWithNoSeedOverTheCap, adopted verbatim in intent:
// backlog seeded to exactly the cap, head K1, and only K1's own revoke failing.
//
// The sequence the sweep runs on this row:
//
//	retryOutstandingRevoke   DELETE /keys/K1 -> 503, the head SURVIVES and the
//	                                           backlog is still on the cap
//	provider.Rotate          mints K3, defers K2 over the surviving head K1
//	                         -> the backlog is full, so the defer is REFUSED
//	revokeOldKeyAndPersistMeta DELETE /keys/K1 -> 503, the head is still K1
//
// Measured, base against the veto removed:
//
//	with the veto:    head="K1"   backlog=32  outstanding=33  sink=[503 K1 503 K1]
//	veto removed:     head="S000" backlog=31  outstanding=32  sink=[503 K1 200 K2]
//
// Without the veto the refused defer overwrites all four head markers anyway, so
// the rotation revokes K2 -- the key whose defer was REFUSED -- its discharge
// promotes S000 into the head, and K1 is evicted into nothing: live at the
// vendor, named in neither the head nor the backlog nor the alarm.
func TestAtBacklogSaturationTheCapRefusalVetoesTheDefer(t *testing.T) {
	h, queries, _, entryID, sink := revokeHistoryEnv(t, capSaturatedBacklogMeta)
	sink.setCode(http.StatusOK)
	sink.setFailSuffix("/keys/K1")

	RotateVaultKeys(h.db, queries, h)
	h.WaitForDelivery(5e9)

	meta, lastErr := revokeHistoryMeta(t, h, queries, entryID)
	backlog, malformed := parseStrandedRevokes(meta)
	outstanding := outstandingRevokeKeyIDs(meta)
	t.Logf("after rotation: last_rotation_error=%q head=%q backlog=%d outstanding=%d sink=%v",
		lastErr, meta[pendingRevokeKeyID], len(backlog), len(outstanding), sink.all())

	if malformed {
		t.Fatalf("the backlog did not parse: %q", meta[pendingRevokeStranded])
	}
	if sink.revokedOK("K1") {
		t.Fatalf("ABORT: the sink accepted a delete of K1, so the head was discharged, the backlog "+
			"dropped below the cap and no refusal ever happened. sink=%v", sink.all())
	}

	// The defer that could not be recorded must not have overwritten the head.
	if meta[pendingRevokeKeyID] != "K1" {
		t.Errorf("the head names %q, want K1.\n"+
			"At the cap the refusal must VETO the defer. If it does not, the head is overwritten with "+
			"K2, the rotation revokes K2 instead, that success promotes S000 into the head, and K1 -- "+
			"whose coordinates were the only record of how to kill it -- is in neither the head nor the "+
			"backlog while still valid at the vendor. head=%q backlog=%d sink=%v",
			meta[pendingRevokeKeyID], meta[pendingRevokeKeyID], len(backlog), sink.all())
	}
	for _, hit := range sink.all() {
		if strings.HasSuffix(hit, "/keys/K2") {
			t.Errorf("the rotation revoked K2 (%v). K2's defer was REFUSED, so it was never recorded "+
				"and must never have been targeted; a hit on it means the head was overwritten.",
				sink.all())
		}
	}

	// Nothing was dropped on the way through. The refusal costs exactly the key
	// it refused: the head plus the full backlog are all still named.
	if len(outstanding) != maxStrandedRevokes+1 {
		t.Errorf("the row names %d outstanding keys, want %d (K1 plus S000..S%03d).\n"+
			"outstanding=%v", len(outstanding), maxStrandedRevokes+1, maxStrandedRevokes-1, outstanding)
	}
	named := strings.Join(outstanding, ",")
	if !strings.Contains(named, "K1") {
		t.Errorf("K1 is no longer named anywhere: outstanding=%v", outstanding)
	}
	for i := 0; i < maxStrandedRevokes; i++ {
		id := fmt.Sprintf("S%03d", i)
		if !strings.Contains(named, id) {
			t.Errorf("%s is no longer named anywhere: outstanding=%v", id, outstanding)
		}
	}

	// The rotation must not report clean. Its own revoke failed, and the refused
	// defer said so through last_revoke_error as well.
	if lastErr == "" {
		t.Errorf("last_rotation_error is empty on the re-read row; a key is live at the vendor. sink=%v",
			sink.all())
	}
	if !strings.Contains(lastErr, revokeStillLiveMsg) {
		t.Errorf("last_rotation_error is %q, want it to carry the still-live alarm", lastErr)
	}
}

// unnameableIDStrandedMeta seeds a head with a live backlog behind it and a
// provider key id that deferRevokeOldProviderKey will refuse to queue.
//
// "K2/../evil" fails revokeTargetIsNameable (path.Clean changes the path), which
// is the OTHER writer of the pre-attempt last_revoke_error. It is here because
// it isolates HIGH-2 with no cap involved at all: one refusal at mint time, one
// successful revoke moments later, nothing else in play.
func unnameableIDStrandedMeta(base string) string {
	encBacklog, err := json.Marshal([]strandedRevoke{{
		KeyID: "B1", Method: "DELETE", URL: base + "/keys/B1", Auth: revokeAuthBearer,
	}})
	if err != nil {
		panic(err)
	}
	out, err := json.Marshal(map[string]string{
		"key_id":              "K2/../evil",
		pendingRevokeMethod:   "DELETE",
		pendingRevokeURL:      base + "/keys/K1",
		pendingRevokeAuth:     revokeAuthBearer,
		pendingRevokeKeyID:    "K1",
		pendingRevokeStranded: string(encBacklog),
	})
	if err != nil {
		panic(err)
	}
	return string(out)
}

// TestARefusedDeferSurvivesARevokeThatSucceedsInTheSameRotation is HIGH-2 on its
// own, with no backlog cap anywhere near it.
//
// The sweep runs: retry K1 -> 200 (head discharged, B1 promoted), mint refuses
// to queue "K2/../evil" and says so through last_revoke_error, then the deferred
// revoke of the promoted head B1 -> 200. That last 200 used to delete the
// refusal, which is the only record that a key this server will not name is live
// at the vendor.
func TestARefusedDeferSurvivesARevokeThatSucceedsInTheSameRotation(t *testing.T) {
	h, queries, _, entryID, sink := revokeHistoryEnv(t, unnameableIDStrandedMeta)
	sink.setCode(http.StatusOK)

	RotateVaultKeys(h.db, queries, h)
	h.WaitForDelivery(5e9)

	meta, lastErr := revokeHistoryMeta(t, h, queries, entryID)
	t.Logf("after rotation: last_rotation_error=%q head=%q backlog=%q sink=%v",
		lastErr, meta[pendingRevokeKeyID], meta[pendingRevokeStranded], sink.all())

	if !sink.revokedOK("K1") || !sink.revokedOK("B1") {
		t.Fatalf("ABORT: the rotation did not settle both K1 and B1, so the successful-revoke half of "+
			"this test never happened. sink=%v", sink.all())
	}
	if lastErr == "" {
		t.Fatalf("last_rotation_error is empty on the re-read row.\n"+
			"The mint refused to queue a revoke for an unnameable predecessor and recorded that in "+
			"last_revoke_error. The revoke that succeeded moments later deleted it, so the rotation "+
			"reports clean while a key nothing in the product can name is still live at the vendor. "+
			"sink=%v", sink.all())
	}
	if !strings.Contains(lastErr, revokeStillLiveMsg) {
		t.Errorf("last_rotation_error is %q, want it to carry the still-live alarm", lastErr)
	}
}

// TestTheManualRotatePathAlsoKeepsARefusalThroughASuccessfulRevoke is the
// MANUAL TWIN of the test above, and it exists because the two paths are
// protected by DIFFERENT MECHANISMS.
//
// The sweep is protected by performPendingRevoke's carry: it lifts any
// pre-attempt last_revoke_error across its own attempt so a same-rotation
// success cannot delete it. That carry is a NO-OP on the manual path.
// h.Rotate lifts the flag out of provider_meta and deletes it BEFORE
// revokeOldKeyAndPersistMeta is ever called, so `carried` is always "" by the
// time performPendingRevoke sees the map. What saves the manual path instead is
// an older, unrelated mechanism: the local pendingRevokeWarn plus the
// `if warn != ""` guard on the revokeOldKeyAndPersistMeta result, which keeps
// the mint-time refusal when this rotation's own revoke SUCCEEDS and returns "".
//
// Two mechanisms doing one job, and until this test both regression tests for
// the refusal drove RotateVaultKeys only. Ablating that guard to the sweep's
// plain assignment -- the shape sitting beside it in the same diff, and the
// obvious thing a future simplification reaches for -- left the entire package
// green. An operator would then click Rotate, get a 200 and a clean success with
// last_rotation_error NULL, while a key this server refused to name is live at
// the provider.
//
// The discriminating case is a refusal at mint time followed by a revoke that
// SUCCEEDS, which is why every delete here returns 200: with the guard the
// refusal survives, without it revokeWarn is overwritten with "" and the alarm
// is never armed. The opening retry must also succeed, or its own stale-retry
// warning would arm the alarm by itself and mask the guard entirely.
func TestTheManualRotatePathAlsoKeepsARefusalThroughASuccessfulRevoke(t *testing.T) {
	h, queries, owner, entryID, sink := revokeHistoryEnv(t, unnameableIDStrandedMeta)
	sink.setCode(http.StatusOK)

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/rotate",
		owner, "user", entryID, `{"password":"`+rotationTestPassword+`"}`))
	h.WaitForDelivery(5e9)
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the manual rotation itself failed with %d, nothing below is being tested: %s",
			rec.Code, rec.Body.String())
	}

	meta, lastErr := revokeHistoryMeta(t, h, queries, entryID)
	t.Logf("MANUAL: last_rotation_error=%q head=%q backlog=%q sink=%v",
		lastErr, meta[pendingRevokeKeyID], meta[pendingRevokeStranded], sink.all())

	if !sink.revokedOK("K1") || !sink.revokedOK("B1") {
		t.Fatalf("ABORT: the manual rotation did not settle both K1 and B1, so the successful-revoke "+
			"half of this test never happened and the guard is not being exercised. sink=%v", sink.all())
	}
	if lastErr == "" {
		t.Fatalf("HIGH-2 DEFEATED ON MANUAL: last_rotation_error is empty on the re-read row.\n"+
			"The mint refused to queue a revoke for an unnameable predecessor and recorded that in "+
			"last_revoke_error, which h.Rotate lifted into pendingRevokeWarn. The revoke that succeeded "+
			"moments later returned \"\", and without the `if warn != \"\"` guard that empty string "+
			"overwrites the refusal. The operator sees a 200 and a clean rotation while a key this "+
			"server will not name is live at the vendor. sink=%v", sink.all())
	}
	if !strings.Contains(lastErr, revokeStillLiveMsg) {
		t.Errorf("last_rotation_error is %q, want it to carry the still-live alarm", lastErr)
	}
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
		// THE FIXTURE HAS TO RE-DEFER A KEY THAT IS ALREADY ON THE BACKLOG, and
		// the previous version did not: its comment said it re-deferred K2 while
		// the code deferred a fourth distinct key K4. Four distinct keys never
		// put a duplicate in front of the dedup loop, so deleting that loop left
		// the whole suite green.
		//
		// The reachable sequence is defer X, defer Y, re-defer X, defer Z:
		//   K1        -> head K1
		//   K2        -> backlog [K1], head K2
		//   K1 again  -> backlog [K1 K2], head K1  (the head now DUPLICATES a
		//                backlog entry, which is the only way the loop is reached)
		//   K3        -> the loop sees K1 already queued and refuses to queue it
		//                a second time; backlog stays [K1 K2], head K3.
		// Without the loop that last defer bakes [K1 K2 K1] in permanently.
		mm := map[string]string{}
		deferRevokeOldProviderKey(mm, "DELETE", "https://api.resend.com/api-keys/K1", revokeAuthBearer, "K1")
		deferRevokeOldProviderKey(mm, "DELETE", "https://api.resend.com/api-keys/K2", revokeAuthBearer, "K2")
		deferRevokeOldProviderKey(mm, "DELETE", "https://api.resend.com/api-keys/K1", revokeAuthBearer, "K1")
		deferRevokeOldProviderKey(mm, "DELETE", "https://api.resend.com/api-keys/K3", revokeAuthBearer, "K3")

		ids := outstandingRevokeKeyIDs(mm)
		seen := map[string]int{}
		for _, id := range ids {
			seen[id]++
		}
		for id, n := range seen {
			if n > 1 {
				t.Errorf("%s appears %d times in %v; the dedup loop in pushDisplacedHeadOntoBacklog "+
					"did not run, so a re-deferred key is queued twice and stays queued forever", id, n, ids)
			}
		}
		if len(ids) != 3 {
			t.Errorf("outstandingRevokeKeyIDs = %v, want K1..K3 once each", ids)
		}
	})
}

// TestTheStrandedBacklogIsBoundedAndKeepsTheOldest pins the overflow direction.
//
// The backlog lives in an encrypted column no operator can prune by hand, so it
// must be bounded. When it is full the OLDEST entries are kept and the newest
// DEFER is refused, because the oldest stranded key is the one that has survived
// the most rotations unretried and is closest to being forgotten.
//
// THE REFUSAL IS A VETO, and asserting that is the whole reason this test was
// rewritten. The previous version drove the same 36 defers and asserted the
// backlog length and backlog[0] -- both of which hold whether or not the refusal
// vetoes anything -- and asserted NOTHING about the three keys it drops. Under
// the version it passed against, the refusal was a log line: the caller
// overwrote the head regardless, so the displaced key was in neither the head
// nor the backlog and the test could not see it go.
func TestTheStrandedBacklogIsBoundedAndKeepsTheOldest(t *testing.T) {
	m := map[string]string{}
	const last = maxStrandedRevokes + 3
	for i := 0; i <= last; i++ {
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
			"key could not be queued for revoke")
	}

	// THE FATE OF THE DROPPED KEYS. The cap is reached while deferring K033, so
	// K033, K034 and K035 are refused. The key that was on the head when the
	// first refusal landed is K032, and it must STILL be there: the refusal
	// vetoes the defer, so nothing overwrites it.
	survivingHead := fmt.Sprintf("K%03d", maxStrandedRevokes)
	if got := m[pendingRevokeKeyID]; got != survivingHead {
		t.Errorf("the head names %q, want %q.\n"+
			"At the cap the refusal must VETO the defer, leaving the surviving head in place. A head "+
			"naming a later key means the refusal was a log line and %s's coordinates were destroyed "+
			"by the very defer that could not preserve them: neither head nor backlog, and live at the "+
			"vendor. backlog=%q", got, survivingHead, survivingHead, m[pendingRevokeStranded])
	}
	if got := m[pendingRevokeURL]; !strings.HasSuffix(got, "/"+survivingHead) {
		t.Errorf("the head URL is %q, want it to still name %s", got, survivingHead)
	}

	// And the refused keys are recorded NOWHERE as coordinates, which is the
	// honest state: the refusal is the record, and it is loud.
	outstanding := strings.Join(outstandingRevokeKeyIDs(m), ",")
	for i := maxStrandedRevokes + 1; i <= last; i++ {
		id := fmt.Sprintf("K%03d", i)
		if strings.Contains(outstanding, id) {
			t.Errorf("%s was queued despite the cap; outstanding=%v", id, outstanding)
		}
	}
	// Everything up to and including the surviving head IS still named, so the
	// refusal cost exactly the keys it refused and nothing else.
	for i := 0; i <= maxStrandedRevokes; i++ {
		id := fmt.Sprintf("K%03d", i)
		if !strings.Contains(outstanding, id) {
			t.Errorf("%s is no longer named anywhere; the refusal dropped a key it had already "+
				"recorded. outstanding=%v", id, outstanding)
		}
	}
	if !strings.Contains(m["last_revoke_error"], "not queued for revoke") {
		t.Errorf("the refusal does not say the key went unqueued: %q", m["last_revoke_error"])
	}
}

// TestABacklogEntryWithNoRecordedIDIsStillNameableToTheAlarm covers the shape
// that made the alarm go silent on a LIVE path.
//
// deferRevokeOldProviderKey DELETES pending_revoke_key_id whenever the id fails
// conservativeKeyIDPattern, and that id is provider_meta["key_id"], which is
// operator-writable and validated nowhere. The head still renders an id, because
// pendingRevokeStatusFromMeta falls back to path.Base of the marker URL. The
// backlog used to copy the RAW recorded id, so the same key became anonymous the
// moment it was displaced, outstandingRevokeKeyIDs skipped it, and settling the
// keys that could be named cleared the whole alarm while it was still live.
func TestABacklogEntryWithNoRecordedIDIsStillNameableToTheAlarm(t *testing.T) {
	m := map[string]string{}
	// "v2/K1" is an ordinary operator-supplied provider_meta["key_id"]. It fails
	// conservativeKeyIDPattern on the slash, so the recorded marker id is
	// DELETED, but it passes revokeTargetIsNameable (the path does not climb) so
	// the revoke is queued and path.Base still names K1. Nothing validates
	// provider_meta values, so this shape needs no corruption to arise.
	deferRevokeOldProviderKey(m, "DELETE", "https://api.resend.com/api-keys/v2/K1", revokeAuthBearer, "v2/K1")
	if _, recorded := m[pendingRevokeKeyID]; recorded {
		t.Fatalf("ABORT: the id was recorded after all, so this fixture is not the shape under test: %q",
			m[pendingRevokeKeyID])
	}
	if st := pendingRevokeStatusFromMeta(m); st == nil || st.PredecessorKeyID != "K1" {
		t.Fatalf("ABORT: the head does not render K1, so nothing below is being tested: %+v", st)
	}

	// Displace it. The key is now on the backlog and the head names K2.
	deferRevokeOldProviderKey(m, "DELETE", "https://api.resend.com/api-keys/K2", revokeAuthBearer, "K2")

	backlog, malformed := parseStrandedRevokes(m)
	if malformed || len(backlog) != 1 {
		t.Fatalf("backlog is %+v (malformed=%v), want one entry", backlog, malformed)
	}
	if backlog[0].KeyID != "K1" {
		t.Errorf("the queued entry carries KeyID %q, want %q derived the way the chip derives it",
			backlog[0].KeyID, "K1")
	}

	ids := outstandingRevokeKeyIDs(m)
	if len(ids) != 2 || ids[0] != "K2" || ids[1] != "K1" {
		t.Fatalf("outstandingRevokeKeyIDs = %v, want [K2 K1].\n"+
			"A backlog entry with no id is INVISIBLE to the alarm: settling K2 would clear it while K1 "+
			"is still authenticating at the vendor.", ids)
	}

	// And the whole point: settling K2 must leave an alarm that still names K1.
	armed := revokeStillLiveMsgFor(ids)
	if got := withoutRevokeStillLiveKeys(armed, []string{"K2"}); got != revokeStillLiveMsgFor([]string{"K1"}) {
		t.Errorf("settling K2 left the alarm as %q; K1 is unnamed and therefore unclearable and "+
			"unreportable", got)
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

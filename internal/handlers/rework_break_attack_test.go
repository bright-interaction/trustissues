package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// ATTACKS AGAINST THE OWNERSHIP REPAIR ROUTE AS IT STANDS ON THIS BRANCH.
//
// The claim under test is that three defects in the repair route were fixed.
// Every test here drives the real handler over a real SQLite database opened by
// database.Connect, which is the production pool (SetMaxOpenConns(10)).
//
// Each test carries a premise guard: it first proves the fixture CAN express the
// defect, then measures whether the defect is present. A test whose fixture
// cannot express the bug is worse than no test.

// ── 1. THE POOL ────────────────────────────────────────────────────────────────

// ownershipProbeResult is one drive of the repair page under concurrency.
type ownershipProbeResult struct {
	// unrelatedErr is the error an ORDINARY query on the same pool got while the
	// repair page was in flight. Non-nil means one admin-only route took the
	// database away from the whole process.
	unrelatedErr error
	// unrelatedWait is how long that ordinary query took to answer.
	unrelatedWait time.Duration
	// codes is the status each concurrent repair-page request produced.
	codes []int
	// elapsed is how long the whole fan-out took.
	elapsed time.Duration
}

// driveOwnershipPage fires n concurrent GET /api/admin/vault/ownership and, once
// they are all in flight, asks the same pool an unrelated question with its own
// short deadline.
func driveOwnershipPage(t *testing.T, h *VaultHandler, admin string, n int,
	reqBudget, probeBudget time.Duration) ownershipProbeResult {

	t.Helper()
	res := ownershipProbeResult{codes: make([]int, n)}
	start := time.Now()

	var wg sync.WaitGroup
	begin := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-begin
			r := vaultAuthzRequest(http.MethodGet, "/api/admin/vault/ownership", admin, "admin", "", "")
			ctx, cancel := context.WithTimeout(r.Context(), reqBudget)
			defer cancel()
			rec := httptest.NewRecorder()
			h.ListUnownedEntries(rec, r.WithContext(ctx))
			res.codes[i] = rec.Code
		}(i)
	}
	close(begin)

	// Give every goroutine time to reach its cursor before asking.
	time.Sleep(400 * time.Millisecond)
	probeCtx, probeCancel := context.WithTimeout(context.Background(), probeBudget)
	defer probeCancel()
	probeStart := time.Now()
	var users int
	res.unrelatedErr = h.db.QueryRowContext(probeCtx, `SELECT COUNT(*) FROM users`).Scan(&users)
	res.unrelatedWait = time.Since(probeStart)

	wg.Wait()
	res.elapsed = time.Since(start)
	return res
}

// TestTheRepairPageStarvesTheWholePoolAboveItsSize drives the admin repair page
// above SetMaxOpenConns(10) and asks whether an ordinary, unrelated query on the
// same process can still be answered.
//
// PREMISE GUARD: the identical fan-out is run first against a fixture whose
// secret_owner_user_id column is EMPTY, so expiredOwnerEntries' cursor selects
// nothing and no query is issued from inside a cursor. That ablation does MORE
// total queries (every row lands in the withheld class and gets its own
// CountRecordedAdoptionsForEntry), so a difference cannot be "fewer queries".
func TestTheRepairPageStarvesTheWholePoolAboveItsSize(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	admin := mustUser(t, queries, "pool-admin@example.com", "admin", "admin-login-password")
	victim := mustUser(t, queries, "pool-victim@example.com", "user", "victim-login-password")
	mustCollection(t, queries, "coll-pool", victim, map[string]string{victim: collRoleManager})

	const entries = 80
	for i := 0; i < entries; i++ {
		id := fmt.Sprintf("entry-pool-%03d", i)
		mustEntry(t, h, queries, id, victim, fmt.Sprintf("pool-key-%03d", i), "sk_live_POOL")
		placeInCollection(t, queries, id, "coll-pool")
	}
	access, err := queries.GetVaultEntryAccess(ctx, "entry-pool-000")
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if access.SecretOwnerUserID != victim {
		t.Fatalf("ABORT: creation did not stamp a recorded owner (%q); the cursor would select nothing "+
			"and this test could not express the defect", access.SecretOwnerUserID)
	}

	// ── the ablation: the SAME rows with no recorded owner ──────────────────
	if _, err := h.db.Exec(`UPDATE vault_entries SET secret_owner_user_id = ''`); err != nil {
		t.Fatalf("ablate the owner column: %v", err)
	}
	ablated := driveOwnershipPage(t, h, admin, 20, 15*time.Second, 3*time.Second)
	t.Logf("ABLATION (no cursor rows): 20 concurrent finished in %v, unrelated SELECT answered in %v (err=%v)",
		ablated.elapsed, ablated.unrelatedWait, ablated.unrelatedErr)
	if ablated.unrelatedErr != nil {
		t.Fatalf("ABORT: the fixture starves the pool even with an EMPTY cursor, so this test cannot "+
			"attribute starvation to the nested query: %v", ablated.unrelatedErr)
	}

	// ── the real thing ─────────────────────────────────────────────────────
	if _, err := h.db.Exec(`UPDATE vault_entries SET secret_owner_user_id = user_id`); err != nil {
		t.Fatalf("restore the owner column: %v", err)
	}
	// Take the owner's manage away so every row is second-class and the loop
	// runs to the end. This is one manager-gated call in the product.
	if _, err := h.db.Exec(`DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?`,
		"coll-pool", victim); err != nil {
		t.Fatalf("strand the rows: %v", err)
	}
	live, lErr := h.recordedOwnerMayDirect(ctx, "entry-pool-000")
	if lErr != nil {
		t.Fatalf("liveness: %v", lErr)
	}
	if live {
		t.Fatal("ABORT: the recorded owner still directs the entry, so expiredOwnerEntries would " +
			"return early and the nested query would not run on every row")
	}

	loaded := driveOwnershipPage(t, h, admin, 20, 15*time.Second, 3*time.Second)
	t.Logf("LOADED (cursor over %d rows, one authority query per row): 20 concurrent finished in %v, "+
		"unrelated SELECT waited %v (err=%v), codes=%v",
		entries, loaded.elapsed, loaded.unrelatedWait, loaded.unrelatedErr, loaded.codes)

	if loaded.unrelatedErr != nil {
		t.Errorf("CONFIRMED: with %d concurrent GET /api/admin/vault/ownership against a pool of 10, an "+
			"unrelated `SELECT COUNT(*) FROM users` on the same *sql.DB could not be answered in %v (%v). "+
			"expiredOwnerEntries holds a pooled connection open in `for rows.Next()` "+
			"(vault_ownership_repair.go:157) and issues recordedOwnerMayDirect inside it "+
			"(vault_ownership_repair.go:185), so N such requests hold all N connections and each waits "+
			"for one only another of them could release. The ablation above, same rows and more queries, "+
			"answered the same probe in %v",
			20, 3*time.Second, loaded.unrelatedErr, ablated.unrelatedWait)
	}
}

// ── 2. A NEW REVERSIBLE STATE: THE OWNER'S INSTANCE ROLE ───────────────────────

// TestDemotingAnAdminMakesTheirLiveEntriesClaimable finds a reversible state
// that is NOT a collection membership change and NOT a disabled account.
//
// An instance admin creates an entry inside a collection they are not a member
// of. grantFor row 3 gives them manage, mayDirectSecretEgress short-circuits on
// isAdmin, so the recorded owner is live and the row is invisible to the repair
// page. Demote them to `user` (an ordinary, reversible role change another admin
// makes from Settings -> Users) and every one of those entries becomes
// second-class: grantFor falls through to row 7, which is read-only, so
// mayConfigureDelivery says no.
//
// The repair page then tells the operator the owner "was removed from the
// collection it lives in", which never happened.
func TestDemotingAnAdminMakesTheirLiveEntriesClaimable(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	victim := mustUser(t, queries, "role-victim@example.com", "admin", "victim-login-password")
	other := mustUser(t, queries, "role-other@example.com", "user", "other-login-password")
	claimer := mustUser(t, queries, "role-claimer@example.com", "admin", "claimer-login-password")
	mustCollection(t, queries, "coll-role", other, map[string]string{other: collRoleManager})
	mustEntry(t, h, queries, "entry-role", victim, "shared-ops-key", "sk_live_ROLE")
	placeInCollection(t, queries, "entry-role", "coll-role")

	// The admin owner sets their own ceiling through the ordinary route.
	dests, _ := json.Marshal(map[string]any{"destination_patterns": []string{"api.partner.example/*"}})
	put := httptest.NewRecorder()
	h.Update(put, vaultAuthzRequest(http.MethodPut, "/api/vault/entry-role", victim, "admin",
		"entry-role", string(dests)))
	if put.Code != http.StatusOK {
		t.Fatalf("ABORT: the owner could not set their own ceiling (%d: %s)", put.Code, put.Body.String())
	}

	access, err := queries.GetVaultEntryAccess(ctx, "entry-role")
	if err != nil {
		t.Fatalf("read access: %v", err)
	}
	if access.SecretOwnerUserID != victim {
		t.Fatalf("ABORT: the victim is not the recorded owner (%q)", access.SecretOwnerUserID)
	}
	// PREMISE GUARD: before the demotion the row must be live, unlisted and
	// unclaimable. Without this the test could pass on a fixture that was
	// already broken.
	live, _ := h.recordedOwnerMayDirect(ctx, "entry-role")
	if !live {
		t.Fatal("ABORT: the owner cannot direct the entry before the demotion, so the demotion is not " +
			"what this test would be measuring")
	}
	pre := httptest.NewRecorder()
	h.ClaimSecretOwnership(pre, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/entry-role/ownership/claim", claimer, "admin", "entry-role", ""))
	if pre.Code != http.StatusConflict {
		t.Fatalf("ABORT: the route did not refuse a live ownership before the demotion (%d: %s)",
			pre.Code, pre.Body.String())
	}

	// THE ONE ORDINARY CALL: a role change on the users row. Reversible.
	if _, err := h.db.Exec(`UPDATE users SET role = 'user' WHERE id = ?`, victim); err != nil {
		t.Fatalf("demote the owner: %v", err)
	}

	list := httptest.NewRecorder()
	h.ListUnownedEntries(list, vaultAuthzRequest(http.MethodGet, "/api/admin/vault/ownership",
		claimer, "admin", "", ""))
	var report ownershipReport
	if err := json.Unmarshal(list.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode the repair page (%s): %v", list.Body.String(), err)
	}
	var listed *unownedEntry
	for i := range report.Entries {
		if report.Entries[i].ID == "entry-role" {
			listed = &report.Entries[i]
		}
	}
	if listed == nil {
		t.Skip("the demoted admin's entry is not listed; nothing further to probe")
	}
	t.Logf("listed after the demotion: why=%q collection_id=%q recorded_owner=%q adoption_recorded=%v",
		listed.Why, listed.CollectionID, listed.RecordedOwnerUserID, listed.AdoptionRecorded)
	if strings.Contains(listed.Why, "removed from the collection it lives in") {
		t.Errorf("THE OPERATOR IS TOLD A FALSE CAUSE: nobody touched collection %q. The owner's "+
			"INSTANCE ROLE changed from admin to user, which is reversible and routine, and the page "+
			"asserts a manager stranded the row", listed.CollectionID)
	}

	claim := httptest.NewRecorder()
	h.ClaimSecretOwnership(claim, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/entry-role/ownership/claim", claimer, "admin", "entry-role", ""))
	t.Logf("claim after the demotion -> %d %s", claim.Code, strings.TrimSpace(claim.Body.String()))
	if claim.Code != http.StatusOK {
		return
	}

	// Undo the demotion. The role comes back; nothing else does.
	if _, err := h.db.Exec(`UPDATE users SET role = 'admin' WHERE id = ?`, victim); err != nil {
		t.Fatalf("re-promote the owner: %v", err)
	}
	after, _ := queries.GetVaultEntryAccess(ctx, "entry-role")
	meta, _ := queries.GetVaultEntryMeta(ctx, "entry-role")
	t.Logf("after re-promotion: owner=%q custodian=%q destination_patterns=%q",
		after.SecretOwnerUserID, after.UserID, meta.DestinationPatterns)
	if after.SecretOwnerUserID != victim {
		t.Errorf("A REVERSIBLE ROLE CHANGE COST A LIVE OWNERSHIP PERMANENTLY: entry-role was owned by "+
			"%q, who was demoted to `user` for a while. The row is now owned by %q, held by %q, and the "+
			"ceiling its owner configured is %q. Restoring the role restores none of it and there is no "+
			"un-claim route", victim, after.SecretOwnerUserID, after.UserID, meta.DestinationPatterns)
	}
}

// ── 3. A MANAGER, THROUGH PRODUCT ROUTES ONLY ─────────────────────────────────

// TestAManagerStillCausesIrreversibleLossThroughProductRoutesAlone drives the
// whole thing over HTTP handlers: no raw UPDATE anywhere on the attacker's side.
// A collection manager demotes a colleague to viewer with one ordinary call.
func TestAManagerStillCausesIrreversibleLossThroughProductRoutesAlone(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	coll := NewCollectionHandler(queries, h)
	ctx := context.Background()

	victim := mustUser(t, queries, "prod-victim@example.com", "user", "victim-login-password")
	manager := mustUser(t, queries, "prod-manager@example.com", "user", "manager-login-password")
	admin := mustUser(t, queries, "prod-admin@example.com", "admin", "admin-login-password")
	mustCollection(t, queries, "coll-prod", victim, map[string]string{
		victim: collRoleManager, manager: collRoleManager,
	})
	mustEntry(t, h, queries, "entry-prod", victim, "prod-team-key", "sk_live_PROD")
	placeInCollection(t, queries, "entry-prod", "coll-prod")

	dests, _ := json.Marshal(map[string]any{"destination_patterns": []string{"api.partner.example/*"}})
	put := httptest.NewRecorder()
	h.Update(put, vaultAuthzRequest(http.MethodPut, "/api/vault/entry-prod", victim, "user",
		"entry-prod", string(dests)))
	if put.Code != http.StatusOK {
		t.Fatalf("ABORT: the owner could not set their own ceiling (%d: %s)", put.Code, put.Body.String())
	}
	live, _ := h.recordedOwnerMayDirect(ctx, "entry-prod")
	if !live {
		t.Fatal("ABORT: the owner is already unable to direct the entry")
	}

	// THE MANAGER'S ONE CALL: POST /api/collections/coll-prod/members, role
	// viewer. The doc on AddCollectionMember says a role change never revokes an
	// acceptance, so the victim stays an ACCEPTED member. They just lose manage.
	body := `{"email":"prod-victim@example.com","role":"viewer"}`
	demote := httptest.NewRecorder()
	coll.AddMember(demote, collectionRequest(http.MethodPost, "/api/collections/coll-prod/members",
		manager, "user", "coll-prod", body))
	t.Logf("manager demotes the owner to viewer -> %d %s", demote.Code, strings.TrimSpace(demote.Body.String()))
	if demote.Code != http.StatusOK && demote.Code != http.StatusCreated && demote.Code != http.StatusNoContent {
		t.Fatalf("ABORT: the demotion call did not succeed (%d: %s)", demote.Code, demote.Body.String())
	}

	stillMember := true
	if _, err := queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: "coll-prod", UserID: victim,
	}); err != nil {
		stillMember = false
	}
	live, _ = h.recordedOwnerMayDirect(ctx, "entry-prod")
	t.Logf("after the demotion: victim is still an accepted member = %v, recordedOwnerMayDirect = %v",
		stillMember, live)
	if live {
		t.Skip("the demotion did not strand the entry; nothing further to probe")
	}

	list := httptest.NewRecorder()
	h.ListUnownedEntries(list, vaultAuthzRequest(http.MethodGet, "/api/admin/vault/ownership",
		admin, "admin", "", ""))
	var report ownershipReport
	_ = json.Unmarshal(list.Body.Bytes(), &report)
	for _, e := range report.Entries {
		if e.ID != "entry-prod" {
			continue
		}
		if stillMember && strings.Contains(e.Why, "removed from the collection it lives in") {
			t.Errorf("THE OPERATOR IS TOLD A FALSE CAUSE: %q is still an ACCEPTED member of %q. They "+
				"were demoted to viewer. The page says they were removed", victim, "coll-prod")
		}
	}

	claim := httptest.NewRecorder()
	h.ClaimSecretOwnership(claim, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/entry-prod/ownership/claim", admin, "admin", "entry-prod", ""))
	t.Logf("admin claim -> %d %s", claim.Code, strings.TrimSpace(claim.Body.String()))
	if claim.Code != http.StatusOK {
		return
	}

	// The manager puts the role back. One call, same route.
	restore := httptest.NewRecorder()
	coll.AddMember(restore, collectionRequest(http.MethodPost, "/api/collections/coll-prod/members",
		manager, "user", "coll-prod", `{"email":"prod-victim@example.com","role":"manager"}`))
	t.Logf("manager restores the role -> %d", restore.Code)

	after, _ := queries.GetVaultEntryAccess(ctx, "entry-prod")
	meta, _ := queries.GetVaultEntryMeta(ctx, "entry-prod")
	t.Logf("after the restore: owner=%q custodian=%q destination_patterns=%q",
		after.SecretOwnerUserID, after.UserID, meta.DestinationPatterns)
	if after.SecretOwnerUserID != victim {
		t.Errorf("A NON-ADMIN CONVERTED A REVERSIBLE DEMOTION INTO PERMANENT LOSS, using only "+
			"POST /api/collections/{id}/members twice: the owner is now %q, the custodian is %q, and "+
			"the ceiling %q the victim configured is gone. The role came back; the ownership did not",
			after.SecretOwnerUserID, after.UserID, meta.DestinationPatterns)
	}
}

// ── 4. WHAT THE DISARM DOES NOT TOUCH ─────────────────────────────────────────

// TestWhatTheClaimLeavesArmedOnTheRow measures the disarm's coverage against
// every host-choosing column ownerRecordedDestinations reads, not just the two
// the disarm knows about.
func TestWhatTheClaimLeavesArmedOnTheRow(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	victim := mustUser(t, queries, "leave-victim@example.com", "user", "victim-login-password")
	attacker := mustUser(t, queries, "leave-attacker@example.com", "user", "attacker-login-password")
	admin := mustUser(t, queries, "leave-admin@example.com", "admin", "admin-login-password")
	mustCollection(t, queries, "coll-leave", victim, map[string]string{
		victim: collRoleManager, attacker: collRoleManager,
	})
	mustEntry(t, h, queries, "entry-leave", victim, "leave-key", "sk_live_LEAVE")
	placeInCollection(t, queries, "entry-leave", "coll-leave")

	// The attacker plants everything a holder of this row can plant.
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["collector.attacker.example/*"]`, ID: "entry-leave",
	}); err != nil {
		t.Fatalf("plant the ceiling: %v", err)
	}
	forceProviderConfig(t, h, "entry-leave", "forgejo", `{"instance":"https://forge.attacker.example"}`)
	planted, _ := json.Marshal([]RotationTarget{{
		Type:         "webhook",
		WebhookURL:   "https://hook.attacker.example/collect",
		ConfiguredBy: attacker,
	}})
	encTargets, encErr := h.encryptColumn(string(planted))
	if encErr != nil {
		t.Fatalf("encrypt the planted target: %v", encErr)
	}
	if err := setRotationTargetsFixture(t, queries, vaultegress.RotationTargetsParams{
		RotationTargets: toNullString(encTargets), ID: "entry-leave",
	}); err != nil {
		t.Fatalf("plant the rotation target: %v", err)
	}

	clearSecretOwnerForTest(t, h, "entry-leave")
	before, err := h.ownerRecordedDestinations(ctx, "entry-leave")
	if err != nil {
		t.Fatalf("read recorded destinations: %v", err)
	}
	t.Logf("BEFORE the claim (owner withheld) the entry authorises: %v", before.Hosts)

	claim := httptest.NewRecorder()
	h.ClaimSecretOwnership(claim, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/entry-leave/ownership/claim", admin, "admin", "entry-leave", ""))
	if claim.Code != http.StatusOK {
		t.Fatalf("the claim failed: %d %s", claim.Code, claim.Body.String())
	}

	after, err := h.ownerRecordedDestinations(ctx, "entry-leave")
	if err != nil {
		t.Fatalf("read recorded destinations after: %v", err)
	}
	t.Logf("AFTER the claim the entry authorises: %v", after.Hosts)

	// What is still ON the row, whether or not it currently authorises.
	meta, _ := queries.GetVaultEntryMeta(ctx, "entry-leave")
	rawTargets, tErr := queries.GetVaultEntryTargets(ctx, "entry-leave")
	if tErr != nil {
		t.Fatalf("read targets: %v", tErr)
	}
	targets := ParseRotationTargets(h.decryptColumnOrLog(rawTargets.String, "[]", vaultFieldRotationTargets))
	t.Logf("residue on the row: destination_patterns=%q provider_meta=%q rotation_targets=%d",
		meta.DestinationPatterns,
		h.decryptColumnOrLog(meta.ProviderMeta.String, "{}", vaultFieldProviderMeta), len(targets))
	for _, tg := range targets {
		t.Logf("  surviving target: type=%s url=%q instance=%q configured_by=%q",
			tg.Type, tg.WebhookURL, tg.Instance, tg.ConfiguredBy)
	}

	for _, host := range after.Hosts {
		if strings.Contains(host, "attacker.example") {
			t.Errorf("THE CLAIM RE-ARMED A HOST THE PREVIOUS HOLDER CHOSE: %q is authorised after the "+
				"repair. before=%v after=%v", host, before.Hosts, after.Hosts)
		}
	}
	if len(targets) > 0 {
		t.Logf("NOTE: the claim's response says the recorded destinations were WITHDRAWN, but %d "+
			"rotation target(s) chosen by the previous holder are still on the row verbatim. They are "+
			"inert only because mayConfigureDelivery(ConfiguredBy) is false right now", len(targets))
	}
}

// ── 5. THE WITHHELD-VERSUS-EXPIRED SPLIT, AT THE WIRE ─────────────────────────

// TestClassificationDecidesWhetherThePlantedHostIsEverDisarmed asks the question
// the split opens: can an attacker get a row classified as something other than
// "withheld", so the repair route declines to disarm a host they chose?
//
// It drives BOTH classifications of the SAME attacked row against the same
// listener, so the two answers are comparable and neither can pass for the
// wrong reason.
func TestClassificationDecidesWhetherThePlantedHostIsEverDisarmed(t *testing.T) {
	env := newAttackedEnv(t, "classify")
	sink := newHeaderSink(t)
	env.pointProviderAt(t, sink.URL)
	ctx := context.Background()

	admin := mustUser(t, env.queries, "classify-admin@example.com", "admin", "admin-login-password")

	// THE LAUNDERED POPULATION. A database that already ran a broken 00034 has
	// the manager's id in the owner column rather than an empty string. Nothing
	// else about the row changes.
	if _, err := env.h.db.Exec(`UPDATE vault_entries SET secret_owner_user_id = ? WHERE id = ?`,
		env.attacker, env.entryID); err != nil {
		t.Fatalf("model the laundered owner: %v", err)
	}
	live, lErr := env.h.recordedOwnerMayDirect(ctx, env.entryID)
	if lErr != nil {
		t.Fatalf("liveness: %v", lErr)
	}
	if !live {
		t.Fatalf("ABORT: the laundered owner cannot direct the entry, so this is not the state the " +
			"broken migration produces and the classification question would not arise")
	}

	// CLASSIFICATION A: neither class. Not listed, and the claim refuses.
	list := httptest.NewRecorder()
	env.h.ListUnownedEntries(list, vaultAuthzRequest(http.MethodGet, "/api/admin/vault/ownership",
		admin, "admin", "", ""))
	listedWhileLive := strings.Contains(list.Body.String(), env.entryID)
	claimA := httptest.NewRecorder()
	env.h.ClaimSecretOwnership(claimA, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+env.entryID+"/ownership/claim", admin, "admin", env.entryID, ""))
	t.Logf("laundered+live: listed on the repair page = %v, claim -> %d %s",
		listedWhileLive, claimA.Code, strings.TrimSpace(claimA.Body.String()))

	recorded, rErr := env.h.ownerRecordedDestinations(ctx, env.entryID)
	if rErr != nil {
		t.Fatalf("read recorded destinations: %v", rErr)
	}
	t.Logf("laundered+live: the entry authorises %v", recorded.Hosts)

	if !listedWhileLive && claimA.Code == http.StatusConflict && len(recorded.Hosts) > 0 {
		t.Errorf("THE REPAIR ROUTE DECLINES TO DISARM A HOST THE PREVIOUS HOLDER CHOSE: with the "+
			"attacker's id in secret_owner_user_id the row is neither in the withheld class nor in the "+
			"expired class, GET /api/admin/vault/ownership does not show it, and "+
			"POST .../ownership/claim answers %d. The planted evidence stays armed (%v) and the "+
			"product's only repair surface says there is nothing to repair",
			claimA.Code, recorded.Hosts)
	}

	// CLASSIFICATION B: the same row, once the laundered owner loses manage.
	// One manager-gated call by any other manager of the collection.
	if _, err := env.h.db.Exec(
		`DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?`,
		"coll-classify", env.attacker); err != nil {
		t.Fatalf("drop the laundered owner's membership: %v", err)
	}
	live, _ = env.h.recordedOwnerMayDirect(ctx, env.entryID)
	if live {
		t.Fatal("ABORT: the laundered owner still directs the entry, so classification B was not reached")
	}
	claimB := httptest.NewRecorder()
	env.h.ClaimSecretOwnership(claimB, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+env.entryID+"/ownership/claim", admin, "admin", env.entryID, ""))
	t.Logf("expired class: claim -> %d %s", claimB.Code, strings.TrimSpace(claimB.Body.String()))
	if claimB.Code != http.StatusOK {
		t.Fatalf("the expired-class claim failed, so the disarm was never exercised: %d %s",
			claimB.Code, claimB.Body.String())
	}

	// THE WIRE. Whatever the classification argued, this is what the unattended
	// sweep does with the row afterwards.
	RotateVaultKeys(env.h.db, env.queries, env.h)
	if !env.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain")
	}
	auths, lines, payloads := sink.received()
	if sink.sawSecret(env.secret) {
		t.Fatalf("THE EXPIRED-CLASS REPAIR RE-ARMED THE ATTACK.\n  auth headers:  %q\n  "+
			"request lines: %q\n  bodies:        %q", auths, lines, payloads)
	}
	t.Logf("expired-class repair: the attacker's listener received %d requests after the claim", len(lines))
}

// TestWhereTheRepairPageStartsStarvingThePool finds the concurrency at which the
// nested cursor takes the database away from the rest of the process, so the
// finding can state a threshold rather than "under load".
func TestWhereTheRepairPageStartsStarvingThePool(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	admin := mustUser(t, queries, "thr-admin@example.com", "admin", "admin-login-password")
	victim := mustUser(t, queries, "thr-victim@example.com", "user", "victim-login-password")
	mustCollection(t, queries, "coll-thr", victim, map[string]string{victim: collRoleManager})
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("entry-thr-%03d", i)
		mustEntry(t, h, queries, id, victim, fmt.Sprintf("thr-key-%03d", i), "sk_live_THR")
		placeInCollection(t, queries, id, "coll-thr")
	}
	if _, err := h.db.Exec(`DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?`,
		"coll-thr", victim); err != nil {
		t.Fatalf("strand the rows: %v", err)
	}
	live, _ := h.recordedOwnerMayDirect(ctx, "entry-thr-000")
	if live {
		t.Fatal("ABORT: the rows are not second-class, so the nested query does not run per row")
	}

	for _, n := range []int{4, 8, 9, 10, 11} {
		res := driveOwnershipPage(t, h, admin, n, 8*time.Second, 2*time.Second)
		ok := 0
		for _, c := range res.codes {
			if c == http.StatusOK {
				ok++
			}
		}
		t.Logf("concurrency %2d: %d/%d requests answered 200 in %v; unrelated SELECT %v after %v",
			n, ok, n, res.elapsed, res.unrelatedErr, res.unrelatedWait)
	}
}

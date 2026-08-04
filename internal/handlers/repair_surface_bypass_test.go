package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE REPAIR SURFACE IS AN ATTACKER-WRITABLE INPUT TO THE NEXT MIGRATION.
//
// exit5 splits the defence in two. ownerRecordedDestinations withholds the
// planted evidence at READ time while an entry has no recorded owner, and
// ClaimSecretOwnership CLEARS that evidence at the moment an admin answers the
// ownership question, so a repair cannot re-arm the previous holder's host.
//
// Both halves are about the entry being repaired. Neither is about the audit
// row the repair writes on its way out, and migrations 00035 and 00036 read
// that audit row as AUTHORITY: an entry named by a vault.ownership_claimed
// detail keeps its recorded owner, because clearing an ownership an admin
// deliberately took would undo a decision rather than an accident.
//
// 00036's own header says a log format is not an API and stops parsing the
// wording of vault.entry_moved for exactly that reason. It then keeps parsing
// the wording of vault.ownership_claimed, on the argument that "that action has
// had exactly one format in its whole existence". That is true of the FORMAT
// and false of the CONTENT: the format interpolates the withdrawn
// destination_patterns and the withdrawn provider_meta values verbatim, and
// those are strings the previous holder wrote.
//
// So the previous holder chooses part of the sentence a later migration parses
// to decide who owns a DIFFERENT secret.

// theInjectedVictimID is a plausible vault entry id: lower(hex(randomblob(16))).
const theInjectedVictimID = "0123456789abcdef0123456789abcdef"

// TestTheRepairAuditDetailCarriesBytesThePreviousHolderChose is stage 1 of the
// chain, driven through the two real handlers.
//
// The attacker is an ordinary `user` who is a MANAGER of a shared collection and
// the custodian of the attacked entry. They hold no admin right anywhere and
// they do not touch secret_owner_user_id, which is the column the whole round
// protects.
func TestTheRepairAuditDetailCarriesBytesThePreviousHolderChose(t *testing.T) {
	env := newAttackedEnv(t, "auditinject")
	payload := "Entry " + theInjectedVictimID + ":"

	// STEP 1. The attacker writes the chosen bytes into provider_meta through
	// the ordinary product route.
	//
	// This is NOT a widening and therefore needs no widening right:
	// metaURLHost("instance") yields no host at all for a non-URL, so
	// egressgate.Decide sees the entry's declared host set SHRINK to nothing and
	// grants a ticket without ever consulting the authority oracle. Narrowing is
	// deliberately ungated, because clearing a destination is the product's only
	// per-secret agent revocation. The attacker is using the revocation lever as
	// a writable free-text field.
	body, _ := json.Marshal(map[string]any{
		"provider":      "forgejo",
		"provider_meta": `{"instance":"` + payload + `"}`,
	})
	put := httptest.NewRecorder()
	env.h.Update(put, vaultAuthzRequest(http.MethodPut, "/api/vault/"+env.entryID,
		env.attacker, "user", env.entryID, string(body)))
	if put.Code != http.StatusOK {
		t.Fatalf("ABORT: the attacker's provider_meta write was refused (%d: %s); the rest of this "+
			"test would be measuring nothing", put.Code, put.Body.String())
	}

	// STEP 2. The admin does the right thing at Settings -> Ownership.
	admin := mustUser(t, env.queries, "auditinject-admin@example.com", "admin", "admin-login-password")
	claim := httptest.NewRecorder()
	env.h.ClaimSecretOwnership(claim, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+env.entryID+"/ownership/claim", admin, "admin", env.entryID, ""))
	if claim.Code != http.StatusOK {
		t.Fatalf("ABORT: the admin could not claim the entry (%d: %s)", claim.Code, claim.Body.String())
	}

	var detail string
	if err := env.h.db.QueryRow(
		`SELECT detail FROM activity_log WHERE action = 'vault.ownership_claimed'
		 ORDER BY rowid DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("no vault.ownership_claimed row was written: %v", err)
	}

	// STEP 3. The predicate migrations 00035 and 00036 run against that row,
	// verbatim from the SQL:
	//
	//   instr(al.detail, 'Entry ' || vault_entries.id || ':') > 0
	//
	// asked about an entry the attacker named rather than the one that was
	// repaired.
	if strings.Contains(detail, payload) {
		t.Fatalf("THE REPAIR SURFACE SIGNED FOR AN ENTRY IT NEVER TOUCHED.\n"+
			"  the admin repaired: %s\n"+
			"  the audit detail also matches the preserve predicate for: %s\n"+
			"  detail: %s\n"+
			"A vault.ownership_claimed row is what migrations 00035 and 00036 accept as proof that an "+
			"admin deliberately chose an owner, and the previous holder of the repaired row supplied "+
			"part of the sentence.", env.entryID, theInjectedVictimID, detail)
	}
	t.Logf("detail: %s", detail)
}

// TestALaunderedOwnerThatSurvivesTheRepairMigrationDelivers is stage 3: the
// consequence, on the wire, of the ownership that 00036 was supposed to
// withdraw and did not.
//
// The row state below is exactly what
// internal/database TestTheInjectedClaimDetailSparesALaunderedOwner leaves
// behind: personal now, custodian is the manager who adopted it, and
// secret_owner_user_id is still the attacker.
func TestALaunderedOwnerThatSurvivesTheRepairMigrationDelivers(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	sink := newHeaderSink(t)
	ctx := context.Background()

	const secret = "sk_live_TEAM_SECRET_LAUNDERED"
	victim := mustUser(t, queries, "laundered-victim@example.com", "user", "victim-login-password")
	attacker := mustUser(t, queries, "laundered-attacker@example.com", "user", "attacker-login-password")
	const entryID = "entry-laundered"
	mustEntry(t, h, queries, entryID, victim, "team-key", secret)

	if _, err := h.db.Exec(
		`UPDATE vault_entries SET user_id = ?, secret_owner_user_id = ?, collection_id = NULL WHERE id = ?`,
		attacker, attacker, entryID); err != nil {
		t.Fatalf("plant the post-00036 state: %v", err)
	}
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["` + attackedHost + `/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("plant the ceiling: %v", err)
	}
	forceProviderConfig(t, h, entryID, "forgejo", `{"instance":"`+sink.URL+`"}`)

	acc, err := queries.GetVaultEntryAccess(ctx, entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if acc.SecretOwnerUserID != attacker {
		t.Fatalf("ABORT: the fixture does not carry the laundered owner (%q)", acc.SecretOwnerUserID)
	}

	RotateVaultKeys(h.db, queries, h)
	if !h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain; the wire assertions would be racing it")
	}
	auths, lines, payloads := sink.received()
	if sink.sawSecret(secret) {
		t.Fatalf("THE ATTACK SUCCEEDED. An ownership migration 00036 was written to withdraw delivered "+
			"a colleague's plaintext to the attacker's host.\n  auth headers:  %q\n  request lines: %q"+
			"\n  bodies:        %q", auths, lines, payloads)
	}
}

// TestAClearedOwnerDoesNotDeliver is the negative control on the same code and
// the same row: with secret_owner_user_id empty, which is what 00036 INTENDS to
// leave behind, the identical planted evidence sends nothing.
func TestAClearedOwnerDoesNotDeliver(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	sink := newHeaderSink(t)

	const secret = "sk_live_TEAM_SECRET_CLEARED"
	victim := mustUser(t, queries, "cleared-victim@example.com", "user", "victim-login-password")
	attacker := mustUser(t, queries, "cleared-attacker@example.com", "user", "attacker-login-password")
	const entryID = "entry-cleared"
	mustEntry(t, h, queries, entryID, victim, "team-key", secret)
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET user_id = ?, secret_owner_user_id = '', collection_id = NULL WHERE id = ?`,
		attacker, entryID); err != nil {
		t.Fatalf("plant: %v", err)
	}
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["` + attackedHost + `/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("plant the ceiling: %v", err)
	}
	forceProviderConfig(t, h, entryID, "forgejo", `{"instance":"`+sink.URL+`"}`)

	RotateVaultKeys(h.db, queries, h)
	if !h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain")
	}
	if _, lines, _ := sink.received(); len(lines) != 0 {
		t.Fatalf("ABORT: the control delivered too (%v), so the test above proves nothing about "+
			"ownership", lines)
	}
}

// ── the repair route that cannot run ────────────────────────────────────────

// TestTheRepairIsImpossibleForADatadogEntryWithARegionalSite is the other end of
// the same surface: a row the migration withheld that the repair route can
// never accept.
//
// disarmRecordedDestinations clears the host-choosing provider_meta keys and
// asks egressgate.Decide to authorise the clear, with NO oracle, on the argument
// that clearing is always a narrowing. For datadog that is false. Its host
// builder falls back to the adapter's own default when meta["site"] is absent,
// so removing the key REPLACES api.<site> with api.datadoghq.com, Decide sees an
// addition, a nil MayRedirect denies it, the handler 500s and the transaction
// rolls back.
//
// The row therefore keeps its empty owner forever. It refuses every new delivery
// destination, its recorded ones are withheld, and the one route in the product
// that could answer the ownership question always fails.
func TestTheRepairIsImpossibleForADatadogEntryWithARegionalSite(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	victim := mustUser(t, queries, "dd-victim@example.com", "user", "victim-login-password")
	admin := mustUser(t, queries, "dd-admin@example.com", "admin", "admin-login-password")

	const entryID = "entry-datadog"
	mustEntry(t, h, queries, entryID, victim, "datadog-key", "sk_live_DATADOG")
	// datadoghq.eu is Datadog's EU region and the setting an EU-sovereign
	// product's customers use. It is also the shape an attacker's planted site
	// takes, and the route cannot tell them apart because it refuses both.
	forceProviderConfig(t, h, entryID, "datadog", `{"site":"datadoghq.eu"}`)
	clearSecretOwnerForTest(t, h, entryID)

	// POSITIVE CONTROL FIRST, so a green run cannot be a broken environment.
	const okID = "entry-ordinary"
	mustEntry(t, h, queries, okID, victim, "ordinary-key", "sk_live_ORDINARY")
	forceProviderConfig(t, h, okID, "forgejo", `{"instance":"https://git.example.com"}`)
	clearSecretOwnerForTest(t, h, okID)
	control := httptest.NewRecorder()
	h.ClaimSecretOwnership(control, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+okID+"/ownership/claim", admin, "admin", okID, ""))
	if control.Code != http.StatusOK {
		t.Fatalf("ABORT: the repair route is broken for every entry (%d: %s), so the assertion below "+
			"would be measuring the environment", control.Code, control.Body.String())
	}

	rec := httptest.NewRecorder()
	h.ClaimSecretOwnership(rec, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+entryID+"/ownership/claim", admin, "admin", entryID, ""))
	acc, err := queries.GetVaultEntryAccess(ctx, entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if rec.Code != http.StatusOK || acc.SecretOwnerUserID == "" {
		t.Fatalf("THE ONLY REPAIR ROUTE CANNOT REPAIR THIS ROW.\n"+
			"  claim  -> %d %s\n"+
			"  owner  -> %q (still withheld)\n"+
			"  control claim on an identical forgejo entry -> %d\n"+
			"Every datadog entry with a regional site is permanently unable to accept a delivery "+
			"destination, and Settings -> Ownership is the surface the migration notice sends the "+
			"operator to.", rec.Code, strings.TrimSpace(rec.Body.String()), acc.SecretOwnerUserID,
			control.Code)
	}
}

// TestRemovingTheOwnerFromACollectionStrandsTheEntryWithNoRepair is the second
// unrepairable state, and this one a NON-ADMIN causes with a single call.
//
// secret_exit_authority.go states the cost of the exit5 rule in its own words:
//
//	"An entry whose owner is recorded but who no longer holds manage (they were
//	 removed from the collection the entry lives in) stops contributing recorded
//	 destinations... Settings -> Ownership is where an admin takes such a row
//	 back"
//
// It does not. ListUnownedEntries selects on secret_owner_user_id = '' so the
// row never appears on the page, and ClaimSecretOwnership refuses any entry that
// already records an owner. A collection manager therefore turns off a
// colleague's rotation delivery permanently with one manager-gated call, writing
// nothing on the entry at all.
func TestRemovingTheOwnerFromACollectionStrandsTheEntryWithNoRepair(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "strand-owner@example.com", "user", "owner-login-password")
	manager := mustUser(t, queries, "strand-manager@example.com", "user", "manager-login-password")
	admin := mustUser(t, queries, "strand-admin@example.com", "admin", "admin-login-password")
	mustCollection(t, queries, "c-strand", owner, map[string]string{
		owner: collRoleManager, manager: collRoleManager,
	})

	const entryID = "entry-strand"
	mustEntry(t, h, queries, entryID, owner, "team-key-strand", "sk_live_STRAND")
	placeInCollection(t, queries, entryID, "c-strand")
	if !h.mayConfigureDelivery(ctx, owner, entryID) {
		t.Fatal("ABORT: the owner cannot direct their own entry before the attack, so nothing below " +
			"measures a loss")
	}

	// THE ATTACK: one manager-gated call, no column on the entry touched.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "c-strand", UserID: owner,
	}); err != nil {
		t.Fatalf("remove the owner from the collection: %v", err)
	}
	stillDirects, err := h.recordedOwnerMayDirect(ctx, entryID)
	if err != nil {
		t.Fatalf("recordedOwnerMayDirect: %v", err)
	}
	if stillDirects {
		t.Skip("the recorded owner still directs, so there is nothing stranded to repair")
	}

	claim := httptest.NewRecorder()
	h.ClaimSecretOwnership(claim, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+entryID+"/ownership/claim", admin, "admin", entryID, ""))
	list := httptest.NewRecorder()
	h.ListUnownedEntries(list, vaultAuthzRequest(http.MethodGet,
		"/api/admin/vault/ownership", admin, "admin", "", ""))

	if claim.Code != http.StatusOK {
		t.Fatalf("THE DOCUMENTED REPAIR DOES NOT EXIST FOR THIS ROW.\n"+
			"  the entry records an owner who may no longer direct it, so it contributes no "+
			"destinations\n"+
			"  POST .../ownership/claim -> %d %s\n"+
			"  GET  /api/admin/vault/ownership -> %s\n"+
			"A collection manager disabled a colleague's delivery permanently with "+
			"DELETE /api/collections/{id}/members/{owner} and wrote nothing on the entry.",
			claim.Code, strings.TrimSpace(claim.Body.String()), strings.TrimSpace(list.Body.String()))
	}
}

// TestAnEntryNameCarriesForeignEntryIDsIntoTheMoveDetail is the third-party
// input to the OTHER half of the same predicate.
//
// 00036 loosened the vault.entry_moved clause to bare containment of the 32-hex
// id and recorded the residual as "an entry NAMED with another entry's 32-hex id
// would be withheld... a self-inflicted denial of service on one row". It is not
// self-inflicted and it is not one row: the name is attacker-chosen, the detail
// carries it verbatim, activity_log is append-only by trigger, and the move
// route can be driven as often as the attacker likes.
func TestAnEntryNameCarriesForeignEntryIDsIntoTheMoveDetail(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	attacker := mustUser(t, queries, "namer@example.com", "user", "attacker-login-password")
	mustCollection(t, queries, "c-namer", attacker, map[string]string{attacker: collRoleManager})

	victims := []string{
		"0123456789abcdef0123456789abcdef",
		"11111111111111111111111111111111",
		"22222222222222222222222222222222",
		"33333333333333333333333333333333",
		"44444444444444444444444444444444",
		"55555555555555555555555555555555",
		"66666666666666666666666666666666",
	}
	const carrier = "entry-namer-carrier"
	mustEntry(t, h, queries, carrier, attacker, strings.Join(victims, " "), "sk_live_CARRIER")

	rec := httptest.NewRecorder()
	h.MoveToCollection(rec, vaultAuthzRequest(http.MethodPut,
		"/api/vault/"+carrier+"/collection", attacker, "user", carrier,
		`{"collection_id":"c-namer"}`))
	if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the move was refused (%d: %s)", rec.Code, rec.Body.String())
	}

	var detail string
	if err := h.db.QueryRow(
		`SELECT detail FROM activity_log WHERE action = 'vault.entry_moved'
		 ORDER BY rowid DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("no vault.entry_moved row: %v", err)
	}
	var hit []string
	for _, v := range victims {
		if strings.Contains(detail, v) {
			hit = append(hit, v)
		}
	}
	if len(hit) > 0 {
		t.Fatalf("ONE MOVE PLANTED %d FOREIGN ENTRY IDS IN THE PREDICATE'S INPUT.\n"+
			"  detail: %s\n"+
			"  matched: %v\n"+
			"Each of these entries will be read by the next ownership backfill as having been in a "+
			"collection, so its owner is withdrawn and its recorded destinations stop contributing. "+
			"The move route can be driven repeatedly and activity_log cannot be deleted.",
			len(hit), detail, hit)
	}
}

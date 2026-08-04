package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// SKEPTIC RE-RUN: "AN EMPTY OWNER DENIES".
//
// The ownership split (migration 00034) rests on one sentence that until now
// existed only as a comment and as a `!= ""` inside mayDirectSecretEgress:
//
//	an entry whose secret_owner_user_id is empty is directable by nobody.
//
// That sentence is load-bearing in a way the ones around it are not. Every OTHER
// ownership claim is about a row somebody wrote through a gate; this one is
// about a row that arrived some other way, which is the case the whole exit
// exists for. A v1 import, a restored backup, a row written by a binary older
// than 00034, and a migration that backfilled NULL all land here. Nothing in the
// suite drove it.
//
// The skeptic that was supposed to check this died on an API connection error
// last round, so the claim shipped unverified. This is the re-run, and it does
// what a comment cannot: it plants the row, gives the attacker every legitimate
// right the product can hand out on it, and reads what a real HTTP server
// received.
//
// THE ATTACKER HERE IS NOT A THIRD PARTY. They are the row's own custodian and
// creator, which is the strongest position a non-admin can hold. If an empty
// owner denied only strangers it would deny nobody who mattered.

// clearSecretOwnerForTest plants the shape a pre-00034 row, a restored backup
// or a v1 import leaves behind: a custodian and no owner.
//
// It writes raw SQL on purpose. The product has exactly one statement that can
// move secret_owner_user_id after a row exists and it demands a TransferProof,
// which is the property TestOnlyTheSanctionedStatementMovesTheSecretOwner pins.
// The rows this fixture is about never went through that statement, so a fixture
// that did would be building a state the test is not about.
func clearSecretOwnerForTest(t *testing.T, h *VaultHandler, entryID string) {
	t.Helper()
	res, err := h.db.Exec(`UPDATE vault_entries SET secret_owner_user_id = '' WHERE id = ?`, entryID)
	if err != nil {
		t.Fatalf("plant the empty owner: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		t.Fatalf("ABORT: planting the empty owner touched %d rows (err %v); the fixture is not the shape "+
			"this test is about", n, err)
	}
}

// TestAnEmptyOwnerDeniesEvenTheCustodian is the skeptic, on the wire.
func TestAnEmptyOwnerDeniesEvenTheCustodian(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	sink := newHeaderSink(t)
	ctx := context.Background()

	const pw = "custodian-pw"
	custodian := mustUser(t, queries, "owner-empty-custodian@example.com", "user", pw)
	const entryID = "entry-owner-empty"
	const secret = "sk_live_EMPTY_OWNER_MUST_NOT_MOVE"
	mustEntry(t, h, queries, entryID, custodian, "legacy-imported-key", secret)

	// PLANT THE ROW SHAPE, deliberately with raw SQL.
	//
	// There is exactly one statement in the module that can move
	// secret_owner_user_id after a row exists, it demands a TransferProof, and
	// AuthorizeTransfer will not issue one for an empty owner. That is correct
	// and it is why the fixture goes round it: the rows this test is about never
	// passed through the product at all. A restored backup, a v1 import and a
	// binary older than migration 00034 all produce exactly this, and none of
	// them ran a sanctioned statement to do it.
	clearSecretOwnerForTest(t, h, entryID)

	access, err := queries.GetVaultEntryAccess(ctx, entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	// GUARD THE PREMISE, both halves.
	if access.SecretOwnerUserID != "" {
		t.Fatalf("ABORT: the fixture did not produce an empty owner (%q); this test would be measuring "+
			"an ordinary owned row", access.SecretOwnerUserID)
	}
	if access.UserID != custodian {
		t.Fatalf("ABORT: the custodian is %q, not the attacker, so they do not hold the rights this "+
			"test is about", access.UserID)
	}
	if g := h.grantFor(ctx, custodian, false, entryID); !g.manage {
		t.Fatalf("ABORT: the custodian does not hold manage on their own entry (%+v); the attack would "+
			"be refused for the wrong reason", g)
	}

	// THE PREDICATE.
	if h.mayDirectSecretEgress(ctx, custodian, false, entryID) {
		t.Error("mayDirectSecretEgress said yes about a row with NO recorded owner. An empty owner is " +
			"not a person who authorised anything; it is the absence of an answer, and the absence of " +
			"an answer has to deny.")
	}

	// AND THE WIRE. Errorf above, not Fatalf, so the run reaches the wire even
	// when the predicate is ablated: the evidence that matters is what the
	// attacker's host received, not what an internal function returned.
	direct := putTargets(t, h, custodian, "user", entryID,
		`[{"type":"webhook","label":"mine","webhook_url":`+quote(sink.URL+"/collect")+`}]`)
	if direct.Code == http.StatusOK {
		t.Errorf("the write gate ACCEPTED a delivery target on an unowned row (%s)", direct.Body.String())
	}

	// A write gate only guards writes it sees, and the rows this test is about
	// are exactly the ones that never passed one. So plant the target too and
	// run a real rotation against it.
	body := `[{"type":"webhook","label":"mine","webhook_url":` + quote(sink.URL+"/collect") +
		`,"configured_by":` + quote(custodian) + `}]`
	planted, encErr := h.encryptColumn(body)
	if encErr != nil {
		t.Fatalf("encrypt planted targets: %v", encErr)
	}
	mustStoreRotationTargetsForTest(t, queries, entryID, planted)

	rot := httptest.NewRecorder()
	h.Rotate(rot, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/rotate",
		custodian, "user", entryID, `{"password":`+quote(pw)+`}`))
	if !h.WaitForDelivery(30 * time.Second) {
		t.Fatal("rotation delivery did not drain; the wire assertions would be racing it")
	}

	auths, lines, payloads := sink.received()
	if sink.sawSecret(secret) {
		t.Fatalf("THE ATTACK SUCCEEDED. A row with no recorded owner delivered its secret to a host its "+
			"custodian chose.\n  auth headers:  %q\n  request lines: %q\n  bodies:        %q",
			auths, lines, payloads)
	}
	if len(lines) != 0 {
		t.Errorf("the custodian's host received %v carrying %q; an unowned row should attempt nothing",
			lines, payloads)
	}
	t.Logf("wire, empty owner: custodian=%s owner=%q, direct target=%d rotate=%d "+
		"(target PLANTED past the write gate), host received %d requests",
		access.UserID, access.SecretOwnerUserID, direct.Code, rot.Code, len(lines))
}

// TestAnEmptyOwnerStillDeniesAnInstanceAdminNothing is the positive control.
//
// The fix must not work by denying everybody: an instance admin holds the
// widening right on every entry by role, so an unowned row is still
// administrable. A test that only proved "nobody can" would pass on a product
// where the feature was simply broken.
func TestAnEmptyOwnerIsStillAdministrable(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	admin := mustUser(t, queries, "owner-empty-admin@example.com", "admin", "admin-pw")
	custodian := mustUser(t, queries, "owner-empty-cust2@example.com", "user", "cust-pw")
	const entryID = "entry-owner-empty-admin"
	mustEntry(t, h, queries, entryID, custodian, "legacy-imported-key-2", "sk_live_ADMIN_CAN_FIX")

	clearSecretOwnerForTest(t, h, entryID)
	if !h.mayDirectSecretEgress(ctx, admin, true, entryID) {
		t.Error("an INSTANCE ADMIN may not direct an unowned row's secret. The empty-owner rule is " +
			"meant to deny the absence of an answer, not to make a legacy row permanently unusable: " +
			"an admin holds the widening right on every entry by role, and taking ownership is how such " +
			"a row gets repaired.")
	}

	// And the repair path works: an admin takes ownership FOR THEMSELVES.
	proof, err := vaultegress.AuthorizeTransfer(vaultegress.TransferRequest{
		EntryID: entryID, Actor: admin, ActorIsInstanceAdmin: true, To: admin,
		Why: "repairing a legacy row that carries no owner",
	})
	if err != nil {
		t.Fatalf("an instance admin could not take ownership of an unowned row: %v", err)
	}
	if _, err := vaultegress.TransferSecretOwnership(ctx, queries, proof,
		vaultegress.TransferOwnershipParams{NewOwnerUserID: admin, ID: entryID}); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	access, err := queries.GetVaultEntryAccess(ctx, entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if access.SecretOwnerUserID != admin {
		t.Fatalf("after the repair the owner is %q, want the admin", access.SecretOwnerUserID)
	}
	if !h.mayDirectSecretEgress(ctx, admin, true, entryID) {
		t.Error("the repaired row is still not directable by its new owner")
	}
	t.Logf("positive control: an unowned row is administrable and repairable; owner is now %s",
		access.SecretOwnerUserID)
}

// TestOwnershipCannotBeHandedToAThirdParty re-checks the other half of the
// transfer rule, which the same dead skeptic was supposed to cover.
//
// AuthorizeTransfer is the only constructor of a TransferProof, and it grants
// one only to an instance admin taking ownership FOR THEMSELVES. Handing the
// widening right to somebody else would be the round-6 attack with an extra
// step: the attacker persuades an admin to "give them" an entry and then directs
// its secret wherever they like.
func TestOwnershipCannotBeHandedToAThirdParty(t *testing.T) {
	const entry = "entry-transfer-rule"
	cases := []struct {
		name    string
		req     vaultegress.TransferRequest
		granted bool
	}{
		{"admin takes it for themselves", vaultegress.TransferRequest{
			EntryID: entry, Actor: "admin-1", ActorIsInstanceAdmin: true, To: "admin-1",
			Why: "adopting an orphaned row"}, true},
		{"admin hands it to somebody else", vaultegress.TransferRequest{
			EntryID: entry, Actor: "admin-1", ActorIsInstanceAdmin: true, To: "attacker",
			Why: "granting ownership"}, false},
		{"non-admin takes it for themselves", vaultegress.TransferRequest{
			EntryID: entry, Actor: "manager-1", ActorIsInstanceAdmin: false, To: "manager-1",
			Why: "I manage this collection"}, false},
		{"non-admin hands it to somebody else", vaultegress.TransferRequest{
			EntryID: entry, Actor: "manager-1", ActorIsInstanceAdmin: false, To: "attacker",
			Why: "handing over"}, false},
		{"admin takes it for themselves with no reason", vaultegress.TransferRequest{
			EntryID: entry, Actor: "admin-1", ActorIsInstanceAdmin: true, To: "admin-1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vaultegress.AuthorizeTransfer(tc.req)
			if tc.granted && err != nil {
				t.Errorf("a transfer that should be allowed was refused: %v", err)
			}
			if !tc.granted && err == nil {
				t.Errorf("AuthorizeTransfer GRANTED a proof for %+v. The widening right is the right to "+
					"choose where a secret goes; handing it to a third party is the round-6 attack with "+
					"one extra step.", tc.req)
			}
		})
	}
}

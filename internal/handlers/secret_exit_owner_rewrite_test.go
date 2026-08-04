package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE ROUND-7 BREAK: REWRITE THE ANSWER, THEN ASK THE QUESTION.
//
// Round 7 put every decrypted secret through one gate and asked one question:
// did the OWNER of the secret being sent authorise this destination. The gate is
// the right shape. It resolved "owner" from vault_entries.user_id, and user_id
// is a column an ordinary product route lets the attacker write to their own id:
//
//	1. DELETE /api/collections/{coll}/members/{creator}
//	   Manager-gated, and the attacker is a manager. The last-manager guard is
//	   satisfied because the attacker is the other one. Now the creator is not an
//	   accepted member of the collection holding their own secret.
//	2. PUT /api/vault/{teamEntry}  {"name":"anything-else"}
//	   managerMayAdoptOrphanedEntry now says yes, and AdoptAndRenameVaultEntry
//	   writes user_id = the attacker in the same statement as the rename.
//
// Two ordinary calls, both of them features. After them mayDirectSecretEgress
// said yes to the attacker about the victim's secret, and the exit then
// authorised the exact round-6 cross-entry delivery it was built to refuse. A
// gate whose input the attacker can write is decoration.
//
// THE FIX IS NOT TO TAKE ADOPTION AWAY. Adoption is what moves the
// UNIQUE(user_id, name) question into the renamer's own namespace, which is what
// keeps a rename from being an existence oracle over a colleague's private
// vault. user_id was carrying two meanings, and the attack is exactly that
// conflation: they are two columns now, and only secret_owner_user_id is the
// exit's.
//
// ASSERTIONS READ WHAT A REAL HTTP SERVER RECEIVED.

// ownerRewriteEnv is the fixture: a shared collection, its creator, and a
// MANAGER who is going to take it over.
type ownerRewriteEnv struct {
	h          *VaultHandler
	coll       *CollectionHandler
	creator    string
	attacker   string
	collection string
	teamEntry  string
	teamName   string
	teamSecret string
	carrier    string
	password   string
}

func newOwnerRewriteEnv(t *testing.T, tag string) *ownerRewriteEnv {
	t.Helper()
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)

	env := &ownerRewriteEnv{
		h:          h,
		coll:       NewCollectionHandler(queries, h),
		creator:    mustUser(t, queries, "own-creator-"+tag+"@example.com", "user", "creator-pw"),
		attacker:   mustUser(t, queries, "own-manager-"+tag+"@example.com", "vault_only", "manager-pw"),
		collection: "coll-own-" + tag,
		teamEntry:  "entry-own-team-" + tag,
		teamName:   "team-stripe-" + tag,
		teamSecret: "sk_live_OWNER_REWRITE_" + strings.ToUpper(tag),
		carrier:    "entry-own-carrier-" + tag,
		password:   "manager-pw",
	}

	mustCollection(t, queries, env.collection, env.creator, map[string]string{
		env.creator: collRoleManager,
		// A MANAGER, not an editor and not a viewer. This is a seat the product
		// hands out on purpose: managers run the team's shared vault.
		env.attacker: collRoleManager,
	})
	mustEntry(t, h, queries, env.teamEntry, env.creator, env.teamName, env.teamSecret)
	placeInCollection(t, queries, env.teamEntry, env.collection)
	mustEntry(t, h, queries, env.carrier, env.attacker, "carrier-"+tag, "carrier-seed")

	ctx := context.Background()
	// GUARD THE PREMISE, both halves. Without the first the attack is not the
	// one under test; without the second it never needed the rewrite.
	if g := h.grantFor(ctx, env.attacker, false, env.teamEntry); !g.manage {
		t.Fatalf("ABORT: the attacker does not hold manage on the team entry (%+v)", g)
	}
	if h.mayDirectSecretEgress(ctx, env.attacker, false, env.teamEntry) {
		t.Fatal("ABORT: the attacker may already direct the team secret's egress before rewriting " +
			"anything, so this test would not be measuring the rewrite")
	}
	return env
}

// takeOwnership drives the two ordinary product calls that used to make the
// attacker the owner, and asserts they BOTH SUCCEEDED.
//
// That assertion is the point. The fix must not work by breaking adoption: if
// the rename started failing, the product lost a feature and this test would be
// passing for the wrong reason.
func (e *ownerRewriteEnv) takeOwnership(t *testing.T) {
	t.Helper()

	rec := httptest.NewRecorder()
	e.coll.RemoveMember(rec, collectionMemberRequest(e.collection, e.creator, e.attacker, "vault_only"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("step 1 (remove the creator from the collection) failed with %d: %s.\n"+
			"The attack under test needs it to succeed; if the product refuses it now, this test is "+
			"measuring the wrong thing.", rec.Code, rec.Body.String())
	}

	put := httptest.NewRecorder()
	e.h.Update(put, vaultAuthzRequest(http.MethodPut, "/api/vault/"+e.teamEntry,
		e.attacker, "vault_only", e.teamEntry, `{"name":"`+e.teamName+`-adopted"}`))
	if put.Code != http.StatusOK && put.Code != http.StatusNoContent {
		t.Fatalf("step 2 (adopt-and-rename) failed with %d: %s.\n"+
			"Adoption is a feature: it moves the uniqueness question into the manager's own namespace "+
			"so a rename cannot be an oracle over the creator's private vault. Breaking it is not the "+
			"fix under test.", put.Code, put.Body.String())
	}
}

// TestAManagerWhoRewritesOwnershipStillCannotDirectTheSecret is the round-7
// attack, driven on the real routes, asserted on the wire.
func TestAManagerWhoRewritesOwnershipStillCannotDirectTheSecret(t *testing.T) {
	env := newOwnerRewriteEnv(t, "kill")
	queries := env.h.queries
	sink := newHeaderSink(t)

	env.takeOwnership(t)

	ctx := context.Background()
	access, err := queries.GetVaultEntryAccess(ctx, env.teamEntry)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	// THE REWRITE HAPPENED. If it did not, the fix is "adoption is broken" and
	// the refusal below proves nothing about the exit.
	if access.UserID != env.attacker {
		t.Fatalf("ABORT: after the two calls the custodian is %q, not the attacker. The ownership "+
			"rewrite this test exists to survive did not occur.", access.UserID)
	}
	// AND THE AUTHORITY DID NOT MOVE WITH IT.
	//
	// Errorf, not Fatalf, deliberately: when this fix is ablated the run has to
	// carry on to the wire, so the evidence is what the attacker's host actually
	// received rather than a claim about an internal predicate.
	if access.SecretOwnerUserID != env.creator {
		t.Errorf("the attacker rewrote the secret's OWNER to %q by adopting the entry. That is the "+
			"finding: the exit resolves its one question from this column, so a route that lets a "+
			"collection manager write it makes the gate decorative.", access.SecretOwnerUserID)
	}
	if env.h.mayDirectSecretEgress(ctx, env.attacker, false, env.teamEntry) {
		t.Error("the attacker may direct the team secret's egress after adopting it")
	}

	// ATTACK A: point the adopted entry's own delivery straight at their host.
	// They hold manage, and under the old rule they were now also its owner.
	direct := putTargets(t, env.h, env.attacker, "vault_only", env.teamEntry,
		`[{"type":"webhook","label":"mine","webhook_url":`+quote(sink.URL+"/collect")+`}]`)
	if direct.Code == http.StatusOK {
		t.Errorf("the write gate ACCEPTED a delivery target the adopting manager pointed at their own "+
			"host on somebody else's secret (%s)", direct.Body.String())
	}

	// ATTACK B: the round-6 shape. Their own carrier entry, an auth_token naming
	// the adopted team secret, rotated with their own password.
	//
	// The write gate refuses it now (checkAuthTokenAuthority), which is the
	// shippability fix in this same branch. That is NOT what is under test here:
	// a write gate can only guard writes it sees, and the whole point of the exit
	// is that it refuses a row written by an older binary, an import or a
	// restored backup. So the refusal is recorded and then the row is PLANTED
	// through the gated writer, exactly as one of those would leave it, and the
	// rotation runs against it.
	body := `[{"type":"forgejo_secret","label":"mine","instance":` + quote(sink.URL) +
		`,"repo":"attacker/repo","secret_name":"STOLEN","auth_token":` + quote(env.teamName+"-adopted") +
		`,"configured_by":` + quote(env.attacker) + `}]`
	writeRefusal := putTargets(t, env.h, env.attacker, "vault_only", env.carrier, body)
	planted, encErr := env.h.encryptColumn(body)
	if encErr != nil {
		t.Fatalf("encrypt planted targets: %v", encErr)
	}
	mustStoreRotationTargetsForTest(t, queries, env.carrier, planted)

	rot := httptest.NewRecorder()
	env.h.Rotate(rot, vaultAuthzRequest(http.MethodPost, "/api/vault/"+env.carrier+"/rotate",
		env.attacker, "vault_only", env.carrier, `{"password":`+quote(env.password)+`}`))
	if !env.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("rotation delivery did not drain; the wire assertions would be racing it")
	}

	auths, lines, payloads := sink.received()
	if sink.sawSecret(env.teamSecret) {
		t.Fatalf("THE ATTACK SUCCEEDED. A collection MANAGER rewrote the entry's ownership through two "+
			"ordinary product routes and then had the team secret delivered to a host they chose.\n"+
			"  auth headers:  %q\n  request lines: %q\n  bodies:        %q", auths, lines, payloads)
	}
	if len(lines) != 0 {
		t.Errorf("the attacker's host received %v carrying %q; nothing should have been attempted",
			lines, payloads)
	}
	t.Logf("wire, manager ownership rewrite: adopt=ok custodian=%s owner=%s, "+
		"direct target=%d auth_token write=%d rotate=%d (target PLANTED past the write gate), "+
		"attacker host received %d requests",
		access.UserID, access.SecretOwnerUserID, direct.Code, writeRefusal.Code, rot.Code, len(lines))
}

// TestTheOriginalOwnerKeepsDirectingTheirOwnSecretAfterAdoption is the positive
// control for the same change, and it is the one that catches "the fix works by
// giving nobody the right".
//
// Adoption moves the custodian, so the creator loses grantFor's isCreator on
// that row and with it manage; a re-invited creator gets manage back and must
// still be the principal the exit names.
func TestTheOriginalOwnerKeepsDirectingTheirOwnSecretAfterAdoption(t *testing.T) {
	env := newOwnerRewriteEnv(t, "pos")
	queries := env.h.queries
	sink := newDeliverySink(t)
	ctx := context.Background()

	env.takeOwnership(t)

	// The creator is re-added to the collection. This is the ordinary "we removed
	// the wrong person" repair, and it is what isolates the property: the
	// creator's rights come back through membership, and the widening right on
	// their own secret has to come back with them.
	mustAcceptedMember(t, queries, env.collection, env.creator, collRoleEditor)

	if !env.h.mayDirectSecretEgress(ctx, env.creator, false, env.teamEntry) {
		t.Fatal("THE FEATURE IS BROKEN. After a manager adopted their entry, the person who deposited " +
			"the plaintext can no longer choose where it goes even as a current member. The fix would " +
			"then be 'nobody owns anything', which refuses the attack by refusing everyone.")
	}

	rec := putTargets(t, env.h, env.creator, "user", env.teamEntry,
		`[{"type":"webhook","label":"deploy","webhook_url":`+quote(sink.URL+"/deploy")+`}]`)
	if rec.Code != http.StatusOK {
		t.Fatalf("the secret's owner could not configure their own webhook (%d: %s)", rec.Code, rec.Body.String())
	}

	rot := httptest.NewRecorder()
	env.h.Rotate(rot, vaultAuthzRequest(http.MethodPost, "/api/vault/"+env.teamEntry+"/rotate",
		env.creator, "user", env.teamEntry, `{"password":"creator-pw"}`))
	if rot.Code != http.StatusOK {
		t.Fatalf("the owner could not rotate their own entry (%d: %s)", rot.Code, rot.Body.String())
	}
	if !env.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("rotation delivery did not drain")
	}
	hosts, bodies := sink.got()
	if len(hosts) == 0 {
		t.Fatal("THE FEATURE IS BROKEN. The owner's own webhook received nothing")
	}
	if !strings.Contains(bodies[0], "vault.key_rotated") {
		t.Fatalf("the webhook received something other than a rotation delivery: %q", bodies[0])
	}
	t.Logf("wire, owner after adoption: %v carrying a freshly rotated plaintext", hosts)
}

// TestTheGenuineOwnershipTransferStillWorksAndIsAttributable is the second
// positive control: the product's ONE real transfer, driven through the admin
// route that performs it.
//
// An instance admin hard-deleting a user re-owns the shared entries that person
// created, so the team keeps them. That has to keep working, has to move the
// exit's notion of owner (or the re-owned entry becomes undirectable forever),
// and has to say on the activity log that it happened.
func TestTheGenuineOwnershipTransferStillWorksAndIsAttributable(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	leaver := mustUser(t, queries, "xfer-leaver@example.com", "user", "")
	admin := mustUser(t, queries, "xfer-admin@example.com", "admin", "")
	mustCollection(t, queries, "coll-xfer", leaver, map[string]string{
		leaver: collRoleManager,
		admin:  collRoleManager,
	})
	mustEntry(t, h, queries, "entry-xfer", leaver, "team-key", "team-key-value")
	placeInCollection(t, queries, "entry-xfer", "coll-xfer")

	users := NewUserHandler(queries, nil)
	users.SetVault(h)
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+leaver, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", leaver)
	rc := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	rc = context.WithValue(rc, timw.UserIDKey, admin)
	rc = context.WithValue(rc, timw.UserRoleKey, "admin")
	users.disposeVaultEntriesOnDelete(req.WithContext(rc), leaver, "xfer-leaver@example.com", admin)

	access, err := queries.GetVaultEntryAccess(ctx, "entry-xfer")
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if access.UserID != admin || access.SecretOwnerUserID != admin {
		t.Fatalf("the genuine transfer left custodian=%q owner=%q, want both %q.\n"+
			"A transfer that moves one and not the other puts UNIQUE(user_id, name) in one namespace "+
			"and the widening right in another.", access.UserID, access.SecretOwnerUserID, admin)
	}
	// It happened for a reason a proof had to state.
	if _, err := vaultegress.AuthorizeTransfer(vaultegress.TransferRequest{
		EntryID: "entry-xfer", Actor: admin, ActorIsInstanceAdmin: false, To: admin, Why: "x",
	}); err == nil {
		t.Fatal("AuthorizeTransfer granted a proof to a non-admin actor; the route's AdminOnly " +
			"middleware would then be the only thing standing between a manager and ownership")
	}

	rows, err := queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
		Action: "admin.entries_reassigned", Limit: 20, Offset: 0,
	})
	if err != nil {
		t.Fatalf("read activity: %v", err)
	}
	found := ""
	for _, r := range rows {
		found = r.Detail.String
	}
	if found == "" {
		t.Fatal("the ownership transfer wrote no admin.entries_reassigned activity row. A transfer " +
			"that moves the authority over a client credential and leaves no trace is not attributable")
	}
	t.Logf("wire, genuine transfer: custodian=%s owner=%s, activity: %s",
		access.UserID, access.SecretOwnerUserID, found)
}

// collectionMemberRequest builds a DELETE /api/collections/{id}/members/{userId}
// carrying the caller's identity, so the real handler runs its real role check.
func collectionMemberRequest(collectionID, targetUser, callerID, callerRole string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete,
		"/api/collections/"+collectionID+"/members/"+targetUser, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", collectionID)
	rctx.URLParams.Add("userId", targetUser)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, timw.UserIDKey, callerID)
	ctx = context.WithValue(ctx, timw.UserRoleKey, callerRole)
	return r.WithContext(ctx)
}

// mustAcceptedMember re-adds somebody to a collection as an ACCEPTED member.
func mustAcceptedMember(t *testing.T, queries *db.Queries, collectionID, userID, role string) {
	t.Helper()
	if err := queries.AddCollectionMember(context.Background(), db.AddCollectionMemberParams{
		CollectionID: collectionID,
		UserID:       userID,
		Role:         role,
		AcceptedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}); err != nil {
		t.Fatalf("re-add member %s to %s: %v", userID, collectionID, err)
	}
}

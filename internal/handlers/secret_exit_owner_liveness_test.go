package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

// THE TWO QUESTIONS recordedOwnerMayDirect ANSWERS THAT NOTHING WAS ASKING.
//
// The round-20 ablation sweep reverted recordedOwnerMayDirect two ways and the
// whole suite stayed green both times:
//
//	owner == ""  ->  fall back to info.UserID     MISSED
//	return owner != "", nil                       MISSED
//
// Neither miss meant the fix was wrong. It meant the three door tests cannot
// see those two shapes, because the attacked fixture they all share happens to
// make both reverts inert: its custodian is an ordinary user, so laundering
// through user_id still fails the owner comparison, and its owner is empty, so
// asking "is one recorded" still answers no.
//
// A guard nothing can fail is not a guard. Each test below is built so that
// exactly one of those reverts delivers the secret, and each states the premise
// that makes it bite, because a fixture that quietly stops biting is how this
// codebase got four green misses in the first place.
//
// Both drive DOOR 3, the unattended sweep. It is the door with no caller at all,
// so nothing in the result can be explained by the request, the session or the
// caller's password, and what the assertions read is what a real listener
// received.

const (
	livenessSecret = "sk_live_OWNER_LIVENESS"
	livenessProv   = "forgejo"
)

// livenessRow is the shared shape: one entry in one collection, created by
// victim, adopted by somebody else, with a provider_meta naming the sink.
type livenessRow struct {
	h       *VaultHandler
	queries *db.Queries
	entryID string
	victim  string
	taker   string
}

// newLivenessRow builds the row up to the point the two tests diverge. It does
// NOT clear the secret owner and it does NOT remove anybody: those are the
// variables, so each test performs its own and says why.
func newLivenessRow(t *testing.T, tag, takerRole, sinkURL string) *livenessRow {
	t.Helper()
	swapProviderHTTP(t)

	h, queries := newCollectionAuthzEnv(t)
	r := &livenessRow{h: h, queries: queries, entryID: "entry-liveness-" + tag}
	r.victim = mustUser(t, queries, "liveness-victim-"+tag+"@example.com", "user", "victim-login-password")
	r.taker = mustUser(t, queries, "liveness-taker-"+tag+"@example.com", takerRole, "taker-login-password")

	coll := "coll-liveness-" + tag
	mustCollection(t, queries, coll, r.victim, map[string]string{
		r.victim: collRoleManager,
		r.taker:  collRoleManager,
	})
	mustEntry(t, h, queries, r.entryID, r.victim, "team-key-liveness-"+tag, livenessSecret)
	placeInCollection(t, queries, r.entryID, coll)

	// The plant. forgejo builds its whole base URL out of meta["instance"], so
	// this single column names the destination outright, and it also arms
	// auto_rotate so the row is in front of the unattended sweep.
	forceProviderConfig(t, h, r.entryID, livenessProv, `{"instance":"`+sinkURL+`"}`)
	return r
}

// removeFromCollection takes a member out, which is how a principal keeps the
// columns they already wrote while losing the right to write more.
func (r *livenessRow) removeFromCollection(t *testing.T, tag, userID string) {
	t.Helper()
	if _, err := r.queries.RemoveCollectionMember(context.Background(), db.RemoveCollectionMemberParams{
		CollectionID: "coll-liveness-" + tag, UserID: userID,
	}); err != nil {
		t.Fatalf("remove %s from the collection: %v", userID, err)
	}
}

// adopt models AdoptAndRenameVaultEntry, which moves user_id and deliberately
// does NOT move secret_owner_user_id.
func (r *livenessRow) adopt(t *testing.T) {
	t.Helper()
	if _, err := r.h.db.Exec(`UPDATE vault_entries SET user_id = ? WHERE id = ?`, r.taker, r.entryID); err != nil {
		t.Fatalf("model the adoption: %v", err)
	}
}

// mustBeDue refuses to read "the sweep sent nothing" off a row the sweep never
// looked at. Without this every test in this file passes for free.
func (r *livenessRow) mustBeDue(t *testing.T) {
	t.Helper()
	due, err := r.queries.ListVaultEntriesNeedingRotation(context.Background())
	if err != nil {
		t.Fatalf("list due entries: %v", err)
	}
	for _, d := range due {
		if d.ID == r.entryID {
			return
		}
	}
	t.Fatalf("ABORT: the row is not due, so the sweep is not exercising it (%d due)", len(due))
}

// sweep runs the unattended rotation and waits for the delivery queue to drain,
// so the wire assertions are not racing it.
func (r *livenessRow) sweep(t *testing.T) {
	t.Helper()
	RotateVaultKeys(r.h.db, r.queries, r.h)
	if !r.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain; the wire assertions would be racing it")
	}
}

// ── the withheld owner, and the friendly-looking way to lose it ─────────────

// TestAWithheldOwnerIsNotLaunderedThroughAnAdminCustodian is the ablation that
// reads "fall back to the custodian for rows the migration withheld".
//
// That revert is inert against an ordinary custodian, because mayConfigureDelivery
// would then compare them against an empty secret_owner_user_id and refuse. It
// is NOT inert against an admin custodian: mayDirectSecretEgress returns true on
// the isAdmin branch before it ever reads the owner column. So an admin who
// adopts an attacked row, which is exactly what an operator does when they go to
// clean one up, would re-arm the attacker's chosen host by touching it.
//
// The premise guard below asserts that fallback WOULD deliver. That is what
// makes this test able to fail.
func TestAWithheldOwnerIsNotLaunderedThroughAnAdminCustodian(t *testing.T) {
	sink := newHeaderSink(t)
	r := newLivenessRow(t, "launder", "admin", sink.URL)
	ctx := context.Background()

	r.removeFromCollection(t, "launder", r.victim)
	r.adopt(t)
	// The deploy: 00034 and 00035 cannot prove who deposited the plaintext on a
	// collection entry, so they withhold.
	clearSecretOwnerForTest(t, r.h, r.entryID)

	access, err := r.queries.GetVaultEntryAccess(ctx, r.entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if access.SecretOwnerUserID != "" {
		t.Fatalf("ABORT: the owner is %q, not withheld; this is not the state under test", access.SecretOwnerUserID)
	}
	if access.UserID != r.taker {
		t.Fatalf("ABORT: the custodian is %q, not the admin; the adoption did not take", access.UserID)
	}
	if !r.h.instanceAdminByRecord(ctx, r.taker) {
		t.Fatal("ABORT: the custodian is not an instance admin by record, so the fallback this test " +
			"exists to refuse would be refused for an unrelated reason")
	}
	// THE ANTI-VACUITY GUARD, and the whole reason this file exists. If the
	// custodian could not direct the secret anyway, a green run here would mean
	// nothing.
	if !r.h.mayConfigureDelivery(ctx, r.taker, r.entryID) {
		t.Fatal("ABORT: the admin custodian may NOT configure delivery, so falling back to them would " +
			"change nothing and this test cannot catch the fallback")
	}
	r.mustBeDue(t)

	r.sweep(t)

	auths, lines, payloads := sink.received()
	if sink.sawSecret(livenessSecret) {
		t.Fatalf("THE WITHHELD OWNER WAS LAUNDERED THROUGH THE CUSTODIAN. The secret reached the "+
			"planted host.\n  auth headers:  %q\n  request lines: %q\n  bodies:        %q",
			auths, lines, payloads)
	}
	if len(lines) != 0 {
		t.Errorf("the planted host received %v; a withheld row should attempt nothing", lines)
	}
}

// TestAnAdminWhoIsTheRecordedOwnerStillDelivers is the control for the test
// above, and it is the one that stops "admins never deliver" from passing as a
// fix. Same admin, same provider, same sink; the only difference is that the
// owner column names them.
func TestAnAdminWhoIsTheRecordedOwnerStillDelivers(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	sink := newHeaderSink(t)
	ctx := context.Background()

	admin := mustUser(t, queries, "liveness-admin-owner@example.com", "admin", "admin-login-password")
	mustEntry(t, h, queries, "entry-liveness-adminowner", admin, "admin-owned-forgejo", livenessSecret)
	forceProviderConfig(t, h, "entry-liveness-adminowner", livenessProv, `{"instance":"`+sink.URL+`"}`)

	access, err := queries.GetVaultEntryAccess(ctx, "entry-liveness-adminowner")
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if access.SecretOwnerUserID != admin {
		t.Fatalf("ABORT: the control's owner is %q, not the admin; it is not the mirror image of the "+
			"attack", access.SecretOwnerUserID)
	}

	RotateVaultKeys(h.db, queries, h)
	if !h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain")
	}

	auths, lines, _ := sink.received()
	if len(lines) == 0 {
		t.Fatal("THE FEATURE IS BROKEN. An admin rotating an entry they own reached nothing, so the " +
			"test above proves nothing")
	}
	if !sink.sawSecret(livenessSecret) {
		t.Fatalf("the sweep reached %v without the key: auths=%q", lines, auths)
	}
}

// ── the recorded owner who is no longer anybody ────────────────────────────

// TestARecordedOwnerWhoLostManageStopsAuthorisingDestinations is the ablation
// that reads "ask whether an owner is RECORDED rather than whether they may
// still direct the secret".
//
// It is inert on the attacked fixture, whose owner is empty. It bites here,
// where the owner IS recorded and has since been removed from the collection the
// entry lives in. That is the same removal the round-7 attack performs, run on
// an instance new enough that the creating statement stamped the owner, which is
// every instance from now on. The attacker keeps the columns they wrote and the
// principal the row names can no longer vouch for them.
//
// The cost is stated in ownerRecordedDestinations rather than discovered here:
// an owner who loses manage stops contributing destinations, and Settings ->
// Ownership is where an admin takes such a row back.
func TestARecordedOwnerWhoLostManageStopsAuthorisingDestinations(t *testing.T) {
	sink := newHeaderSink(t)
	r := newLivenessRow(t, "lostmanage", "user", sink.URL)
	ctx := context.Background()

	r.removeFromCollection(t, "lostmanage", r.victim)
	r.adopt(t)

	access, err := r.queries.GetVaultEntryAccess(ctx, r.entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	// THE PREMISE, and it is the opposite of the withheld case: the owner is
	// recorded. A revert that asks only whether one is recorded says yes here.
	if access.SecretOwnerUserID != r.victim {
		t.Fatalf("ABORT: the recorded owner is %q, not the victim. This test is about a row that HAS "+
			"an owner, so a withheld one would make it vacuous", access.SecretOwnerUserID)
	}
	if access.UserID != r.taker {
		t.Fatalf("ABORT: the custodian is %q, not the taker; the adoption did not take", access.UserID)
	}
	if r.h.grantFor(ctx, r.victim, false, r.entryID).manage {
		t.Fatal("ABORT: the recorded owner still holds manage, so nothing about this row has expired " +
			"and the test cannot catch the revert")
	}
	if r.h.mayConfigureDelivery(ctx, r.victim, r.entryID) {
		t.Fatal("ABORT: the recorded owner may still configure delivery; the premise has regressed")
	}
	r.mustBeDue(t)

	r.sweep(t)

	auths, lines, payloads := sink.received()
	if sink.sawSecret(livenessSecret) {
		t.Fatalf("A RECORDED-BUT-EXPIRED OWNER STILL AUTHORISED THE PLANT. The secret reached the "+
			"planted host.\n  auth headers:  %q\n  request lines: %q\n  bodies:        %q",
			auths, lines, payloads)
	}
	if len(lines) != 0 {
		t.Errorf("the planted host received %v; an expired owner should authorise nothing", lines)
	}
}

// TestARecordedOwnerWhoStillHoldsManageStillDelivers is the control, and it is
// the tightest one in the file: it differs from the test above by a single
// statement, the removal from the collection. If this fails, the rule is not
// refusing expired owners, it is refusing everybody.
func TestARecordedOwnerWhoStillHoldsManageStillDelivers(t *testing.T) {
	sink := newHeaderSink(t)
	r := newLivenessRow(t, "stillholds", "user", sink.URL)
	ctx := context.Background()

	// No removal. The owner is still an accepted manager of the collection.
	if !r.h.mayConfigureDelivery(ctx, r.victim, r.entryID) {
		t.Fatal("ABORT: the still-present owner may not configure delivery, so this control is not " +
			"the mirror image of the attack")
	}
	r.mustBeDue(t)

	r.sweep(t)

	auths, lines, _ := sink.received()
	if len(lines) == 0 {
		t.Fatal("THE FEATURE IS BROKEN. An owner who still holds manage rotated to nothing, so the " +
			"expired-owner test above proves nothing")
	}
	if !sink.sawSecret(livenessSecret) {
		t.Fatalf("the sweep reached %v without the key: auths=%q", lines, auths)
	}
}

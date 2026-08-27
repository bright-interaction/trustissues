package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

// collectionRequest builds an authenticated request against a collection route,
// with the chi {id} param and the middleware identity keys populated. Same shape
// as vaultAuthzRequest, which does the entry-scoped equivalent.
func collectionRequest(method, path, userID, role, collectionID, body string) *http.Request {
	return vaultAuthzRequest(method, path, userID, role, collectionID, body)
}

// TestPendingInviteDoesNotRevealWhetherAnAccountExists locks the cross-client
// isolation fix on the members list.
//
// The attack needed no special role. Any authenticated user, including a
// vault_only account (the role /api/invitations/redeem hands out over a PUBLIC
// endpoint), could:
//
//	POST /api/collections            -> 201, creator seeded as accepted MANAGER
//	POST /api/collections/{id}/members {"email":"victim@other-client.com"}
//	                                 -> 200, constant "if that address belongs
//	                                    to an account..." wording, leaking nothing
//	GET  /api/collections/{id}/members
//	                                 -> a pending row appeared, carrying the
//	                                    victim's user_id, email AND real name,
//	                                    but ONLY when the address had an account
//
// So the careful constant-time answer on AddMember was undone one call later,
// twice over: the identity fields handed out the display name and user id, and
// the mere presence of the row answered "is this address registered?". On a
// shared instance that is client A enumerating client B's staff directory, which
// is required for the scoped external-client mode: one client's collection
// manager must not learn whether an address belongs to another client account.
//
// The invariant: a pending seat looks the same whether or not the address
// matches an account, and identity appears only after the invitee accepts.
func TestPendingInviteDoesNotRevealWhetherAnAccountExists(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewCollectionHandler(queries, vh)
	ctx := context.Background()

	// The attacker holds the most restricted role in the product, to show the
	// enumeration does not need any privilege at all.
	attacker := mustUser(t, queries, "attacker@attacker-client.example", "vault_only", "")
	victim, err := queries.CreateUser(ctx, db.CreateUserParams{
		Email:        "victim@other-client.example",
		PasswordHash: "not-a-real-hash",
		Name:         toNullString("Victoria Realname"),
		Role:         "user",
	})
	if err != nil {
		t.Fatalf("create victim: %v", err)
	}

	// Step 1: the attacker creates a collection through the real handler and is
	// seeded as its accepted manager.
	rec := httptest.NewRecorder()
	h.Create(rec, collectionRequest(http.MethodPost, "/api/collections", attacker, "vault_only", "",
		`{"name":"probe","description":""}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create collection: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var created collectionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created collection: %v", err)
	}
	collID := created.ID
	if collID == "" {
		t.Fatal("ABORT: no collection id came back, the probe cannot run")
	}

	// Step 2: probe one address that HAS an account and one that does not. Both
	// must answer identically, which they already did before this fix.
	invite := func(email string) string {
		t.Helper()
		rr := httptest.NewRecorder()
		h.AddMember(rr, collectionRequest(http.MethodPost, "/api/collections/"+collID+"/members",
			attacker, "vault_only", collID, `{"email":"`+email+`","role":"viewer"}`))
		if rr.Code != http.StatusOK {
			t.Fatalf("invite %s: HTTP %d: %s", email, rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
	hit := invite("victim@other-client.example")
	miss := invite("nobody-here@other-client.example")
	if hit != miss {
		t.Fatalf("AddMember answered differently for a registered and an unregistered address:\n hit:  %s\n miss: %s", hit, miss)
	}

	// Pin both seat rows to one timestamp before listing. added_at is the field
	// most likely to drift back into a distinguisher (the membership row has its
	// own added_at), and comparing two live clock values would pass by
	// coincidence rather than by rule. With the source rows pinned, any seat
	// whose added_at comes from somewhere else shows up as a difference.
	if _, err := vh.db.Exec(
		`UPDATE collection_invitations SET created_at = '2026-01-01 00:00:00' WHERE collection_id = ?`,
		collID); err != nil {
		t.Fatalf("pin seat timestamps: %v", err)
	}

	// Step 3: the members list. This is where the answer used to leak.
	listMembers := func(who, role string) (int, string, []memberResponse) {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ListMembers(rr, collectionRequest(http.MethodGet, "/api/collections/"+collID+"/members",
			who, role, collID, ""))
		var got []memberResponse
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode members: %v (%s)", err, rr.Body.String())
			}
		}
		return rr.Code, rr.Body.String(), got
	}

	code, raw, members := listMembers(attacker, "vault_only")
	if code != http.StatusOK {
		t.Fatalf("list members: HTTP %d: %s", code, raw)
	}
	if strings.Contains(raw, victim.ID) {
		t.Errorf("the members list leaked the victim's user id for an UNACCEPTED invite: %s", raw)
	}
	if strings.Contains(raw, "Victoria Realname") {
		t.Errorf("the members list leaked the victim's display name for an UNACCEPTED invite: %s", raw)
	}

	// The two probed seats must be indistinguishable apart from the address the
	// attacker typed themselves. Absence is a leak too: it used to be the whole
	// signal for an address with no account.
	var hitSeat, missSeat *memberResponse
	for i := range members {
		switch members[i].Email {
		case "victim@other-client.example":
			hitSeat = &members[i]
		case "nobody-here@other-client.example":
			missSeat = &members[i]
		}
	}
	if hitSeat == nil || missSeat == nil {
		t.Fatalf("expected a pending seat for BOTH probed addresses; a missing seat is itself the "+
			"account-existence answer. got %s", raw)
	}
	for _, c := range []struct {
		label string
		seat  *memberResponse
	}{{"registered address", hitSeat}, {"unregistered address", missSeat}} {
		if !c.seat.Pending {
			t.Errorf("%s: seat is not marked pending", c.label)
		}
		if c.seat.UserID != "" {
			t.Errorf("%s: pending seat carries a user id %q", c.label, c.seat.UserID)
		}
		if c.seat.Name != "" {
			t.Errorf("%s: pending seat carries a display name %q", c.label, c.seat.Name)
		}
		if c.seat.AcceptedAt != nil {
			t.Errorf("%s: pending seat carries an accepted_at", c.label)
		}
	}
	if hitSeat.Role != missSeat.Role {
		t.Errorf("pending seats differ in role: %q vs %q", hitSeat.Role, missSeat.Role)
	}
	// Field-by-field checks only cover the fields somebody thought to list, and
	// added_at was not one of them: both seats read it from
	// collection_invitations.created_at today, but a change that sourced the hit
	// seat from collection_members.added_at instead would reintroduce a
	// distinguisher and keep every assertion above green. Compare the WHOLE
	// struct, with the address the attacker typed themselves zeroed out.
	hitCmp, missCmp := *hitSeat, *missSeat
	hitCmp.Email, missCmp.Email = "", ""
	if !reflect.DeepEqual(hitCmp, missCmp) {
		t.Errorf("the two pending seats are not byte-identical, so one of the fields answers "+
			"'does this address have an account':\n registered:   %s\n unregistered: %s",
			renderSeat(hitCmp), renderSeat(missCmp))
	}

	// The audit trail is a surface too. collection.member_invited used to be
	// written only when the address matched an account, so activity_log answered
	// the question this endpoint refuses to answer, for anyone who can read it.
	var hitRows, missRows int
	if err := vh.db.QueryRow(
		`SELECT COUNT(*) FROM activity_log WHERE action = 'collection.member_invited' AND detail LIKE ?`,
		"%victim@other-client.example%").Scan(&hitRows); err != nil {
		t.Fatalf("count activity rows: %v", err)
	}
	if err := vh.db.QueryRow(
		`SELECT COUNT(*) FROM activity_log WHERE action = 'collection.member_invited' AND detail LIKE ?`,
		"%nobody-here@other-client.example%").Scan(&missRows); err != nil {
		t.Fatalf("count activity rows: %v", err)
	}
	if hitRows != missRows {
		t.Errorf("the activity log recorded %d rows for the registered address and %d for the unregistered one; "+
			"that difference is the same oracle in the audit trail", hitRows, missRows)
	}

	// Step 4: a member below manager gets no address at all. They did not type
	// it, and an unanswered invitation is not yet a relationship the invitee has
	// agreed to expose to the rest of the team.
	bystander := mustUser(t, queries, "bystander@attacker-client.example", "user", "")
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: collID, UserID: bystander, Role: collRoleViewer,
		AcceptedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}); err != nil {
		t.Fatalf("seed bystander: %v", err)
	}
	_, bystanderRaw, bystanderMembers := listMembers(bystander, "user")
	if strings.Contains(bystanderRaw, "victim@other-client.example") ||
		strings.Contains(bystanderRaw, "nobody-here@other-client.example") {
		t.Errorf("a non-manager member saw the invited addresses: %s", bystanderRaw)
	}
	pendingSeen := 0
	for _, m := range bystanderMembers {
		if m.Pending {
			pendingSeen++
		}
	}
	if pendingSeen != 2 {
		t.Errorf("a non-manager saw %d pending seats, want 2 (the seat stays visible, only the identity is withheld)", pendingSeen)
	}

	// Step 5: accepting is what makes identity visible. Otherwise this fix would
	// have broken the point of a shared collection rather than secured it.
	rec = httptest.NewRecorder()
	h.AcceptInvite(rec, collectionRequest(http.MethodPost, "/api/collections/"+collID+"/accept",
		victim.ID, "user", collID, ""))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("victim accepts: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	_, afterRaw, after := listMembers(attacker, "vault_only")
	var accepted *memberResponse
	for i := range after {
		if after[i].UserID == victim.ID {
			accepted = &after[i]
		}
	}
	if accepted == nil {
		t.Fatalf("an ACCEPTED member is invisible in the members list: %s", afterRaw)
	}
	if accepted.Pending {
		t.Error("an accepted member is still marked pending")
	}
	if accepted.Email != "victim@other-client.example" || accepted.Name != "Victoria Realname" {
		t.Errorf("an accepted member should be fully visible, got email=%q name=%q", accepted.Email, accepted.Name)
	}
}

// TestRescindInvitationWithdrawsSeatWithoutAnOracle covers the endpoint the
// members-list fix made necessary.
//
// Removal is by user id, and a pending seat no longer publishes one, so without
// an email-addressed rescind an invitation could never be withdrawn again. That
// is the same dead end the acceptance-agnostic existence check in RemoveMember
// was written to fix (TestPendingInviteCanBeRescinded), so it must not come
// back through the new door. The rescind itself must also stay silent about
// whether the address matched an account.
func TestRescindInvitationWithdrawsSeatWithoutAnOracle(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewCollectionHandler(queries, vh)
	ctx := context.Background()

	manager := mustUser(t, queries, "mgr@example.com", "user", "")
	invitee := mustUser(t, queries, "oops@example.com", "user", "")
	mustCollection(t, queries, "coll-rescind", manager, map[string]string{manager: collRoleManager})

	invite := func(email string) {
		t.Helper()
		rr := httptest.NewRecorder()
		h.AddMember(rr, collectionRequest(http.MethodPost, "/api/collections/coll-rescind/members",
			manager, "user", "coll-rescind", `{"email":"`+email+`","role":"viewer"}`))
		if rr.Code != http.StatusOK {
			t.Fatalf("invite %s: HTTP %d: %s", email, rr.Code, rr.Body.String())
		}
	}
	invite("oops@example.com")
	invite("never-registered@example.com")

	rescind := func(email string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		h.RescindInvitation(rr, collectionRequest(http.MethodDelete, "/api/collections/coll-rescind/invitations",
			manager, "user", "coll-rescind", `{"email":"`+email+`"}`))
		return rr
	}

	// Identical answers for a registered address, an unregistered one, and one
	// that was never invited at all.
	got := rescind("oops@example.com")
	if got.Code != http.StatusNoContent {
		t.Fatalf("rescind a real invite: HTTP %d: %s", got.Code, got.Body.String())
	}
	for _, email := range []string{"never-registered@example.com", "was-never-invited@example.com"} {
		rr := rescind(email)
		if rr.Code != got.Code || rr.Body.String() != got.Body.String() {
			t.Errorf("rescinding %q answered %d %q, want the same %d %q as a real invite: the difference "+
				"is an account-existence oracle", email, rr.Code, rr.Body.String(), got.Code, got.Body.String())
		}
	}

	// And it really withdrew it: the invitation must no longer be acceptable.
	res, err := queries.AcceptCollectionInvite(ctx, db.AcceptCollectionInviteParams{
		CollectionID: "coll-rescind", UserID: invitee,
	})
	if err != nil {
		t.Fatalf("accept after rescind: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Fatal("a rescinded invitation was still acceptable")
	}

	rr := httptest.NewRecorder()
	h.ListMembers(rr, collectionRequest(http.MethodGet, "/api/collections/coll-rescind/members",
		manager, "user", "coll-rescind", ""))
	if strings.Contains(rr.Body.String(), "oops@example.com") ||
		strings.Contains(rr.Body.String(), "never-registered@example.com") {
		t.Errorf("a withdrawn invitation is still listed: %s", rr.Body.String())
	}
}

// renderSeat prints a member row with its timestamp POINTERS dereferenced. %+v
// on the struct prints addresses for added_at and accepted_at, which is exactly
// the field a differential is most likely to hide in, and an address tells the
// reader nothing about whether the two seats differ.
func renderSeat(m memberResponse) string {
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	return fmt.Sprintf("user_id=%q email=%q name=%q role=%q added_at=%s accepted_at=%s pending=%t",
		m.UserID, m.Email, m.Name, m.Role, str(m.AddedAt), str(m.AcceptedAt), m.Pending)
}

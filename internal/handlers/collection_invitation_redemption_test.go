package handlers

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// TestInviteToAnUnregisteredAddressCanBeRedeemed walks the whole client
// onboarding flow: invite -> register -> redeem -> membership.
//
// Recording collection seats by EMAIL is what stopped the members list from
// answering "does this address have an account". It also broke the flow the
// feature exists for. collection_members.user_id is a foreign key, so an invite
// to an address with no account wrote a seat and nothing else, and NOTHING ever
// converted that seat into a membership:
//
//	AddMember("newhire@rev.example")     -> 200 "an invitation is now pending"
//	(the address then signs up)
//	GET  /api/collections/invitations    -> []
//	POST /api/collections/{id}/accept    -> 404 "no pending invitation for this collection"
//	GET  /api/collections/{id}/members   -> a pending seat, forever
//
// Before the seat existed the invite was silently dropped, which was at least
// honest. Now the manager sees a pending row that will never resolve, so the
// regression is a lie in the UI as well as a dead end.
//
// The invariant: a seat created for an address with no account becomes a real
// PENDING membership the moment that account is created, the invitee can accept
// it, and the members list looks exactly the same before and after the account
// appears (or the claim itself becomes the account-existence oracle).
func TestInviteToAnUnregisteredAddressCanBeRedeemed(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewCollectionHandler(queries, vh)
	uh := NewUserHandler(queries, &config.Config{VaultKey: strings.Repeat("k", 32)})
	uh.SetVault(vh)
	ctx := context.Background()

	const newHire = "newhire@rev.example"
	manager := mustUser(t, queries, "manager@rev.example", "user", "")
	admin := mustUser(t, queries, "admin@rev.example", "admin", "")
	mustCollection(t, queries, "coll-onboarding", manager, map[string]string{manager: collRoleManager})

	// 1. The manager invites a client who has no account yet. This is the whole
	//    point of the shared instance: invite first, they sign up after.
	rec := httptest.NewRecorder()
	h.AddMember(rec, collectionRequest(http.MethodPost, "/api/collections/coll-onboarding/members",
		manager, "user", "coll-onboarding", `{"email":"`+newHire+`","role":"editor"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("invite an unregistered address: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	members := func() []memberResponse {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ListMembers(rr, collectionRequest(http.MethodGet, "/api/collections/coll-onboarding/members",
			manager, "user", "coll-onboarding", ""))
		if rr.Code != http.StatusOK {
			t.Fatalf("list members: HTTP %d: %s", rr.Code, rr.Body.String())
		}
		var got []memberResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode members: %v (%s)", err, rr.Body.String())
		}
		return got
	}
	seatFor := func(list []memberResponse, email string) *memberResponse {
		for i := range list {
			if list[i].Email == email {
				return &list[i]
			}
		}
		return nil
	}
	beforeSignup := seatFor(members(), newHire)
	if beforeSignup == nil || !beforeSignup.Pending {
		t.Fatalf("ABORT: the invitation left no pending seat, the flow cannot be tested: %+v", members())
	}

	// 2. The operator sends them an instance invitation and they redeem it,
	//    which is the only way a new account is created on a closed instance.
	inviteRec := httptest.NewRecorder()
	inviteReq := httptest.NewRequest(http.MethodPost, "/api/admin/invitations",
		strings.NewReader(`{"email":"`+newHire+`","name":"New Hire","role":"user"}`))
	inviteReq = inviteReq.WithContext(context.WithValue(inviteReq.Context(), middleware.UserIDKey, admin))
	uh.CreateInvitation(inviteRec, inviteReq)
	if inviteRec.Code != http.StatusCreated && inviteRec.Code != http.StatusOK {
		t.Fatalf("create instance invitation: HTTP %d: %s", inviteRec.Code, inviteRec.Body.String())
	}
	var created struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(inviteRec.Body.Bytes(), &created); err != nil || created.Code == "" {
		t.Fatalf("no invitation code came back: %s", inviteRec.Body.String())
	}

	redeemRec := httptest.NewRecorder()
	uh.RedeemInvitation(redeemRec, httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
		strings.NewReader(`{"code":"`+created.Code+`","password":"N3wHirePassw0rd!"}`)))
	if redeemRec.Code != http.StatusOK && redeemRec.Code != http.StatusCreated {
		t.Fatalf("redeem: HTTP %d: %s", redeemRec.Code, redeemRec.Body.String())
	}
	var redeemed redeemInvitationResponse
	if err := json.Unmarshal(redeemRec.Body.Bytes(), &redeemed); err != nil || redeemed.User.ID == "" {
		t.Fatalf("decode redemption: %v (%s)", err, redeemRec.Body.String())
	}
	newUser := redeemed.User.ID

	// 3. The seat is now a real pending invitation the new account can see.
	pendingRec := httptest.NewRecorder()
	h.ListPendingInvites(pendingRec, collectionRequest(http.MethodGet, "/api/collections/invitations",
		newUser, "user", "", ""))
	var pending []pendingInviteResponse
	if err := json.Unmarshal(pendingRec.Body.Bytes(), &pending); err != nil {
		t.Fatalf("decode pending invites: %v (%s)", err, pendingRec.Body.String())
	}
	found := false
	for _, p := range pending {
		if p.CollectionID == "coll-onboarding" {
			found = true
			if p.Role != collRoleEditor {
				t.Errorf("the claimed seat carries role %q, want the invited %q", p.Role, collRoleEditor)
			}
			if p.InvitedByEmail != "manager@rev.example" {
				t.Errorf("the consent card should name who invited them, got %q", p.InvitedByEmail)
			}
		}
	}
	if !found {
		t.Fatalf("the account was created but the invitation is still a dead letter: %s", pendingRec.Body.String())
	}

	// 4. The manager's view must not have changed just because the address now
	//    has an account. A difference here is the enumeration oracle again, one
	//    step later: invite an address, watch the members list, learn whether
	//    they registered.
	afterSignup := seatFor(members(), newHire)
	if afterSignup == nil {
		t.Fatalf("the pending seat vanished once the account existed: %+v", members())
	}
	if !reflect.DeepEqual(*beforeSignup, *afterSignup) {
		t.Errorf("the members list changed when the address got an account, which answers "+
			"'is this address registered':\n before: %+v\n after:  %+v", *beforeSignup, *afterSignup)
	}

	// 5. And they can actually accept, which is the step that was 404ing.
	acceptRec := httptest.NewRecorder()
	h.AcceptInvite(acceptRec, collectionRequest(http.MethodPost, "/api/collections/coll-onboarding/accept",
		newUser, "user", "coll-onboarding", ""))
	if acceptRec.Code != http.StatusNoContent {
		t.Fatalf("accept after redeeming: HTTP %d: %s", acceptRec.Code, acceptRec.Body.String())
	}

	final := members()
	accepted := seatFor(final, newHire)
	if accepted == nil {
		t.Fatalf("the accepted member is invisible in the members list: %+v", final)
	}
	if accepted.Pending || accepted.UserID != newUser || accepted.Role != collRoleEditor {
		t.Errorf("after accepting, the member should be a full editor with an id: %+v", *accepted)
	}
	pendingSeats := 0
	for _, m := range final {
		if m.Pending {
			pendingSeats++
		}
	}
	if pendingSeats != 0 {
		t.Errorf("an answered invitation is still listed as pending: %+v", final)
	}

	// 6. The membership must be real, not just rendered: the entries in the
	//    collection are what they were invited for.
	role, err := queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: "coll-onboarding", UserID: newUser,
	})
	if err != nil {
		t.Fatalf("the accepted membership is not in the database: %v", err)
	}
	if role != collRoleEditor {
		t.Errorf("stored role = %q, want %q", role, collRoleEditor)
	}
}

// TestEveryAccountCreationPathClaimsCollectionInvitations is the structural half
// of the same fix.
//
// An invitation seat only becomes redeemable if the path that creates the
// account claims it, and there are three such paths (first-run register, admin
// create, invitation redeem). Miss one and that path's users are back in the
// dead-letter state, silently, for exactly the accounts that path creates. This
// is the same one-property-many-doors shape as the AI gateway and the capability
// bridge, so it gets the same kind of guard: a new account-creation path fails
// here until it claims.
func TestEveryAccountCreationPathClaimsCollectionInvitations(t *testing.T) {
	// The queries that insert a users row. Any function calling one of these has
	// created an account.
	creators := map[string]bool{
		"CreateUser":        true,
		"CreateInvitedUser": true,
		"CreateFirstAdmin":  true,
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			createsAccount, claims := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.SelectorExpr:
					if creators[f.Sel.Name] {
						createsAccount = true
					}
				case *ast.Ident:
					if f.Name == "claimCollectionInvitations" || f.Name == "claimCollectionInvitationsBestEffort" {
						claims = true
					}
				}
				return true
			})
			if !createsAccount {
				continue
			}
			found++
			if !claims {
				t.Errorf("%s:%s creates an account but never calls claimCollectionInvitations, so a collection "+
					"seat waiting for that address stays a dead letter: the invitee cannot accept and the manager "+
					"sees a pending row that never resolves", name, funcIdentity(fn))
			}
		}
	}
	if found < 3 {
		t.Errorf("found only %d account-creation paths, expected at least 3 (register, admin create, redeem). "+
			"If a path was renamed, update this guard rather than letting it scan nothing.", found)
	}
}

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// TestLastManagerCannotLeaveViaDecline locks a guard that existed on one exit
// from a collection but not the other.
//
// RemoveMember refuses to remove the last accepted manager ("cannot remove the
// last manager; promote another member first"). DeclineInvite calls the same
// RemoveCollectionMember query with no checks at all, and it doubles as "leave
// this collection", so the sole manager could simply walk out. The collection
// then has no manager: nobody can add a member, change a role or delete it, and
// every secret inside is stranded with only an instance admin able to recover
// it.
//
// Two sibling handlers, one shared invariant, one guard: the same shape as the
// capability lookup that was scoped while the ACL behind it was not.
func TestLastManagerCannotLeaveViaDecline(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	boss := mustUser(t, queries, "decline-boss@example.com", "user", "")
	member := mustUser(t, queries, "decline-member@example.com", "user", "")

	mustCollection(t, queries, "coll-solo", boss, map[string]string{
		boss:   collRoleManager,
		member: collRoleEditor,
	})

	ch := &CollectionHandler{queries: queries}
	decline := func(userID string) (int, string) {
		r := httptest.NewRequest(http.MethodPost, "/api/collections/coll-solo/decline", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "coll-solo")
		r = r.WithContext(context.WithValue(
			context.WithValue(r.Context(), chi.RouteCtxKey, rctx),
			middleware.UserIDKey, userID))
		w := httptest.NewRecorder()
		ch.DeclineInvite(w, r)
		return w.Code, w.Body.String()
	}

	// Guard the setup: the manager must actually be an accepted manager, or the
	// refusal below would be passing for the wrong reason.
	if role, err := queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: "coll-solo", UserID: boss,
	}); err != nil || role != collRoleManager {
		t.Fatalf("ABORT: fixture manager role is %q (err=%v)", role, err)
	}

	code, body := decline(boss)
	if code != http.StatusConflict {
		t.Fatalf("the last manager left the collection (%d): %s\n"+
			"nobody can now manage members or delete it, and its secrets are stranded", code, body)
	}

	// A non-manager must still be able to leave freely: a guard that blocked
	// everyone would pass the assertion above while breaking the feature.
	if code, body := decline(member); code != http.StatusNoContent {
		t.Errorf("an editor could not leave the collection (%d): %s", code, body)
	}

	// And once a second manager exists, the first may leave.
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: "coll-solo", UserID: member, Role: collRoleManager,
	}); err != nil {
		t.Fatalf("add second manager: %v", err)
	}
	if _, err := queries.AcceptCollectionInvite(ctx, db.AcceptCollectionInviteParams{
		CollectionID: "coll-solo", UserID: member,
	}); err != nil {
		t.Fatalf("accept second manager: %v", err)
	}
	if code, body := decline(boss); code != http.StatusNoContent {
		t.Errorf("a manager could not leave even with a second manager present (%d): %s", code, body)
	}
}

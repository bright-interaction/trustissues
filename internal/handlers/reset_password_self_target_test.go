package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// TestResetPasswordRefusesSelfTarget locks the P0 escalation a stolen admin
// API key could otherwise use to obtain a login it fully controls.
//
// ResetPassword never compared the target to the caller, unlike its two
// siblings (Update refuses self-demotion, Delete refuses self-deletion) and
// unlike AuthHandler.ChangePassword, which additionally requires the CURRENT
// password. The route is AdminOnly, and AdminOnly is satisfied by a bare
// X-API-Key: the API-key auth branch fills IsAdmin from the users row via
// enrichUserContext, no session or current-password check involved.
//
// So a stolen admin API key alone could chain: GET /api/auth/me for its own
// id, POST /api/admin/users/{self}/reset-password with a password of the
// attacker's choosing (204, no current password required), log in with it,
// then POST /api/vault/unlock to read plaintext of every secret in the
// instance. require_totp defaults false, so nothing in the shipped default
// stops this.
//
// The fix is symmetric with Update and Delete: refuse when target == caller.
// Admins change their OWN password through ChangePassword instead, which
// demands the current one.
func TestResetPasswordRefusesSelfTarget(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "self-reset-admin@example.com", "admin", "admin-original-pw-0123")

	users := NewUserHandler(queries, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+admin+"/reset-password",
		strings.NewReader(`{"password":"AttackerChosenPassw0rd!"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", admin)
	rc := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	rc = context.WithValue(rc, timw.UserIDKey, admin)
	rc = context.WithValue(rc, timw.UserRoleKey, "admin")
	req = req.WithContext(rc)

	rec := httptest.NewRecorder()
	users.ResetPassword(rec, req)

	if rec.Code == http.StatusNoContent {
		t.Fatalf("ESCALATION REPRODUCED: a caller reset their OWN password through the admin route "+
			"and got %d with no current password required. Chained with the stolen API key that made "+
			"this call possible in the first place, this reaches a login the attacker fully controls "+
			"and from there plaintext of every vault secret via POST /api/vault/unlock. Body: %s",
			rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 refusing the self-targeted reset, got %d: %s", rec.Code, rec.Body.String())
	}

	// The guard must not be "refuse every reset": resetting SOMEONE ELSE'S
	// password, the route's actual purpose, still has to work.
	other := mustUser(t, queries, "self-reset-victim@example.com", "user", "victim-original-pw-0123")
	req2 := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+other+"/reset-password",
		strings.NewReader(`{"password":"AdminChosenPassw0rd!23"}`))
	rctx2 := chi.NewRouteContext()
	rctx2.URLParams.Add("id", other)
	rc2 := context.WithValue(req2.Context(), chi.RouteCtxKey, rctx2)
	rc2 = context.WithValue(rc2, timw.UserIDKey, admin)
	rc2 = context.WithValue(rc2, timw.UserRoleKey, "admin")
	req2 = req2.WithContext(rc2)

	rec2 := httptest.NewRecorder()
	users.ResetPassword(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("resetting ANOTHER user's password was refused (%d): %s; the guard is too broad",
			rec2.Code, rec2.Body.String())
	}
}

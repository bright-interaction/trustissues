package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// mustServiceIdentity seeds a live (unrevoked) service identity owned by
// ownerID and returns its id.
func mustServiceIdentity(t *testing.T, queries *db.Queries, ownerID, name string) string {
	t.Helper()
	id := generateID()
	if err := queries.CreateServiceIdentity(context.Background(), db.CreateServiceIdentityParams{
		ID:              id,
		Name:            name,
		Description:     "",
		AllowedSecrets:  "[]",
		KeyHash:         "hash-" + id,
		KeyPrefix:       id[:8],
		CreatedByUserID: sql.NullString{String: ownerID, Valid: true},
	}); err != nil {
		t.Fatalf("seed service identity %s: %v", name, err)
	}
	return id
}

// serviceIdentityIsLive reports whether id is still an unrevoked identity
// owned by ownerID, using the same query the runtime gate and the offboarding
// path both rely on.
func serviceIdentityIsLive(t *testing.T, queries *db.Queries, ownerID, id string) bool {
	t.Helper()
	rows, err := queries.ListServiceIdentitiesByUser(context.Background(), sql.NullString{String: ownerID, Valid: true})
	if err != nil {
		t.Fatalf("list service identities: %v", err)
	}
	for _, row := range rows {
		if row.ID == id {
			return true
		}
	}
	return false
}

// TestResetPasswordRevokesServiceIdentity is the P1 half of this fix.
//
// user_offboard.go's docstring claimed service-identity revocation was
// "inherited by all three callers (disable, delete, password reset)" while
// the code only wired it into two (disable, delete). ResetPassword revoked
// sessions and API keys inline but never touched service_identities, so an
// admin resetting a compromised account's password in response to an
// incident left that account's machine credentials live: FetchOwnSecrets
// resolves every secret as the identity's created_by_user_id and keeps
// serving plaintext, including values rotated after the reset, with
// revoked_at still NULL.
//
// This proves the shared invalidateCredentials helper closes that gap for
// the admin reset path.
func TestResetPasswordRevokesServiceIdentity(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "reset-svc-admin@example.com", "admin", "admin-original-pw-0123")
	victim := mustUser(t, queries, "reset-svc-victim@example.com", "user", "victim-original-pw-0123")
	svc := mustServiceIdentity(t, queries, victim, "reset-svc-identity")

	if !serviceIdentityIsLive(t, queries, victim, svc) {
		t.Fatal("ABORT: fixture identity is not live before the reset; the test would pass for the wrong reason")
	}

	users := NewUserHandler(queries, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+victim+"/reset-password",
		strings.NewReader(`{"password":"AdminChosenPassw0rd!23"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", victim)
	rc := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	rc = context.WithValue(rc, timw.UserIDKey, admin)
	rc = context.WithValue(rc, timw.UserRoleKey, "admin")
	req = req.WithContext(rc)

	rec := httptest.NewRecorder()
	users.ResetPassword(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("reset failed (%d): %s", rec.Code, rec.Body.String())
	}

	if serviceIdentityIsLive(t, queries, victim, svc) {
		t.Fatal("an admin password reset left the target's service identity LIVE. A stolen service key " +
			"tied to this account keeps reading its vault straight through the incident-response reset " +
			"meant to cut it off.")
	}

	rows, err := queries.ListActivityEntriesByAction(context.Background(), db.ListActivityEntriesByActionParams{
		Action: "admin.service_identities_revoked", Limit: 20, Offset: 0,
	})
	if err != nil {
		t.Fatalf("read activity: %v", err)
	}
	found := false
	for _, r := range rows {
		if strings.Contains(r.Detail.String, "reset-svc-victim@example.com") {
			found = true
		}
	}
	if !found {
		t.Error("the service-identity revocation triggered by a password reset wrote no " +
			"admin.service_identities_revoked activity row naming the account; a revoked machine " +
			"credential with no trace looks like a mystery outage to whoever owns it")
	}
}

// TestChangePasswordRevokesServiceIdentity is the ChangePassword half of the
// same gap: a user's own incident-response password change (after, say,
// their laptop is compromised) has to cut off service identities they minted
// too, or a stolen service key survives the very action meant to lock the
// account down.
func TestChangePasswordRevokesServiceIdentity(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "change-svc-user@example.com", "user", "current-original-pw-0123")
	svc := mustServiceIdentity(t, queries, userID, "change-svc-identity")

	if !serviceIdentityIsLive(t, queries, userID, svc) {
		t.Fatal("ABORT: fixture identity is not live before the change; the test would pass for the wrong reason")
	}

	auth := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password",
		strings.NewReader(`{"current_password":"current-original-pw-0123","new_password":"BrandNewPassw0rd!23"}`))
	rc := context.WithValue(req.Context(), timw.UserIDKey, userID)
	rc = context.WithValue(rc, timw.UserRoleKey, "user")
	req = req.WithContext(rc)

	rec := httptest.NewRecorder()
	auth.ChangePassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password failed (%d): %s", rec.Code, rec.Body.String())
	}

	if serviceIdentityIsLive(t, queries, userID, svc) {
		t.Fatal("a self-service password change left the caller's OWN service identity LIVE. A stolen " +
			"service key survives the exact incident-response action meant to lock the account down.")
	}
}

// changePasswordTestCurrentPassword is the fixture password for the
// change-password step below, which needs to supply it back as
// current_password.
const changePasswordTestCurrentPassword = "current-original-pw-0123"

// TestEveryCredentialInvalidatingActionRevokesServiceIdentities is the
// caller-set guard: the full set of actions this codebase considers
// "someone's reach ends now" (disable, delete, admin password reset,
// self-service password change) each has to leave no live service identity
// behind for its target.
//
// This is deliberately behavioural rather than a source-text match against a
// helper name. A structural grep for a call to some shared function rots the
// moment that function is renamed or the logic is inlined differently per
// caller, and this codebase has already shipped that exact failure mode
// twice: a rekey guard anchored on one spelling that reported clean while
// three writers had no durability, and a mirror gate that matched its own
// source. Driving each of the four real HTTP entry points end-to-end and
// asserting the observable outcome (a previously-live service identity is
// revoked) survives any of those refactors; it only breaks, correctly, if one
// of the four actions actually stops revoking.
//
// A fifth action added later that reintroduces this bug by revoking sessions
// and API keys inline without also revoking service identities will not be
// caught by this test automatically, since it does not exist yet to be
// driven. What this test guarantees is that the four actions on record today
// cannot silently regress one at a time, the way ResetPassword did.
func TestEveryCredentialInvalidatingActionRevokesServiceIdentities(t *testing.T) {
	type step struct {
		name string
		run  func(t *testing.T, queries *db.Queries, vault *VaultHandler, admin, target string)
	}

	steps := []step{
		{
			name: "disable",
			run: func(t *testing.T, queries *db.Queries, vault *VaultHandler, admin, target string) {
				users := NewUserHandler(queries, nil)
				users.SetVault(vault)
				req := httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+target,
					strings.NewReader(`{"disabled":true}`))
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("id", target)
				rc := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
				rc = context.WithValue(rc, timw.UserIDKey, admin)
				rc = context.WithValue(rc, timw.UserRoleKey, "admin")
				req = req.WithContext(rc)
				rec := httptest.NewRecorder()
				users.Update(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("disable failed (%d): %s", rec.Code, rec.Body.String())
				}
			},
		},
		{
			name: "delete",
			run: func(t *testing.T, queries *db.Queries, vault *VaultHandler, admin, target string) {
				users := NewUserHandler(queries, nil)
				users.SetVault(vault)
				req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+target, nil)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("id", target)
				rc := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
				rc = context.WithValue(rc, timw.UserIDKey, admin)
				rc = context.WithValue(rc, timw.UserRoleKey, "admin")
				req = req.WithContext(rc)
				rec := httptest.NewRecorder()
				users.Delete(rec, req)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("delete failed (%d): %s", rec.Code, rec.Body.String())
				}
			},
		},
		{
			name: "reset-password",
			run: func(t *testing.T, queries *db.Queries, vault *VaultHandler, admin, target string) {
				users := NewUserHandler(queries, nil)
				users.SetVault(vault)
				req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+target+"/reset-password",
					strings.NewReader(`{"password":"AdminChosenPassw0rd!23"}`))
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("id", target)
				rc := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
				rc = context.WithValue(rc, timw.UserIDKey, admin)
				rc = context.WithValue(rc, timw.UserRoleKey, "admin")
				req = req.WithContext(rc)
				rec := httptest.NewRecorder()
				users.ResetPassword(rec, req)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("reset-password failed (%d): %s", rec.Code, rec.Body.String())
				}
			},
		},
		{
			// Self-service: the target IS the caller, matching how
			// ChangePassword is actually reached in the product.
			name: "change-password",
			run: func(t *testing.T, queries *db.Queries, vault *VaultHandler, admin, target string) {
				auth := NewAuthHandler(queries, &config.Config{
					JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
				})
				auth.SetVault(vault)
				req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password",
					strings.NewReader(`{"current_password":"`+changePasswordTestCurrentPassword+
						`","new_password":"BrandNewPassw0rd!23"}`))
				req = req.WithContext(context.WithValue(req.Context(), timw.UserIDKey, target))
				rec := httptest.NewRecorder()
				auth.ChangePassword(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("change-password failed (%d): %s", rec.Code, rec.Body.String())
				}
			},
		},
	}

	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			vault, queries := newCollectionAuthzEnv(t)
			admin := mustUser(t, queries, "chokepoint-admin-"+s.name+"@example.com", "admin", "admin-original-pw-0123")
			targetPassword := "target-original-pw-0123"
			if s.name == "change-password" {
				targetPassword = changePasswordTestCurrentPassword
			}
			target := mustUser(t, queries, "chokepoint-target-"+s.name+"@example.com", "user", targetPassword)
			svc := mustServiceIdentity(t, queries, target, "chokepoint-svc-"+s.name)

			if !serviceIdentityIsLive(t, queries, target, svc) {
				t.Fatal("ABORT: fixture identity is not live before the action; the test would pass for the wrong reason")
			}

			s.run(t, queries, vault, admin, target)

			if serviceIdentityIsLive(t, queries, target, svc) {
				t.Errorf("%s left the target's service identity LIVE. Every credential-invalidating action "+
					"(disable, delete, reset-password, change-password) has to revoke service identities "+
					"alongside sessions and API keys, or a stolen machine credential outlives the very "+
					"action meant to cut it off, which is precisely the gap that shipped for reset-password "+
					"and change-password despite the offboarding docstring's claim otherwise.", s.name)
			}
		})
	}
}

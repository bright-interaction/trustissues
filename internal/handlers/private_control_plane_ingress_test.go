package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/go-chi/chi/v5"
)

func runControlPlaneRequest(configured bool, zone middleware.IngressZone,
	handler http.HandlerFunc, request *http.Request) collectionProbeResponse {
	recorder := httptest.NewRecorder()
	wrapped := middleware.StampPrivateIngressConfigured(configured)(
		middleware.StampIngressZone(zone)(handler),
	)
	wrapped.ServeHTTP(recorder, request)
	return collectionProbeResponse{
		code:   recorder.Code,
		body:   recorder.Body.String(),
		header: recorder.Result().Header.Clone(),
	}
}

// TestConfiguredControlPlaneRefusalIsStateIndependent proves the configured
// public listener never asks whether protected state exists. The exact same
// requests are sampled before and after a target gains protected-collection
// impact; each response, including headers, remains byte-for-byte identical.
func TestConfiguredControlPlaneRefusalIsStateIndependent(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "configured-control-admin@example.com", "admin", "")
	target := mustUser(t, queries, "configured-control-target@example.com", "user", "")
	users := NewUserHandler(queries, nil)
	users.SetVault(vault)
	activity := NewActivityHandler(queries)
	capability := setupCapabilityHandlerWithVault(t, vault)

	type surface struct {
		name    string
		handler http.HandlerFunc
		request func() *http.Request
	}
	surfaces := []surface{
		{
			name: "hard user delete", handler: users.Delete,
			request: func() *http.Request { return deleteUserRequest(target, admin) },
		},
		{
			name: "activity list", handler: activity.List,
			request: func() *http.Request { return httptest.NewRequest(http.MethodGet, "/api/activity", nil) },
		},
		{
			name: "activity csv", handler: activity.ExportCSV,
			request: func() *http.Request { return httptest.NewRequest(http.MethodGet, "/api/activity/export/csv", nil) },
		},
		{
			name: "activity json", handler: activity.ExportJSON,
			request: func() *http.Request { return httptest.NewRequest(http.MethodGet, "/api/activity/export/json", nil) },
		},
		{
			name: "capability audit", handler: capability.ListCapabilityLog,
			request: func() *http.Request { return httptest.NewRequest(http.MethodGet, "/api/capability-log", nil) },
		},
		{
			name: "vault key status", handler: vault.VaultKeyStatus,
			request: func() *http.Request { return httptest.NewRequest(http.MethodGet, "/api/admin/vault-key", nil) },
		},
		{
			name: "vault key rekey", handler: vault.VaultKeyRekey,
			request: func() *http.Request { return httptest.NewRequest(http.MethodPost, "/api/admin/vault-key/rekey", nil) },
		},
	}

	before := make(map[string]collectionProbeResponse, len(surfaces))
	for _, endpoint := range surfaces {
		response := runControlPlaneRequest(true, middleware.IngressPublic, endpoint.handler, endpoint.request())
		if response.code != http.StatusForbidden || !strings.Contains(response.body, middleware.PrivateIngressRequiredCode) {
			t.Fatalf("configured public %s = HTTP %d %s", endpoint.name, response.code, response.body)
		}
		before[endpoint.name] = response
	}

	const collectionID = "configured-control-protected"
	mustCollection(t, queries, collectionID, admin, map[string]string{
		admin:  collRoleManager,
		target: collRoleEditor,
	})
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "sensitive_private")

	for _, endpoint := range surfaces {
		after := runControlPlaneRequest(true, middleware.IngressPublic, endpoint.handler, endpoint.request())
		if !reflect.DeepEqual(before[endpoint.name], after) {
			t.Fatalf("configured public %s disclosed protected-state change\nbefore: %#v\nafter:  %#v",
				endpoint.name, before[endpoint.name], after)
		}
	}

	// Target existence and the self-delete branch are also state. The configured
	// gate must precede both lookups/branches.
	for name, request := range map[string]*http.Request{
		"missing": deleteUserRequest("missing-configured-control-user", admin),
		"self":    deleteUserRequest(admin, admin),
	} {
		response := runControlPlaneRequest(true, middleware.IngressPublic, users.Delete, request)
		if !reflect.DeepEqual(before["hard user delete"], response) {
			t.Fatalf("configured hard delete disclosed %s target state\ntarget: %#v\n%s: %#v",
				name, before["hard user delete"], name, response)
		}
	}
}

// TestDisabledPrivateConnectorRetainsPublicCompatibility pins the opt-in
// contract. An unstamped/default-false deployment keeps the historical
// latch/global/impact checks, so an instance with only standard state remains
// usable on its public listener.
func TestDisabledPrivateConnectorRetainsPublicCompatibility(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "disabled-control-admin@example.com", "admin", "")
	target := mustUser(t, queries, "disabled-control-target@example.com", "user", "")
	users := NewUserHandler(queries, nil)
	users.SetVault(vault)
	activity := NewActivityHandler(queries)
	capability := setupCapabilityHandlerWithVault(t, vault)

	tests := []struct {
		name     string
		handler  http.HandlerFunc
		request  *http.Request
		wantCode int
	}{
		{name: "activity list", handler: activity.List, request: httptest.NewRequest(http.MethodGet, "/api/activity", nil), wantCode: http.StatusOK},
		{name: "activity csv", handler: activity.ExportCSV, request: httptest.NewRequest(http.MethodGet, "/api/activity/export/csv", nil), wantCode: http.StatusOK},
		{name: "activity json", handler: activity.ExportJSON, request: httptest.NewRequest(http.MethodGet, "/api/activity/export/json", nil), wantCode: http.StatusOK},
		{name: "capability audit", handler: capability.ListCapabilityLog, request: httptest.NewRequest(http.MethodGet, "/api/capability-log", nil), wantCode: http.StatusOK},
		{name: "vault key status", handler: vault.VaultKeyStatus, request: httptest.NewRequest(http.MethodGet, "/api/admin/vault-key", nil), wantCode: http.StatusOK},
		{name: "vault key rekey", handler: vault.VaultKeyRekey, request: httptest.NewRequest(http.MethodPost, "/api/admin/vault-key/rekey", nil), wantCode: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// configured=false is explicit here; direct handler calls have the same
			// default, which keeps existing tests and connector-free deployments compatible.
			response := runControlPlaneRequest(false, middleware.IngressPublic, test.handler, test.request)
			if response.code != test.wantCode {
				t.Fatalf("HTTP %d, want %d: %s", response.code, test.wantCode, response.body)
			}
			if strings.Contains(response.body, middleware.PrivateIngressRequiredCode) {
				t.Fatalf("disabled connector unexpectedly required private ingress: %s", response.body)
			}
		})
	}

	deleted := runControlPlaneRequest(false, middleware.IngressPublic, users.Delete, deleteUserRequest(target, admin))
	if deleted.code != http.StatusNoContent {
		t.Fatalf("standard hard delete with disabled connector = HTTP %d %s", deleted.code, deleted.body)
	}
}

func TestDisabledPrivateConnectorKeepsConditionalProtectedGates(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "disabled-protected-admin@example.com", "admin", "")
	target := mustUser(t, queries, "disabled-protected-target@example.com", "user", "")
	const collectionID = "disabled-protected-collection"
	mustCollection(t, queries, collectionID, admin, map[string]string{
		admin:  collRoleManager,
		target: collRoleEditor,
	})
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "fully_private")

	users := NewUserHandler(queries, nil)
	users.SetVault(vault)
	activity := NewActivityHandler(queries)
	capability := setupCapabilityHandlerWithVault(t, vault)
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		request *http.Request
	}{
		{name: "hard user delete", handler: users.Delete, request: deleteUserRequest(target, admin)},
		{name: "activity list", handler: activity.List, request: httptest.NewRequest(http.MethodGet, "/api/activity", nil)},
		{name: "activity csv", handler: activity.ExportCSV, request: httptest.NewRequest(http.MethodGet, "/api/activity/export/csv", nil)},
		{name: "activity json", handler: activity.ExportJSON, request: httptest.NewRequest(http.MethodGet, "/api/activity/export/json", nil)},
		{name: "capability audit", handler: capability.ListCapabilityLog, request: httptest.NewRequest(http.MethodGet, "/api/capability-log", nil)},
		{name: "vault key status", handler: vault.VaultKeyStatus, request: httptest.NewRequest(http.MethodGet, "/api/admin/vault-key", nil)},
		{name: "vault key rekey", handler: vault.VaultKeyRekey, request: httptest.NewRequest(http.MethodPost, "/api/admin/vault-key/rekey", nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := runControlPlaneRequest(false, middleware.IngressPublic, test.handler, test.request)
			if response.code != http.StatusForbidden ||
				!strings.Contains(response.body, middleware.PrivateIngressRequiredCode) {
				t.Fatalf("disabled connector reopened protected surface: HTTP %d %s", response.code, response.body)
			}
		})
	}
}

func TestConfiguredConnectorKeepsDisablePublicAndMakesResetPrivate(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "emergency-control-admin@example.com", "admin", "")
	disableTarget := mustUser(t, queries, "emergency-disable@example.com", "user", "")
	resetTarget := mustUser(t, queries, "emergency-reset@example.com", "user", "")
	users := NewUserHandler(queries, nil)
	users.SetVault(vault)

	request := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, "/api/admin/users/"+target, strings.NewReader(body))
		route := chi.NewRouteContext()
		route.URLParams.Add("id", target)
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, route)
		ctx = context.WithValue(ctx, middleware.UserIDKey, admin)
		ctx = context.WithValue(ctx, middleware.UserRoleKey, "admin")
		return req.WithContext(ctx)
	}

	disabled := runControlPlaneRequest(true, middleware.IngressPublic, users.Update,
		request(http.MethodPatch, disableTarget, `{"disabled":true}`))
	if disabled.code != http.StatusOK {
		t.Fatalf("configured public disable = HTTP %d %s", disabled.code, disabled.body)
	}
	reset := runControlPlaneRequest(true, middleware.IngressPublic, users.ResetPassword,
		request(http.MethodPost, resetTarget, `{"password":"AdminChosenPassw0rd!23"}`))
	if reset.code != http.StatusForbidden ||
		!strings.Contains(reset.body, middleware.PrivateIngressRequiredCode) {
		t.Fatalf("configured public reset = HTTP %d %s", reset.code, reset.body)
	}
	privateReset := runControlPlaneRequest(true, middleware.IngressPrivate, users.ResetPassword,
		request(http.MethodPost, resetTarget, `{"password":"AdminChosenPassw0rd!23"}`))
	if privateReset.code != http.StatusNoContent {
		t.Fatalf("configured private reset = HTTP %d %s", privateReset.code, privateReset.body)
	}
}

func TestConfiguredConnectorMakesAccessExpandingAdminControlsPrivate(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "expansion-control-admin@example.com", "admin", "")
	member := mustUser(t, queries, "expansion-control-member@example.com", "user", "")
	alreadyAdmin := mustUser(t, queries, "expansion-control-existing-admin@example.com", "admin", "")
	disabled := mustUser(t, queries, "expansion-control-disabled@example.com", "user", "")
	if _, err := queries.Handle().ExecContext(context.Background(),
		`UPDATE users SET disabled = 1 WHERE id = ?`, disabled); err != nil {
		t.Fatalf("disable fixture account: %v", err)
	}

	cfg := &config.Config{
		BaseURL:  "https://vault.example.test",
		VaultKey: strings.Repeat("k", 32),
	}
	users := NewUserHandler(queries, cfg)
	users.SetVault(vault)

	adminRequest := func(method, path, target, body string) *http.Request {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if target != "" {
			route := chi.NewRouteContext()
			route.URLParams.Add("id", target)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		}
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, admin)
		ctx = context.WithValue(ctx, middleware.UserRoleKey, middleware.RoleAdmin)
		return req.WithContext(ctx)
	}
	assertPrivate := func(name string, got collectionProbeResponse) {
		t.Helper()
		if got.code != http.StatusForbidden || !strings.Contains(got.body, middleware.PrivateIngressRequiredCode) {
			t.Fatalf("configured public %s = HTTP %d %s, want private-ingress refusal", name, got.code, got.body)
		}
	}
	assertSame := func(name string, first, second collectionProbeResponse) {
		t.Helper()
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("configured public %s disclosed target state\nfirst: %#v\nsecond: %#v", name, first, second)
		}
	}

	// Direct admin creation is refused before the unique-email insert. The same
	// request is byte-identical after that address starts existing.
	createAdmin := func() collectionProbeResponse {
		return runControlPlaneRequest(true, middleware.IngressPublic, users.Create,
			adminRequest(http.MethodPost, "/api/admin/users", "",
				`{"email":"direct-admin@example.com","password":"DirectAdminPassw0rd!","role":"admin"}`))
	}
	beforeExisting := createAdmin()
	assertPrivate("direct admin creation", beforeExisting)
	mustUser(t, queries, "direct-admin@example.com", "user", "")
	assertSame("direct admin creation", beforeExisting, createAdmin())

	// Promotion and re-enable gate on the request shape before target lookup, so
	// missing/current/already-admin states cannot be distinguished publicly.
	promote := func(target string) collectionProbeResponse {
		return runControlPlaneRequest(true, middleware.IngressPublic, users.Update,
			adminRequest(http.MethodPatch, "/api/admin/users/"+target, target, `{"role":"admin"}`))
	}
	promotion := promote(member)
	assertPrivate("admin promotion", promotion)
	assertSame("admin promotion existing role", promotion, promote(alreadyAdmin))
	assertSame("admin promotion target existence", promotion, promote("missing-expansion-user"))

	reenable := func(target string) collectionProbeResponse {
		return runControlPlaneRequest(true, middleware.IngressPublic, users.Update,
			adminRequest(http.MethodPatch, "/api/admin/users/"+target, target, `{"disabled":false}`))
	}
	enablement := reenable(disabled)
	assertPrivate("account re-enable", enablement)
	assertSame("account re-enable current state", enablement, reenable(member))
	assertSame("account re-enable target existence", enablement, reenable("missing-enable-user"))

	// Admin invitation creation does not reveal whether the invited address has
	// an account; both shapes are stopped before code generation/persistence.
	inviteAdmin := func(email string) collectionProbeResponse {
		return runControlPlaneRequest(true, middleware.IngressPublic, users.CreateInvitation,
			adminRequest(http.MethodPost, "/api/admin/invitations", "",
				`{"email":"`+email+`","name":"Private admin","role":"admin"}`))
	}
	invitation := inviteAdmin("new-admin-invite@example.com")
	assertPrivate("admin invitation creation", invitation)
	assertSame("admin invitation account existence", invitation,
		inviteAdmin("expansion-control-member@example.com"))

	// The same operations remain usable from the listener that stamped the
	// request private.
	privateCreate := runControlPlaneRequest(true, middleware.IngressPrivate, users.Create,
		adminRequest(http.MethodPost, "/api/admin/users", "",
			`{"email":"private-created-admin@example.com","password":"PrivateAdminPassw0rd!","role":"admin"}`))
	if privateCreate.code != http.StatusCreated {
		t.Fatalf("private direct admin creation = HTTP %d %s", privateCreate.code, privateCreate.body)
	}
	privatePromote := runControlPlaneRequest(true, middleware.IngressPrivate, users.Update,
		adminRequest(http.MethodPatch, "/api/admin/users/"+member, member, `{"role":"admin"}`))
	if privatePromote.code != http.StatusOK {
		t.Fatalf("private admin promotion = HTTP %d %s", privatePromote.code, privatePromote.body)
	}
	privateEnable := runControlPlaneRequest(true, middleware.IngressPrivate, users.Update,
		adminRequest(http.MethodPatch, "/api/admin/users/"+disabled, disabled, `{"disabled":false}`))
	if privateEnable.code != http.StatusOK {
		t.Fatalf("private account re-enable = HTTP %d %s", privateEnable.code, privateEnable.body)
	}

	privateInvite := runControlPlaneRequest(true, middleware.IngressPrivate, users.CreateInvitation,
		adminRequest(http.MethodPost, "/api/admin/invitations", "",
			`{"email":"redeem-private-admin@example.com","name":"Redeem private admin","role":"admin"}`))
	if privateInvite.code != http.StatusCreated {
		t.Fatalf("private admin invitation creation = HTTP %d %s", privateInvite.code, privateInvite.body)
	}
	var created invitationResponse
	if err := json.Unmarshal([]byte(privateInvite.body), &created); err != nil || created.Code == "" {
		t.Fatalf("decode private admin invitation: %v (%s)", err, privateInvite.body)
	}
	redeem := func(zone middleware.IngressZone) collectionProbeResponse {
		return runControlPlaneRequest(true, zone, users.RedeemInvitation,
			httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
				strings.NewReader(`{"code":"`+created.Code+`","password":"RedeemedAdminPassw0rd!"}`)))
	}
	publicRedeem := redeem(middleware.IngressPublic)
	assertPrivate("admin invitation redemption", publicRedeem)
	if _, err := queries.GetUserByEmail(context.Background(), "redeem-private-admin@example.com"); err != sql.ErrNoRows {
		t.Fatalf("public admin redemption changed account state: %v", err)
	}
	privateRedeem := redeem(middleware.IngressPrivate)
	if privateRedeem.code != http.StatusOK {
		t.Fatalf("private admin invitation redemption = HTTP %d %s", privateRedeem.code, privateRedeem.body)
	}
	createdAdmin, err := queries.GetUserByEmail(context.Background(), "redeem-private-admin@example.com")
	if err != nil || createdAdmin.Role != middleware.RoleAdmin {
		t.Fatalf("private admin redemption did not create an admin: role=%q err=%v", createdAdmin.Role, err)
	}
}

func TestConfiguredConnectorKeepsReductionsAndClientOnboardingPublic(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "public-reduction-admin@example.com", "admin", "")
	demoted := mustUser(t, queries, "public-reduction-second-admin@example.com", "admin", "")
	cfg := &config.Config{BaseURL: "https://vault.example.test", VaultKey: strings.Repeat("k", 32)}
	users := NewUserHandler(queries, cfg)
	users.SetVault(vault)

	request := func(method, path, target, body string) *http.Request {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if target != "" {
			route := chi.NewRouteContext()
			route.URLParams.Add("id", target)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		}
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, admin)
		ctx = context.WithValue(ctx, middleware.UserRoleKey, middleware.RoleAdmin)
		return req.WithContext(ctx)
	}

	demotion := runControlPlaneRequest(true, middleware.IngressPublic, users.Update,
		request(http.MethodPatch, "/api/admin/users/"+demoted, demoted, `{"role":"user"}`))
	if demotion.code != http.StatusOK {
		t.Fatalf("configured public demotion = HTTP %d %s", demotion.code, demotion.body)
	}
	ordinaryCreate := runControlPlaneRequest(true, middleware.IngressPublic, users.Create,
		request(http.MethodPost, "/api/admin/users", "",
			`{"email":"public-client-user@example.com","password":"PublicClientPassw0rd!","role":"vault_only"}`))
	if ordinaryCreate.code != http.StatusCreated {
		t.Fatalf("configured public client creation = HTTP %d %s", ordinaryCreate.code, ordinaryCreate.body)
	}
	ordinaryInvite := runControlPlaneRequest(true, middleware.IngressPublic, users.CreateInvitation,
		request(http.MethodPost, "/api/admin/invitations", "",
			`{"email":"public-client-invite@example.com","name":"Public client","role":"vault_only"}`))
	if ordinaryInvite.code != http.StatusCreated {
		t.Fatalf("configured public client invitation = HTTP %d %s", ordinaryInvite.code, ordinaryInvite.body)
	}
	var invite invitationResponse
	if err := json.Unmarshal([]byte(ordinaryInvite.body), &invite); err != nil || invite.Code == "" {
		t.Fatalf("decode public client invitation: %v (%s)", err, ordinaryInvite.body)
	}
	ordinaryRedeem := runControlPlaneRequest(true, middleware.IngressPublic, users.RedeemInvitation,
		httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
			strings.NewReader(`{"code":"`+invite.Code+`","password":"PublicInvitePassw0rd!"}`)))
	if ordinaryRedeem.code != http.StatusOK {
		t.Fatalf("configured public client redemption = HTTP %d %s", ordinaryRedeem.code, ordinaryRedeem.body)
	}
}

func TestDisabledConnectorKeepsAdminOnboardingAndExpansionCompatible(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "disabled-expansion-admin@example.com", "admin", "")
	promoted := mustUser(t, queries, "disabled-expansion-member@example.com", "user", "")
	reenabled := mustUser(t, queries, "disabled-expansion-reenabled@example.com", "user", "")
	if _, err := queries.Handle().ExecContext(context.Background(),
		`UPDATE users SET disabled = 1 WHERE id = ?`, reenabled); err != nil {
		t.Fatalf("disable fixture account: %v", err)
	}
	cfg := &config.Config{BaseURL: "https://vault.example.test", VaultKey: strings.Repeat("k", 32)}
	users := NewUserHandler(queries, cfg)
	users.SetVault(vault)

	request := func(method, path, target, body string) *http.Request {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if target != "" {
			route := chi.NewRouteContext()
			route.URLParams.Add("id", target)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		}
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, admin)
		ctx = context.WithValue(ctx, middleware.UserRoleKey, middleware.RoleAdmin)
		return req.WithContext(ctx)
	}
	check := func(name string, got collectionProbeResponse, want int) {
		t.Helper()
		if got.code != want || strings.Contains(got.body, middleware.PrivateIngressRequiredCode) {
			t.Fatalf("disabled connector %s = HTTP %d %s, want %d without private refusal", name, got.code, got.body, want)
		}
	}

	check("direct admin creation", runControlPlaneRequest(false, middleware.IngressPublic, users.Create,
		request(http.MethodPost, "/api/admin/users", "",
			`{"email":"disabled-created-admin@example.com","password":"DisabledAdminPassw0rd!","role":"admin"}`)), http.StatusCreated)
	check("admin promotion", runControlPlaneRequest(false, middleware.IngressPublic, users.Update,
		request(http.MethodPatch, "/api/admin/users/"+promoted, promoted, `{"role":"admin"}`)), http.StatusOK)
	check("account re-enable", runControlPlaneRequest(false, middleware.IngressPublic, users.Update,
		request(http.MethodPatch, "/api/admin/users/"+reenabled, reenabled, `{"disabled":false}`)), http.StatusOK)

	adminInvite := runControlPlaneRequest(false, middleware.IngressPublic, users.CreateInvitation,
		request(http.MethodPost, "/api/admin/invitations", "",
			`{"email":"disabled-invited-admin@example.com","name":"Compatible admin","role":"admin"}`))
	check("admin invitation creation", adminInvite, http.StatusCreated)
	var invite invitationResponse
	if err := json.Unmarshal([]byte(adminInvite.body), &invite); err != nil || invite.Code == "" {
		t.Fatalf("decode compatible admin invitation: %v (%s)", err, adminInvite.body)
	}
	check("admin invitation redemption", runControlPlaneRequest(false, middleware.IngressPublic, users.RedeemInvitation,
		httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
			strings.NewReader(`{"code":"`+invite.Code+`","password":"CompatibleInvitePassw0rd!"}`))), http.StatusOK)
}

func TestConfiguredConnectorMakesFirstAdminBootstrapPrivate(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	cfg := &config.Config{
		JWTSecret: strings.Repeat("j", 32),
		VaultKey:  strings.Repeat("k", 32),
	}
	auth := NewAuthHandler(queries, cfg)
	request := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(
			`{"email":"first-private-admin@example.com","password":"FirstPrivateAdminPassw0rd!"}`,
		))
	}

	before := runControlPlaneRequest(true, middleware.IngressPublic, auth.Register, request())
	if before.code != http.StatusForbidden || !strings.Contains(before.body, middleware.PrivateIngressRequiredCode) {
		t.Fatalf("configured public first-admin bootstrap = HTTP %d %s", before.code, before.body)
	}
	if count, err := queries.CountUsers(context.Background()); err != nil || count != 0 {
		t.Fatalf("public first-admin refusal changed users: count=%d err=%v", count, err)
	}

	created := runControlPlaneRequest(true, middleware.IngressPrivate, auth.Register, request())
	if created.code != http.StatusCreated {
		t.Fatalf("configured private first-admin bootstrap = HTTP %d %s", created.code, created.body)
	}

	// Setup state is public handler state too. The configured public listener
	// must keep the same refusal after the first account exists rather than
	// switching to its ordinary setup-complete response.
	after := runControlPlaneRequest(true, middleware.IngressPublic, auth.Register, request())
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("configured public first-admin bootstrap disclosed setup state\nbefore: %#v\nafter: %#v", before, after)
	}
}

func TestDisabledConnectorKeepsFirstAdminBootstrapPublic(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	auth := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32),
		VaultKey:  strings.Repeat("k", 32),
	})
	response := runControlPlaneRequest(false, middleware.IngressPublic, auth.Register,
		httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(
			`{"email":"first-public-admin@example.com","password":"FirstPublicAdminPassw0rd!"}`,
		)))
	if response.code != http.StatusCreated || strings.Contains(response.body, middleware.PrivateIngressRequiredCode) {
		t.Fatalf("disabled connector first-admin bootstrap = HTTP %d %s", response.code, response.body)
	}
}

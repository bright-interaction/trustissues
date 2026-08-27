package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/go-chi/chi/v5"
)

type onboardingHTTPResult struct {
	status int
	body   string
}

func onboardingRequest(t *testing.T, serverURL, method, path, bearer, apiKey, body string) onboardingHTTPResult {
	t.Helper()
	req, err := http.NewRequest(method, serverURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, path, err)
	}
	return onboardingHTTPResult{status: resp.StatusCode, body: string(data)}
}

func loginForOnboarding(t *testing.T, serverURL, email, password string) string {
	t.Helper()
	result := onboardingRequest(t, serverURL, http.MethodPost, "/api/auth/login", "", "",
		`{"email":"`+email+`","password":"`+password+`"}`)
	if result.status != http.StatusOK {
		t.Fatalf("login %s: HTTP %d %s", email, result.status, result.body)
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(result.body), &response); err != nil || response.Token == "" {
		t.Fatalf("login %s returned no interactive token: %s", email, result.body)
	}
	return response.Token
}

// This pins the intended external-client lifecycle through actual HTTP routing
// and authentication middleware. The public invitation bearer creates only a
// password-having account and pending standard-collection seat. Reusable API
// authority appears only after an interactive login, cannot reproduce itself,
// and is cut off by both collection removal and account disable.
func TestExternalClientWebFirstOnboardingAndOffboardingJourney(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	cfg := &config.Config{
		VaultKey: strings.Repeat("k", 32), JWTSecret: strings.Repeat("j", 32),
		BaseURL: "https://vault.example.test",
	}
	users := NewUserHandler(queries, cfg)
	users.SetVault(vault)
	auth := NewAuthHandler(queries, cfg)
	auth.SetVault(vault)
	apiKeys := NewAPIKeyHandler(queries)
	collections := NewCollectionHandler(queries, vault)
	ctx := context.Background()

	const (
		adminEmail     = "web-first-admin@example.com"
		adminPassword  = "AdminPassw0rd!"
		clientEmail    = "external-client@example.com"
		clientPassword = "ClientChosenPassw0rd!"
		collectionID   = "external-client-standard-vault"
	)
	adminID := mustUser(t, queries, adminEmail, "admin", adminPassword)
	if err := queries.CreateCollectionWithPolicy(ctx, db.CreateCollectionWithPolicyParams{
		ID: collectionID, Name: "External client vault", Description: "client-owned credentials",
		CreatedBy: toNullString(adminID), PrivateAccessPolicy: "standard",
	}); err != nil {
		t.Fatalf("seed standard client collection: %v", err)
	}
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: collectionID, UserID: adminID, Role: "manager",
		AcceptedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}, InvitedBy: toNullString(adminID),
	}); err != nil {
		t.Fatalf("seed collection manager: %v", err)
	}
	if err := queries.UpsertCollectionInvitation(ctx, db.UpsertCollectionInvitationParams{
		CollectionID: collectionID, Email: clientEmail, Role: "viewer", InvitedBy: toNullString(adminID),
	}); err != nil {
		t.Fatalf("seed external client seat: %v", err)
	}

	router := chi.NewRouter()
	router.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", auth.Login)
		r.Post("/invitations/redeem", users.RedeemInvitation)
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTOrAPIKeyAuth(cfg.JWTSecret, vault.db))
			r.Use(middleware.RequireTOTPEnrollment(vault.db))
			r.Route("/api-keys", func(r chi.Router) {
				r.Get("/", apiKeys.List)
				r.Post("/", apiKeys.Create)
			})
			r.Get("/collections/invitations", collections.ListPendingInvites)
			r.Route("/collections/{id}", func(r chi.Router) {
				r.Get("/", collections.Get)
				r.Post("/accept", collections.AcceptInvite)
				r.Delete("/members/{userId}", collections.RemoveMember)
			})
			r.Group(func(r chi.Router) {
				r.Use(middleware.AdminOnly())
				r.Post("/admin/invitations", users.CreateInvitation)
				r.Patch("/admin/users/{id}", users.Update)
			})
		})
	})
	server := httptest.NewServer(router)
	defer server.Close()

	adminToken := loginForOnboarding(t, server.URL, adminEmail, adminPassword)
	created := onboardingRequest(t, server.URL, http.MethodPost, "/api/admin/invitations", adminToken, "",
		`{"email":"`+clientEmail+`","name":"External client","role":"vault_only"}`)
	if created.status != http.StatusCreated {
		t.Fatalf("create client invitation: HTTP %d %s", created.status, created.body)
	}
	var invitation struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(created.body), &invitation); err != nil || invitation.Code == "" {
		t.Fatalf("client invitation returned no code: %s", created.body)
	}

	redeemed := onboardingRequest(t, server.URL, http.MethodPost, "/api/invitations/redeem", "", "",
		`{"code":"`+invitation.Code+`","password":"`+clientPassword+`"}`)
	if redeemed.status != http.StatusOK {
		t.Fatalf("redeem client invitation: HTTP %d %s", redeemed.status, redeemed.body)
	}
	if strings.Contains(redeemed.body, `"api_key"`) || strings.Contains(redeemed.body, `"server_url"`) {
		t.Fatalf("public redemption returned reusable extension authority: %s", redeemed.body)
	}
	var client struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(redeemed.body), &client); err != nil || client.User.ID == "" {
		t.Fatalf("redemption returned no client identity: %s", redeemed.body)
	}
	if got := countAtomicityRows(t, vault.db, `SELECT COUNT(*) FROM api_keys WHERE user_id = ?`, client.User.ID); got != 0 {
		t.Fatalf("redemption implicitly minted %d API key(s), want zero", got)
	}
	var policy string
	var acceptedAt sql.NullTime
	if err := vault.db.QueryRowContext(ctx, `
		SELECT c.private_access_policy, cm.accepted_at
		FROM collection_members cm JOIN collections c ON c.id = cm.collection_id
		WHERE cm.user_id = ? AND cm.collection_id = ?`, client.User.ID, collectionID,
	).Scan(&policy, &acceptedAt); err != nil {
		t.Fatalf("read claimed collection seat: %v", err)
	}
	if policy != "standard" || acceptedAt.Valid {
		t.Fatalf("claimed seat policy=%q accepted=%v, want pending standard only", policy, acceptedAt.Valid)
	}
	if got := countAtomicityRows(t, vault.db, `SELECT COUNT(*) FROM collection_members WHERE user_id = ?`, client.User.ID); got != 1 {
		t.Fatalf("client received %d collection seats, want exactly the dedicated standard seat", got)
	}

	clientToken := loginForOnboarding(t, server.URL, clientEmail, clientPassword)
	pending := onboardingRequest(t, server.URL, http.MethodGet, "/api/collections/invitations", clientToken, "", "")
	if pending.status != http.StatusOK || !strings.Contains(pending.body, collectionID) {
		t.Fatalf("pending client vault is not visible after login: HTTP %d %s", pending.status, pending.body)
	}
	beforeAccept := onboardingRequest(t, server.URL, http.MethodGet, "/api/collections/"+collectionID, clientToken, "", "")
	if beforeAccept.status != http.StatusNotFound {
		t.Fatalf("pending seat granted collection access before consent: HTTP %d %s", beforeAccept.status, beforeAccept.body)
	}
	accepted := onboardingRequest(t, server.URL, http.MethodPost, "/api/collections/"+collectionID+"/accept", clientToken, "", "")
	if accepted.status != http.StatusNoContent {
		t.Fatalf("accept client vault: HTTP %d %s", accepted.status, accepted.body)
	}
	afterAccept := onboardingRequest(t, server.URL, http.MethodGet, "/api/collections/"+collectionID, clientToken, "", "")
	if afterAccept.status != http.StatusOK {
		t.Fatalf("accepted client cannot access dedicated vault: HTTP %d %s", afterAccept.status, afterAccept.body)
	}

	minted := onboardingRequest(t, server.URL, http.MethodPost, "/api/api-keys", clientToken, "",
		`{"name":"Client browser"}`)
	if minted.status != http.StatusCreated {
		t.Fatalf("interactive client session could not mint API key: HTTP %d %s", minted.status, minted.body)
	}
	var key struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(minted.body), &key); err != nil || key.Key == "" {
		t.Fatalf("API-key mint returned no key: %s", minted.body)
	}
	successor := onboardingRequest(t, server.URL, http.MethodPost, "/api/api-keys", "", key.Key,
		`{"name":"Illicit successor"}`)
	if successor.status != http.StatusForbidden || !strings.Contains(successor.body, "interactive_session_required") {
		t.Fatalf("API key could mint a successor: HTTP %d %s", successor.status, successor.body)
	}
	if got := countAtomicityRows(t, vault.db, `SELECT COUNT(*) FROM api_keys WHERE user_id = ?`, client.User.ID); got != 1 {
		t.Fatalf("successor attempt left %d client keys, want exactly the interactive-session key", got)
	}

	removed := onboardingRequest(t, server.URL, http.MethodDelete,
		"/api/collections/"+collectionID+"/members/"+client.User.ID, adminToken, "", "")
	if removed.status != http.StatusNoContent {
		t.Fatalf("remove external client from collection: HTTP %d %s", removed.status, removed.body)
	}
	afterRemoval := onboardingRequest(t, server.URL, http.MethodGet,
		"/api/collections/"+collectionID, "", key.Key, "")
	if afterRemoval.status != http.StatusNotFound {
		t.Fatalf("removed client's API key retained collection access: HTTP %d %s", afterRemoval.status, afterRemoval.body)
	}

	disabled := onboardingRequest(t, server.URL, http.MethodPatch,
		"/api/admin/users/"+client.User.ID, adminToken, "", `{"disabled":true}`)
	if disabled.status != http.StatusOK {
		t.Fatalf("disable external client: HTTP %d %s", disabled.status, disabled.body)
	}
	afterDisable := onboardingRequest(t, server.URL, http.MethodGet, "/api/api-keys", "", key.Key, "")
	if afterDisable.status != http.StatusUnauthorized {
		t.Fatalf("disabled client's API key still authenticated: HTTP %d %s", afterDisable.status, afterDisable.body)
	}
}

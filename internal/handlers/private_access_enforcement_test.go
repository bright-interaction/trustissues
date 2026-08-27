package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/go-chi/chi/v5"
)

func setCollectionPrivateAccessPolicy(t *testing.T, queries *db.Queries, id, policy string) {
	t.Helper()
	if err := queries.UpdateCollection(context.Background(), db.UpdateCollectionParams{
		Name: id, Description: "", PrivateAccessPolicy: sql.NullString{String: policy, Valid: true}, ID: id,
	}); err != nil {
		t.Fatalf("set collection %s policy to %s: %v", id, policy, err)
	}
}

func servePrivate(rec *httptest.ResponseRecorder, handler http.Handler, req *http.Request) {
	middleware.StampIngressZone(middleware.IngressPrivate)(handler).ServeHTTP(rec, req)
}

func TestPrivateAccessEntryMetadataAndSensitiveGates(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "private-gate@example.com", "user", "")
	const collectionID = "internal-collection"
	const entryID = "internal-entry"
	mustCollection(t, queries, collectionID, userID, map[string]string{userID: collRoleManager})
	mustEntry(t, vault, queries, entryID, userID, "production credential", "secret")
	placeInCollection(t, queries, entryID, collectionID)
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "sensitive_private")

	publicTargets := httptest.NewRecorder()
	spoofed := vaultAuthzRequest(http.MethodGet, "/api/vault/"+entryID+"/targets", userID, "user", entryID, "")
	// None of these request-controlled values can turn public ingress private.
	spoofed.Host = "private.tailnet.example"
	spoofed.RemoteAddr = "100.64.0.10:4321"
	spoofed.Header.Set("X-TrustIssues-Ingress-Zone", "private")
	spoofed.Header.Set("Tailscale-User-Login", "admin@example.com")
	vault.GetTargets(publicTargets, spoofed)
	if publicTargets.Code != http.StatusForbidden || !strings.Contains(publicTargets.Body.String(), middleware.PrivateIngressRequiredCode) {
		t.Fatalf("public sensitive operation got HTTP %d: %s", publicTargets.Code, publicTargets.Body.String())
	}

	privateTargets := httptest.NewRecorder()
	servePrivate(privateTargets, http.HandlerFunc(vault.GetTargets),
		vaultAuthzRequest(http.MethodGet, "/api/vault/"+entryID+"/targets", userID, "user", entryID, ""))
	if privateTargets.Code != http.StatusOK {
		t.Fatalf("private sensitive operation got HTTP %d: %s", privateTargets.Code, privateTargets.Body.String())
	}

	// sensitive_private keeps metadata visible. fully_private removes both the
	// collection and its entries from the public inventory and makes a direct
	// public probe indistinguishable from a missing resource.
	publicList := httptest.NewRecorder()
	vault.List(publicList, vaultAuthzRequest(http.MethodGet, "/api/vault", userID, "user", "", ""))
	var entries []vaultEntryMeta
	if err := json.NewDecoder(publicList.Body).Decode(&entries); err != nil || len(entries) != 1 {
		t.Fatalf("sensitive_private public metadata = %+v, decode err=%v, body=%s", entries, err, publicList.Body.String())
	}

	setCollectionPrivateAccessPolicy(t, queries, collectionID, "fully_private")
	publicList = httptest.NewRecorder()
	vault.List(publicList, vaultAuthzRequest(http.MethodGet, "/api/vault", userID, "user", "", ""))
	entries = nil
	if err := json.NewDecoder(publicList.Body).Decode(&entries); err != nil || len(entries) != 0 {
		t.Fatalf("fully_private public metadata = %+v, decode err=%v, body=%s", entries, err, publicList.Body.String())
	}

	directProbe := httptest.NewRecorder()
	vault.GetTargets(directProbe,
		vaultAuthzRequest(http.MethodGet, "/api/vault/"+entryID+"/targets", userID, "user", entryID, ""))
	if directProbe.Code != http.StatusNotFound {
		t.Fatalf("fully_private direct public probe got HTTP %d, want 404: %s", directProbe.Code, directProbe.Body.String())
	}
	missingProbe := httptest.NewRecorder()
	vault.GetTargets(missingProbe,
		vaultAuthzRequest(http.MethodGet, "/api/vault/missing-entry/targets", userID, "user", "missing-entry", ""))
	if directProbe.Code != missingProbe.Code || directProbe.Body.String() != missingProbe.Body.String() {
		t.Fatalf("fully-private probe differs from missing entry:\nprotected: HTTP %d %s\nmissing: HTTP %d %s",
			directProbe.Code, directProbe.Body.String(), missingProbe.Code, missingProbe.Body.String())
	}
	for _, header := range []string{"Content-Type", "Cache-Control"} {
		if got, want := directProbe.Header().Values(header), missingProbe.Header().Values(header); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("fully-private %s headers = %v, missing = %v", header, got, want)
		}
	}

	privateList := httptest.NewRecorder()
	servePrivate(privateList, http.HandlerFunc(vault.List),
		vaultAuthzRequest(http.MethodGet, "/api/vault", userID, "user", "", ""))
	entries = nil
	if err := json.NewDecoder(privateList.Body).Decode(&entries); err != nil || len(entries) != 1 {
		t.Fatalf("fully_private private metadata = %+v, decode err=%v, body=%s", entries, err, privateList.Body.String())
	}
}

func TestRotationTargetReferenceFollowsReferencedEntryPolicyWithoutANameOracle(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "private-target-ref@example.com", "user", "")

	const (
		carrierID    = "standard-target-carrier"
		tokenID      = "private-target-token"
		collectionID = "private-target-token-collection"
		tokenName    = "shared forgejo token"
	)
	mustEntry(t, vault, queries, carrierID, userID, "client credential", "carrier-value")
	mustCollection(t, queries, collectionID, userID, map[string]string{userID: collRoleManager})
	mustEntry(t, vault, queries, tokenID, userID, tokenName, "forgejo-token-value")
	placeInCollection(t, queries, tokenID, collectionID)
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "fully_private")

	targetBody := func(authToken string) string {
		body, err := json.Marshal([]RotationTarget{{
			Type:       "forgejo_secret",
			Label:      "internal forgejo",
			Instance:   "https://git.internal.example",
			Repo:       "team/service",
			SecretName: "CLIENT_KEY",
			AuthToken:  authToken,
		}})
		if err != nil {
			t.Fatalf("marshal target: %v", err)
		}
		return string(body)
	}

	// A public caller must not be able to discover whether a guessed token name
	// is absent or names a fully-private entry. Neither attempt is persisted.
	missing := httptest.NewRecorder()
	vault.UpdateTargets(missing, targetsRequest(vault, userID, "user", carrierID, targetBody("does not exist")))
	hidden := httptest.NewRecorder()
	vault.UpdateTargets(hidden, targetsRequest(vault, userID, "user", carrierID, targetBody(tokenName)))
	if missing.Code != hidden.Code || missing.Body.String() != hidden.Body.String() {
		t.Fatalf("protected token differs from missing token:\nmissing: HTTP %d %s\nprotected: HTTP %d %s",
			missing.Code, missing.Body.String(), hidden.Code, hidden.Body.String())
	}
	if missing.Code != http.StatusForbidden ||
		!strings.Contains(missing.Body.String(), middleware.PrivateIngressRequiredCode) {
		t.Fatalf("public unresolved/protected token refusal = HTTP %d %s", missing.Code, missing.Body.String())
	}

	// The same reference remains an ordinary public operation while its source
	// collection is standard.
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "standard")
	standardSave := httptest.NewRecorder()
	vault.UpdateTargets(standardSave, targetsRequest(vault, userID, "user", carrierID, targetBody(tokenName)))
	if standardSave.Code != http.StatusOK {
		t.Fatalf("standard token reference was refused: HTTP %d %s", standardSave.Code, standardSave.Body.String())
	}
	standardGet := httptest.NewRecorder()
	vault.GetTargets(standardGet,
		vaultAuthzRequest(http.MethodGet, "/api/vault/"+carrierID+"/targets", userID, "user", carrierID, ""))
	if standardGet.Code != http.StatusOK {
		t.Fatalf("standard target read was refused: HTTP %d %s", standardGet.Code, standardGet.Body.String())
	}

	// Promotion takes effect on the indirect reference immediately, even though
	// the carrier entry itself remains standard. Private ingress can still read
	// and update the configuration.
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "fully_private")
	publicAfterPromotion := httptest.NewRecorder()
	vault.GetTargets(publicAfterPromotion,
		vaultAuthzRequest(http.MethodGet, "/api/vault/"+carrierID+"/targets", userID, "user", carrierID, ""))
	if publicAfterPromotion.Code != http.StatusForbidden ||
		!strings.Contains(publicAfterPromotion.Body.String(), middleware.PrivateIngressRequiredCode) {
		t.Fatalf("promoted token target remained public: HTTP %d %s",
			publicAfterPromotion.Code, publicAfterPromotion.Body.String())
	}

	privateGet := httptest.NewRecorder()
	servePrivate(privateGet, http.HandlerFunc(vault.GetTargets),
		vaultAuthzRequest(http.MethodGet, "/api/vault/"+carrierID+"/targets", userID, "user", carrierID, ""))
	if privateGet.Code != http.StatusOK {
		t.Fatalf("private target read failed: HTTP %d %s", privateGet.Code, privateGet.Body.String())
	}
	var loaded struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(privateGet.Body.Bytes(), &loaded); err != nil || loaded.Version == "" {
		t.Fatalf("decode private target version: version=%q err=%v body=%s",
			loaded.Version, err, privateGet.Body.String())
	}
	privateSave := httptest.NewRecorder()
	servePrivate(privateSave, http.HandlerFunc(vault.UpdateTargets),
		vaultAuthzRequest(http.MethodPut,
			"/api/vault/"+carrierID+"/targets?version="+loaded.Version,
			userID, "user", carrierID, targetBody(tokenName)))
	if privateSave.Code != http.StatusOK {
		t.Fatalf("private protected-token save failed: HTTP %d %s", privateSave.Code, privateSave.Body.String())
	}
}

func TestPublicBulkRevealKeepsStandardVaultsUsableWithoutDisclosingProtectedEntries(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "private-bulk@example.com", "user", "")
	mustEntry(t, vault, queries, "personal-entry", userID, "personal", "personal-value")
	mustCollection(t, queries, "standard-client", userID, map[string]string{userID: collRoleViewer})
	mustEntry(t, vault, queries, "standard-client-entry", userID, "client", "client-value")
	placeInCollection(t, queries, "standard-client-entry", "standard-client")
	mustCollection(t, queries, "protected-bulk", userID, map[string]string{userID: collRoleViewer})
	mustEntry(t, vault, queries, "protected-bulk-entry", userID, "protected", "value")
	placeInCollection(t, queries, "protected-bulk-entry", "protected-bulk")
	setCollectionPrivateAccessPolicy(t, queries, "protected-bulk", "fully_private")

	publicReq := vaultAuthzRequest(http.MethodPost, "/api/vault/unlock", userID, "user", "", "")
	publicEntries, err := vault.revealAccessibleVaultEntries(publicReq, userID, "test public unlock", false)
	if err != nil {
		t.Fatalf("public reveal: %v", err)
	}
	if len(publicEntries) != 2 {
		t.Fatalf("public reveal returned %d rows, want personal + standard client only: %+v", len(publicEntries), publicEntries)
	}
	for _, entry := range publicEntries {
		if entry.ID == "protected-bulk-entry" {
			t.Fatal("public reveal disclosed the fully-private entry")
		}
	}

	var privateEntries []vaultEntryFull
	privateRec := httptest.NewRecorder()
	servePrivate(privateRec, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateEntries, err = vault.revealAccessibleVaultEntries(r, userID, "test private unlock", false)
		w.WriteHeader(http.StatusNoContent)
	}), publicReq)
	if err != nil {
		t.Fatalf("private reveal: %v", err)
	}
	if len(privateEntries) != 3 {
		t.Fatalf("private reveal returned %d rows, want all three: %+v", len(privateEntries), privateEntries)
	}
}

func TestCapabilityTokenDoesNotCarryPrivateIngressAuthority(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "private-capability@example.com", "user", "")
	mustCollection(t, queries, "protected-capability", userID, map[string]string{userID: collRoleEditor})
	mustEntry(t, vault, queries, "protected-capability-entry", userID, "agent key", "value")
	placeInCollection(t, queries, "protected-capability-entry", "protected-capability")
	setCollectionPrivateAccessPolicy(t, queries, "protected-capability", "sensitive_private")
	mustExec(t, vault.db,
		`UPDATE vault_entries SET destination_patterns = ?, injection_spec = ? WHERE id = ?`,
		`["api.example.com/*"]`, `{"type":"bearer"}`, "protected-capability-entry")

	capabilityHandler := setupCapabilityHandlerWithVault(t, vault)
	body := `{"secret":"agent key","agent_id":"test-agent","destination":"api.example.com/v1","method":"POST"}`
	publicIssue := httptest.NewRecorder()
	capabilityHandler.Issue(publicIssue,
		vaultAuthzRequest(http.MethodPost, "/api/secrets/issue", userID, "user", "", body))
	if publicIssue.Code != http.StatusForbidden || !strings.Contains(publicIssue.Body.String(), middleware.PrivateIngressRequiredCode) {
		t.Fatalf("public capability issue got HTTP %d: %s", publicIssue.Code, publicIssue.Body.String())
	}

	privateIssue := httptest.NewRecorder()
	servePrivate(privateIssue, http.HandlerFunc(capabilityHandler.Issue),
		vaultAuthzRequest(http.MethodPost, "/api/secrets/issue", userID, "user", "", body))
	if privateIssue.Code != http.StatusCreated {
		t.Fatalf("private capability issue got HTTP %d: %s", privateIssue.Code, privateIssue.Body.String())
	}
	var issued issueResponse
	if err := json.NewDecoder(privateIssue.Body).Decode(&issued); err != nil || issued.Token == "" {
		t.Fatalf("decode issued capability: token=%q err=%v body=%s", issued.Token, err, privateIssue.Body.String())
	}

	// Spending through the public proxy must still fail before nonce spend,
	// decryption, or any upstream network request.
	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capabilityHandler.Proxy)
	publicSpend := httptest.NewRecorder()
	spendReq := httptest.NewRequest(http.MethodPost, "/proxy/api.example.com/v1", strings.NewReader(`{}`))
	spendReq.Header.Set("Authorization", "Capability "+issued.Token)
	router.ServeHTTP(publicSpend, spendReq)
	if publicSpend.Code != http.StatusForbidden || !strings.Contains(publicSpend.Body.String(), middleware.PrivateIngressRequiredCode) {
		t.Fatalf("public capability spend got HTTP %d: %s", publicSpend.Code, publicSpend.Body.String())
	}
}

func TestHistoricalAuditReadersStayPrivateAfterProtectedCollectionIsGone(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "private-audit-latch@example.com", "admin", "")
	const collectionID = "private-audit-latch"
	mustCollection(t, queries, collectionID, userID, map[string]string{userID: collRoleManager})
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "fully_private")
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "standard")
	if err := queries.DeleteCollection(context.Background(), collectionID); err != nil {
		t.Fatalf("delete downgraded source collection: %v", err)
	}

	publicRec := httptest.NewRecorder()
	publicReq := vaultAuthzRequest(http.MethodGet, "/api/activity", userID, "admin", "", "")
	if requireHistoricalPrivateAuditIngress(publicRec, publicReq, queries) {
		t.Fatal("public ingress reopened historical audit readers after downgrade/delete")
	}
	if publicRec.Code != http.StatusForbidden ||
		!strings.Contains(publicRec.Body.String(), middleware.PrivateIngressRequiredCode) {
		t.Fatalf("public historical audit refusal = HTTP %d %s", publicRec.Code, publicRec.Body.String())
	}

	privateAllowed := false
	privateRec := httptest.NewRecorder()
	servePrivate(privateRec, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateAllowed = requireHistoricalPrivateAuditIngress(w, r, queries)
		w.WriteHeader(http.StatusNoContent)
	}), publicReq)
	if !privateAllowed {
		t.Fatal("private ingress was refused by the historical audit latch")
	}
}

func TestGlobalRekeyControlPlaneSharesTheProtectedPolicySnapshot(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "private-rekey@example.com", "admin", "")
	const collectionID = "private-rekey-collection"
	mustCollection(t, queries, collectionID, admin, map[string]string{admin: collRoleManager})
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "sensitive_private")

	request := func(method, path string) *http.Request {
		return vaultAuthzRequest(method, path, admin, "admin", "", "")
	}
	for _, endpoint := range []struct {
		name    string
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{name: "status", method: http.MethodGet, path: "/api/admin/vault-key", handler: vault.VaultKeyStatus},
		{name: "sweep", method: http.MethodPost, path: "/api/admin/vault-key/rekey", handler: vault.VaultKeyRekey},
	} {
		t.Run(endpoint.name+" public", func(t *testing.T) {
			rec := httptest.NewRecorder()
			endpoint.handler(rec, request(endpoint.method, endpoint.path))
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), middleware.PrivateIngressRequiredCode) {
				t.Fatalf("public global %s = HTTP %d %s", endpoint.name, rec.Code, rec.Body.String())
			}
		})
		t.Run(endpoint.name+" private", func(t *testing.T) {
			rec := httptest.NewRecorder()
			servePrivate(rec, endpoint.handler, request(endpoint.method, endpoint.path))
			if rec.Code != http.StatusOK {
				t.Fatalf("private global %s = HTTP %d %s", endpoint.name, rec.Code, rec.Body.String())
			}
		})
	}

	// Boot/headless rekey is server-initiated work, not an HTTP ingress bypass.
	// It must remain available so an operator can recover/rotate keys while the
	// optional connector itself is being repaired.
	if _, err := vault.RekeyVault(context.Background()); err != nil {
		t.Fatalf("server-initiated rekey with protected collections: %v", err)
	}
}

func TestAIConfigNormalizesHiddenSelectionAndProtectsExistingBinding(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	adminID := mustUser(t, queries, "private-ai-config@example.com", "admin", "")
	const collectionID = "private-ai-collection"
	const entryID = "private-ai-entry"
	mustCollection(t, queries, collectionID, adminID, map[string]string{adminID: collRoleManager})
	mustEntry(t, vault, queries, entryID, adminID, "hidden AI key", "provider-key")
	placeInCollection(t, queries, entryID, collectionID)
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "fully_private")

	h := NewAIGatewayHandler(queries, &config.Config{
		BaseURL:         "https://vault.example.test",
		ShieldHintLevel: "full",
	}, vault, nil)

	request := func(body string) *http.Request {
		return vaultAuthzRequest(http.MethodPut, "/api/settings/ai", adminID, "admin", "", body)
	}
	missing := httptest.NewRecorder()
	h.UpdateConfig(missing, request(`{"anthropic_entry_id":"missing-entry"}`))
	hidden := httptest.NewRecorder()
	h.UpdateConfig(hidden, request(`{"anthropic_entry_id":"`+entryID+`"}`))
	if missing.Code != hidden.Code || missing.Body.String() != hidden.Body.String() {
		t.Fatalf("hidden AI selection differs from missing selection:\nmissing: HTTP %d %s\nhidden: HTTP %d %s",
			missing.Code, missing.Body.String(), hidden.Code, hidden.Body.String())
	}
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing/hidden selection got HTTP %d, want 400", missing.Code)
	}

	if err := queries.UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: "ai_key_anthropic", Value: entryID,
	}); err != nil {
		t.Fatalf("bind hidden AI entry: %v", err)
	}
	h.cfg.PrivateBaseURL = "https://vault-private.example.test"
	publicWrite := httptest.NewRecorder()
	h.UpdateConfig(publicWrite, request(`{"openai_entry_id":""}`))
	if publicWrite.Code != http.StatusForbidden ||
		!strings.Contains(publicWrite.Body.String(), middleware.PrivateIngressRequiredCode) {
		t.Fatalf("public write with hidden current binding = HTTP %d %s", publicWrite.Code, publicWrite.Body.String())
	}

	privateClear := httptest.NewRecorder()
	servePrivate(privateClear, http.HandlerFunc(h.UpdateConfig), request(`{"anthropic_entry_id":""}`))
	if privateClear.Code != http.StatusOK {
		t.Fatalf("private clear of hidden binding = HTTP %d %s", privateClear.Code, privateClear.Body.String())
	}
}

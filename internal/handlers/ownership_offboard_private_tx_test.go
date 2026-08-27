package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
	"github.com/go-chi/chi/v5"
)

func waitOwnershipOffboardResponse(t *testing.T, responses <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case <-time.After(3 * time.Second):
		t.Fatal("request did not finish after the competing transaction committed")
		return nil
	}
}

func deleteUserRequest(targetID, adminID string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+targetID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", targetID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, timw.UserIDKey, adminID)
	ctx = context.WithValue(ctx, timw.UserRoleKey, timw.RoleAdmin)
	return r.WithContext(ctx)
}

// TestOwnershipClaimSeesConcurrentFullyPrivatePromotion reproduces the stale
// policy window in the repair route. The old handler read access and policy
// through the pool, then waited for the writer only when it began the ownership
// transaction; after the promotion committed it transferred the now-hidden
// entry on public ingress. The first read now occurs after the write transaction
// is acquired, so the protected row is indistinguishable from a missing one.
func TestOwnershipClaimSeesConcurrentFullyPrivatePromotion(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "ownership-race-admin@example.com", "admin", "")
	leaver := mustUser(t, queries, "ownership-race-leaver@example.com", "user", "")
	const (
		collectionID = "ownership-race-collection"
		entryID      = "ownership-race-entry"
	)
	mustCollection(t, queries, collectionID, leaver, map[string]string{
		leaver: collRoleManager,
		admin:  collRoleManager,
	})
	mustEntry(t, vault, queries, entryID, leaver, "ownership race key", "secret")
	placeInCollection(t, queries, entryID, collectionID)
	if _, err := vault.db.Exec(`UPDATE vault_entries SET secret_owner_user_id = '' WHERE id = ?`, entryID); err != nil {
		t.Fatalf("withhold recorded owner: %v", err)
	}

	blocker, err := vault.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin competing promotion: %v", err)
	}
	defer blocker.Rollback()
	if err := queries.WithTx(blocker).UpdateCollection(context.Background(), db.UpdateCollectionParams{
		Name: collectionID, Description: "",
		PrivateAccessPolicy: sql.NullString{String: string(privateaccess.PolicyFullyPrivate), Valid: true},
		ID:                  collectionID,
	}); err != nil {
		t.Fatalf("stage private promotion: %v", err)
	}

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		vault.ClaimSecretOwnership(response, vaultAuthzRequest(http.MethodPost,
			"/api/admin/vault/"+entryID+"/ownership/claim", admin, "admin", entryID, ""))
		responses <- response
	}()
	time.Sleep(100 * time.Millisecond)
	if err := blocker.Commit(); err != nil {
		t.Fatalf("commit private promotion: %v", err)
	}

	hidden := waitOwnershipOffboardResponse(t, responses)
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("public claim spent its stale standard-policy decision: HTTP %d, want 404: %s",
			hidden.Code, hidden.Body.String())
	}
	missing := httptest.NewRecorder()
	vault.ClaimSecretOwnership(missing, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/missing-ownership-race/ownership/claim", admin, "admin", "missing-ownership-race", ""))
	if hidden.Code != missing.Code || hidden.Body.String() != missing.Body.String() {
		t.Fatalf("fully-private and missing claim probes differ\nprivate: %d %s\nmissing: %d %s",
			hidden.Code, hidden.Body.String(), missing.Code, missing.Body.String())
	}

	access, err := queries.GetVaultEntryAccess(context.Background(), entryID)
	if err != nil {
		t.Fatalf("read refused entry: %v", err)
	}
	if access.SecretOwnerUserID != "" || access.UserID != leaver {
		t.Fatalf("refused public claim mutated ownership: custodian=%q owner=%q",
			access.UserID, access.SecretOwnerUserID)
	}
}

// TestUserDeleteSeesConcurrentPrivatePromotionBeforeCleanup covers the admin
// offboarding variant. The previous conditional DELETE correctly refused after
// a promotion, but credential and target cleanup had already committed in
// separate statements. A denied public request therefore changed the target
// account. The policy decision now precedes every side effect in one write
// transaction.
func TestUserDeleteSeesConcurrentPrivatePromotionBeforeCleanup(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "offboard-race-admin@example.com", "admin", "")
	target := mustUser(t, queries, "offboard-race-target@example.com", "user", "")
	serviceID := mustServiceIdentity(t, queries, target, "offboard-race-service")
	const (
		collectionID = "offboard-race-collection"
		entryID      = "offboard-race-entry"
	)
	mustCollection(t, queries, collectionID, target, map[string]string{
		target: collRoleManager,
		admin:  collRoleManager,
	})
	mustEntry(t, vault, queries, entryID, target, "offboard race key", "secret")
	placeInCollection(t, queries, entryID, collectionID)
	targets := []RotationTarget{{
		Type: "webhook", WebhookURL: "https://delivery.example.test/hook", ConfiguredBy: target,
	}}
	rawTargets, err := json.Marshal(targets)
	if err != nil {
		t.Fatalf("encode target fixture: %v", err)
	}
	sealedTargets, err := vault.encryptColumn(string(rawTargets))
	if err != nil {
		t.Fatalf("seal target fixture: %v", err)
	}
	if err := setRotationTargetsFixture(t, queries, vaultegress.RotationTargetsParams{
		RotationTargets: toNullString(sealedTargets), ID: entryID,
	}); err != nil {
		t.Fatalf("seed target fixture: %v", err)
	}

	blocker, err := vault.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin competing promotion: %v", err)
	}
	defer blocker.Rollback()
	if err := queries.WithTx(blocker).UpdateCollection(context.Background(), db.UpdateCollectionParams{
		Name: collectionID, Description: "",
		PrivateAccessPolicy: sql.NullString{String: string(privateaccess.PolicyFullyPrivate), Valid: true},
		ID:                  collectionID,
	}); err != nil {
		t.Fatalf("stage private promotion: %v", err)
	}

	users := NewUserHandler(queries, nil)
	users.SetVault(vault)
	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		users.Delete(response, deleteUserRequest(target, admin))
		responses <- response
	}()
	time.Sleep(100 * time.Millisecond)
	if err := blocker.Commit(); err != nil {
		t.Fatalf("commit private promotion: %v", err)
	}

	response := waitOwnershipOffboardResponse(t, responses)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), timw.PrivateIngressRequiredCode) {
		t.Fatalf("public delete after promotion got HTTP %d, want private-ingress refusal: %s",
			response.Code, response.Body.String())
	}
	if _, err := queries.GetUserByID(context.Background(), target); err != nil {
		t.Fatalf("refused delete removed the target user: %v", err)
	}
	if !serviceIdentityIsLive(t, queries, target, serviceID) {
		t.Fatal("refused public delete revoked a service identity before observing the private policy")
	}
	stored, err := queries.GetVaultEntryTargets(context.Background(), entryID)
	if err != nil {
		t.Fatalf("read targets after refusal: %v", err)
	}
	left := ParseRotationTargets(vault.decryptColumnOrLog(stored.String, "[]", vaultFieldRotationTargets))
	if len(left) != 1 || left[0].ConfiguredBy != target {
		t.Fatalf("refused public delete purged the target before observing the private policy: %+v", left)
	}
}

// TestUserDeleteRollsBackWhenSharedVaultTransferFails pins the atomicity half.
// Hard deletion must not commit the identity/credential revocation and then
// discover that a shared secret could not be transferred. The trigger models a
// storage failure at the ownership chokepoint; every earlier offboarding write
// must roll back with it.
func TestUserDeleteRollsBackWhenSharedVaultTransferFails(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	admin := mustUser(t, queries, "offboard-rollback-admin@example.com", "admin", "")
	target := mustUser(t, queries, "offboard-rollback-target@example.com", "user", "")
	serviceID := mustServiceIdentity(t, queries, target, "offboard-rollback-service")
	const (
		collectionID = "offboard-rollback-collection"
		entryID      = "offboard-rollback-entry"
	)
	mustCollection(t, queries, collectionID, target, map[string]string{
		target: collRoleManager,
		admin:  collRoleManager,
	})
	mustEntry(t, vault, queries, entryID, target, "offboard rollback key", "secret")
	placeInCollection(t, queries, entryID, collectionID)
	if _, err := vault.db.Exec(`
		CREATE TRIGGER fail_offboard_transfer
		BEFORE UPDATE OF user_id ON vault_entries
		WHEN OLD.id = '` + entryID + `'
		BEGIN
			SELECT RAISE(ABORT, 'offboard transfer blocked');
		END`); err != nil {
		t.Fatalf("install transfer failure: %v", err)
	}

	users := NewUserHandler(queries, nil)
	users.SetVault(vault)
	response := httptest.NewRecorder()
	users.Delete(response, deleteUserRequest(target, admin))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("failed transfer returned HTTP %d, want 500: %s", response.Code, response.Body.String())
	}
	if _, err := queries.GetUserByID(context.Background(), target); err != nil {
		t.Fatalf("failed offboarding still deleted the user: %v", err)
	}
	if !serviceIdentityIsLive(t, queries, target, serviceID) {
		t.Fatal("failed offboarding committed credential revocation instead of rolling it back")
	}
	access, err := queries.GetVaultEntryAccess(context.Background(), entryID)
	if err != nil {
		t.Fatalf("read entry after rollback: %v", err)
	}
	if access.UserID != target || access.SecretOwnerUserID != target {
		t.Fatalf("failed offboarding partially transferred ownership: custodian=%q owner=%q",
			access.UserID, access.SecretOwnerUserID)
	}
}

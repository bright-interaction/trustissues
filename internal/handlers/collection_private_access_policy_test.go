package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
)

func TestCollectionPrivateAccessPolicyCreateAndValidation(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	handler := NewCollectionHandler(queries, vault)
	creator := mustUser(t, queries, "policy-creator@example.com", "user", "")

	create := func(body map[string]any, private bool) (*httptest.ResponseRecorder, collectionResponse) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := liveCollectionRequest(t, http.MethodPost, "/api/collections", creator, "", body)
		serve := http.HandlerFunc(handler.Create)
		if private {
			middleware.StampIngressZone(middleware.IngressPrivate)(serve).ServeHTTP(rec, req)
		} else {
			serve.ServeHTTP(rec, req)
		}
		var response collectionResponse
		if rec.Code == http.StatusCreated {
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Fatalf("decode create response: %v", err)
			}
		}
		return rec, response
	}

	rec, standard := create(map[string]any{"name": "Compatible", "description": ""}, false)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create without policy got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if standard.PrivateAccessPolicy != privateaccess.PolicyStandard {
		t.Fatalf("omitted create policy = %q, want %q", standard.PrivateAccessPolicy, privateaccess.PolicyStandard)
	}
	stored, err := queries.GetCollection(context.Background(), standard.ID)
	if err != nil {
		t.Fatalf("read compatible collection: %v", err)
	}
	if stored.PrivateAccessPolicy != string(privateaccess.PolicyStandard) {
		t.Fatalf("stored omitted policy = %q, want standard", stored.PrivateAccessPolicy)
	}

	rec, _ = create(map[string]any{
		"name": "Public cannot opt in", "description": "", "private_access_policy": "fully_private",
	}, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("public protected create got HTTP %d, want 403: %s", rec.Code, rec.Body.String())
	}

	rec, fullyPrivate := create(map[string]any{
		"name": "Private", "description": "", "private_access_policy": "fully_private",
	}, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with policy got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if fullyPrivate.PrivateAccessPolicy != privateaccess.PolicyFullyPrivate {
		t.Fatalf("create response policy = %q, want fully_private", fullyPrivate.PrivateAccessPolicy)
	}
	stored, err = queries.GetCollection(context.Background(), fullyPrivate.ID)
	if err != nil || stored.PrivateAccessPolicy != string(privateaccess.PolicyFullyPrivate) {
		t.Fatalf("stored explicit policy = %q, err=%v", stored.PrivateAccessPolicy, err)
	}

	before, err := queries.ListAllCollections(context.Background())
	if err != nil {
		t.Fatalf("list before invalid creates: %v", err)
	}
	for _, invalid := range []string{"private", "STANDARD", " fully_private "} {
		rec, _ := create(map[string]any{
			"name": "Rejected", "description": "", "private_access_policy": invalid,
		}, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("create accepted policy %q with HTTP %d: %s", invalid, rec.Code, rec.Body.String())
		}
	}
	after, err := queries.ListAllCollections(context.Background())
	if err != nil || len(after) != len(before) {
		t.Fatalf("invalid create changed collection count %d -> %d (err=%v)", len(before), len(after), err)
	}
}

func TestCollectionPrivateAccessPolicyUpdateAuthorizationAndReadScope(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	handler := NewCollectionHandler(queries, vault)
	manager := mustUser(t, queries, "policy-manager@example.com", "user", "")
	viewer := mustUser(t, queries, "policy-viewer@example.com", "user", "")
	pending := mustUser(t, queries, "policy-pending@example.com", "user", "")
	outsider := mustUser(t, queries, "policy-outsider@example.com", "user", "")
	admin := mustUser(t, queries, "policy-admin@example.com", "admin", "")
	const collectionID = "policy-collection"
	mustCollection(t, queries, collectionID, manager, map[string]string{
		manager: collRoleManager,
		viewer:  collRoleViewer,
	})
	if err := queries.AddCollectionMember(context.Background(), db.AddCollectionMemberParams{
		CollectionID: collectionID,
		UserID:       pending,
		Role:         collRoleViewer,
		AcceptedAt:   sql.NullTime{},
		InvitedBy:    toNullString(manager),
	}); err != nil {
		t.Fatalf("add pending member: %v", err)
	}

	update := func(who, instanceRole string, body map[string]any, private bool) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal update body: %v", err)
		}
		rec := httptest.NewRecorder()
		req := collectionRequest(http.MethodPut, "/api/collections/"+collectionID,
			who, instanceRole, collectionID, string(raw))
		serve := http.HandlerFunc(handler.Update)
		if private {
			middleware.StampIngressZone(middleware.IngressPrivate)(serve).ServeHTTP(rec, req)
		} else {
			serve.ServeHTTP(rec, req)
		}
		return rec
	}
	readPolicy := func() string {
		t.Helper()
		row, err := queries.GetCollection(context.Background(), collectionID)
		if err != nil {
			t.Fatalf("read collection: %v", err)
		}
		return row.PrivateAccessPolicy
	}

	rec := update(manager, "user", map[string]any{
		"name": collectionID, "description": "manager update", "private_access_policy": "sensitive_private",
	}, true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("manager policy update got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if got := readPolicy(); got != string(privateaccess.PolicySensitivePrivate) {
		t.Fatalf("manager update stored %q, want sensitive_private", got)
	}
	rec = update(manager, "user", map[string]any{
		"name": collectionID, "description": "public downgrade", "private_access_policy": "standard",
	}, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("public downgrade got HTTP %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if got := readPolicy(); got != string(privateaccess.PolicySensitivePrivate) {
		t.Fatalf("public downgrade changed policy to %q", got)
	}

	// An old client sends only name and description. That must never silently
	// downgrade an already-protected collection to the default.
	rec = update(manager, "user", map[string]any{
		"name": collectionID, "description": "legacy client update",
	}, true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("policy-omitting update got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if got := readPolicy(); got != string(privateaccess.PolicySensitivePrivate) {
		t.Fatalf("policy-omitting update changed policy to %q", got)
	}

	for _, invalid := range []string{"", "private", "SENSITIVE_PRIVATE"} {
		rec = update(manager, "user", map[string]any{
			"name": collectionID, "description": "invalid", "private_access_policy": invalid,
		}, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("update accepted policy %q with HTTP %d: %s", invalid, rec.Code, rec.Body.String())
		}
		if got := readPolicy(); got != string(privateaccess.PolicySensitivePrivate) {
			t.Fatalf("invalid update %q changed policy to %q", invalid, got)
		}
	}

	rec = update(viewer, "user", map[string]any{
		"name": collectionID, "description": "viewer", "private_access_policy": "standard",
	}, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer policy update got HTTP %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if got := readPolicy(); got != string(privateaccess.PolicySensitivePrivate) {
		t.Fatalf("viewer changed policy to %q", got)
	}

	// Instance admins retain the existing manager-equivalent authority even
	// without a collection membership.
	rec = update(admin, "admin", map[string]any{
		"name": collectionID, "description": "admin", "private_access_policy": "fully_private",
	}, true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin policy update got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if got := readPolicy(); got != string(privateaccess.PolicyFullyPrivate) {
		t.Fatalf("admin update stored %q, want fully_private", got)
	}

	// An accepted viewer may read the policy through both authorized collection
	// surfaces, but a non-member gets the same 404 as any other collection probe.
	get := httptest.NewRecorder()
	middleware.StampIngressZone(middleware.IngressPrivate)(http.HandlerFunc(handler.Get)).ServeHTTP(get,
		liveCollectionRequest(t, http.MethodGet, "/api/collections/"+collectionID, viewer, collectionID, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("viewer get got HTTP %d: %s", get.Code, get.Body.String())
	}
	var gotCollection collectionResponse
	if err := json.NewDecoder(get.Body).Decode(&gotCollection); err != nil {
		t.Fatalf("decode viewer get: %v", err)
	}
	if gotCollection.PrivateAccessPolicy != privateaccess.PolicyFullyPrivate {
		t.Fatalf("viewer get policy = %q, want fully_private", gotCollection.PrivateAccessPolicy)
	}

	list := httptest.NewRecorder()
	middleware.StampIngressZone(middleware.IngressPrivate)(http.HandlerFunc(handler.List)).ServeHTTP(list,
		liveCollectionRequest(t, http.MethodGet, "/api/collections", viewer, "", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("viewer list got HTTP %d: %s", list.Code, list.Body.String())
	}
	var listed []collectionResponse
	if err := json.NewDecoder(list.Body).Decode(&listed); err != nil {
		t.Fatalf("decode viewer list: %v", err)
	}
	if len(listed) != 1 || listed[0].PrivateAccessPolicy != privateaccess.PolicyFullyPrivate {
		t.Fatalf("viewer list = %+v, want one fully_private collection", listed)
	}
	publicList := httptest.NewRecorder()
	handler.List(publicList, liveCollectionRequest(t, http.MethodGet, "/api/collections", viewer, "", nil))
	var publicListed []collectionResponse
	if publicList.Code != http.StatusOK {
		t.Fatalf("public collection list got HTTP %d: %s", publicList.Code, publicList.Body.String())
	}
	if err := json.NewDecoder(publicList.Body).Decode(&publicListed); err != nil {
		t.Fatalf("decode public collection list: %v", err)
	}
	if len(publicListed) != 0 {
		t.Fatalf("public list disclosed fully_private collection: %+v", publicListed)
	}

	missing := httptest.NewRecorder()
	handler.Get(missing, liveCollectionRequest(
		t, http.MethodGet, "/api/collections/"+collectionID, outsider, collectionID, nil,
	))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("non-member get got HTTP %d, want 404: %s", missing.Code, missing.Body.String())
	}

	// A pending invitation is intentionally not an authorized membership. Its
	// consent card can identify the collection, but must not expose policy.
	pendingList := httptest.NewRecorder()
	middleware.StampIngressZone(middleware.IngressPrivate)(http.HandlerFunc(handler.ListPendingInvites)).ServeHTTP(
		pendingList,
		liveCollectionRequest(t, http.MethodGet, "/api/collections/invitations", pending, "", nil))
	if pendingList.Code != http.StatusOK {
		t.Fatalf("pending list got HTTP %d: %s", pendingList.Code, pendingList.Body.String())
	}
	var pendingPayload []map[string]any
	if err := json.NewDecoder(pendingList.Body).Decode(&pendingPayload); err != nil {
		t.Fatalf("decode pending list: %v", err)
	}
	if len(pendingPayload) != 1 {
		t.Fatalf("pending list has %d rows, want the one real invitation", len(pendingPayload))
	}
	if _, disclosed := pendingPayload[0]["private_access_policy"]; disclosed {
		t.Fatalf("pending invitation disclosed collection policy: %+v", pendingPayload[0])
	}
}

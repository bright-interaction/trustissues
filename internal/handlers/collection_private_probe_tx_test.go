package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
	"github.com/go-chi/chi/v5"
)

type collectionProbeResponse struct {
	code   int
	body   string
	header http.Header
}

func runCollectionProbe(handler http.HandlerFunc, request *http.Request) collectionProbeResponse {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return collectionProbeResponse{
		code:   recorder.Code,
		body:   recorder.Body.String(),
		header: recorder.Result().Header.Clone(),
	}
}

// TestFullyPrivateCollectionIDSurfacesMatchMissing proves that no collection-id
// route performs a role-specific 403 before hiding a fully-private collection.
// A viewer used to get 403 on management routes for a real protected id and 404
// for a missing id, which made the supposedly hidden collection enumerable.
func TestFullyPrivateCollectionIDSurfacesMatchMissing(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	handler := NewCollectionHandler(queries, vault)
	ctx := context.Background()

	manager := mustUser(t, queries, "private-probe-manager@example.com", "user", "")
	manager2 := mustUser(t, queries, "private-probe-manager2@example.com", "user", "")
	viewer := mustUser(t, queries, "private-probe-viewer@example.com", "user", "")
	pending := mustUser(t, queries, "private-probe-pending@example.com", "user", "")
	target := mustUser(t, queries, "private-probe-target@example.com", "user", "")
	const protectedID = "fully-private-probe"
	const missingID = "missing-private-probe"
	mustCollection(t, queries, protectedID, manager, map[string]string{
		manager:  collRoleManager,
		manager2: collRoleManager,
		viewer:   collRoleViewer,
		target:   collRoleEditor,
	})
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: protectedID,
		UserID:       pending,
		Role:         collRoleViewer,
		AcceptedAt:   sql.NullTime{},
		InvitedBy:    toNullString(manager),
	}); err != nil {
		t.Fatalf("add pending member: %v", err)
	}
	if err := queries.UpdateCollection(ctx, db.UpdateCollectionParams{
		Name:                protectedID,
		Description:         "",
		PrivateAccessPolicy: sql.NullString{String: string(privateaccess.PolicyFullyPrivate), Valid: true},
		ID:                  protectedID,
	}); err != nil {
		t.Fatalf("protect collection: %v", err)
	}

	type surface struct {
		name       string
		method     string
		suffix     string
		body       string
		handler    http.HandlerFunc
		targetUser string
	}
	surfaces := []surface{
		{name: "get", method: http.MethodGet, handler: handler.Get},
		{name: "update", method: http.MethodPut, body: `{"name":"probe","description":""}`, handler: handler.Update},
		{name: "delete", method: http.MethodDelete, handler: handler.Delete},
		{name: "list members", method: http.MethodGet, suffix: "/members", handler: handler.ListMembers},
		{name: "add member", method: http.MethodPost, suffix: "/members", body: `{"email":"someone@example.com","role":"viewer"}`, handler: handler.AddMember},
		{name: "remove member", method: http.MethodDelete, suffix: "/members/" + target, handler: handler.RemoveMember, targetUser: target},
		{name: "rescind invitation", method: http.MethodDelete, suffix: "/invitations", body: `{"email":"someone@example.com"}`, handler: handler.RescindInvitation},
	}

	request := func(test surface, collectionID, actor string) *http.Request {
		r := collectionRequest(test.method, "/api/collections/"+collectionID+test.suffix,
			actor, "user", collectionID, test.body)
		if test.targetUser != "" {
			chi.RouteContext(r.Context()).URLParams.Add("userId", test.targetUser)
		}
		return r
	}
	for principalName, actor := range map[string]string{"viewer": viewer, "manager": manager} {
		for _, test := range surfaces {
			t.Run(principalName+"/"+test.name, func(t *testing.T) {
				protected := runCollectionProbe(test.handler, request(test, protectedID, actor))
				missing := runCollectionProbe(test.handler, request(test, missingID, actor))
				if protected.code != http.StatusNotFound {
					t.Fatalf("protected probe got HTTP %d, want 404: %s", protected.code, protected.body)
				}
				if !reflect.DeepEqual(protected, missing) {
					t.Fatalf("fully-private and missing probes differ\nprotected: %#v\nmissing:   %#v", protected, missing)
				}
			})
		}
	}

	for _, test := range []surface{
		{name: "accept", method: http.MethodPost, suffix: "/accept", handler: handler.AcceptInvite},
		{name: "decline", method: http.MethodPost, suffix: "/decline", handler: handler.DeclineInvite},
	} {
		t.Run("pending/"+test.name, func(t *testing.T) {
			protected := runCollectionProbe(test.handler, request(test, protectedID, pending))
			missing := runCollectionProbe(test.handler, request(test, missingID, pending))
			if protected.code != http.StatusNotFound || !reflect.DeepEqual(protected, missing) {
				t.Fatalf("fully-private and missing probes differ\nprotected: %#v\nmissing:   %#v", protected, missing)
			}
		})
	}
}

func waitForCollectionResponse(t *testing.T, responses <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case <-time.After(3 * time.Second):
		t.Fatal("collection request did not finish after the blocking transaction committed")
		return nil
	}
}

func startCollectionUpdate(handler *CollectionHandler, userID, collectionID string) <-chan *httptest.ResponseRecorder {
	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		handler.Update(response, collectionRequest(http.MethodPut, "/api/collections/"+collectionID,
			userID, "user", collectionID, `{"name":"stale write","description":""}`))
		responses <- response
	}()
	return responses
}

// TestCollectionUpdateRechecksPolicyAndRoleAfterConcurrentCommit exercises the
// exact check/use window: a competing writer changes the policy or caller role
// while the request waits for SQLite's write lock. Authorization must happen
// after that commit, in the same transaction as the update.
func TestCollectionUpdateRechecksPolicyAndRoleAfterConcurrentCommit(t *testing.T) {
	for _, test := range []struct {
		name   string
		key    string
		change func(*testing.T, *db.Queries, string, string)
		code   int
	}{
		{
			name: "policy becomes fully private",
			key:  "policy",
			change: func(t *testing.T, qtx *db.Queries, collectionID, _ string) {
				t.Helper()
				if err := qtx.UpdateCollection(context.Background(), db.UpdateCollectionParams{
					Name: collectionID, Description: "",
					PrivateAccessPolicy: sql.NullString{String: string(privateaccess.PolicyFullyPrivate), Valid: true},
					ID:                  collectionID,
				}); err != nil {
					t.Fatalf("stage protected policy: %v", err)
				}
			},
			code: http.StatusNotFound,
		},
		{
			name: "manager is demoted",
			key:  "role",
			change: func(t *testing.T, qtx *db.Queries, collectionID, manager string) {
				t.Helper()
				if err := qtx.AddCollectionMember(context.Background(), db.AddCollectionMemberParams{
					CollectionID: collectionID, UserID: manager, Role: collRoleViewer,
					AcceptedAt: sql.NullTime{}, InvitedBy: toNullString(manager),
				}); err != nil {
					t.Fatalf("stage manager demotion: %v", err)
				}
			},
			code: http.StatusForbidden,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			vault, queries := newCollectionAuthzEnv(t)
			handler := NewCollectionHandler(queries, vault)
			manager := mustUser(t, queries, "update-race-"+test.key+"@example.com", "user", "")
			collectionID := "update-race-" + test.key
			mustCollection(t, queries, collectionID, manager, map[string]string{manager: collRoleManager})

			blocker, err := vault.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatalf("begin blocking transaction: %v", err)
			}
			defer blocker.Rollback()
			test.change(t, queries.WithTx(blocker), collectionID, manager)

			responses := startCollectionUpdate(handler, manager, collectionID)
			time.Sleep(100 * time.Millisecond)
			if err := blocker.Commit(); err != nil {
				t.Fatalf("commit concurrent change: %v", err)
			}
			response := waitForCollectionResponse(t, responses)
			if response.Code != test.code {
				t.Fatalf("stale update got HTTP %d, want %d: %s", response.Code, test.code, response.Body.String())
			}
			stored, err := queries.GetCollection(context.Background(), collectionID)
			if err != nil {
				t.Fatalf("read collection after race: %v", err)
			}
			if stored.Name == "stale write" {
				t.Fatal("collection update used authorization from before the concurrent commit")
			}
		})
	}
}

// TestCollectionDeleteCountsInsideItsWriteTransaction prevents a newly-added
// entry from landing after the confirmation count but before the cascading
// delete. The request begins while that entry move is uncommitted; after it
// becomes visible, the delete must demand a fresh entry_count confirmation.
func TestCollectionDeleteCountsInsideItsWriteTransaction(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	handler := NewCollectionHandler(queries, vault)
	manager := mustUser(t, queries, "delete-race-manager@example.com", "user", "")
	const collectionID = "delete-race-collection"
	mustCollection(t, queries, collectionID, manager, map[string]string{manager: collRoleManager})
	mustEntry(t, vault, queries, "delete-race-entry", manager, "concurrent entry", "secret")

	blocker, err := vault.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin blocking transaction: %v", err)
	}
	defer blocker.Rollback()
	placeInCollection(t, queries.WithTx(blocker), "delete-race-entry", collectionID)

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		handler.Delete(response, deleteCollectionRequest(collectionID, manager, ""))
		responses <- response
	}()
	time.Sleep(100 * time.Millisecond)
	if err := blocker.Commit(); err != nil {
		t.Fatalf("commit concurrent entry move: %v", err)
	}
	response := waitForCollectionResponse(t, responses)
	if response.Code != http.StatusConflict {
		t.Fatalf("delete used stale empty count: HTTP %d, want 409: %s", response.Code, response.Body.String())
	}
	if _, err := queries.GetCollection(context.Background(), collectionID); err != nil {
		t.Fatalf("collection was destroyed despite the newly visible entry: %v", err)
	}
	count, err := queries.CountCollectionEntries(context.Background(), sql.NullString{String: collectionID, Valid: true})
	if err != nil || count != 1 {
		t.Fatalf("entry count after refused delete = %d, err=%v; want 1", count, err)
	}
}

// TestMemberRemovalAuthorizationAndLastManagerGuardShareOneTransaction covers
// the orphaning race: while one writer removes manager B, B tries to remove A.
// Once B's removal commits, B must not be allowed to spend their stale manager
// role to remove the only manager left.
func TestMemberRemovalAuthorizationAndLastManagerGuardShareOneTransaction(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	handler := NewCollectionHandler(queries, vault)
	managerA := mustUser(t, queries, "remove-race-a@example.com", "user", "")
	managerB := mustUser(t, queries, "remove-race-b@example.com", "user", "")
	const collectionID = "remove-race-collection"
	mustCollection(t, queries, collectionID, managerA, map[string]string{
		managerA: collRoleManager,
		managerB: collRoleManager,
	})

	blocker, err := vault.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin blocking transaction: %v", err)
	}
	defer blocker.Rollback()
	if _, err := queries.WithTx(blocker).RemoveCollectionMember(context.Background(), db.RemoveCollectionMemberParams{
		CollectionID: collectionID, UserID: managerB,
	}); err != nil {
		t.Fatalf("stage first manager removal: %v", err)
	}

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		request := collectionRequest(http.MethodDelete, "/api/collections/"+collectionID+"/members/"+managerA,
			managerB, "user", collectionID, "")
		chi.RouteContext(request.Context()).URLParams.Add("userId", managerA)
		handler.RemoveMember(response, request)
		responses <- response
	}()
	time.Sleep(100 * time.Millisecond)
	if err := blocker.Commit(); err != nil {
		t.Fatalf("commit first manager removal: %v", err)
	}
	response := waitForCollectionResponse(t, responses)
	if response.Code != http.StatusNotFound {
		t.Fatalf("removed manager spent stale authority: HTTP %d, want 404: %s", response.Code, response.Body.String())
	}
	count, err := queries.CountCollectionManagers(context.Background(), collectionID)
	if err != nil || count != 1 {
		t.Fatalf("manager count after race = %d, err=%v; want 1", count, err)
	}
	if role, err := queries.GetCollectionMemberRole(context.Background(), db.GetCollectionMemberRoleParams{
		CollectionID: collectionID, UserID: managerA,
	}); err != nil || role != collRoleManager {
		t.Fatalf("surviving manager role = %q, err=%v; want manager", role, err)
	}
}

func TestSensitivePrivateCollectionDoesNotBecomeOutsiderOracle(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	handler := NewCollectionHandler(queries, vault)
	manager := mustUser(t, queries, "sensitive-probe-manager@example.com", "user", "")
	viewer := mustUser(t, queries, "sensitive-probe-viewer@example.com", "user", "")
	outsider := mustUser(t, queries, "sensitive-probe-outsider@example.com", "user", "")
	const collectionID = "sensitive-probe"
	mustCollection(t, queries, collectionID, manager, map[string]string{
		manager: collRoleManager,
		viewer:  collRoleViewer,
	})
	if err := queries.UpdateCollection(context.Background(), db.UpdateCollectionParams{
		Name: collectionID, Description: "",
		PrivateAccessPolicy: sql.NullString{String: string(privateaccess.PolicySensitivePrivate), Valid: true},
		ID:                  collectionID,
	}); err != nil {
		t.Fatalf("set sensitive policy: %v", err)
	}

	update := func(actor string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.Update(response, collectionRequest(http.MethodPut, "/api/collections/"+collectionID,
			actor, "user", collectionID, `{"name":"probe","description":""}`))
		return response
	}
	if response := update(outsider); response.Code != http.StatusNotFound {
		t.Fatalf("outsider learned sensitive collection exists: HTTP %d: %s", response.Code, response.Body.String())
	}
	if response := update(viewer); response.Code != http.StatusForbidden {
		t.Fatalf("viewer role denial got HTTP %d, want 403: %s", response.Code, response.Body.String())
	} else {
		var payload map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode viewer denial: %v", err)
		}
		if payload["code"] == "private_ingress_required" {
			t.Fatalf("viewer without mutation authority received the policy-specific ingress code: %s", response.Body.String())
		}
	}
	if response := update(manager); response.Code != http.StatusForbidden {
		t.Fatalf("manager public mutation got HTTP %d, want private-ingress 403: %s", response.Code, response.Body.String())
	} else {
		var payload map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode manager denial: %v", err)
		}
		if payload["code"] != "private_ingress_required" {
			t.Fatalf("authorized manager did not receive actionable ingress code: %s", response.Body.String())
		}
	}
}

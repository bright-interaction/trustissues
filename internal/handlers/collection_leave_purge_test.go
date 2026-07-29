package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
)

// TestLeavingACollectionPurgesTheLeaversTargets covers the offboarding property
// through the door a member opens themselves.
//
// Every earlier round closed a path a MANAGER or ADMIN takes: removing a member,
// disabling an account, deleting one. DeclineInvite is the path the member takes,
// it is the same DELETE of the membership row, the code comment says leaving and
// being removed are deliberately the same operation, and the UI ships a Leave
// button on every collection at every role. It ran no cleanup at all.
//
// Two consequences, and the second is the serious one:
//   - the stale target made every later rotation "partial" and fired an alert
//     forever, with the endpoint still sitting in the panel looking live;
//   - UpdateTargets restamped ConfiguredBy across the whole submitted array, and
//     the rotation panel PUTs everything it loaded, so the owner simply saving
//     that panel re-attributed the departed member's webhook to themselves and
//     targetStillAuthorized then approved it. The next rotation POSTed the fresh
//     plaintext secret to someone who had left.
func TestLeavingACollectionPurgesTheLeaversTargets(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "leave-owner@example.com", "user", "")
	leaver := mustUser(t, queries, "leave-editor@example.com", "user", "")

	mustCollection(t, queries, "coll-leave", owner, map[string]string{
		owner:  collRoleManager,
		leaver: collRoleEditor,
	})
	const entryID = "entry-leave"
	mustEntry(t, h, queries, entryID, owner, "Stripe live key", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-leave")

	// The leaver configures a delivery target while they are a legitimate editor.
	body := `[{"type":"webhook","label":"editor-hook","webhook_url":"https://editor.example.com/h"}]`
	rec := putTargets(t, h, leaver, "user", entryID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the editor could not set a target while a member: %d %s", rec.Code, rec.Body.String())
	}

	readTargets := func() []RotationTarget {
		raw, err := queries.GetVaultEntryTargets(ctx, entryID)
		if err != nil {
			t.Fatalf("read targets: %v", err)
		}
		return ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", "rotation_targets"))
	}

	// Guard the setup: the target must exist and be authorized right now.
	stored := readTargets()
	if len(stored) != 1 || stored[0].ConfiguredBy != leaver {
		t.Fatalf("ABORT: unexpected stored target %+v", stored)
	}
	if err := targetStillAuthorized(ctx, h, entryID, stored[0]); err != nil {
		t.Fatalf("ABORT: target not authorized while the editor is a member: %v", err)
	}

	// They leave, of their own accord, via the shipped Leave button.
	ch := &CollectionHandler{queries: queries, vault: h}
	r := httptest.NewRequest(http.MethodPost, "/api/collections/coll-leave/decline", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "coll-leave")
	r = r.WithContext(context.WithValue(
		context.WithValue(r.Context(), chi.RouteCtxKey, rctx), middleware.UserIDKey, leaver))
	w := httptest.NewRecorder()
	ch.DeclineInvite(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("leave failed: %d %s", w.Code, w.Body.String())
	}

	if left := readTargets(); len(left) != 0 {
		t.Errorf("leaving did not purge the leaver's delivery target: %+v\n"+
			"every later rotation is permanently partial and the dead endpoint still shows as live", left)
	}

	// The laundering half. Even if a target survives (one planted before this
	// fix, or restored from a backup), an unrelated save by the owner must not
	// re-authorize it.
	planted := []RotationTarget{{
		Type: "webhook", Label: "stale", WebhookURL: "https://editor.example.com/h", ConfiguredBy: leaver,
	}}
	encoded, err := json.Marshal(planted)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	enc, err := h.encryptColumn(string(encoded))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := queries.UpdateVaultEntryRotationTargets(ctx, db.UpdateVaultEntryRotationTargetsParams{
		RotationTargets: toNullString(enc), ID: entryID,
	}); err != nil {
		t.Fatalf("plant target: %v", err)
	}

	// The owner opens the rotation panel and saves it back unchanged, which is
	// exactly what the UI does.
	sameBody := `[{"type":"webhook","label":"stale","webhook_url":"https://editor.example.com/h"}]`
	rec = putTargets(t, h, owner, "user", entryID, sameBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner save failed: %d %s", rec.Code, rec.Body.String())
	}

	after := readTargets()
	if len(after) != 1 {
		t.Fatalf("unexpected targets after owner save: %+v", after)
	}
	if after[0].ConfiguredBy == owner {
		t.Error("an unrelated save re-attributed the departed member's webhook to the owner; " +
			"the next rotation would deliver the fresh plaintext secret to someone who left")
	}
	if err := targetStillAuthorized(ctx, h, entryID, after[0]); err == nil {
		t.Error("the departed member's target is authorized again after an unrelated save")
	}
}

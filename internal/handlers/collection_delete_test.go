package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// deleteCollectionRequest builds an authenticated DELETE /api/collections/{id}
// request, optionally carrying ?entry_count=. rawEntryCount lets a case send a
// value the server should read as "absent" or "malformed" rather than going
// through the normal int64 formatting.
func deleteCollectionRequest(collectionID, userID string, rawEntryCount string) *http.Request {
	target := "/api/collections/" + collectionID
	if rawEntryCount != "" {
		target += "?entry_count=" + rawEntryCount
	}
	r := httptest.NewRequest(http.MethodDelete, target, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", collectionID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	return r.WithContext(ctx)
}

// TestDeleteCollectionRefusesStaleOrMissingEntryCount is the compare-and-swap
// guard on DeleteCollection. The route cascades (ON DELETE CASCADE on
// vault_entries.collection_id) straight through every secret in the
// collection with no recovery path, and it sits in the general authenticated
// group, so any collection manager, including a vault_only account, can
// destroy them in one call. The UI's confirmation dialog is not a server-side
// control: anyone calling the API directly skips it entirely. This test is
// the SERVER-enforced backstop: a non-empty collection must refuse the
// delete unless the caller's ?entry_count= matches what the server currently
// counts, proving the caller actually knew the state it was about to
// destroy.
func TestDeleteCollectionRefusesStaleOrMissingEntryCount(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	boss := mustUser(t, queries, "delcas-boss@example.com", "user", "")
	mustCollection(t, queries, "coll-cas", boss, map[string]string{boss: collRoleManager})

	mustEntry(t, vh, queries, "entry-cas-1", boss, "AWS", "secret-1")
	mustEntry(t, vh, queries, "entry-cas-2", boss, "GitHub", "secret-2")
	placeInCollection(t, queries, "entry-cas-1", "coll-cas")
	placeInCollection(t, queries, "entry-cas-2", "coll-cas")

	ch := &CollectionHandler{queries: queries, vault: vh}
	del := func(raw string) (int, string) {
		w := httptest.NewRecorder()
		ch.Delete(w, deleteCollectionRequest("coll-cas", boss, raw))
		return w.Code, w.Body.String()
	}
	assertSurvives := func(t *testing.T, label string) {
		t.Helper()
		if _, err := queries.GetCollection(ctx, "coll-cas"); err != nil {
			t.Fatalf("%s: collection was destroyed anyway: %v", label, err)
		}
		count, err := queries.CountCollectionEntries(ctx, sql.NullString{String: "coll-cas", Valid: true})
		if err != nil {
			t.Fatalf("%s: count entries: %v", label, err)
		}
		if count != 2 {
			t.Fatalf("%s: entries did not survive: count=%d, want 2", label, count)
		}
	}

	// Case 1: no entry_count at all.
	if code, body := del(""); code != http.StatusConflict {
		t.Fatalf("absent entry_count: got %d, want 409 Conflict: %s", code, body)
	}
	assertSurvives(t, "absent entry_count")

	// Case 2: a stale entry_count (the collection holds 2, not 1).
	if code, body := del("1"); code != http.StatusConflict {
		t.Fatalf("stale entry_count=1: got %d, want 409 Conflict: %s", code, body)
	}
	assertSurvives(t, "stale entry_count")

	// Case 3: a malformed entry_count must not be parsed as anything that
	// happens to match.
	if code, body := del("not-a-number"); code != http.StatusConflict {
		t.Fatalf("malformed entry_count: got %d, want 409 Conflict: %s", code, body)
	}
	assertSurvives(t, "malformed entry_count")

	// Control: the CORRECT count succeeds and the entries are actually gone
	// afterwards. Without this, a guard that refused EVERYTHING would pass
	// every assertion above while breaking the feature.
	if code, body := del("2"); code != http.StatusNoContent {
		t.Fatalf("correct entry_count=2: got %d, want 204: %s", code, body)
	}
	if _, err := queries.GetCollection(ctx, "coll-cas"); err == nil {
		t.Fatal("correct entry_count: collection still exists after delete")
	}
	count, err := queries.CountCollectionEntries(ctx, sql.NullString{String: "coll-cas", Valid: true})
	if err != nil {
		t.Fatalf("count entries after delete: %v", err)
	}
	if count != 0 {
		t.Fatalf("entries survived a confirmed delete: count=%d, want 0", count)
	}
}

// TestDeleteCollectionAllowsEmptyCollectionWithNoConfirmation matches the
// finding's own framing: nothing is lost when a collection holds no entries,
// so requiring a confirmation there would only make routine cleanup annoying.
// This also guards against a guard that is too broad: if the CAS check ran
// even for an empty collection, this would fail.
func TestDeleteCollectionAllowsEmptyCollectionWithNoConfirmation(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	boss := mustUser(t, queries, "delcas-empty@example.com", "user", "")
	mustCollection(t, queries, "coll-empty", boss, map[string]string{boss: collRoleManager})

	ch := &CollectionHandler{queries: queries, vault: vh}
	w := httptest.NewRecorder()
	ch.Delete(w, deleteCollectionRequest("coll-empty", boss, ""))
	if w.Code != http.StatusNoContent {
		t.Fatalf("empty collection delete with no entry_count: got %d, want 204: %s", w.Code, w.Body.String())
	}
}

// TestDeleteCollectionLogsNamedDamage proves the second half of the fix:
// activity_log, the one append-only tamper-evident trail this product has,
// must be able to answer "which credentials do we now have to rotate
// upstream" after a collection is destroyed. Before this change the only row
// written was "Collection deleted (id: %s)": no name, no count, no entry
// names.
func TestDeleteCollectionLogsNamedDamage(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	boss := mustUser(t, queries, "delcas-log@example.com", "user", "")
	mustCollection(t, queries, "coll-log", boss, map[string]string{boss: collRoleManager})
	if err := queries.UpdateCollection(ctx, db.UpdateCollectionParams{
		Name: "Client Rotation Vault", Description: "", ID: "coll-log",
	}); err != nil {
		t.Fatalf("name the collection: %v", err)
	}

	names := []string{"AWS root", "Stripe live key", "Datadog API token"}
	for i, name := range names {
		id := fmt.Sprintf("entry-log-%d", i)
		mustEntry(t, vh, queries, id, boss, name, "secret-value")
		placeInCollection(t, queries, id, "coll-log")
	}

	ch := &CollectionHandler{queries: queries, vault: vh}
	w := httptest.NewRecorder()
	ch.Delete(w, deleteCollectionRequest("coll-log", boss, "3"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204: %s", w.Code, w.Body.String())
	}

	rows, err := queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
		Action: "collection.delete", Limit: 10, Offset: 0,
	})
	if err != nil {
		t.Fatalf("list activity: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d collection.delete rows, want 1", len(rows))
	}
	detail := rows[0].Detail.String

	if !strings.Contains(detail, "Client Rotation Vault") {
		t.Errorf("activity detail does not name the collection: %q", detail)
	}
	if !strings.Contains(detail, "3") {
		t.Errorf("activity detail does not account for the destroyed entry count: %q", detail)
	}
	for _, name := range names {
		if !strings.Contains(detail, name) {
			t.Errorf("activity detail does not name destroyed entry %q: %q", name, detail)
		}
	}
}

// TestDeleteCollectionCapsLoggedEntrySample proves the sample written to
// activity_log is bounded: a collection with more entries than
// collectionDeleteEntrySample must still log the full count (nothing is
// under-reported) while naming only the first collectionDeleteEntrySample of
// them (nothing unbounded is written to the one append-only trail this
// product has).
func TestDeleteCollectionCapsLoggedEntrySample(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	boss := mustUser(t, queries, "delcas-cap@example.com", "user", "")
	mustCollection(t, queries, "coll-cap", boss, map[string]string{boss: collRoleManager})

	total := collectionDeleteEntrySample + 5
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("entry-cap-%03d", i)
		// Zero-padded names sort predictably, so the first
		// collectionDeleteEntrySample by name ASC are entry-cap-000..024.
		mustEntry(t, vh, queries, id, boss, fmt.Sprintf("secret-%03d", i), "v")
		placeInCollection(t, queries, id, "coll-cap")
	}

	ch := &CollectionHandler{queries: queries, vault: vh}
	w := httptest.NewRecorder()
	ch.Delete(w, deleteCollectionRequest("coll-cap", boss, fmt.Sprintf("%d", total)))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204: %s", w.Code, w.Body.String())
	}

	rows, err := queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
		Action: "collection.delete", Limit: 10, Offset: 0,
	})
	if err != nil {
		t.Fatalf("list activity: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d collection.delete rows, want 1", len(rows))
	}
	detail := rows[0].Detail.String

	// The exact count must survive even though the sample is capped.
	if !strings.Contains(detail, fmt.Sprintf("%d", total)) {
		t.Errorf("activity detail lost the true count (%d) behind the cap: %q", total, detail)
	}
	// One entry past the cap must not be named individually.
	if strings.Contains(detail, "secret-029") {
		t.Errorf("activity detail named an entry past the %d-entry cap: %q", collectionDeleteEntrySample, detail)
	}
	// One entry inside the cap must be named.
	if !strings.Contains(detail, "secret-000") {
		t.Errorf("activity detail dropped an entry that should be within the cap: %q", detail)
	}
	if !strings.Contains(detail, "more") {
		t.Errorf("activity detail does not say more entries exist beyond the sample: %q", detail)
	}
}

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The write responses (PUT /api/vault/{id}, POST /{id}/rotate, PUT /{id}/schedule)
// are all built from GetVaultEntryMeta. Clients cache an entry and merge the
// write response over it, so any field the projection gets wrong is a field the
// client silently corrupts on every save.
//
// Two shapes were wrong, and both were being worked around in the browser
// extension instead of fixed here:
//
//   - collection_id was never SELECTed, so the response always said null. A
//     client merging that answer moved every shared entry back to "Personal".
//     The workaround (never honour a null) then made the reverse impossible:
//     an entry genuinely moved out of a collection kept its stale badge.
//   - custom_fields carried `omitempty`, so an entry whose last custom field was
//     just deleted answered with no key at all. That is indistinguishable from
//     "this endpoint does not report custom fields", so the deleted TOTP seed
//     stayed on screen until the next full unlock.
//
// Both are contract bugs. These tests pin the contract so the clients can go
// back to a plain merge.

// decodeMeta returns the response body as a raw map, because half of what is
// under test is whether a KEY is present at all, which a typed struct erases.
func decodeMeta(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, body)
	}
	return m
}

func TestUpdateResponseReportsTheEntrysRealCollection(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "collresp@example.com", "user", "")
	mustCollection(t, queries, "col-shape", owner, map[string]string{owner: "manager"})
	mustEntry(t, h, queries, "shape-1", owner, "Shared secret", "v")
	placeInCollection(t, queries, "shape-1", "col-shape")

	rec := updateEntry(t, h, owner, "shape-1", map[string]any{"name": "Renamed"})
	if rec.Code != http.StatusOK {
		t.Fatalf("update failed: %d %s", rec.Code, rec.Body.String())
	}

	m := decodeMeta(t, rec.Body.Bytes())
	if got := m["collection_id"]; got != "col-shape" {
		t.Errorf("PUT /vault/{id} answered collection_id=%v, want \"col-shape\"; "+
			"a client that merges this response moves every shared entry back to Personal", got)
	}
}

func TestUpdateResponseReportsAMoveBackToPersonal(t *testing.T) {
	// The other direction has to be reported too, otherwise a client cannot
	// tell "the server does not know about collections" from "this entry has
	// none", which is exactly why the extension's merge could never honour a
	// null and kept showing a stale collection badge.
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "personal@example.com", "user", "")
	mustCollection(t, queries, "col-leave", owner, map[string]string{owner: "manager"})
	mustEntry(t, h, queries, "shape-2", owner, "Was shared", "v")
	placeInCollection(t, queries, "shape-2", "col-leave")
	placeInCollection(t, queries, "shape-2", "")

	rec := updateEntry(t, h, owner, "shape-2", map[string]any{"name": "Now personal"})
	if rec.Code != http.StatusOK {
		t.Fatalf("update failed: %d %s", rec.Code, rec.Body.String())
	}

	m := decodeMeta(t, rec.Body.Bytes())
	if _, ok := m["collection_id"]; !ok {
		t.Fatal("PUT /vault/{id} omitted collection_id entirely")
	}
	if got := m["collection_id"]; got != nil {
		t.Errorf("collection_id=%v for a personal entry, want null", got)
	}
}

func TestUpdateResponseAlwaysCarriesTheCustomFieldsKey(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "cf@example.com", "user", "")
	mustEntry(t, h, queries, "shape-3", owner, "Has fields", "v")

	// Set a custom field, then delete it: the delete is the case omitempty broke.
	rec := updateEntry(t, h, owner, "shape-3", map[string]any{
		"name": "Has fields",
		"custom_fields": []any{
			map[string]any{"label": "TOTP", "value": "JBSWY3DPEHPK3PXP", "secret": true},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("set custom field failed: %d %s", rec.Code, rec.Body.String())
	}
	m := decodeMeta(t, rec.Body.Bytes())
	fields, ok := m["custom_fields"].([]any)
	if !ok || len(fields) != 1 {
		t.Fatalf("custom_fields=%v, want the one field just written", m["custom_fields"])
	}

	rec = updateEntry(t, h, owner, "shape-3", map[string]any{
		"name":          "Has fields",
		"custom_fields": []any{},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("clear custom fields failed: %d %s", rec.Code, rec.Body.String())
	}
	m = decodeMeta(t, rec.Body.Bytes())
	if _, ok := m["custom_fields"]; !ok {
		t.Error("PUT /vault/{id} omitted custom_fields after the last one was deleted; " +
			"a client merging this response keeps showing the deleted secret")
	}
	if fields, _ := m["custom_fields"].([]any); len(fields) != 0 {
		t.Errorf("custom_fields=%v after deleting them all, want an empty list", m["custom_fields"])
	}
}

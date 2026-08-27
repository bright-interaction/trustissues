package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func callVaultCreate(t *testing.T, h *VaultHandler, userID string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal create request: %v", err)
	}
	req := vaultAuthzRequest(http.MethodPost, "/api/vault", userID, "user", "", string(raw))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	return rec
}

func validVaultCreateBody() map[string]any {
	return map[string]any{
		"name": "Portable entry", "value": "secret", "url": "https://example.com/login",
		"alias_url": "https://example.com/", "username": "alice", "category": "login",
		"notes": "note", "rotation_interval_days": 90,
		"custom_fields": []map[string]any{{"label": "PIN", "value": "1234", "secret": true}},
	}
}

func TestCreateRejectsNonPortableEntryShapes(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "create-validation@example.com", "user", "")

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"oversize name", func(body map[string]any) { body["name"] = strings.Repeat("n", maxEntryNameLen+1) }},
		{"oversize value", func(body map[string]any) { body["value"] = strings.Repeat("v", maxEntryValueLen+1) }},
		{"oversize url", func(body map[string]any) { body["url"] = strings.Repeat("u", maxEntryURLLen+1) }},
		{"oversize alias", func(body map[string]any) { body["alias_url"] = strings.Repeat("a", maxEntryURLLen+1) }},
		{"oversize username", func(body map[string]any) { body["username"] = strings.Repeat("u", maxEntryUsernameLen+1) }},
		{"oversize notes", func(body map[string]any) { body["notes"] = strings.Repeat("n", maxEntryNotesLen+1) }},
		{"invalid category", func(body map[string]any) { body["category"] = "untrusted" }},
		{"zero rotation interval", func(body map[string]any) { body["rotation_interval_days"] = 0 }},
		{"oversize rotation interval", func(body map[string]any) { body["rotation_interval_days"] = maxRotationDays + 1 }},
		{"whitespace-only custom label", func(body map[string]any) {
			body["custom_fields"] = []map[string]any{{"label": "   ", "value": "1234"}}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := validVaultCreateBody()
			test.mutate(body)
			rec := callVaultCreate(t, h, userID, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got HTTP %d, want 400: %s", rec.Code, rec.Body.String())
			}
			rows, err := queries.ListAllVaultEntries(context.Background())
			if err != nil {
				t.Fatalf("list entries: %v", err)
			}
			if len(rows) != 0 {
				t.Fatalf("rejected create wrote %d vault entries", len(rows))
			}
		})
	}
}

type vaultWriteSnapshot struct {
	Name                              string
	EncryptedValue, Nonce             []byte
	URL, AliasURL, Username           sql.NullString
	Category, Notes                   sql.NullString
	AutoLogin                         int64
	RotationIntervalDays              sql.NullInt64
	ExpiresAt, LastRotatedAt          sql.NullTime
	Provider, ProviderMeta            sql.NullString
	AutoRotate                        sql.NullInt64
	CustomFields, DestinationPatterns string
	CreatedAt, UpdatedAt              sql.NullTime
}

func snapshotVaultWrite(t *testing.T, h *VaultHandler, id string) vaultWriteSnapshot {
	t.Helper()
	var got vaultWriteSnapshot
	err := h.db.QueryRowContext(context.Background(), `
SELECT name, encrypted_value, nonce, url, alias_url, username, category, notes,
       auto_login, rotation_interval_days, expires_at, last_rotated_at,
       provider, provider_meta, auto_rotate, custom_fields, destination_patterns,
       created_at, updated_at
FROM vault_entries WHERE id = ?`, id).Scan(
		&got.Name, &got.EncryptedValue, &got.Nonce, &got.URL, &got.AliasURL, &got.Username,
		&got.Category, &got.Notes, &got.AutoLogin, &got.RotationIntervalDays,
		&got.ExpiresAt, &got.LastRotatedAt, &got.Provider, &got.ProviderMeta,
		&got.AutoRotate, &got.CustomFields, &got.DestinationPatterns,
		&got.CreatedAt, &got.UpdatedAt,
	)
	if err != nil {
		t.Fatalf("snapshot vault entry: %v", err)
	}
	return got
}

func TestUpdateRejectsNonPortableEntryShapesAtomically(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "update-validation@example.com", "user", "")
	const id = "live-validation-entry"
	mustEntry(t, h, queries, id, userID, "Original", "original-secret")
	before := snapshotVaultWrite(t, h, id)

	tests := []struct {
		name  string
		field string
		value any
	}{
		{"oversize name", "name", strings.Repeat("n", maxEntryNameLen+1)},
		{"oversize value", "value", strings.Repeat("v", maxEntryValueLen+1)},
		{"oversize url", "url", strings.Repeat("u", maxEntryURLLen+1)},
		{"oversize alias", "alias_url", strings.Repeat("a", maxEntryURLLen+1)},
		{"oversize username", "username", strings.Repeat("u", maxEntryUsernameLen+1)},
		{"oversize notes", "notes", strings.Repeat("n", maxEntryNotesLen+1)},
		{"invalid category", "category", "untrusted"},
		{"zero rotation interval", "rotation_interval_days", 0},
		{"oversize rotation interval", "rotation_interval_days", maxRotationDays + 1},
		{"whitespace-only custom label", "custom_fields", []map[string]any{{"label": "   ", "value": "1234"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// auto_login would be a valid mutation if validation ever happened after
			// writes. Its presence makes the no-change assertion non-vacuous.
			body := map[string]any{"auto_login": true, test.field: test.value}
			rec := updateEntry(t, h, userID, id, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got HTTP %d, want 400: %s", rec.Code, rec.Body.String())
			}
			after := snapshotVaultWrite(t, h, id)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("rejected update changed the row\nbefore: %#v\nafter:  %#v", before, after)
			}
		})
	}
}

func assertStoredVaultIdentifiers(t *testing.T, h *VaultHandler,
	id, wantName, wantURL, wantAlias, wantUsername, wantLabel string) {
	t.Helper()
	row, err := h.queries.GetVaultEntryMeta(context.Background(), id)
	if err != nil {
		t.Fatalf("read stored entry: %v", err)
	}
	checks := []struct {
		name, got, want string
	}{
		{"name", h.decryptColumnOrLog(row.Name, "", vaultFieldName), wantName},
		{"url", h.decryptColumnOrLog(row.Url.String, "", vaultFieldURL), wantURL},
		{"alias_url", h.decryptColumnOrLog(row.AliasUrl.String, "", vaultFieldAliasURL), wantAlias},
		{"username", h.decryptColumnOrLog(row.Username.String, "", vaultFieldUsername), wantUsername},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("stored %s = %q, want %q", check.name, check.got, check.want)
		}
	}
	fields := h.decryptCustomFields(row.CustomFields)
	if len(fields) != 1 || fields[0].Label != wantLabel {
		t.Errorf("stored custom fields = %+v, want one field labelled %q", fields, wantLabel)
	}
}

func TestLiveVaultWritesStoreCanonicalIdentifiers(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "canonical-live-write@example.com", "user", "")

	body := validVaultCreateBody()
	body["name"] = "  Created entry  "
	body["url"] = "  https://create.example/login  "
	body["alias_url"] = "  https://create.example/  "
	body["username"] = "  alice  "
	body["custom_fields"] = []map[string]any{{"label": "  PIN  ", "value": "1234"}}
	rec := callVaultCreate(t, h, userID, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("canonical create got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var created vaultEntryMeta
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	assertStoredVaultIdentifiers(t, h, created.ID,
		"Created entry", "https://create.example/login", "https://create.example/", "alice", "PIN")

	rec = updateEntry(t, h, userID, created.ID, map[string]any{
		"name": "  Updated entry  ", "url": "  https://update.example/login  ",
		"alias_url": "  https://update.example/  ", "username": "  bob  ",
		"custom_fields": []map[string]any{{"label": "  Recovery PIN  ", "value": "5678"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("canonical update got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	assertStoredVaultIdentifiers(t, h, created.ID,
		"Updated entry", "https://update.example/login", "https://update.example/", "bob", "Recovery PIN")
}

func TestPortableCustomFieldValidationPreservesLegacyLabels(t *testing.T) {
	legacy := []CustomField{{Label: "  ", Value: "legacy blank label"}, {Label: "  PIN  ", Value: "1234"}}
	if err := validatePortableCustomFields(legacy); err != nil {
		t.Fatalf("portable validation refused legacy labels: %v", err)
	}
	if legacy[0].Label != "  " || legacy[1].Label != "  PIN  " {
		t.Fatalf("portable validation mutated legacy labels: %+v", legacy)
	}

	live := []CustomField{{Label: "  PIN  ", Value: "1234"}}
	if err := validateCustomFields(live); err != nil {
		t.Fatalf("live validation refused a normalizable label: %v", err)
	}
	if live[0].Label != "PIN" {
		t.Fatalf("live validation stored label %q, want canonical %q", live[0].Label, "PIN")
	}
	if err := validateCustomFields([]CustomField{{Label: "   "}}); err == nil {
		t.Fatal("live validation accepted a whitespace-only label")
	}

	h, _ := newCollectionAuthzEnv(t)
	stored, err := h.encryptCustomFields(legacy)
	if err != nil {
		t.Fatalf("encrypt legacy custom fields: %v", err)
	}
	if err := h.validateExportCustomFields(stored); err != nil {
		t.Fatalf("export refused legacy custom labels: %v", err)
	}
}

func TestUpdateEmptyValueStillMeansKeepCurrentSecret(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "empty-value@example.com", "user", "")
	const id = "empty-value-entry"
	mustEntry(t, h, queries, id, userID, "Original", "original-secret")
	before := snapshotVaultWrite(t, h, id)

	rec := updateEntry(t, h, userID, id, map[string]any{
		"value": "", "notes": "metadata still changes",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("empty-value update got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	after := snapshotVaultWrite(t, h, id)
	if !bytes.Equal(after.EncryptedValue, before.EncryptedValue) || !bytes.Equal(after.Nonce, before.Nonce) {
		t.Fatal("an empty update value replaced or re-encrypted the current secret")
	}
	plainNotes, err := h.decryptColumn(after.Notes.String, vaultFieldNotes)
	if err != nil {
		t.Fatalf("decrypt updated notes: %v", err)
	}
	if plainNotes != "metadata still changes" {
		t.Fatalf("metadata update was lost: notes = %q", plainNotes)
	}
}

func liveCollectionRequest(t *testing.T, method, path, userID, collectionID string, body map[string]any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal collection request: %v", err)
	}
	return vaultAuthzRequest(method, path, userID, "user", collectionID, string(raw))
}

func TestCollectionWritesSharePortableLimits(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "collection-validation@example.com", "user", "")
	handler := NewCollectionHandler(queries, h)

	invalid := []struct {
		name, value, description string
	}{
		{"whitespace-only name", "   ", "description"},
		{"oversize name", strings.Repeat("n", maxCollectionNameLen+1), "description"},
		{"oversize description", "Team", strings.Repeat("d", maxCollectionDescriptionLen+1)},
	}
	for _, test := range invalid {
		t.Run("create "+test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.Create(rec, liveCollectionRequest(t, http.MethodPost, "/api/collections", userID, "",
				map[string]any{"name": test.value, "description": test.description}))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got HTTP %d, want 400: %s", rec.Code, rec.Body.String())
			}
			rows, err := queries.ListAllCollections(context.Background())
			if err != nil || len(rows) != 0 {
				t.Fatalf("rejected create wrote collections: count=%d err=%v", len(rows), err)
			}
		})
	}

	const collectionID = "live-validation-collection"
	mustCollection(t, queries, collectionID, userID, map[string]string{userID: collRoleManager})
	before, err := queries.GetCollection(context.Background(), collectionID)
	if err != nil {
		t.Fatalf("read collection before updates: %v", err)
	}
	for _, test := range invalid {
		t.Run("update "+test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.Update(rec, liveCollectionRequest(t, http.MethodPut, "/api/collections/"+collectionID,
				userID, collectionID, map[string]any{"name": test.value, "description": test.description}))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got HTTP %d, want 400: %s", rec.Code, rec.Body.String())
			}
			after, err := queries.GetCollection(context.Background(), collectionID)
			if err != nil {
				t.Fatalf("read collection after rejected update: %v", err)
			}
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("rejected collection update changed the row\nbefore: %#v\nafter:  %#v", before, after)
			}
		})
	}

	rec := httptest.NewRecorder()
	handler.Create(rec, liveCollectionRequest(t, http.MethodPost, "/api/collections", userID, "",
		map[string]any{"name": "  Created Team  ", "description": "description"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("canonical collection create got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var created collectionResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode collection create response: %v", err)
	}
	stored, err := queries.GetCollection(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("read canonical created collection: %v", err)
	}
	if stored.Name != "Created Team" {
		t.Fatalf("stored created collection name = %q, want %q", stored.Name, "Created Team")
	}

	rec = httptest.NewRecorder()
	handler.Update(rec, liveCollectionRequest(t, http.MethodPut, "/api/collections/"+collectionID,
		userID, collectionID, map[string]any{"name": "  Updated Team  ", "description": "description"}))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("canonical collection update got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	stored, err = queries.GetCollection(context.Background(), collectionID)
	if err != nil {
		t.Fatalf("read canonical updated collection: %v", err)
	}
	if stored.Name != "Updated Team" {
		t.Fatalf("stored updated collection name = %q, want %q", stored.Name, "Updated Team")
	}
}

func TestUnsafeTenantMetadataNeverSeedsAnInvalidCeiling(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "tenant-seed-validation@example.com", "user", "")

	tests := []struct {
		id, tenant, want string
	}{
		{"unsafe-tenant-seed", "a@b", "[]"},
		{"safe-tenant-seed", "acme", `["acme.auth0.com/*"]`},
	}
	for _, test := range tests {
		mustEntry(t, h, queries, test.id, userID, test.id, "secret")
		rec := updateEntry(t, h, userID, test.id, map[string]any{
			"provider": "auth0", "provider_meta": `{"tenant":"` + test.tenant + `"}`,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: provider update got HTTP %d: %s", test.id, rec.Code, rec.Body.String())
		}
		row, err := queries.GetVaultEntryMeta(context.Background(), test.id)
		if err != nil {
			t.Fatalf("%s: read entry: %v", test.id, err)
		}
		if row.DestinationPatterns != test.want {
			t.Fatalf("%s: destination_patterns = %q, want %q", test.id, row.DestinationPatterns, test.want)
		}
	}
}

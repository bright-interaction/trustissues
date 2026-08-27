package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

func nativeTime(value string) *string { return &value }

func nativeCollectionRef(value string) *string { return &value }

func nativeImportDocumentFixture() vaultExportDocument {
	return vaultExportDocument{
		Format:     vaultExportFormat,
		Version:    vaultExportVersion,
		ExportedAt: "2026-08-20T10:11:12Z",
		Collections: []vaultExportCollection{{
			SourceID: "source-collection", Name: "Imported team vault", Description: "portable collection",
			CreatedAt: nativeTime("2025-01-02T03:04:05Z"), UpdatedAt: nativeTime("2025-06-07T08:09:10Z"),
		}},
		Entries: []vaultExportEntry{
			{
				SourceID: "source-entry-shared", CollectionID: nativeCollectionRef("source-collection"),
				Name: "enc:v1:literal imported name", URL: "https://api.openai.com/login",
				AliasURL: "https://openai.com/", Username: "importer@example.com",
				Value: "enc:v1:literal imported value", Category: "api_key", Notes: "portable note",
				AutoLogin: true, RotationIntervalDays: intPtr(90), ExpiresAt: nativeTime("2027-01-02T03:04:05Z"),
				LastRotatedAt: nativeTime("2026-01-02T03:04:05Z"), Provider: "openai",
				ProviderMeta: `{"key_id":"portable-key-id","priority":7,"enabled":true}`, AutoRotate: true,
				CustomFields:        []CustomField{{Label: "Recovery PIN", Value: "1234-5678", Secret: true}},
				DestinationPatterns: []string{"api.openai.com/v1/*"},
				CreatedAt:           nativeTime("2025-01-02T03:04:05Z"), UpdatedAt: nativeTime("2026-02-03T04:05:06Z"),
			},
			{
				SourceID: "source-entry-personal", Name: "Personal imported login", URL: "https://example.com/login",
				AliasURL: "", Username: "alice", Value: "personal-imported-password", Category: "login",
				Notes: "", Provider: "retired-custom-provider", ProviderMeta: "", CustomFields: []CustomField{},
				DestinationPatterns: []string{}, CreatedAt: nativeTime("2024-01-02T03:04:05Z"),
				UpdatedAt: nativeTime("2024-03-04T05:06:07Z"),
			},
		},
	}
}

func compactJSONArray(element string, count int) string {
	if count == 0 {
		return "[]"
	}
	return "[" + strings.Repeat(element+",", count-1) + element + "]"
}

func intPtr(v int) *int { return &v }

func nativeMultipartRequest(t *testing.T, path, userID, role, password string,
	document vaultExportDocument) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "trustissues-vault.json")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if err := json.NewEncoder(part).Encode(document); err != nil {
		t.Fatalf("encode native document: %v", err)
	}
	if password != "" {
		if err := writer.WriteField("password", password); err != nil {
			t.Fatalf("write password: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}
	req := vaultAuthzRequest(http.MethodPost, path, userID, role, "", body.String())
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "native-import-test")
	return req
}

func callNativeConfirm(t *testing.T, h *VaultImportHandler, userID, password string,
	document vaultExportDocument) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.NativeImportConfirm(rec, nativeMultipartRequest(t, "/api/vault/import/native/confirm",
		userID, "user", password, document))
	return rec
}

func TestNativeImportStrictValidation(t *testing.T) {
	base := nativeImportDocumentFixture()
	tests := []struct {
		name   string
		mutate func(*vaultExportDocument)
	}{
		{"wrong format", func(d *vaultExportDocument) { d.Format = "database-dump" }},
		{"missing entries", func(d *vaultExportDocument) { d.Entries = nil }},
		{"duplicate source id", func(d *vaultExportDocument) { d.Entries[1].SourceID = d.Entries[0].SourceID }},
		{"dangling collection", func(d *vaultExportDocument) { d.Entries[0].CollectionID = nativeCollectionRef("missing") }},
		{"unreferenced collection", func(d *vaultExportDocument) { d.Entries[0].CollectionID = nil }},
		{"malformed timestamp", func(d *vaultExportDocument) { d.Entries[0].CreatedAt = nativeTime("next Tuesday") }},
		{"withheld custom field", func(d *vaultExportDocument) { d.Entries[0].CustomFields[0].Withheld = true }},
		{"reserved provider state", func(d *vaultExportDocument) {
			d.Entries[0].ProviderMeta = `{"pending_revoke_url":"https://attacker.invalid"}`
		}},
		{"unsafe destination", func(d *vaultExportDocument) { d.Entries[0].DestinationPatterns = []string{"127.0.0.1/*"} }},
		{"noncanonical destination", func(d *vaultExportDocument) {
			d.Entries[0].DestinationPatterns = []string{"api.openai.com/v1/*", "api.openai.com/v1/*"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := base
			document.Collections = append([]vaultExportCollection(nil), base.Collections...)
			document.Entries = append([]vaultExportEntry(nil), base.Entries...)
			document.Entries[0].CustomFields = append([]CustomField(nil), base.Entries[0].CustomFields...)
			document.Entries[0].DestinationPatterns = append([]string(nil), base.Entries[0].DestinationPatterns...)
			test.mutate(&document)
			if _, err := validateNativeImportDocument(document); err == nil {
				t.Fatal("invalid native document was accepted")
			}
		})
	}

	valid, err := validateNativeImportDocument(base)
	if err != nil {
		t.Fatalf("valid native document was refused: %v", err)
	}
	if valid.autoRotateDisabled != 1 {
		t.Errorf("auto-rotate disable count = %d, want 1", valid.autoRotateDisabled)
	}

	unknown := strings.NewReader(`{"format":"trustissues-vault","version":1,"exported_at":"2026-01-01T00:00:00Z","collections":[],"entries":[],"future":true}`)
	if _, err := decodeNativeImportDocument(unknown); err == nil {
		t.Fatal("unknown top-level field was accepted")
	}
	trailing := strings.NewReader(`{"format":"trustissues-vault"} {}`)
	if _, err := decodeNativeImportDocument(trailing); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestNativeImportDecoderBoundsCompactArraysBeforeExtraElement(t *testing.T) {
	prefix := `{"format":"trustissues-vault","version":1,"exported_at":"2026-01-01T00:00:00Z",`
	collection := `{"source_id":"x","name":"x","description":"","created_at":"x","updated_at":"x"}`
	entry := `{"source_id":"x","collection_id":null,"name":"x","url":"","alias_url":"","username":"",` +
		`"value":"x","category":"","notes":"","auto_login":false,"rotation_interval_days":null,` +
		`"expires_at":null,"last_rotated_at":null,"provider":"","provider_meta":"{}","auto_rotate":false,` +
		`"custom_fields":[],"destination_patterns":[],"created_at":"x","updated_at":"x"}`
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"collections", prefix + `"collections":` + compactJSONArray(collection, maxImportEntries+1) + `,"entries":[]}`,
			errNativeTooManyCollections},
		{"entries", prefix + `"collections":[],"entries":` + compactJSONArray(entry, maxImportEntries+1) + `}`,
			errNativeTooManyEntries},
		{"custom fields", prefix + `"collections":[],"entries":[{"custom_fields":` +
			compactJSONArray(`{"label":"","value":"","secret":false}`, maxCustomFields+1) + `}]}`,
			errNativeTooManyCustomFields},
		{"destination patterns", prefix + `"collections":[],"entries":[{"destination_patterns":` +
			compactJSONArray(`"example.com/*"`, maxDestinationPatterns+1) + `}]}`, errNativeTooManyDestinations},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeNativeImportDocument(strings.NewReader(test.raw)); !errors.Is(err, test.want) {
				t.Fatalf("decode error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNativeImportDecoderRequiresV1FieldsAndTypes(t *testing.T) {
	prefix := `{"format":"trustissues-vault","version":1,"exported_at":"2026-01-01T00:00:00Z",`
	for name, raw := range map[string]string{
		"missing entry field": prefix + `"collections":[],"entries":[{"source_id":"x"}]}`,
		"null string": prefix + `"collections":[],"entries":[{` +
			`"source_id":"x","collection_id":null,"name":"x","url":null,"alias_url":"","username":"",` +
			`"value":"x","category":"","notes":"","auto_login":false,"rotation_interval_days":null,` +
			`"expires_at":null,"last_rotated_at":null,"provider":"","provider_meta":"{}","auto_rotate":false,` +
			`"custom_fields":[],"destination_patterns":[],"created_at":"x","updated_at":"x"}]}`,
		"missing top-level field": `{"format":"trustissues-vault","version":1,"exported_at":"2026-01-01T00:00:00Z","collections":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeNativeImportDocument(strings.NewReader(raw)); !errors.Is(err, errNativeJSONMalformed) {
				t.Fatalf("decode error = %v, want strict malformed error", err)
			}
		})
	}
}

func TestNativeImportDecoderRejectsUnknownNestedFields(t *testing.T) {
	prefix := `{"format":"trustissues-vault","version":1,"exported_at":"2026-01-01T00:00:00Z",`
	for name, raw := range map[string]string{
		"collection": prefix + `"collections":[{"future":true}],"entries":[]}`,
		"entry":      prefix + `"collections":[],"entries":[{"future":true}]}`,
		"custom":     prefix + `"collections":[],"entries":[{"custom_fields":[{"future":true}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeNativeImportDocument(strings.NewReader(raw)); !errors.Is(err, errNativeJSONMalformed) {
				t.Fatalf("decode error = %v, want strict malformed error", err)
			}
		})
	}
}

func TestNativeImportUploadErrorsCleanMultipartState(t *testing.T) {
	makeRequest := func(t *testing.T, filename string, includeFile bool) *http.Request {
		t.Helper()
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if includeFile {
			part, err := writer.CreateFormFile("file", filename)
			if err != nil {
				t.Fatalf("create form file: %v", err)
			}
			if _, err := part.Write([]byte(`{}`)); err != nil {
				t.Fatalf("write form file: %v", err)
			}
		} else if err := writer.WriteField("password", "irrelevant"); err != nil {
			t.Fatalf("write form field: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close multipart: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/vault/import/native/preview", &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		return req
	}
	for _, test := range []struct {
		name        string
		filename    string
		includeFile bool
	}{
		{"missing file", "", false},
		{"wrong extension", "vault.txt", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := makeRequest(t, test.filename, test.includeFile)
			if _, err := openNativeImportUpload(req); err == nil {
				t.Fatal("invalid upload was accepted")
			}
			if req.MultipartForm != nil {
				t.Fatal("multipart state was not cleaned after error")
			}
		})
	}
}

func TestNativeImportPreviewAndConflictsWriteNothing(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	importer := NewVaultImportHandler(vault.db, vault)
	userID := mustUser(t, queries, "native-conflict@example.com", "user", "native-conflict-password")
	mustEntry(t, vault, queries, "existing-native-entry", userID, "Personal imported login", "existing-value")

	document := nativeImportDocumentFixture()
	document.Entries = append(document.Entries, document.Entries[1])
	document.Entries[2].SourceID = "source-entry-duplicate-name"
	document.Entries[2].Value = "must-never-appear-in-preview"

	preview := httptest.NewRecorder()
	importer.NativeImportPreview(preview, nativeMultipartRequest(t, "/api/vault/import/native/preview",
		userID, "user", "", document))
	if preview.Code != http.StatusOK {
		t.Fatalf("preview: got HTTP %d: %s", preview.Code, preview.Body.String())
	}
	var got nativeImportPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if !slices.Equal(got.Conflicts, []string{"Personal imported login"}) {
		t.Errorf("conflicts = %v", got.Conflicts)
	}
	if strings.Contains(preview.Body.String(), document.Entries[2].Value) {
		t.Fatal("secret value appeared in preview")
	}
	if !strings.Contains(preview.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("preview Cache-Control = %q", preview.Header().Get("Cache-Control"))
	}

	beforeEntries, err := queries.ListAllVaultEntries(context.Background())
	if err != nil {
		t.Fatalf("list before conflict: %v", err)
	}
	confirm := callNativeConfirm(t, importer, userID, "native-conflict-password", document)
	if confirm.Code != http.StatusConflict {
		t.Fatalf("conflicting confirm: got HTTP %d: %s", confirm.Code, confirm.Body.String())
	}
	afterEntries, _ := queries.ListAllVaultEntries(context.Background())
	collections, _ := queries.ListAllCollections(context.Background())
	if len(afterEntries) != len(beforeEntries) || len(collections) != 0 {
		t.Fatalf("conflict performed writes: entries %d -> %d, collections=%d",
			len(beforeEntries), len(afterEntries), len(collections))
	}
}

func TestNativeImportEmptyExportIsAuditedNoOp(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	importer := NewVaultImportHandler(vault.db, vault)
	const password = "native-empty-password"
	userID := mustUser(t, queries, "native-empty@example.com", "user", password)
	document := nativeImportDocumentFixture()
	document.Collections = []vaultExportCollection{}
	document.Entries = []vaultExportEntry{}

	if _, err := validateNativeImportDocument(document); err != nil {
		t.Fatalf("structurally valid empty export was refused: %v", err)
	}
	previewRequest := nativeMultipartRequest(t, "/api/vault/import/native/preview", userID, "user", "", document)
	preview := httptest.NewRecorder()
	importer.NativeImportPreview(preview, previewRequest)
	if preview.Code != http.StatusOK {
		t.Fatalf("empty preview: got HTTP %d: %s", preview.Code, preview.Body.String())
	}
	if previewRequest.MultipartForm != nil {
		t.Fatal("preview left parsed multipart state behind")
	}

	confirmRequest := nativeMultipartRequest(t, "/api/vault/import/native/confirm", userID, "user", password, document)
	rec := httptest.NewRecorder()
	importer.NativeImportConfirm(rec, confirmRequest)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty import: got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if confirmRequest.MultipartForm != nil {
		t.Fatal("confirm left parsed multipart state behind")
	}
	var result map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result["imported"] != 0 || result["collections_created"] != 0 || result["auto_rotate_disabled"] != 0 {
		t.Fatalf("empty result = %+v", result)
	}
	entries, _ := queries.ListAllVaultEntries(context.Background())
	collections, _ := queries.ListAllCollections(context.Background())
	if len(entries) != 0 || len(collections) != 0 {
		t.Fatalf("empty import wrote vault data: entries=%d collections=%d", len(entries), len(collections))
	}
	audits, err := queries.ListActivityEntriesByAction(context.Background(), db.ListActivityEntriesByActionParams{
		Action: "vault.native_imported", Limit: 10, Offset: 0})
	if err != nil || len(audits) != 1 {
		t.Fatalf("empty import audit rows=%d err=%v", len(audits), err)
	}
}

func TestNativeImportAcceptsExportableLegacyFields(t *testing.T) {
	document := nativeImportDocumentFixture()
	document.Collections[0].Name = strings.Repeat("n", 256)
	document.Collections[0].Description = strings.Repeat("d", 10001)
	document.Entries[1].Value = strings.Repeat("v", maxEntryValueLen+1)
	document.Entries[1].URL = "  https://example.com/legacy  "
	document.Entries[1].AliasURL = strings.Repeat("a", maxEntryURLLen+1)
	document.Entries[1].Username = " padded legacy username "
	document.Entries[1].Category = "legacy_custom_category"
	document.Entries[1].Notes = strings.Repeat("n", maxEntryNotesLen+1)
	document.Entries[1].RotationIntervalDays = intPtr(-37)
	document.Entries[1].Provider = " retired-or-future-provider "
	document.Entries[1].ProviderMeta = `{"":true," padded key ":7,"future_object":{"nested":true}}`
	document.Entries[1].CustomFields = []CustomField{{Label: "  ", Value: "legacy blank label"}}
	if _, err := validateNativeImportDocument(document); err != nil {
		t.Fatalf("exportable legacy fields were refused: %v", err)
	}
}

func TestNativeImportRoundTripIsAtomicPrivateAndEncrypted(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	importer := NewVaultImportHandler(vault.db, vault)
	const password = "correct-native-import-password"
	userID := mustUser(t, queries, "native-import@example.com", "user", password)
	document := nativeImportDocumentFixture()

	wrong := callNativeConfirm(t, importer, userID, "wrong-native-import-password", document)
	if wrong.Code != http.StatusForbidden {
		t.Fatalf("wrong password: got HTTP %d: %s", wrong.Code, wrong.Body.String())
	}
	if rows, _ := queries.ListAllVaultEntries(context.Background()); len(rows) != 0 {
		t.Fatalf("wrong password imported %d entries", len(rows))
	}

	rec := callNativeConfirm(t, importer, userID, password, document)
	if rec.Code != http.StatusOK {
		t.Fatalf("native import: got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result["imported"] != 2 || result["collections_created"] != 1 || result["auto_rotate_disabled"] != 1 {
		t.Errorf("result = %+v", result)
	}

	collections, err := queries.ListCollectionsForUser(context.Background(), userID)
	if err != nil || len(collections) != 1 {
		t.Fatalf("private collection = %+v, err=%v", collections, err)
	}
	collection := collections[0]
	if collection.ID == document.Collections[0].SourceID || collection.CreatedBy.String != userID ||
		collection.Role != "manager" {
		t.Errorf("collection authority/fresh id = %+v", collection)
	}

	rows, err := vault.db.QueryContext(context.Background(), `SELECT id, user_id, secret_owner_user_id,
name, encrypted_value, nonce, encryption_version, url, url_bidx, name_bidx, collection_id,
provider, provider_meta, auto_rotate, destination_patterns, injection_spec, custom_fields
FROM vault_entries ORDER BY id`)
	if err != nil {
		t.Fatalf("read raw imported rows: %v", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var id, owner, secretOwner, storedName, storedURL, urlBidx, nameBidx string
		var ciphertext, nonce []byte
		var version int
		var collectionID, provider, providerMeta sql.NullString
		var autoRotate int
		var destinations, injection, customFields string
		if err := rows.Scan(&id, &owner, &secretOwner, &storedName, &ciphertext, &nonce, &version,
			&storedURL, &urlBidx, &nameBidx, &collectionID, &provider, &providerMeta, &autoRotate,
			&destinations, &injection, &customFields); err != nil {
			t.Fatalf("scan imported row: %v", err)
		}
		if id == "source-entry-shared" || id == "source-entry-personal" || owner != userID || secretOwner != userID {
			t.Errorf("entry fresh id/ownership = id=%q owner=%q secret_owner=%q", id, owner, secretOwner)
		}
		name, err := vault.decryptColumn(storedName, vaultFieldName)
		if err != nil {
			t.Fatalf("open imported name: %v", err)
		}
		seen[name] = true
		if storedName == name || (storedURL != "" && !strings.HasPrefix(storedURL, vaultColumnEncPrefix)) {
			t.Errorf("client metadata was not sealed at rest: name=%q url=%q", storedName, storedURL)
		}
		if nameBidx != vault.nameBlindIndex(userID, name) {
			t.Errorf("name blind index mismatch for %q", name)
		}
		plain, err := vault.openVersionForTest(ciphertext, nonce, version)
		if err != nil {
			t.Fatalf("open imported secret: %v", err)
		}
		if name == document.Entries[0].Name && !plain.EqualsString(document.Entries[0].Value) {
			t.Error("ciphertext-looking client value was passed through instead of stored literally")
		}
		plain.Wipe()
		if autoRotate != 0 {
			t.Errorf("auto_rotate = %d, want disabled", autoRotate)
		}
		if collectionID.Valid {
			if collectionID.String != collection.ID || urlBidx != vault.urlBlindIndex("c:"+collection.ID, document.Entries[0].URL) {
				t.Errorf("shared grouping/scope index mismatch: collection=%+v url_bidx=%q", collectionID, urlBidx)
			}
			if destinations != `["api.openai.com/v1/*"]` || injection == "{}" {
				t.Errorf("capability defaults/final ceiling = destinations=%q injection=%q", destinations, injection)
			}
			if !strings.HasPrefix(providerMeta.String, vaultColumnEncPrefix) ||
				!strings.HasPrefix(customFields, vaultColumnEncPrefix) {
				t.Error("provider metadata or custom fields were not encrypted at rest")
			}
		} else {
			if provider.String != document.Entries[1].Provider || destinations != "[]" || injection != "{}" {
				t.Errorf("unknown provider was not preserved inert: provider=%q destinations=%q injection=%q",
					provider.String, destinations, injection)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate imported rows: %v", err)
	}
	for _, want := range []string{document.Entries[0].Name, document.Entries[1].Name} {
		if !seen[want] {
			t.Errorf("imported entry %q missing", want)
		}
	}

	exported := exportVaultAs(vault, userID, "user", password)
	if exported.Code != http.StatusOK {
		t.Fatalf("round-trip export: got HTTP %d: %s", exported.Code, exported.Body.String())
	}
	var roundTrip vaultExportDocument
	if err := json.Unmarshal(exported.Body.Bytes(), &roundTrip); err != nil {
		t.Fatalf("decode round-trip export: %v", err)
	}
	if len(roundTrip.Collections) != 1 || roundTrip.Collections[0].SourceID == document.Collections[0].SourceID ||
		roundTrip.Collections[0].Name != document.Collections[0].Name ||
		roundTrip.Collections[0].Description != document.Collections[0].Description ||
		roundTrip.Collections[0].CreatedAt == nil || *roundTrip.Collections[0].CreatedAt != *document.Collections[0].CreatedAt ||
		roundTrip.Collections[0].UpdatedAt == nil || *roundTrip.Collections[0].UpdatedAt != *document.Collections[0].UpdatedAt ||
		len(roundTrip.Entries) != 2 {
		t.Fatalf("round-trip grouping/content = %+v / %+v", roundTrip.Collections, roundTrip.Entries)
	}
	byName := map[string]vaultExportEntry{}
	for _, entry := range roundTrip.Entries {
		byName[entry.Name] = entry
	}
	shared := byName[document.Entries[0].Name]
	if shared.Value != document.Entries[0].Value || shared.URL != document.Entries[0].URL ||
		shared.AliasURL != document.Entries[0].AliasURL || shared.Username != document.Entries[0].Username ||
		shared.Category != document.Entries[0].Category || shared.Notes != document.Entries[0].Notes ||
		shared.AutoLogin != document.Entries[0].AutoLogin || shared.AutoRotate ||
		shared.RotationIntervalDays == nil || *shared.RotationIntervalDays != *document.Entries[0].RotationIntervalDays ||
		shared.ExpiresAt == nil || *shared.ExpiresAt != *document.Entries[0].ExpiresAt ||
		shared.LastRotatedAt == nil || *shared.LastRotatedAt != *document.Entries[0].LastRotatedAt ||
		shared.Provider != document.Entries[0].Provider || shared.CreatedAt == nil ||
		*shared.CreatedAt != *document.Entries[0].CreatedAt || shared.UpdatedAt == nil ||
		*shared.UpdatedAt != *document.Entries[0].UpdatedAt ||
		!slices.Equal(shared.CustomFields, document.Entries[0].CustomFields) ||
		!slices.Equal(shared.DestinationPatterns, document.Entries[0].DestinationPatterns) ||
		shared.CollectionID == nil || *shared.CollectionID != roundTrip.Collections[0].SourceID {
		t.Errorf("supported fields did not round-trip: %+v", shared)
	}
	var typedProviderMeta map[string]json.RawMessage
	if err := json.Unmarshal([]byte(shared.ProviderMeta), &typedProviderMeta); err != nil {
		t.Fatalf("round-trip provider metadata is invalid: %v", err)
	}
	if string(typedProviderMeta["priority"]) != "7" || string(typedProviderMeta["enabled"]) != "true" {
		t.Errorf("non-string provider metadata did not round-trip: %s", shared.ProviderMeta)
	}
	var personalMeta map[string]json.RawMessage
	personal := byName[document.Entries[1].Name]
	if personal.Provider != document.Entries[1].Provider {
		t.Errorf("unknown provider did not round-trip: got %q want %q", personal.Provider, document.Entries[1].Provider)
	}
	if err := json.Unmarshal([]byte(personal.ProviderMeta), &personalMeta); err != nil || personalMeta == nil || len(personalMeta) != 0 {
		t.Errorf("legacy empty provider metadata was not canonicalized to an empty object: %q",
			personal.ProviderMeta)
	}
	audits, err := queries.ListActivityEntriesByAction(context.Background(), db.ListActivityEntriesByActionParams{
		Action: "vault.native_imported", Limit: 10, Offset: 0})
	if err != nil || len(audits) != 1 {
		t.Fatalf("native import audit rows=%d err=%v", len(audits), err)
	}
	for _, forbidden := range []string{document.Entries[0].Name, document.Entries[0].Value,
		document.Entries[0].Username, document.Entries[0].URL} {
		if strings.Contains(audits[0].Detail.String, forbidden) {
			t.Errorf("audit detail leaked vault data %q: %q", forbidden, audits[0].Detail.String)
		}
	}
}

func TestNativeImportAuditFailureRollsBackEverything(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	importer := NewVaultImportHandler(vault.db, vault)
	const password = "native-audit-failure-password"
	userID := mustUser(t, queries, "native-audit-failure@example.com", "user", password)
	if _, err := vault.db.ExecContext(context.Background(), `CREATE TRIGGER fail_native_import_audit
BEFORE INSERT ON activity_log WHEN NEW.action = 'vault.native_imported'
BEGIN SELECT RAISE(FAIL, 'simulated native import audit outage'); END`); err != nil {
		t.Fatalf("install audit failure trigger: %v", err)
	}
	rec := callNativeConfirm(t, importer, userID, password, nativeImportDocumentFixture())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure: got HTTP %d: %s", rec.Code, rec.Body.String())
	}
	entries, _ := queries.ListAllVaultEntries(context.Background())
	collections, _ := queries.ListAllCollections(context.Background())
	if len(entries) != 0 || len(collections) != 0 {
		t.Fatalf("audit failure left partial writes: entries=%d collections=%d", len(entries), len(collections))
	}
	for _, secret := range []string{"enc:v1:literal imported value", "personal-imported-password"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("audit failure response leaked %q", secret)
		}
	}
}

func TestNativeImportOverEntryLimitIsRejected(t *testing.T) {
	document := nativeImportDocumentFixture()
	document.Collections = []vaultExportCollection{}
	document.Entries = make([]vaultExportEntry, maxImportEntries+1)
	for i := range document.Entries {
		document.Entries[i] = vaultExportEntry{SourceID: fmt.Sprintf("source-%d", i),
			Name: fmt.Sprintf("entry-%d", i), Value: "v", ProviderMeta: `{}`,
			CustomFields: []CustomField{}, DestinationPatterns: []string{},
			CreatedAt: nativeTime("2025-01-01T00:00:00Z"), UpdatedAt: nativeTime("2025-01-01T00:00:00Z")}
	}
	if _, err := validateNativeImportDocument(document); err == nil {
		t.Fatalf("%d-entry native document was accepted", len(document.Entries))
	}
}

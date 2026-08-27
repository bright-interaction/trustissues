package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/middleware"
)

func createScopedEntry(t *testing.T, h *VaultHandler, userID, name string,
	collectionID *string, private bool) (*httptest.ResponseRecorder, vaultEntryMeta) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name": name, "value": "value-for-" + name, "category": "password",
		"collection_id": collectionID,
	})
	if err != nil {
		t.Fatalf("encode create: %v", err)
	}
	req := vaultAuthzRequest(http.MethodPost, "/api/vault", userID, "user", "", string(body))
	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(h.Create)
	if private {
		middleware.StampIngressZone(middleware.IngressPrivate)(handler).ServeHTTP(rec, req)
	} else {
		handler.ServeHTTP(rec, req)
	}
	var entry vaultEntryMeta
	if rec.Code == http.StatusCreated {
		if err := json.NewDecoder(rec.Body).Decode(&entry); err != nil {
			t.Fatalf("decode create response: %v", err)
		}
	}
	return rec, entry
}

func TestVaultNameUniquenessIsScopedWithoutFullyPrivateOracle(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "scope-owner@example.com", "user", "")
	peer := mustUser(t, queries, "scope-peer@example.com", "user", "")
	const privateCollection = "scope-private"
	const standardCollection = "scope-standard"
	mustCollection(t, queries, privateCollection, owner, map[string]string{owner: collRoleManager})
	mustCollection(t, queries, standardCollection, owner, map[string]string{
		owner: collRoleManager, peer: collRoleEditor,
	})
	setCollectionPrivateAccessPolicy(t, queries, privateCollection, "fully_private")

	privateRef := privateCollection
	hiddenCreate, hidden := createScopedEntry(t, h, owner, "Shared label", &privateRef, true)
	if hiddenCreate.Code != http.StatusCreated {
		t.Fatalf("create fully-private entry: HTTP %d: %s", hiddenCreate.Code, hiddenCreate.Body.String())
	}
	hiddenRenameCreate, hiddenRename := createScopedEntry(t, h, owner, "Hidden rename target", &privateRef, true)
	if hiddenRenameCreate.Code != http.StatusCreated {
		t.Fatalf("create second fully-private entry: HTTP %d: %s", hiddenRenameCreate.Code, hiddenRenameCreate.Body.String())
	}
	// If a public personal write walks collection names, these malformed sealed
	// values make it fail. Scope isolation means neither is ever opened there.
	for _, id := range []string{hidden.ID, hiddenRename.ID} {
		if _, err := h.db.Exec(`UPDATE vault_entries SET name = ? WHERE id = ?`, "enc:v1:not-valid-"+id, id); err != nil {
			t.Fatalf("corrupt hidden-name fixture %s: %v", id, err)
		}
	}

	personalCreate, personal := createScopedEntry(t, h, owner, "Shared label", nil, false)
	if personalCreate.Code != http.StatusCreated {
		t.Fatalf("public personal create collided with hidden collection: HTTP %d: %s",
			personalCreate.Code, personalCreate.Body.String())
	}
	personalDuplicate, _ := createScopedEntry(t, h, owner, "Shared label", nil, false)
	if personalDuplicate.Code != http.StatusConflict {
		t.Fatalf("same personal scope duplicate got HTTP %d, want 409: %s",
			personalDuplicate.Code, personalDuplicate.Body.String())
	}

	standardRef := standardCollection
	standardCreate, standard := createScopedEntry(t, h, owner, "Shared label", &standardRef, false)
	if standardCreate.Code != http.StatusCreated {
		t.Fatalf("standard collection could not reuse personal/private label: HTTP %d: %s",
			standardCreate.Code, standardCreate.Body.String())
	}
	collectionDuplicate, _ := createScopedEntry(t, h, peer, "Shared label", &standardRef, false)
	if collectionDuplicate.Code != http.StatusConflict {
		t.Fatalf("second custodian duplicated one collection scope with HTTP %d: %s",
			collectionDuplicate.Code, collectionDuplicate.Body.String())
	}

	oldCreate, old := createScopedEntry(t, h, owner, "Rename me", nil, false)
	if oldCreate.Code != http.StatusCreated {
		t.Fatalf("create rename source: HTTP %d: %s", oldCreate.Code, oldCreate.Body.String())
	}
	siblingCreate, sibling := createScopedEntry(t, h, owner, "Personal sibling", nil, false)
	if siblingCreate.Code != http.StatusCreated {
		t.Fatalf("create rename sibling: HTTP %d: %s", siblingCreate.Code, siblingCreate.Body.String())
	}
	rename := httptest.NewRecorder()
	h.Update(rename, vaultAuthzRequest(http.MethodPut, "/api/vault/"+old.ID, owner, "user", old.ID,
		`{"name":"Hidden rename target"}`))
	if rename.Code != http.StatusOK && rename.Code != http.StatusNoContent {
		t.Fatalf("personal rename collided with hidden collection: HTTP %d: %s", rename.Code, rename.Body.String())
	}
	duplicateRename := httptest.NewRecorder()
	h.Update(duplicateRename, vaultAuthzRequest(http.MethodPut, "/api/vault/"+old.ID, owner, "user", old.ID,
		`{"name":"Personal sibling"}`))
	if duplicateRename.Code != http.StatusConflict {
		t.Fatalf("same personal-scope rename got HTTP %d, want 409: %s",
			duplicateRename.Code, duplicateRename.Body.String())
	}

	assertToken := func(entryID, want string) {
		t.Helper()
		var got string
		if err := h.db.QueryRow(`SELECT name_bidx FROM vault_entries WHERE id = ?`, entryID).Scan(&got); err != nil {
			t.Fatalf("read name token for %s: %v", entryID, err)
		}
		if got != want {
			t.Fatalf("entry %s name token = %q, want scoped token %q", entryID, got, want)
		}
	}
	assertToken(personal.ID, h.scopedNameBlindIndex(bidxScope(owner, sql.NullString{}), "Shared label"))
	assertToken(standard.ID, h.scopedNameBlindIndex(bidxScope(owner,
		sql.NullString{String: standardCollection, Valid: true}), "Shared label"))
	assertToken(old.ID, h.scopedNameBlindIndex(bidxScope(owner, sql.NullString{}), "Hidden rename target"))
	_ = sibling
}

func TestBootBackfillRepairsLegacyCollectionNameCollisionsDeterministically(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	firstOwner := mustUser(t, queries, "scope-backfill-a@example.com", "user", "")
	secondOwner := mustUser(t, queries, "scope-backfill-b@example.com", "user", "")
	const collectionID = "scope-backfill-collision"
	const firstID = "scope-backfill-entry-a"
	const secondID = "scope-backfill-entry-b"
	const legacyName = "Shared legacy label"
	mustCollection(t, queries, collectionID, firstOwner, map[string]string{
		firstOwner: collRoleManager, secondOwner: collRoleEditor,
	})

	// Before 00045, the same visible collection name was legal when two
	// custodians supplied it because each token was keyed to its user. Preserve
	// those old tokens while placing both rows into the same collection.
	mustEntry(t, h, queries, firstID, firstOwner, legacyName, "first")
	mustEntry(t, h, queries, secondID, secondOwner, legacyName, "second")
	placeInCollection(t, queries, firstID, collectionID)
	placeInCollection(t, queries, secondID, collectionID)
	// Make the row that will lose the name-index race carry pre-encryption
	// metadata too. A collision must not roll back these seals and leave the row
	// readable in a keyless database copy.
	if _, err := h.db.Exec(`UPDATE vault_entries
SET name = ?, url = ?, username = ?, notes = ? WHERE id = ?`,
		legacyName, "https://legacy.example.test/login", "legacy-user", "legacy note", secondID); err != nil {
		t.Fatalf("rewind losing legacy metadata: %v", err)
	}

	if _, err := h.BackfillMetadataAtRest(); err != nil {
		t.Fatalf("scope backfill: %v", err)
	}

	wantNames := map[string]string{
		firstID:  legacyName,
		secondID: metadataBackfillDuplicateName(legacyName, secondID, 1),
	}
	collectionScope := bidxScope(firstOwner,
		sql.NullString{String: collectionID, Valid: true})
	for id, wantName := range wantNames {
		if got := entryNamePlain(t, h, queries, id); got != wantName {
			t.Errorf("entry %s name = %q, want %q", id, got, wantName)
		}
		var stored, token string
		if err := h.db.QueryRow(`SELECT name, name_bidx FROM vault_entries WHERE id = ?`, id).
			Scan(&stored, &token); err != nil {
			t.Fatalf("read repaired entry %s: %v", id, err)
		}
		if metaColumnNeedsEncrypt(stored) {
			t.Errorf("entry %s was left with an unsealed name", id)
		}
		if want := h.scopedNameBlindIndex(collectionScope, wantName); token != want {
			t.Errorf("entry %s token = %q, want collection-scoped %q", id, token, want)
		}
	}
	var storedURL, storedUsername, storedNotes string
	if err := h.db.QueryRow(`SELECT url, username, notes FROM vault_entries WHERE id = ?`, secondID).
		Scan(&storedURL, &storedUsername, &storedNotes); err != nil {
		t.Fatalf("read losing row metadata: %v", err)
	}
	for field, stored := range map[string]string{
		"url": storedURL, "username": storedUsername, "notes": storedNotes,
	} {
		if metaColumnNeedsEncrypt(stored) {
			t.Errorf("losing row %s remained cleartext after name collision", field)
		}
	}

	// The repair is a stable migration, not a suffix added on every boot.
	if _, err := h.BackfillMetadataAtRest(); err != nil {
		t.Fatalf("second scope backfill: %v", err)
	}
	for id, wantName := range wantNames {
		if got := entryNamePlain(t, h, queries, id); got != wantName {
			t.Errorf("second pass changed entry %s to %q, want %q", id, got, wantName)
		}
	}
}

func TestMetadataBackfillDuplicateNameIsValidUTF8AndLengthBounded(t *testing.T) {
	name := strings.Repeat("å", maxEntryNameLen)
	got := metadataBackfillDuplicateName(name, "entry-with-a-stable-id", 12)
	if !strings.Contains(got, " (duplicate ") {
		t.Fatalf("duplicate marker missing from %q", got)
	}
	if len(got) > maxEntryNameLen {
		t.Fatalf("duplicate name is %d bytes, want at most %d", len(got), maxEntryNameLen)
	}
	if strings.ToValidUTF8(got, "replacement") != got {
		t.Fatalf("duplicate name is not valid UTF-8: %q", got)
	}
}

func csvImportRequest(t *testing.T, path, userID, name string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "vault.csv")
	if err != nil {
		t.Fatalf("create CSV form file: %v", err)
	}
	_, _ = part.Write([]byte("Title,Website,Username,Password\n" + name + ",https://example.com,user,password\n"))
	if err := writer.Close(); err != nil {
		t.Fatalf("close CSV multipart: %v", err)
	}
	req := vaultAuthzRequest(http.MethodPost, path, userID, "user", "", body.String())
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestPublicImportsIgnoreFullyPrivateCollectionNameScope(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	importer := NewVaultImportHandler(h.db, h)
	const password = "scope-import-password"
	userID := mustUser(t, queries, "scope-import@example.com", "user", password)
	const collectionID = "scope-import-private"
	mustCollection(t, queries, collectionID, userID, map[string]string{userID: collRoleManager})
	setCollectionPrivateAccessPolicy(t, queries, collectionID, "fully_private")
	collectionRef := collectionID

	hiddenCSVRec, hiddenCSV := createScopedEntry(t, h, userID, "Hidden CSV guess", &collectionRef, true)
	hiddenNativeRec, hiddenNative := createScopedEntry(t, h, userID, "Hidden native guess", &collectionRef, true)
	if hiddenCSVRec.Code != http.StatusCreated || hiddenNativeRec.Code != http.StatusCreated {
		t.Fatalf("create hidden fixtures: CSV=%d native=%d", hiddenCSVRec.Code, hiddenNativeRec.Code)
	}
	for _, id := range []string{hiddenCSV.ID, hiddenNative.ID} {
		if _, err := h.db.Exec(`UPDATE vault_entries SET name = ? WHERE id = ?`, "enc:v1:malformed-"+id, id); err != nil {
			t.Fatalf("corrupt hidden import fixture: %v", err)
		}
	}

	preview := httptest.NewRecorder()
	importer.ImportPreview(preview, csvImportRequest(t, "/api/vault/import/preview", userID, "Hidden CSV guess"))
	if preview.Code != http.StatusOK {
		t.Fatalf("CSV preview touched hidden scope: HTTP %d: %s", preview.Code, preview.Body.String())
	}
	var csvPreview VaultImportPreview
	if err := json.NewDecoder(preview.Body).Decode(&csvPreview); err != nil {
		t.Fatalf("decode CSV preview: %v", err)
	}
	if len(csvPreview.Conflicts) != 0 {
		t.Fatalf("hidden collection name appeared as a public CSV conflict: %v", csvPreview.Conflicts)
	}
	confirmBody, _ := json.Marshal(map[string]any{"entries": []ImportEntry{{
		Name: "Hidden CSV guess", Value: "imported-csv-value", URL: "https://example.com",
	}}})
	csvConfirm := httptest.NewRecorder()
	importer.ImportConfirm(csvConfirm, vaultAuthzRequest(http.MethodPost, "/api/vault/import/confirm",
		userID, "user", "", string(confirmBody)))
	if csvConfirm.Code != http.StatusOK || !strings.Contains(csvConfirm.Body.String(), `"imported":1`) {
		t.Fatalf("CSV confirm collided with hidden scope: HTTP %d: %s", csvConfirm.Code, csvConfirm.Body.String())
	}

	document := nativeImportDocumentFixture()
	personal := document.Entries[1]
	personal.SourceID = "scope-native-personal"
	personal.Name = "Hidden native guess"
	personal.Value = "imported-native-value"
	document.Collections = []vaultExportCollection{}
	document.Entries = []vaultExportEntry{personal}
	nativePreviewRec := httptest.NewRecorder()
	importer.NativeImportPreview(nativePreviewRec, nativeMultipartRequest(t,
		"/api/vault/import/native/preview", userID, "user", "", document))
	if nativePreviewRec.Code != http.StatusOK {
		t.Fatalf("native preview touched hidden scope: HTTP %d: %s",
			nativePreviewRec.Code, nativePreviewRec.Body.String())
	}
	var nativePreviewBody nativeImportPreview
	if err := json.NewDecoder(nativePreviewRec.Body).Decode(&nativePreviewBody); err != nil {
		t.Fatalf("decode native preview: %v", err)
	}
	if len(nativePreviewBody.Conflicts) != 0 || strings.Contains(nativePreviewRec.Body.String(), "Hidden native guess") {
		t.Fatalf("hidden collection name leaked through native preview: %s", nativePreviewRec.Body.String())
	}
	nativeConfirm := callNativeConfirm(t, importer, userID, password, document)
	if nativeConfirm.Code != http.StatusOK {
		t.Fatalf("native confirm collided with hidden scope: HTTP %d: %s",
			nativeConfirm.Code, nativeConfirm.Body.String())
	}

	names, err := importer.personalImportNameSet(context.Background(), queries, userID)
	if err != nil {
		t.Fatalf("read imported personal names: %v", err)
	}
	for _, name := range []string{"Hidden CSV guess", "Hidden native guess"} {
		if _, found := names[name]; !found {
			t.Errorf("personal import %q was not persisted", name)
		}
	}
}

func TestNativeImportDuplicateNamesAreScoped(t *testing.T) {
	document := nativeImportDocumentFixture()
	document.Entries[0].Name = "Reusable label"
	document.Entries[1].Name = "Reusable label"
	plan, err := validateNativeImportDocument(document)
	if err != nil {
		t.Fatalf("validate cross-scope duplicate labels: %v", err)
	}
	if len(plan.intraConflicts) != 0 {
		t.Fatalf("personal+collection labels were joined into one namespace: %v", plan.intraConflicts)
	}

	duplicate := document.Entries[0]
	duplicate.SourceID = "same-collection-duplicate"
	duplicate.Value = "different-value"
	document.Entries = append(document.Entries, duplicate)
	plan, err = validateNativeImportDocument(document)
	if err != nil {
		t.Fatalf("validate same-scope duplicate document: %v", err)
	}
	if !slices.Equal(plan.intraConflicts, []string{"Reusable label"}) {
		t.Fatalf("same collection duplicate conflicts = %v", plan.intraConflicts)
	}
}

func TestNameBlindIndexCandidatesCoverCurrentAndPreviousScopeKeys(t *testing.T) {
	current := deriveVaultKeyMaterial(strings.Repeat("c", 32))
	previous := deriveVaultKeyMaterial(strings.Repeat("p", 32))
	h := &VaultHandler{bidxKey: current.bidx, previous: &previous}
	scope := bidxScope("ignored-in-collection", sql.NullString{String: "scope-candidates", Valid: true})
	got := h.nameBlindIndexCandidates(scope, "Exact Case Label")
	want := []string{
		nameBlindIndexWith(current.bidx, scope, "Exact Case Label"),
		nameBlindIndexWith(previous.bidx, scope, "Exact Case Label"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("name index candidates = %v, want current+previous %v", got, want)
	}
	if got[0] == h.nameBlindIndex("ignored-in-collection", "Exact Case Label") {
		t.Fatal("collection token unexpectedly equals the custodian's personal token")
	}
}

func TestOwnershipClaimConvergesLegacyCollectionNameScope(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	creator := mustUser(t, queries, "scope-claim-creator@example.com", "user", "")
	admin := mustUser(t, queries, "scope-claim-admin@example.com", "admin", "")
	const collectionID = "scope-claim-collection"
	const entryID = "scope-claim-entry"
	const name = "Legacy collection label"
	mustCollection(t, queries, collectionID, creator, map[string]string{creator: collRoleManager})
	mustEntry(t, h, queries, entryID, creator, name, "value")
	// The low-level placement fixture deliberately preserves 00040's personal
	// token so the ownership writer has a real compatibility row to converge.
	placeInCollection(t, queries, entryID, collectionID)
	if _, err := h.db.Exec(`UPDATE vault_entries SET secret_owner_user_id = '' WHERE id = ?`, entryID); err != nil {
		t.Fatalf("clear legacy owner: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ClaimSecretOwnership(rec, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+entryID+"/ownership/claim", admin, "admin", entryID, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("claim ownership: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	var custodian, owner, gotBidx string
	if err := h.db.QueryRow(`SELECT user_id, secret_owner_user_id, name_bidx FROM vault_entries WHERE id = ?`, entryID).
		Scan(&custodian, &owner, &gotBidx); err != nil {
		t.Fatalf("read claimed row: %v", err)
	}
	if custodian != admin || owner != admin {
		t.Fatalf("ownership did not move atomically: custodian=%q owner=%q want %q", custodian, owner, admin)
	}
	want := h.scopedNameBlindIndex(bidxScope(admin,
		sql.NullString{String: collectionID, Valid: true}), name)
	if gotBidx != want {
		t.Fatalf("ownership claim left a legacy/empty token: got %q want collection token %q", gotBidx, want)
	}
}

func TestPreviousKeyNameTokenConflictsStayInsideThePersonalScope(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	const password = "previous-key-scope-password"
	userID := mustUser(t, queries, "scope-previous@example.com", "user", password)
	previous := deriveVaultKeyMaterial(strings.Repeat("p", 32))
	h.previous = &previous
	const name = "Previous-key personal label"
	mustEntry(t, h, queries, "scope-previous-existing", userID, name, "existing")
	previousToken := nameBlindIndexWith(previous.bidx,
		bidxScope(userID, sql.NullString{}), name)
	if _, err := h.db.Exec(`UPDATE vault_entries SET name_bidx = ? WHERE id = ?`,
		previousToken, "scope-previous-existing"); err != nil {
		t.Fatalf("plant previous-key token: %v", err)
	}

	create, _ := createScopedEntry(t, h, userID, name, nil, false)
	if create.Code != http.StatusConflict {
		t.Fatalf("create ignored previous-key token/name: HTTP %d: %s", create.Code, create.Body.String())
	}
	renameSource, source := createScopedEntry(t, h, userID, "Previous-key rename source", nil, false)
	if renameSource.Code != http.StatusCreated {
		t.Fatalf("create rename source: HTTP %d: %s", renameSource.Code, renameSource.Body.String())
	}
	rename := httptest.NewRecorder()
	h.Update(rename, vaultAuthzRequest(http.MethodPut, "/api/vault/"+source.ID,
		userID, "user", source.ID, `{"name":"`+name+`"}`))
	if rename.Code != http.StatusConflict {
		t.Fatalf("rename ignored previous-key token/name: HTTP %d: %s", rename.Code, rename.Body.String())
	}

	importer := NewVaultImportHandler(h.db, h)
	csvPreviewRec := httptest.NewRecorder()
	importer.ImportPreview(csvPreviewRec,
		csvImportRequest(t, "/api/vault/import/preview", userID, name))
	var csvPreview VaultImportPreview
	if csvPreviewRec.Code != http.StatusOK || json.NewDecoder(csvPreviewRec.Body).Decode(&csvPreview) != nil {
		t.Fatalf("CSV preview failed: HTTP %d: %s", csvPreviewRec.Code, csvPreviewRec.Body.String())
	}
	if !slices.Equal(csvPreview.Conflicts, []string{name}) {
		t.Fatalf("CSV conflicts = %v, want previous-key name %q", csvPreview.Conflicts, name)
	}
	csvBody, _ := json.Marshal(map[string]any{"entries": []ImportEntry{{Name: name, Value: "csv"}}})
	csvConfirm := httptest.NewRecorder()
	importer.ImportConfirm(csvConfirm, vaultAuthzRequest(http.MethodPost,
		"/api/vault/import/confirm", userID, "user", "", string(csvBody)))
	if csvConfirm.Code != http.StatusOK || !strings.Contains(csvConfirm.Body.String(), `"imported":0`) {
		t.Fatalf("CSV confirm did not refuse previous-key duplicate: HTTP %d: %s",
			csvConfirm.Code, csvConfirm.Body.String())
	}

	document := nativeImportDocumentFixture()
	personal := document.Entries[1]
	personal.SourceID = "scope-previous-native"
	personal.CollectionID = nil
	personal.Name = name
	personal.Value = "native"
	document.Collections = []vaultExportCollection{}
	document.Entries = []vaultExportEntry{personal}
	nativePreviewRec := httptest.NewRecorder()
	importer.NativeImportPreview(nativePreviewRec, nativeMultipartRequest(t,
		"/api/vault/import/native/preview", userID, "user", "", document))
	var nativePreviewBody nativeImportPreview
	if nativePreviewRec.Code != http.StatusOK || json.NewDecoder(nativePreviewRec.Body).Decode(&nativePreviewBody) != nil {
		t.Fatalf("native preview failed: HTTP %d: %s", nativePreviewRec.Code, nativePreviewRec.Body.String())
	}
	if !slices.Equal(nativePreviewBody.Conflicts, []string{name}) {
		t.Fatalf("native conflicts = %v, want previous-key name %q", nativePreviewBody.Conflicts, name)
	}
	nativeConfirm := callNativeConfirm(t, importer, userID, password, document)
	if nativeConfirm.Code != http.StatusConflict {
		t.Fatalf("native confirm ignored previous-key duplicate: HTTP %d: %s",
			nativeConfirm.Code, nativeConfirm.Body.String())
	}
}

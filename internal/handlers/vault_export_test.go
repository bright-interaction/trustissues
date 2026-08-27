package handlers

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

func exportVaultAs(h *VaultHandler, userID, role, password string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := vaultAuthzRequest(http.MethodPost, "/api/vault/export", userID, role, "",
		`{"password":`+quote(password)+`}`)
	req.Header.Set("User-Agent", "vault-export-test")
	h.Export(rec, req)
	return rec
}

func TestVaultExportReauthScopeHeadersAndRedaction(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const password = "correct-export-password"
	caller := mustUser(t, queries, "export-caller@example.com", "user", password)
	owner := mustUser(t, queries, "export-owner@example.com", "user", password)

	const (
		personalID      = "entry-export-personal"
		personalName    = "Caller login"
		personalValue   = "pw_PERSONAL_ONLY"
		sharedID        = "entry-export-shared"
		sharedValue     = "pw_SHARED_ALLOWED"
		privateID       = "entry-export-private"
		privateName     = "Owner private login"
		privateValue    = "pw_OWNER_PRIVATE"
		secretField     = "otpauth://totp/export-test?secret=FIELD_SECRET"
		reservedURL     = "https://reserved-marker.invalid/revoke/old-key"
		reservedKeyID   = "SERVER_OLD_KEY_ID"
		reservedErrText = "SERVER_REVOKE_ERROR"
	)

	mustEntry(t, h, queries, personalID, caller, personalName, personalValue)
	mustEntry(t, h, queries, sharedID, owner, "Shared login", sharedValue)
	mustEntry(t, h, queries, privateID, owner, privateName, privateValue)
	mustCollection(t, queries, "collection-export-shared", owner, map[string]string{
		owner:  collRoleManager,
		caller: collRoleViewer,
	})
	placeInCollection(t, queries, sharedID, "collection-export-shared")

	// Seed the server-owned marker shape left by a failed deferred revoke. The
	// ordinary key_id must survive; every reserved key and value must disappear
	// from the attachment.
	rawProviderMeta := `{"key_id":"client-visible-key","pending_revoke_method":"DELETE",` +
		`"pending_revoke_url":` + quote(reservedURL) + `,"pending_revoke_auth":"bearer",` +
		`"pending_revoke_key_id":` + quote(reservedKeyID) + `,` +
		`"pending_revoke_stranded":"server-queue","last_revoke_error":` + quote(reservedErrText) + `}`
	providerMeta, err := h.encryptColumn(rawProviderMeta)
	if err != nil {
		t.Fatalf("encrypt provider metadata: %v", err)
	}
	customFields, err := h.encryptCustomFields([]CustomField{
		{Label: "Account", Value: "ordinary-field", Secret: false},
		{Label: "TOTP", Value: secretField, Secret: true},
	})
	if err != nil {
		t.Fatalf("encrypt custom fields: %v", err)
	}
	if _, err := h.db.ExecContext(ctx, `UPDATE vault_entries
SET provider = 'resend', provider_meta = ?, custom_fields = ?,
    destination_patterns = '["api.example.test/*"]'
WHERE id = ?`, providerMeta, customFields, personalID); err != nil {
		t.Fatalf("seed export metadata: %v", err)
	}

	t.Run("wrong password returns no secrets and is not cacheable", func(t *testing.T) {
		rec := exportVaultAs(h, caller, "user", "wrong-export-password")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("wrong password: got HTTP %d, want 403: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Errorf("wrong-password Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
		}
		if got := rec.Header().Get("Content-Disposition"); got != "" {
			t.Errorf("wrong-password response was presented as an attachment: %q", got)
		}
		for _, secret := range []string{personalValue, sharedValue, privateValue, secretField} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("wrong-password response leaked %q", secret)
			}
		}
		if rows, err := queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
			Action: "vault.exported", Limit: 10, Offset: 0,
		}); err != nil {
			t.Fatalf("read export audit rows: %v", err)
		} else if len(rows) != 0 {
			t.Fatalf("wrong password wrote %d vault.exported rows, want none", len(rows))
		}
	})

	t.Run("success is a safe native attachment in Unlock scope", func(t *testing.T) {
		rec := exportVaultAs(h, caller, "user", password)
		if rec.Code != http.StatusOK {
			t.Fatalf("export: got HTTP %d, want 200: %s", rec.Code, rec.Body.String())
		}

		if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
		if got := rec.Header().Get("Pragma"); got != "no-cache" {
			t.Errorf("Pragma = %q, want no-cache", got)
		}
		if got := rec.Header().Get("Expires"); got != "0" {
			t.Errorf("Expires = %q, want 0", got)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
		}

		disposition, params, err := mime.ParseMediaType(rec.Header().Get("Content-Disposition"))
		if err != nil {
			t.Fatalf("parse Content-Disposition: %v", err)
		}
		if disposition != "attachment" {
			t.Errorf("Content-Disposition type = %q, want attachment", disposition)
		}
		filename := params["filename"]
		if !regexp.MustCompile(`^trustissues-vault-[0-9]{8}-[0-9]{6}\.json$`).MatchString(filename) {
			t.Errorf("unsafe or unexpected export filename %q", filename)
		}
		if strings.ContainsAny(filename, "/\\\r\n") {
			t.Errorf("filename contains a path or header delimiter: %q", filename)
		}
		if got, err := strconv.Atoi(rec.Header().Get("Content-Length")); err != nil || got != rec.Body.Len() {
			t.Errorf("Content-Length = %q, body is %d bytes", rec.Header().Get("Content-Length"), rec.Body.Len())
		}

		var document vaultExportDocument
		if err := json.Unmarshal(rec.Body.Bytes(), &document); err != nil {
			t.Fatalf("decode native export: %v", err)
		}
		if document.Format != vaultExportFormat || document.Version != vaultExportVersion {
			t.Errorf("format/version = %q/%d, want %q/%d", document.Format, document.Version,
				vaultExportFormat, vaultExportVersion)
		}
		if _, err := time.Parse(time.RFC3339Nano, document.ExportedAt); err != nil {
			t.Errorf("exported_at is not RFC3339Nano: %q: %v", document.ExportedAt, err)
		}
		if len(document.Collections) != 1 || document.Collections[0].SourceID != "collection-export-shared" {
			t.Errorf("referenced collections = %+v, want only collection-export-shared", document.Collections)
		}

		entries := make(map[string]vaultExportEntry, len(document.Entries))
		for _, entry := range document.Entries {
			entries[entry.SourceID] = entry
		}
		if len(entries) != 2 {
			t.Fatalf("exported %d entries, want caller personal + accepted shared: %+v", len(entries), entries)
		}
		if got := entries[personalID].Value; got != personalValue {
			t.Errorf("personal value = %q, want %q", got, personalValue)
		}
		if got := entries[sharedID].Value; got != sharedValue {
			t.Errorf("shared value = %q, want %q", got, sharedValue)
		}
		if _, ok := entries[privateID]; ok {
			t.Fatal("another user's private entry was exported")
		}
		if strings.Contains(rec.Body.String(), privateValue) || strings.Contains(rec.Body.String(), privateName) {
			t.Fatal("another user's private entry data appeared in the attachment")
		}

		personal := entries[personalID]
		if len(personal.CustomFields) != 2 || personal.CustomFields[1].Value != secretField ||
			personal.CustomFields[1].Withheld {
			t.Errorf("secret custom field did not make the successful export intact: %+v", personal.CustomFields)
		}
		if len(personal.DestinationPatterns) != 1 || personal.DestinationPatterns[0] != "api.example.test/*" {
			t.Errorf("destination patterns = %v", personal.DestinationPatterns)
		}
		var safeMeta map[string]json.RawMessage
		if err := json.Unmarshal([]byte(personal.ProviderMeta), &safeMeta); err != nil {
			t.Fatalf("provider_meta is not valid JSON: %q: %v", personal.ProviderMeta, err)
		}
		if _, ok := safeMeta["key_id"]; !ok {
			t.Errorf("ordinary provider metadata was lost: %s", personal.ProviderMeta)
		}
		for _, key := range reservedProviderMetaKeys {
			if _, ok := safeMeta[key]; ok {
				t.Errorf("reserved provider metadata key %q leaked: %s", key, personal.ProviderMeta)
			}
			if strings.Contains(rec.Body.String(), `"`+key+`"`) {
				t.Errorf("reserved provider metadata key %q appeared elsewhere in attachment", key)
			}
		}
		for _, reservedValue := range []string{reservedURL, reservedKeyID, reservedErrText, "server-queue"} {
			if strings.Contains(rec.Body.String(), reservedValue) {
				t.Errorf("reserved provider metadata value %q leaked", reservedValue)
			}
		}

		rows, err := queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
			Action: "vault.exported", Limit: 10, Offset: 0,
		})
		if err != nil {
			t.Fatalf("read export audit row: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("vault.exported rows = %d, want 1", len(rows))
		}
		detail := nullStringToString(rows[0].Detail)
		if !strings.Contains(detail, "entries: 2") {
			t.Errorf("audit detail lost safe entry count: %q", detail)
		}
		for _, forbidden := range []string{personalName, personalValue, sharedValue, privateValue,
			secretField, reservedURL, "client-visible-key"} {
			if strings.Contains(detail, forbidden) {
				t.Errorf("audit detail contains vault data %q: %q", forbidden, detail)
			}
		}
	})

	t.Run("an unreadable row fails before any partial attachment is written", func(t *testing.T) {
		if _, err := h.db.ExecContext(ctx,
			`UPDATE vault_entries SET encrypted_value = x'00', nonce = x'00' WHERE id = ?`, personalID); err != nil {
			t.Fatalf("corrupt accessible row: %v", err)
		}
		rec := exportVaultAs(h, caller, "user", password)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("incomplete export: got HTTP %d, want 500: %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Disposition"); got != "" {
			t.Errorf("failed export was presented as an attachment: %q", got)
		}
		if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Errorf("failed export Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
		}
		for _, secret := range []string{personalValue, sharedValue, privateValue, secretField} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("failed export leaked partial value %q", secret)
			}
		}
	})

	t.Run("corrupt encrypted metadata fails instead of exporting a blank field", func(t *testing.T) {
		ciphertext, nonce, err := h.EncryptValue([]byte(personalValue))
		if err != nil {
			t.Fatalf("repair value: %v", err)
		}
		if _, err := h.db.ExecContext(ctx, `UPDATE vault_entries
SET encrypted_value = ?, nonce = ?, notes = 'enc:v1:not-valid-base64'
WHERE id = ?`, ciphertext, nonce, personalID); err != nil {
			t.Fatalf("corrupt encrypted metadata: %v", err)
		}
		rec := exportVaultAs(h, caller, "user", password)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("corrupt-metadata export: got HTTP %d, want 500: %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Disposition"); got != "" {
			t.Errorf("corrupt-metadata response was presented as an attachment: %q", got)
		}
		for _, secret := range []string{personalValue, sharedValue, secretField} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("corrupt-metadata failure leaked partial value %q", secret)
			}
		}
	})
}

func TestVaultExportFailsClosedWhenAuditTrailIsUnavailable(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const (
		password = "correct-audit-failure-password"
		value    = "pw_MUST_NOT_LEAVE_WITHOUT_AUDIT"
	)
	caller := mustUser(t, queries, "export-audit-failure@example.com", "user", password)
	mustEntry(t, h, queries, "entry-export-audit-failure", caller, "Audited login", value)

	if _, err := h.db.ExecContext(ctx, `CREATE TRIGGER fail_export_audit
BEFORE INSERT ON activity_log
WHEN NEW.action = 'vault.exported'
BEGIN
  SELECT RAISE(FAIL, 'simulated audit outage');
END`); err != nil {
		t.Fatalf("install failing audit trigger: %v", err)
	}

	rec := exportVaultAs(h, caller, "user", password)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure: got HTTP %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); got != "" {
		t.Errorf("audit-failure response was presented as an attachment: %q", got)
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("audit-failure Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if strings.Contains(rec.Body.String(), value) {
		t.Fatal("audit-failure response leaked the vault value")
	}
	if rows, err := queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
		Action: "vault.exported", Limit: 10, Offset: 0,
	}); err != nil {
		t.Fatalf("read export audit rows: %v", err)
	} else if len(rows) != 0 {
		t.Fatalf("failed audit insert left %d vault.exported rows, want none", len(rows))
	}
}

func TestVaultExportRefusesDocumentsTheNativeImporterCannotBound(t *testing.T) {
	t.Run("entry ceiling is checked before bulk reveal", func(t *testing.T) {
		h, queries := newCollectionAuthzEnv(t)
		ctx := context.Background()
		const password = "correct-over-count-export-password"
		caller := mustUser(t, queries, "export-over-count@example.com", "user", password)

		// Deliberately store invalid ciphertext. A correct preflight returns 413
		// from the bounded count without ever trying to reveal one of these rows;
		// moving the check after bulk reveal turns this into a 500 instead.
		if _, err := h.db.ExecContext(ctx, `WITH RECURSIVE seq(n) AS (
  SELECT 1
  UNION ALL SELECT n + 1 FROM seq WHERE n < ?
)
INSERT INTO vault_entries
  (id, user_id, secret_owner_user_id, name, encrypted_value, nonce, encryption_version)
SELECT printf('entry-export-over-count-%06d', n), ?, ?,
       printf('Export over count %06d', n), x'00', x'00', 2
FROM seq`, maxImportEntries+1, caller, caller); err != nil {
			t.Fatalf("seed over-count vault: %v", err)
		}

		rec := exportVaultAs(h, caller, "user", password)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("over-count export: got HTTP %d, want 413: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"code":"native_export_too_large"`) {
			t.Errorf("over-count response lost stable error code: %s", rec.Body.String())
		}
		if got := rec.Header().Get("Content-Disposition"); got != "" {
			t.Errorf("over-count response was presented as an attachment: %q", got)
		}
		if rows, err := queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
			Action: "vault.exported", Limit: 10, Offset: 0,
		}); err != nil {
			t.Fatalf("read export audit rows: %v", err)
		} else if len(rows) != 0 {
			t.Fatalf("refused over-count export wrote %d success audit rows", len(rows))
		}
	})

	t.Run("stored-size lower bound is checked before decryption or audit", func(t *testing.T) {
		h, queries := newCollectionAuthzEnv(t)
		ctx := context.Background()
		const password = "correct-over-bytes-export-password"
		caller := mustUser(t, queries, "export-over-bytes@example.com", "user", password)
		mustEntry(t, h, queries, "entry-export-over-bytes", caller, "Oversized legacy login", "small")
		// zeroblob keeps the test fixture cheap while making the stored ciphertext
		// one byte too large to yield a portable plaintext value. Its nonce and
		// contents are deliberately invalid: a 413 proves the size lower-bound ran
		// before OpenEntrySecret; attempting decryption would return 500 instead.
		if _, err := h.db.ExecContext(ctx, `UPDATE vault_entries
SET encrypted_value = zeroblob(?), nonce = x'00'
WHERE id = ?`, MaxNativeVaultFileBytes+17, "entry-export-over-bytes"); err != nil {
			t.Fatalf("seed oversized stored value: %v", err)
		}

		rec := exportVaultAs(h, caller, "user", password)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("over-byte export: got HTTP %d, want 413: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"code":"native_export_too_large"`) {
			t.Errorf("over-byte response lost stable error code: %s", rec.Body.String())
		}
		if got := rec.Header().Get("Content-Disposition"); got != "" {
			t.Errorf("over-byte response was presented as an attachment: %q", got)
		}
		if rows, err := queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
			Action: "vault.exported", Limit: 10, Offset: 0,
		}); err != nil {
			t.Fatalf("read export audit rows: %v", err)
		} else if len(rows) != 0 {
			t.Fatalf("refused over-byte export wrote %d success audit rows", len(rows))
		}
	})
}

func TestVaultExportRejectsLossyStoredShapes(t *testing.T) {
	tests := []struct {
		name   string
		column string
		value  func(*testing.T, *VaultHandler) string
	}{
		{
			name:   "future custom-field member",
			column: "custom_fields",
			value: func(t *testing.T, h *VaultHandler) string {
				t.Helper()
				stored, err := h.encryptColumn(`[{"label":"TOTP","value":"seed","secret":true,"future":1}]`)
				if err != nil {
					t.Fatalf("encrypt custom fields: %v", err)
				}
				return stored
			},
		},
		{
			name:   "null destination array",
			column: "destination_patterns",
			value:  func(_ *testing.T, _ *VaultHandler) string { return "null" },
		},
		{
			name:   "unsafe destination pattern",
			column: "destination_patterns",
			value:  func(_ *testing.T, _ *VaultHandler) string { return `["*"]` },
		},
		{
			name:   "non-canonical destination pattern",
			column: "destination_patterns",
			value:  func(_ *testing.T, _ *VaultHandler) string { return `[" api.example.test/* "]` },
		},
		{
			name:   "non-object provider metadata",
			column: "provider_meta",
			value: func(t *testing.T, h *VaultHandler) string {
				t.Helper()
				stored, err := h.encryptColumn(`[]`)
				if err != nil {
					t.Fatalf("encrypt provider metadata: %v", err)
				}
				return stored
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, queries := newCollectionAuthzEnv(t)
			const (
				password = "correct-malformed-row-password"
				value    = "pw_MALFORMED_ROW_MUST_NOT_LEAK"
			)
			caller := mustUser(t, queries, "export-malformed@example.com", "user", password)
			const entryID = "entry-export-malformed"
			mustEntry(t, h, queries, entryID, caller, "Malformed login", value)

			query := "UPDATE vault_entries SET " + test.column + " = ? WHERE id = ?"
			if _, err := h.db.ExecContext(context.Background(), query, test.value(t, h), entryID); err != nil {
				t.Fatalf("seed malformed row: %v", err)
			}

			rec := exportVaultAs(h, caller, "user", password)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("malformed export: got HTTP %d, want 500: %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Disposition"); got != "" {
				t.Errorf("malformed response was presented as an attachment: %q", got)
			}
			if strings.Contains(rec.Body.String(), value) {
				t.Fatal("malformed response leaked the vault value")
			}
		})
	}
}

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

const (
	secondaryGatePassword = "correct horse battery staple"
	secondaryCustomSecret = "otpauth://totp/acme?secret=SECONDARY_CUSTOM_SECRET"
	secondaryDatadogKey   = "dd-app-SECONDARY_PROVIDER_CREDENTIAL"
)

func apiKeyVaultRequest(method, path, userID, entryID, body string) *http.Request {
	r := vaultAuthzRequest(method, path, userID, "vault_only", entryID, body)
	ctx := context.WithValue(r.Context(), timw.PrincipalKindKey, timw.PrincipalAPIKey)
	return r.WithContext(ctx)
}

func seedSecondarySecrets(t *testing.T, h *VaultHandler, queries *db.Queries, userID, entryID string) {
	t.Helper()
	mustEntry(t, h, queries, entryID, userID, "Datadog production", "dd-primary-api-key")

	customFields, err := h.encryptCustomFields([]CustomField{
		{Label: "TOTP", Value: secondaryCustomSecret, Secret: true},
		{Label: "region", Value: "eu"},
	})
	if err != nil {
		t.Fatalf("encrypt custom fields: %v", err)
	}
	providerMeta, err := h.encryptColumn(`{"site":"datadoghq.eu","app_key":"` + secondaryDatadogKey + `"}`)
	if err != nil {
		t.Fatalf("encrypt provider_meta: %v", err)
	}
	if _, err := h.db.ExecContext(context.Background(), `
UPDATE vault_entries
SET provider = 'datadog', provider_meta = ?, custom_fields = ?
WHERE id = ?`, providerMeta, customFields, entryID); err != nil {
		t.Fatalf("seed secondary secrets: %v", err)
	}
}

func assertSecondarySecretsAbsent(t *testing.T, body string) {
	t.Helper()
	for _, secret := range []string{secondaryCustomSecret, secondaryDatadogKey} {
		if strings.Contains(body, secret) {
			t.Fatalf("non-reauthenticated response leaked %q: %s", secret, body)
		}
	}
}

// TestAPIKeyMetadataCannotRevealSecondarySecrets covers every ordinary response
// shape that previously re-opened the secondary credentials: list, a no-op
// update echo, and the schedule echo. The principal is explicitly the
// vault_only browser-extension API-key path, not an interactive session.
func TestAPIKeyMetadataCannotRevealSecondarySecrets(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "secondary-api-key@example.com", "vault_only", secondaryGatePassword)
	const entryID = "secondary-api-key-entry"
	seedSecondarySecrets(t, h, queries, userID, entryID)

	t.Run("GET list redacts provider credential", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.List(rec, apiKeyVaultRequest(http.MethodGet, "/api/vault", userID, "", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("list returned %d: %s", rec.Code, rec.Body.String())
		}
		assertSecondarySecretsAbsent(t, rec.Body.String())

		var entries []vaultEntryMeta
		if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil || len(entries) != 1 {
			t.Fatalf("decode list: entries=%d err=%v body=%s", len(entries), err, rec.Body.String())
		}
		var meta map[string]string
		if err := json.Unmarshal([]byte(entries[0].ProviderMeta), &meta); err != nil {
			t.Fatalf("decode provider_meta: %v", err)
		}
		if meta["site"] != "datadoghq.eu" || meta["app_key"] != "" {
			t.Fatalf("provider metadata was not selectively redacted: %s", entries[0].ProviderMeta)
		}
		if len(entries[0].ProviderMetaWithheld) != 1 || entries[0].ProviderMetaWithheld[0] != "app_key" {
			t.Fatalf("response did not distinguish withheld app_key from absent: %v",
				entries[0].ProviderMetaWithheld)
		}
	})

	t.Run("no-op PUT does not reveal", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.Update(rec, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entryID,
			userID, entryID, `{"notes":"ordinary metadata edit"}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("update returned %d: %s", rec.Code, rec.Body.String())
		}
		assertSecondarySecretsAbsent(t, rec.Body.String())
		var entry vaultEntryMeta
		if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
			t.Fatalf("decode update: %v", err)
		}
		if len(entry.CustomFields) != 2 || !entry.CustomFields[0].Withheld ||
			entry.CustomFields[0].Value != "" || entry.CustomFields[1].Value != "eu" {
			t.Fatalf("custom field metadata shape is unsafe: %+v", entry.CustomFields)
		}
	})

	t.Run("echoed markers preserve both credential stores", func(t *testing.T) {
		body := `{"provider_meta":"{\"site\":\"datadoghq.eu\"}",` +
			`"custom_fields":[{"label":"TOTP","value":"","secret":true,"withheld":true},` +
			`{"label":"region","value":"se"}]}`
		rec := httptest.NewRecorder()
		h.Update(rec, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entryID, userID, entryID, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("marker-preserving update returned %d: %s", rec.Code, rec.Body.String())
		}
		assertSecondarySecretsAbsent(t, rec.Body.String())

		row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
		if err != nil {
			t.Fatalf("read stored entry: %v", err)
		}
		fields := h.decryptCustomFields(row.CustomFields)
		if len(fields) != 2 || fields[0].Value != secondaryCustomSecret || fields[1].Value != "se" {
			t.Fatalf("withheld merge lost a secret or legitimate edit: %+v", fields)
		}
		rawMeta := h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)
		meta := ParseProviderMeta(rawMeta)
		if meta["app_key"] != secondaryDatadogKey || meta["site"] != "datadoghq.eu" {
			t.Fatalf("provider credential was erased by redacted write-back: %s", rawMeta)
		}
	})

	t.Run("schedule echo does not reveal", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.UpdateSchedule(rec, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entryID+"/schedule",
			userID, entryID, `{"rotation_interval_days":30,"auto_rotate":false}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("schedule returned %d: %s", rec.Code, rec.Body.String())
		}
		assertSecondarySecretsAbsent(t, rec.Body.String())
	})

	t.Run("password-gated unlock still reveals", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.Unlock(rec, apiKeyVaultRequest(http.MethodPost, "/api/vault/unlock", userID, "",
			`{"password":"`+secondaryGatePassword+`"}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("unlock returned %d: %s", rec.Code, rec.Body.String())
		}
		for _, secret := range []string{secondaryCustomSecret, secondaryDatadogKey} {
			if !strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("password-gated unlock did not return %q: %s", secret, rec.Body.String())
			}
		}
	})

	t.Run("provider-only change cannot launder the old provider credential", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.Update(rec, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entryID,
			userID, entryID, `{"provider":"grafana"}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("provider-only update returned %d: %s", rec.Code, rec.Body.String())
		}
		assertSecondarySecretsAbsent(t, rec.Body.String())

		row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
		if err != nil {
			t.Fatalf("read provider-changed entry: %v", err)
		}
		rawMeta := h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)
		if meta := ParseProviderMeta(rawMeta); meta["app_key"] != "" {
			t.Fatalf("old Datadog app_key followed the entry to Grafana: %s", rawMeta)
		}
	})
}

func TestCreateResponseWithholdsSecondarySecrets(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "secondary-create@example.com", "vault_only", secondaryGatePassword)
	// Create/native import retain historical or unknown provider spellings. The
	// credential classification must not become bypassable by title-casing the
	// provider tag even though adapter execution remains registry-exact.
	body := `{"name":"Datadog create","value":"primary","provider":"Datadog",` +
		`"provider_meta":"{\"site\":\"datadoghq.com\",\"app_key\":\"` + secondaryDatadogKey + `\"}",` +
		`"custom_fields":[{"label":"TOTP","value":"` + secondaryCustomSecret + `","secret":true}]}`
	rec := httptest.NewRecorder()
	h.Create(rec, apiKeyVaultRequest(http.MethodPost, "/api/vault", userID, "", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	assertSecondarySecretsAbsent(t, rec.Body.String())

	var entry vaultEntryMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if len(entry.CustomFields) != 1 || !entry.CustomFields[0].Withheld ||
		len(entry.ProviderMetaWithheld) != 1 || entry.ProviderMetaWithheld[0] != "app_key" {
		t.Fatalf("create response did not mark withheld credentials: custom=%+v provider=%v",
			entry.CustomFields, entry.ProviderMetaWithheld)
	}

	// Canonicalizing the historical provider spelling must not look like a
	// cross-vendor move and silently discard the credential we just protected.
	update := httptest.NewRecorder()
	h.Update(update, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entry.ID,
		userID, entry.ID, `{"provider":"datadog","provider_meta":"{\"site\":\"datadoghq.com\"}"}`))
	if update.Code != http.StatusOK {
		t.Fatalf("provider spelling normalization returned %d: %s", update.Code, update.Body.String())
	}
	assertSecondarySecretsAbsent(t, update.Body.String())
	row, err := queries.GetVaultEntryMeta(context.Background(), entry.ID)
	if err != nil {
		t.Fatalf("read spelling-normalized entry: %v", err)
	}
	meta := ParseProviderMeta(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta))
	if meta["app_key"] != secondaryDatadogKey {
		t.Fatalf("provider spelling normalization discarded app_key: %+v", meta)
	}
}

func TestProviderMetadataCredentialCanBeDeliberatelyReplacedWithoutEcho(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "secondary-replace@example.com", "vault_only", "")
	const entryID = "secondary-replace-entry"
	const replacement = "dd-app-deliberate-replacement"
	seedSecondarySecrets(t, h, queries, userID, entryID)

	body := `{"provider_meta":"{\"site\":\"datadoghq.eu\",\"app_key\":\"` + replacement + `\"}"}`
	rec := httptest.NewRecorder()
	h.Update(rec, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entryID, userID, entryID, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("credential replacement returned %d: %s", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{secondaryDatadogKey, replacement} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("credential replacement echoed %q: %s", secret, rec.Body.String())
		}
	}

	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("read stored provider metadata: %v", err)
	}
	meta := ParseProviderMeta(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta))
	if meta["app_key"] != replacement {
		t.Fatalf("deliberate credential replacement stored %q, want %q", meta["app_key"], replacement)
	}
}

func TestWithheldCustomFieldIdentityMismatchIsRefused(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "secondary-mismatch@example.com", "vault_only", "")
	const entryID = "secondary-mismatch-entry"
	seedSecondarySecrets(t, h, queries, userID, entryID)

	rec := httptest.NewRecorder()
	h.Update(rec, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entryID, userID, entryID,
		`{"custom_fields":[{"label":"renamed","value":"","secret":true,"withheld":true},`+
			`{"label":"region","value":"eu"}]}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("ambiguous withheld marker returned %d, want 409: %s", rec.Code, rec.Body.String())
	}
	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("read stored fields: %v", err)
	}
	if fields := h.decryptCustomFields(row.CustomFields); len(fields) != 2 || fields[0].Value != secondaryCustomSecret {
		t.Fatalf("mismatched marker changed the stored credential: %+v", fields)
	}
}

// Native-v1 restores historical labels byte-for-byte, including surrounding
// whitespace that current interactive writes normalize. A metadata marker must
// retain that exact identity through validation or the server rejects its own
// response on the next safe save.
func TestWithheldMarkerPreservesPortableLegacyLabel(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "secondary-legacy-label@example.com", "vault_only", "")
	const entryID = "secondary-legacy-label-entry"
	const legacyLabel = "  legacy recovery key  "
	mustEntry(t, h, queries, entryID, userID, "Legacy import", "primary")

	stored, err := h.encryptCustomFields([]CustomField{
		{Label: legacyLabel, Value: secondaryCustomSecret, Secret: true},
	})
	if err != nil {
		t.Fatalf("encrypt legacy custom field: %v", err)
	}
	if err := queries.UpdateVaultEntryCustomFields(context.Background(),
		db.UpdateVaultEntryCustomFieldsParams{CustomFields: stored, ID: entryID}); err != nil {
		t.Fatalf("store legacy custom field: %v", err)
	}

	first := httptest.NewRecorder()
	h.Update(first, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entryID,
		userID, entryID, `{"notes":"ordinary edit"}`))
	if first.Code != http.StatusOK {
		t.Fatalf("ordinary legacy edit returned %d: %s", first.Code, first.Body.String())
	}
	var response vaultEntryMeta
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode legacy marker: %v", err)
	}
	if len(response.CustomFields) != 1 || response.CustomFields[0].Label != legacyLabel ||
		!response.CustomFields[0].Withheld {
		t.Fatalf("server did not retain the portable label in its marker: %+v", response.CustomFields)
	}

	body, err := json.Marshal(map[string]any{"custom_fields": response.CustomFields})
	if err != nil {
		t.Fatalf("encode marker echo: %v", err)
	}
	second := httptest.NewRecorder()
	h.Update(second, apiKeyVaultRequest(http.MethodPut, "/api/vault/"+entryID,
		userID, entryID, string(body)))
	if second.Code != http.StatusOK {
		t.Fatalf("server refused its exact legacy marker (%d): %s", second.Code, second.Body.String())
	}
	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("read legacy field after echo: %v", err)
	}
	fields := h.decryptCustomFields(row.CustomFields)
	if len(fields) != 1 || fields[0].Label != legacyLabel || fields[0].Value != secondaryCustomSecret {
		t.Fatalf("legacy marker preservation changed the stored field: %+v", fields)
	}
}

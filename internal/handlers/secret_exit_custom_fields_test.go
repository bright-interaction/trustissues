package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// THE SECOND EXIT THE ROUND-7 SCOPE BOUNDARY MISSED.
//
// vault_entries.custom_fields is AES-encrypted at rest exactly like the entry's
// value. A field with secret:true is operator-designated secret material: an API
// key pasted into a labelled field, a recovery PIN, a database password. The UI
// masks those values for that reason.
//
// It was decrypted by decryptCustomFields and written straight into the response
// body next to the entry's own value, which went through secretexit.Exit. So one
// credential on the row was gated and the other was not, and the SCOPE BOUNDARY
// comment claimed to enumerate every encrypted thing outside the exit and did
// not mention it, which reads as coverage.

// customFieldEnv is an entry carrying one secret and one ordinary custom field.
type customFieldEnv struct {
	h        *VaultHandler
	owner    string
	outsider string
	entry    string
	name     string
	secret   string
}

func newCustomFieldEnv(t *testing.T) *customFieldEnv {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	env := &customFieldEnv{
		h:      h,
		entry:  "entry-cf",
		name:   "billing-api",
		secret: "cf_live_SECOND_CREDENTIAL",
	}
	env.owner = mustUser(t, queries, "cf-owner@example.com", "user", "")
	env.outsider = mustUser(t, queries, "cf-outsider@example.com", "user", "")
	mustEntry(t, h, queries, env.entry, env.owner, env.name, "the-entrys-own-value")

	stored, err := h.encryptCustomFields([]CustomField{
		{Label: "recovery-pin", Value: env.secret, Secret: true},
		{Label: "account-region", Value: "eu-north-1"},
	})
	if err != nil {
		t.Fatalf("encrypt custom fields: %v", err)
	}
	if err := queries.UpdateVaultEntryCustomFields(context.Background(),
		db.UpdateVaultEntryCustomFieldsParams{CustomFields: stored, ID: env.entry}); err != nil {
		t.Fatalf("store custom fields: %v", err)
	}
	return env
}

// storedCustomFields reads the raw at-rest column back.
func (e *customFieldEnv) storedCustomFields(t *testing.T) string {
	t.Helper()
	row, err := e.h.queries.GetVaultEntryMeta(context.Background(), e.entry)
	if err != nil {
		t.Fatalf("read stored custom fields: %v", err)
	}
	return row.CustomFields
}

// TestSecretCustomFieldsGoThroughTheExit is the positive control and the
// defensive half in one, because either alone would be misleading: a gate that
// refuses everybody has not fixed anything, and a gate that refuses nobody is
// not a gate.
func TestSecretCustomFieldsGoThroughTheExit(t *testing.T) {
	env := newCustomFieldEnv(t)
	ctx := context.Background()

	// POSITIVE CONTROL, on a real route. PUT /api/vault/{id} echoes the entry it
	// just saved, and that echo is one of the response paths that carries custom
	// fields. The owner has to get their own secret field back, byte for byte,
	// exactly as before this change.
	rec := httptest.NewRecorder()
	env.h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+env.entry,
		env.owner, "user", env.entry, `{"notes":"unchanged"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner could not save their own entry (%d: %s)", rec.Code, rec.Body.String())
	}
	var out vaultEntryMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]CustomField{}
	for _, f := range out.CustomFields {
		got[f.Label] = f
	}
	if got["recovery-pin"].Value != env.secret {
		t.Fatalf("THE FEATURE IS BROKEN. The owner's own secret custom field came back as %q, want "+
			"the stored value. Routing it through the exit must not stop it reaching the person who "+
			"deposited it.", got["recovery-pin"].Value)
	}
	if got["recovery-pin"].Withheld {
		t.Error("the owner's own field was marked withheld")
	}
	if got["account-region"].Value != "eu-north-1" {
		t.Errorf("the ordinary custom field did not survive: %q", got["account-region"].Value)
	}

	// THE DEFENSIVE HALF. The exit asks grantFor(...).read about the entry the
	// field belongs to, and it is asked per field at the moment of release rather
	// than inferred from how the row was obtained. This drives the converter with
	// a principal the entry's owner does not admit, which is what a list query
	// that widened by accident would hand it.
	refused := env.h.customFieldsForCaller(ctx, env.entry, env.name, env.storedCustomFields(t), env.outsider)
	byLabel := map[string]CustomField{}
	for _, f := range refused {
		byLabel[f.Label] = f
	}
	if v := byLabel["recovery-pin"].Value; v != "" {
		t.Fatalf("A SECOND EXIT. The secret custom field was released to a principal the entry's "+
			"owner does not admit: %q", v)
	}
	if !byLabel["recovery-pin"].Withheld {
		t.Error("the refused field was blanked but not marked withheld, so the client cannot tell " +
			"'not set' from 'not released to you'")
	}
	t.Logf("custom_fields exit: owner released %d bytes, outsider released 0 and got withheld=true",
		len(env.secret))
}

// TestASaveCannotWriteBackAWithheldCustomField closes the hazard the blanking
// introduces.
//
// The edit form resubmits every field it was shown. A secret field the exit
// withheld comes back blank, so a save would replace a live credential with an
// empty string, permanently, with a 200 and a success toast. Same class as the
// refuse-to-overwrite guards on the metadata columns and on rotation_targets,
// and this one is sharper because the blank is one this server produced.
func TestASaveCannotWriteBackAWithheldCustomField(t *testing.T) {
	env := newCustomFieldEnv(t)

	body := `{"custom_fields":[{"label":"recovery-pin","value":"","secret":true,"withheld":true},` +
		`{"label":"account-region","value":"eu-north-1"}]}`
	rec := httptest.NewRecorder()
	env.h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+env.entry,
		env.owner, "user", env.entry, body))
	if rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
		t.Fatal("a save carrying a withheld field was accepted, so the blank this server rendered " +
			"just overwrote the real secret")
	}
	if !strings.Contains(rec.Body.String(), "not released") {
		t.Errorf("the refusal does not say why: %s", rec.Body.String())
	}

	// AND THE STORED VALUE IS UNTOUCHED.
	after := env.h.decryptCustomFields(env.storedCustomFields(t))
	for _, f := range after {
		if f.Label == "recovery-pin" && f.Value != env.secret {
			t.Fatalf("the stored secret custom field is now %q; the refusal came after the write", f.Value)
		}
	}
	t.Logf("save with a withheld field refused %d, stored value intact", rec.Code)
}

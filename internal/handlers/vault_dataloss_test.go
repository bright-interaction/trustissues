package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestRenameConflictIsReportedNotSwallowed locks a half-applied write that
// reported success.
//
// UpdateVaultEntryName's error was logged and stepped over, so a rename onto a
// name the user already had hit UNIQUE(user_id, name), the handler carried on,
// applied every OTHER field in the same request, and returned 200. The UI closed
// the editor, re-locked the vault and toasted "Secret updated". Create has
// returned a proper 409 for the identical condition all along.
//
// The field matters: entry names are the lookup key for service-identity
// allowed_secrets and for MCP list_secrets/use_secret, so a rename the operator
// believes happened is found later by an agent that cannot resolve the secret.
func TestRenameConflictIsReportedNotSwallowed(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "rename@example.com", "user", "")

	mustEntry(t, h, queries, "entry-aws", owner, "AWS", "v1")
	mustEntry(t, h, queries, "entry-gcp", owner, "GCP", "v2")

	rec := updateEntry(t, h, owner, "entry-gcp", map[string]any{"name": "AWS", "notes": "changed-notes"})
	if rec.Code != http.StatusConflict {
		t.Errorf("a colliding rename returned %d, want 409: %s", rec.Code, rec.Body.String())
	}

	meta, err := queries.GetVaultEntryMeta(ctx, "entry-gcp")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if h.EntryNamePlain(meta.Name) != "GCP" {
		t.Errorf("name changed to %q despite the conflict", h.EntryNamePlain(meta.Name))
	}
	// The other field in the same request must NOT have landed: a refused
	// request has to be all-or-nothing, or the operator is left guessing which
	// half applied.
	if notes := h.decryptColumnOrLog(meta.Notes.String, "", vaultFieldNotes); notes == "changed-notes" {
		t.Error("the request was half-applied: the rename was refused but notes were written")
	}
}

// TestBlankNameIsRejectedOnUpdate covers the same block. Create rejects an empty
// name; Update accepted one and stored it, leaving an entry that
// lookupSecretByName and MCP list_secrets can never resolve.
func TestBlankNameIsRejectedOnUpdate(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "blank@example.com", "user", "")
	mustEntry(t, h, queries, "entry-blank", owner, "Real name", "v")

	if rec := updateEntry(t, h, owner, "entry-blank", map[string]any{"name": "   "}); rec.Code != http.StatusBadRequest {
		t.Errorf("a blank name returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	meta, err := queries.GetVaultEntryMeta(context.Background(), "entry-blank")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if h.EntryNamePlain(meta.Name) != "Real name" {
		t.Errorf("name was blanked to %q", h.EntryNamePlain(meta.Name))
	}
}

// TestUndecryptableMetadataIsNotOverwritten locks the guard the secret VALUE has
// had since round 1 and the metadata columns did not.
//
// decryptColumnOrLog renders a decrypt failure as "", and the edit form always
// resubmits url/username/category/notes/custom_fields. So an operator who opened
// a damaged entry, saw blank fields and fixed an unrelated typo replaced still
// recoverable ciphertext with NULL, permanently, with a 200 and a success toast.
// custom_fields can hold secret:true values, so this is not merely metadata.
//
// The boot sentinel does not cover it: it catches a whole-database key mismatch,
// while this is one damaged row, a torn write, or a row left under an older key
// after the documented ALLOW_KEY_MISMATCH escape hatch re-sealed the sentinel.
func TestUndecryptableMetadataIsNotOverwritten(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "damaged@example.com", "user", "")
	mustEntry(t, h, queries, "entry-damaged", owner, "Damaged", "v")

	sealed, err := h.encryptColumn("production runbook, do not lose")
	if err != nil {
		t.Fatalf("seal notes: %v", err)
	}
	// Corrupt one byte of the ciphertext body, leaving the enc:v1: marker so the
	// row still declares itself encrypted.
	body := []byte(sealed)
	body[len(body)-3] ^= 0x01
	if err := queries.UpdateVaultEntryNotes(ctx, db.UpdateVaultEntryNotesParams{
		Notes: toNullString(string(body)), ID: "entry-damaged",
	}); err != nil {
		t.Fatalf("store damaged notes: %v", err)
	}

	// Guard the fixture: it must genuinely fail to decrypt, or this proves nothing.
	if _, decErr := h.decryptColumn(string(body), vaultFieldNotes); decErr == nil {
		t.Fatal("ABORT: the corrupted column still decrypts; the test would be vacuous")
	}

	rec := updateEntry(t, h, owner, "entry-damaged", map[string]any{"name": "Renamed", "notes": ""})
	if rec.Code != http.StatusConflict {
		t.Errorf("an ordinary save over an undecryptable column returned %d, want 409: %s", rec.Code, rec.Body.String())
	}

	meta, err := queries.GetVaultEntryMeta(ctx, "entry-damaged")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if meta.Notes.String != string(body) {
		t.Error("the still-recoverable ciphertext was overwritten; it is unrecoverable now even with the correct key")
	}
	if h.EntryNamePlain(meta.Name) != "Damaged" {
		t.Errorf("the refused request still applied the rename: name = %q", h.EntryNamePlain(meta.Name))
	}
}

// TestImportCarriesTOTPAndCustomFields locks the field-level loss.
//
// The row imports fine, so `skipped` is empty by construction and the modal
// toasts plain success, while every TOTP seed and every extra field in a
// Bitwarden or LastPass export was discarded server-side. The documented
// responsible next step after an import is deleting the plaintext export.
func TestImportCarriesTOTPAndCustomFields(t *testing.T) {
	headers := []string{"type", "name", "login_uri", "login_username", "login_password", "login_totp", "fields"}
	record := []string{"login", "AWS Console", "https://aws.amazon.com", "ops@example.com", "hunter2",
		"otpauth://totp/AWS?secret=JBSWY3DPEHPK3PXP", "recovery_pin: 998877\nregion: eu-north-1"}
	entry, _ := parseRecordByFormat(headers, record, FormatBitwarden)
	if entry == nil {
		t.Fatal("ABORT: the Bitwarden row did not parse at all")
	}
	if entry.Value != "hunter2" {
		t.Fatalf("ABORT: fixture did not parse the password: %+v", entry)
	}

	var gotTOTP, gotPIN bool
	for _, cf := range entry.CustomFields {
		if strings.Contains(cf.Value, "JBSWY3DPEHPK3PXP") {
			gotTOTP = true
			if !cf.Secret {
				t.Error("the TOTP seed is not marked secret, so the UI would show it in the clear")
			}
		}
		if cf.Label == "recovery_pin" && cf.Value == "998877" {
			gotPIN = true
		}
	}
	if !gotTOTP {
		t.Error("the TOTP seed was dropped; the team loses every 2FA code and only finds out after deleting the export")
	}
	if !gotPIN {
		t.Error("Bitwarden custom fields were dropped (recovery PINs, hosts, second tokens)")
	}

	// LastPass carries its seed in a different column.
	lp, _ := parseRecordByFormat(
		[]string{"name", "url", "username", "password", "totp"},
		[]string{"Bank", "https://bank.example", "u", "p", "JBSWY3DPEHPK3PXP"},
		FormatLastPass)
	if lp == nil || len(lp.CustomFields) == 0 {
		t.Error("the LastPass TOTP column was dropped")
	}
}

// TestGuardRunsBeforeEveryWrite is the test the first version of this guard
// needed and did not have.
//
// The guard originally sat BELOW the custom_fields, destination_patterns and
// value writes. For custom_fields that made it inert: it re-read the row after
// that column had already been replaced, inspected its own fresh write, and
// returned 200 with the recoverable ciphertext gone. For any other damaged
// column it returned 409 "nothing was changed" having already wiped
// custom_fields and the agent destination ceiling.
//
// TestUndecryptableMetadataIsNotOverwritten could not see either case, because
// it damages `notes` and asserts on `notes` and `name`, both of which are
// written AFTER the guard. A test whose request shape never includes the
// columns written first cannot detect a guard that runs too late.
func TestGuardRunsBeforeEveryWrite(t *testing.T) {
	corrupt := func(t *testing.T, h *VaultHandler, plain string) string {
		t.Helper()
		sealed, err := h.encryptColumn(plain)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		b := []byte(sealed)
		b[len(b)-3] ^= 0x01
		if _, decErr := h.decryptColumn(string(b), vaultFieldRotationTargets); decErr == nil {
			t.Fatal("ABORT: the corrupted blob still decrypts; the test would be vacuous")
		}
		return string(b)
	}

	// Case A: custom_fields IS the damaged column. The old guard read its own
	// fresh write here and returned 200.
	t.Run("damaged custom_fields is not silently replaced", func(t *testing.T) {
		h, queries := newCollectionAuthzEnv(t)
		ctx := context.Background()
		owner := mustUser(t, queries, "guardA@example.com", "user", "")
		mustEntry(t, h, queries, "entry-gA", owner, "A", "v")

		bad := corrupt(t, h, `[{"label":"recovery_pin","value":"998877","secret":true}]`)
		if err := queries.UpdateVaultEntryCustomFields(ctx, db.UpdateVaultEntryCustomFieldsParams{
			CustomFields: bad, ID: "entry-gA",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		// Exactly what the shipped edit form sends: custom_fields always included.
		rec := updateEntry(t, h, owner, "entry-gA", map[string]any{
			"name": "A", "notes": "typo fixed", "custom_fields": []any{},
		})
		if rec.Code != http.StatusConflict {
			t.Errorf("a save over damaged custom_fields returned %d, want 409: %s", rec.Code, rec.Body.String())
		}
		meta, err := queries.GetVaultEntryMeta(ctx, "entry-gA")
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if meta.CustomFields != bad {
			t.Errorf("the damaged custom_fields blob was replaced with %q; TOTP seeds and recovery PINs in it are unrecoverable now", meta.CustomFields)
		}
	})

	// Case B: a DIFFERENT column is damaged. The 409 must be literally true:
	// custom_fields and destination_patterns must be untouched.
	t.Run("409 nothing-was-changed is true for the columns written first", func(t *testing.T) {
		h, queries := newCollectionAuthzEnv(t)
		ctx := context.Background()
		owner := mustUser(t, queries, "guardB@example.com", "user", "")
		mustEntry(t, h, queries, "entry-gB", owner, "B", "v")

		goodCF, err := h.encryptColumn(`[{"label":"pin","value":"1234","secret":true}]`)
		if err != nil {
			t.Fatalf("seal cf: %v", err)
		}
		if err := queries.UpdateVaultEntryCustomFields(ctx, db.UpdateVaultEntryCustomFieldsParams{
			CustomFields: goodCF, ID: "entry-gB",
		}); err != nil {
			t.Fatalf("seed cf: %v", err)
		}
		if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
			DestinationPatterns: `["api.stripe.com/v1/*"]`, ID: "entry-gB",
		}); err != nil {
			t.Fatalf("seed dp: %v", err)
		}
		badNotes := corrupt(t, h, "runbook")
		if err := queries.UpdateVaultEntryNotes(ctx, db.UpdateVaultEntryNotesParams{
			Notes: toNullString(badNotes), ID: "entry-gB",
		}); err != nil {
			t.Fatalf("seed notes: %v", err)
		}

		rec := updateEntry(t, h, owner, "entry-gB", map[string]any{
			"name": "B", "notes": "", "custom_fields": []any{},
			"destination_patterns": []any{"evil.example.com/*"},
		})
		if rec.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
		}

		meta, err := queries.GetVaultEntryMeta(ctx, "entry-gB")
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if meta.CustomFields != goodCF {
			t.Error(`the 409 said "nothing was changed" but custom_fields was already wiped`)
		}
		if meta.DestinationPatterns != `["api.stripe.com/v1/*"]` {
			t.Errorf(`the 409 said "nothing was changed" but the agent destination ceiling became %q; `+
				"an operator who saw the refusal has silently changed which hosts an agent token can reach",
				meta.DestinationPatterns)
		}
	})
}

// TestRejectedRenameLeavesEverythingUntouched locks the atomicity of Update.
//
// Update writes each column with its own statement, so a validation that runs
// late used to reject the request AFTER earlier writes had committed. The
// rename collision is the reachable case: the user renames an entry to a name
// already taken and pastes a new value in the same save. The server replaced
// custom_fields (destroying imported TOTP seeds and recovery PINs), wrote the
// new value, restamped last_rotated_at, then hit UNIQUE(user_id, name) and
// returned 409. The toast says the save was rejected and the still-open editor
// shows the old data, so nothing tells the user their secrets are gone.
//
// The comment on the name block claimed it ran FIRST precisely so this could not
// happen. It was third.
func TestRejectedRenameLeavesEverythingUntouched(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "atomic@example.com", "user", "")

	mustEntry(t, h, queries, "atomic-a", owner, "GitHub", "ORIGINAL-TOKEN")
	mustEntry(t, h, queries, "atomic-b", owner, "GitHub Deploy", "OTHER")

	cf, err := h.encryptColumn(`[{"label":"totp","value":"JBSWY3DPEHPK3PXP","secret":true}]`)
	if err != nil {
		t.Fatalf("seal custom fields: %v", err)
	}
	if err := queries.UpdateVaultEntryCustomFields(ctx, db.UpdateVaultEntryCustomFieldsParams{
		CustomFields: cf, ID: "atomic-a",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := queries.GetVaultEntryMeta(ctx, "atomic-a")
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	// Rename onto the taken name AND supply a new value, the way the edit form
	// submits the whole form at once.
	rec := updateEntry(t, h, owner, "atomic-a", map[string]any{
		"name": "GitHub Deploy", "value": "BRAND-NEW-TOKEN", "custom_fields": []any{},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for the name collision, got %d: %s", rec.Code, rec.Body.String())
	}

	after, err := queries.GetVaultEntryMeta(ctx, "atomic-a")
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if after.CustomFields != before.CustomFields {
		t.Error("the rejected save destroyed custom_fields; the TOTP seed is unrecoverable")
	}
	if after.Name != before.Name {
		t.Errorf("the rejected rename was applied anyway: %q", after.Name)
	}
	if after.LastRotatedAt != before.LastRotatedAt {
		t.Error("the rejected save restamped last_rotated_at, so the entry now looks freshly rotated")
	}

	// The secret value must be the original one.
	entries, err := queries.ListVaultEntriesWithSecrets(ctx, owner)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, e := range entries {
		if e.ID != "atomic-a" {
			continue
		}
		plain, dErr := h.openForTest(e.EncryptedValue, e.Nonce)
		if dErr != nil {
			t.Fatalf("decrypt: %v", dErr)
		}
		if !plain.EqualsString("ORIGINAL-TOKEN") {
			t.Errorf("the rejected save replaced the secret value (len %d)", plain.Len())
		}
	}
}

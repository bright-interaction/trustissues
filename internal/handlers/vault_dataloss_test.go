package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
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
	if meta.Name != "GCP" {
		t.Errorf("name changed to %q despite the conflict", meta.Name)
	}
	// The other field in the same request must NOT have landed: a refused
	// request has to be all-or-nothing, or the operator is left guessing which
	// half applied.
	if notes := h.decryptColumnOrLog(meta.Notes.String, "", "notes"); notes == "changed-notes" {
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
	if meta.Name != "Real name" {
		t.Errorf("name was blanked to %q", meta.Name)
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
	if _, decErr := h.decryptColumn(string(body)); decErr == nil {
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
	if meta.Name != "Damaged" {
		t.Errorf("the refused request still applied the rename: name = %q", meta.Name)
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
	entry := parseRecordByFormat(headers, record, FormatBitwarden)
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
	lp := parseRecordByFormat(
		[]string{"name", "url", "username", "password", "totp"},
		[]string{"Bank", "https://bank.example", "u", "p", "JBSWY3DPEHPK3PXP"},
		FormatLastPass)
	if lp == nil || len(lp.CustomFields) == 0 {
		t.Error("the LastPass TOTP column was dropped")
	}
}

package handlers

import (
	"strings"
	"testing"
)

// An import must never lose a row silently, at the PARSER layer.
//
// TestImportReportsEveryDroppedRow (vault_import_skip_test.go) covers the same property
// one layer down, in ImportConfirm, and it does so structurally by reading the source.
// Neither it nor anything else covered parseRecordByFormat, which drops rows BEFORE the
// preview is ever built, so the two guards are complements rather than duplicates. This
// one is behavioural, because a structural check cannot see whether a reported skip
// actually reaches the operator.
//
// Every count shown is computed AFTER the parser drops rows, so the numbers alone can
// never reveal a loss: a Bitwarden export of 500 items containing 120 secure notes
// previewed as 380 entries, imported 380, and showed a plain success toast,
// indistinguishable from a clean export of 380. A secure note keeps its content in the
// notes field, so those are secrets the operator believed they had migrated, right
// before the documented next step of deleting the plaintext export.
//
// The old parser test asserted `want 1 (non-login skipped)` and nothing about
// reporting, so it PINNED the silence as correct. Fixing this required deleting a
// passing assertion, which is worth recording: a guard can be worse than no guard.
func TestImportReportsRowsDroppedByTheParser(t *testing.T) {
	vh, _ := newCollectionAuthzEnv(t)
	h := NewVaultImportHandler(vh.db, vh)

	const csvData = "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password\n" +
		",,login,Site A,,,https://a.example,user-a,pass-a\n" +
		",,note,Recovery Codes,8 backup codes here,,,,\n" +
		",,card,Company Amex,,,,,\n" +
		",,identity,Passport,,,,,\n"

	entries, skipped, err := h.parseCSV(strings.NewReader(csvData), FormatBitwarden)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if len(skipped) != 3 {
		t.Fatalf("got %d reported skips, want 3 (note, card, identity).\n"+
			"A row the parser drops with nothing recording it is invisible at every layer "+
			"above: total is the post-drop count, so nothing can tell the operator that "+
			"part of their export did not arrive.", len(skipped))
	}

	// Each skip must NAME the row, or the operator cannot find it in their export.
	byName := map[string]string{}
	for _, s := range skipped {
		byName[s.Name] = s.Reason
	}
	for _, want := range []string{"Recovery Codes", "Company Amex", "Passport"} {
		reason, ok := byName[want]
		if !ok {
			t.Errorf("dropped row %q was not named in the report: %+v", want, skipped)
			continue
		}
		if reason == "" {
			t.Errorf("dropped row %q was reported with no reason", want)
		}
	}
}

// The reported reason must match the branch that was actually taken.
//
// Both causes reported "no password value in the export row (secure notes, cards and
// identities have none)". A row that HAD a password and merely lacked a name was
// therefore explained as a secure note, which sends the operator looking in the wrong
// place in their export for the one problem they could have fixed in a minute.
func TestSkipReasonNamesTheRealCause(t *testing.T) {
	cases := []struct {
		name        string
		entry       ImportEntry
		wantPhrase  string
		wrongPhrase string
	}{
		{
			name:        "has a password but no name",
			entry:       ImportEntry{Name: "", Value: "hunter2"},
			wantPhrase:  "no name",
			wrongPhrase: "no password value",
		},
		{
			name:       "has a name but no password",
			entry:      ImportEntry{Name: "Secure Note", Value: ""},
			wantPhrase: "no password value",
		},
		{
			name:       "has neither",
			entry:      ImportEntry{Name: "", Value: ""},
			wantPhrase: "neither a name nor a password",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := importSkipReason(tc.entry)
			if !strings.Contains(got, tc.wantPhrase) {
				t.Errorf("reason %q does not mention %q", got, tc.wantPhrase)
			}
			if tc.wrongPhrase != "" && strings.Contains(got, tc.wrongPhrase) {
				t.Errorf("reason %q blames %q, which is not why this row was dropped",
					got, tc.wrongPhrase)
			}
		})
	}
}

// Import enforces the same field rules as the other two write paths.
//
// It enforced none of them, so a legitimate CSV could write a row the edit form could
// never save: Update re-validates on every save and the form resubmits every field, so
// an over-length name came back 400 about a field the operator had not touched. An
// untrimmed name additionally defeats checkConflicts (it compares raw names) and
// UNIQUE(user_id, name), since "GitHub" and "GitHub " are different strings to both.
func TestImportEnforcesTheSameFieldRulesAsCreate(t *testing.T) {
	long := strings.Repeat("a", maxEntryNameLen+1)
	cases := []struct {
		name   string
		fields vaultEntryFields
		wantOK bool
	}{
		{"an over-length name is refused", vaultEntryFields{Name: long, Value: "v"}, false},
		{"an over-length value is refused", vaultEntryFields{Name: "n", Value: strings.Repeat("v", maxEntryValueLen+1)}, false},
		{"an over-length url is refused", vaultEntryFields{Name: "n", Value: "v", URL: strings.Repeat("u", maxEntryURLLen+1)}, false},
		{"a normal row is accepted", vaultEntryFields{Name: "GitHub", Value: "hunter2"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.fields
			msg := normalizeAndValidateEntryFields(&f)
			if tc.wantOK && msg != "" {
				t.Errorf("a legitimate row was refused: %s", msg)
			}
			if !tc.wantOK && msg == "" {
				t.Error("an invalid row was accepted, so import can write a row the edit form " +
					"will refuse to save")
			}
		})
	}

	// Trimming has to happen, or conflict detection and UNIQUE see different
	// strings than the database does.
	f := vaultEntryFields{Name: "  GitHub  ", Value: "v", Username: "  octocat "}
	if msg := normalizeAndValidateEntryFields(&f); msg != "" {
		t.Fatalf("unexpected refusal: %s", msg)
	}
	if f.Name != "GitHub" || f.Username != "octocat" {
		t.Errorf("fields were not trimmed: %+v", f)
	}
}

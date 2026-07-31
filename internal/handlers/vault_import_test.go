package handlers

import (
	"strings"
	"testing"
)

// TestDetectFormat proves header-based format detection for the three
// supported password managers plus the unknown fallback.
func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name     string
		headers  []string
		expected PasswordManagerFormat
	}{
		{"1password", []string{"Title", "Website", "Username", "Password", "Notes"}, Format1Password},
		{"bitwarden", []string{"folder", "favorite", "type", "name", "notes", "fields", "login_uri", "login_username", "login_password", "login_totp"}, FormatBitwarden},
		{"lastpass", []string{"url", "username", "password", "extra", "name", "grouping", "fav"}, FormatLastPass},
		{"unknown", []string{"a", "b", "c"}, FormatUnknown},
	}
	for _, tc := range cases {
		if got := detectFormat(tc.headers); got != tc.expected {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.expected)
		}
	}
}

// TestParseCSVFormats exercises full CSV parsing per format, including quoted
// fields and the Bitwarden non-login skip.
func TestParseCSVFormats(t *testing.T) {
	h := &VaultImportHandler{}

	t.Run("1password", func(t *testing.T) {
		csvData := "Title,Website,Username,Password,Notes\n" +
			"GitHub,https://github.com,octocat,hunter2,\"my, note\"\n"
		entries, _, err := h.parseCSV(strings.NewReader(csvData), Format1Password)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("got %d entries, want 1", len(entries))
		}
		e := entries[0]
		if e.Name != "GitHub" || e.URL != "https://github.com" || e.Username != "octocat" || e.Value != "hunter2" || e.Notes != "my, note" {
			t.Fatalf("bad entry: %+v", e)
		}
	})

	t.Run("bitwarden skips non-login", func(t *testing.T) {
		csvData := "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password\n" +
			",,login,Site A,,,https://a.example,user-a,pass-a\n" +
			",,note,Secure Note,,,,,\n"
		entries, skipped, err := h.parseCSV(strings.NewReader(csvData), FormatBitwarden)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("got %d entries, want 1", len(entries))
		}
		if entries[0].Name != "Site A" || entries[0].Value != "pass-a" {
			t.Fatalf("bad entry: %+v", entries[0])
		}
		// The non-login row must be REPORTED, not silently dropped.
		//
		// This used to assert `want 1 (non-login skipped)` and nothing else,
		// which pinned the silence as correct behaviour: the row vanished in the
		// parser, `total` is computed after the drop, and a 500-item export with
		// 120 secure notes was indistinguishable from a clean export of 380. A
		// secure note carries its content in the notes field, so those are
		// secrets the operator believed they had migrated.
		if len(skipped) != 1 {
			t.Fatalf("got %d reported skips, want 1; a dropped row that nothing reports is "+
				"invisible at every layer above this one", len(skipped))
		}
		if skipped[0].Name != "Secure Note" {
			t.Errorf("the skip does not name the row: %+v", skipped[0])
		}
		if !strings.Contains(skipped[0].Reason, "note") {
			t.Errorf("the reason does not say what kind of item was dropped: %+v", skipped[0])
		}
	})

	t.Run("lastpass", func(t *testing.T) {
		csvData := "url,username,password,extra,name,grouping,fav\n" +
			"https://b.example,user-b,pass-b,extra note,Site B,Work,0\n"
		entries, _, err := h.parseCSV(strings.NewReader(csvData), FormatLastPass)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("got %d entries, want 1", len(entries))
		}
		e := entries[0]
		if e.Name != "Site B" || e.URL != "https://b.example" || e.Username != "user-b" || e.Value != "pass-b" || e.Notes != "extra note" {
			t.Fatalf("bad entry: %+v", e)
		}
	})

	t.Run("mismatched column count errors", func(t *testing.T) {
		csvData := "url,username,password,extra,name,grouping,fav\n" +
			"only,two\n"
		if _, _, err := h.parseCSV(strings.NewReader(csvData), FormatLastPass); err == nil {
			t.Fatal("expected error on mismatched columns")
		}
	})
}

// TestContainsAllAndGetFirstField covers the small parsing helpers.
func TestContainsAllAndGetFirstField(t *testing.T) {
	if !containsAll("title,website,username,password", []string{"title", "password"}) {
		t.Fatal("containsAll false negative")
	}
	if containsAll("title,website", []string{"password"}) {
		t.Fatal("containsAll false positive")
	}
	fields := map[string]string{"title": "", "name": "fallback"}
	if got := getFirstField(fields, []string{"title", "name"}); got != "fallback" {
		t.Fatalf("getFirstField: got %q", got)
	}
	if got := getFirstField(fields, []string{"missing"}); got != "" {
		t.Fatalf("getFirstField on missing: got %q", got)
	}
}

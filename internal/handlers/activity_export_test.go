package handlers

import (
	"context"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
)

// TestActivityExportHonoursCategoryFilter locks the export twin of the category
// filter. The list endpoint learned "vault.*" but the export kept exact-matching,
// so choosing a category and clicking Export silently downloaded an EMPTY file.
// A filtered export that yields nothing with no error reads as "there is no such
// activity", which is the worst possible failure for an audit surface.
func TestActivityExportHonoursCategoryFilter(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	LogActivity(queries, nil, "vault.rotation_failed", "a")
	LogActivity(queries, nil, "vault.entry_created", "b")
	LogActivity(queries, nil, "auth.login", "c")

	exp := func(filter string) int {
		t.Helper()
		rows, err := queries.ExportActivityEntries(ctx, db.ExportActivityEntriesParams{
			UserFilter:   "",
			ActionFilter: exportExactAction(filter),
			ActionPrefix: exportPrefixAction(filter),
		})
		if err != nil {
			t.Fatalf("export %q: %v", filter, err)
		}
		return len(rows)
	}

	if n := exp("vault.*"); n != 2 {
		t.Fatalf("category export returned %d rows, want 2 (an empty file reads as 'no such activity')", n)
	}
	if n := exp("auth.login"); n != 1 {
		t.Fatalf("exact export returned %d rows, want 1", n)
	}
	if n := exp("nomatch.*"); n != 0 {
		t.Fatalf("non-matching category returned %d rows, want 0", n)
	}
	if n := exp(""); n != 3 {
		t.Fatalf("unfiltered export returned %d rows, want 3", n)
	}
}

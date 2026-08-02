package handlers

import (
	"context"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
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

// TestActivityListAndExportAgree locks the two surfaces together.
//
// The list endpoint used a switch whose first arm was "a user is selected", so
// combining a user with an action filter silently dropped the action half. The
// export twin already combined them, so the table and the CSV of the SAME view
// returned different rows. For an audit surface, two disagreeing answers is
// worse than one wrong answer, because neither can be trusted.
func TestActivityListAndExportAgree(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	alice := mustUser(t, queries, "agree-alice@example.com", "admin", "")
	bob := mustUser(t, queries, "agree-bob@example.com", "user", "")

	seed := func(user, action string) {
		LogActivity(queries, &user, action, "x")
	}
	seed(alice, "vault.entry_created")
	seed(alice, "vault.entry_updated")
	seed(alice, "admin.user_created")
	seed(bob, "vault.entry_created")

	const prefix = "vault."
	n, err := queries.CountActivityEntriesFiltered(ctx, db.CountActivityEntriesFilteredParams{
		UserFilter: alice, ActionFilter: "", ActionPrefix: prefix,
	})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("user+category filter returned %d rows, want 2; the action filter is being dropped", n)
	}

	exported, err := queries.ExportActivityEntries(ctx, db.ExportActivityEntriesParams{
		UserFilter: alice, ActionFilter: "", ActionPrefix: prefix,
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if int64(len(exported)) != n {
		t.Errorf("the table shows %d rows and the export returns %d for the same filters", n, len(exported))
	}
}

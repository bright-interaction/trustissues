package handlers

import (
	"context"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestActivityCategoryFilterActuallyFilters locks the fix for the dead category
// filters.
//
// The Activity page has always offered "vault.*" style options, but the only
// filter query was `WHERE action = ?`, so selecting one sent the literal string
// "vault.*", matched nothing, and rendered an empty table. Anyone checking
// whether a rotation failure had been recorded by filtering for its category
// would conclude it never happened.
func TestActivityCategoryFilterActuallyFilters(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	LogActivity(queries, nil, "vault.rotation_failed", "rotation blew up")
	LogActivity(queries, nil, "vault.entry_created", "made a thing")
	LogActivity(queries, nil, "auth.login", "signed in")

	pattern := likePrefixPattern("vault.")

	n, err := queries.CountActivityEntriesByActionPrefix(ctx, pattern)
	if err != nil {
		t.Fatalf("count by prefix: %v", err)
	}
	if n != 2 {
		t.Fatalf("vault.* matched %d rows, want 2 (the filter is not filtering)", n)
	}

	rows, err := queries.ListActivityEntriesByActionPrefix(ctx, db.ListActivityEntriesByActionPrefixParams{
		Action: pattern, Limit: 50, Offset: 0,
	})
	if err != nil {
		t.Fatalf("list by prefix: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("listed %d rows, want 2", len(rows))
	}
	for _, r := range rows {
		if !strings.HasPrefix(r.Action, "vault.") {
			t.Fatalf("prefix filter returned an unrelated action: %q", r.Action)
		}
	}

	// The exact-match filter must still work, so a specific action stays
	// selectable.
	exact, err := queries.CountActivityEntriesByAction(ctx, "auth.login")
	if err != nil || exact != 1 {
		t.Fatalf("exact filter broke: %d rows (err %v)", exact, err)
	}
}

// TestLikePrefixPatternCannotBeWidened guards the escaping.
//
// The filter value arrives on the query string. Without escaping, a `%` in it
// is a SQL LIKE wildcard, so a caller could pass "%" and match every row while
// the UI claims a narrow category is selected. A filter that quietly means
// something other than what it says is a bug even when, as here, the endpoint
// is admin-only and the rows are already visible to that caller.
func TestLikePrefixPatternCannotBeWidened(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	LogActivity(queries, nil, "vault.entry_created", "a")
	LogActivity(queries, nil, "auth.login", "b")

	// A bare "%" must be treated as a literal, matching nothing, not as
	// "everything".
	n, err := queries.CountActivityEntriesByActionPrefix(ctx, likePrefixPattern("%"))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("a literal %% matched %d rows: the wildcard was not escaped and the filter can be widened", n)
	}

	// "_" is LIKE's single-character wildcard; it must not match "a" either.
	if n, err = queries.CountActivityEntriesByActionPrefix(ctx, likePrefixPattern("_")); err != nil {
		t.Fatalf("count: %v", err)
	} else if n != 0 {
		t.Fatalf("a literal _ matched %d rows: single-char wildcard not escaped", n)
	}

	// And a genuine prefix still works after escaping.
	if n, err = queries.CountActivityEntriesByActionPrefix(ctx, likePrefixPattern("auth.")); err != nil {
		t.Fatalf("count: %v", err)
	} else if n != 1 {
		t.Fatalf("escaping broke a legitimate prefix: %d rows, want 1", n)
	}
}

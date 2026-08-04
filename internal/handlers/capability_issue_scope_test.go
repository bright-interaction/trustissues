package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestIssueIsCollectionScoped drives the Issue HANDLER, not the lookup helpers.
//
// This distinction is the whole point of the test. Round 3 widened
// lookupSecretByName/ByDestination to accessibleEntriesPredicate and its own
// comment claimed it had fixed "a current viewer or editor of a collection could
// NOT mint for a shared secret they legitimately have access to". It had not.
// Behind the widened lookup sat a second, independent ACL (agentCanUse) still
// ending in `vault_entries WHERE id = ? AND user_id = ?`, so a fellow member
// resolved the entry and was then refused 403 agent_not_granted.
//
// TestCapabilityLookupIsCollectionScoped passed throughout, because it calls the
// lookup helpers directly and never reaches the ACL. A test that stops at the
// first authorization gate cannot see the second one. Both gates are exercised
// here through the real HTTP entry point.
//
// The failure it locks is not a leak, it is the headline feature being dead: on
// a shared team vault, "let an agent use a secret it never sees" worked only for
// whoever happened to create each entry, and the grant its error message asks
// for has no writer anywhere in the codebase.
func TestIssueIsCollectionScoped(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "issue-creator@example.com", "user", "")
	editor := mustUser(t, queries, "issue-editor@example.com", "user", "")
	viewer := mustUser(t, queries, "issue-viewer@example.com", "user", "")
	removed := mustUser(t, queries, "issue-removed@example.com", "user", "")
	stranger := mustUser(t, queries, "issue-stranger@example.com", "user", "")

	mustCollection(t, queries, "coll-issue", creator, map[string]string{
		creator: collRoleManager,
		editor:  collRoleEditor,
		viewer:  collRoleViewer,
		removed: collRoleEditor,
	})
	const entryID = "entry-issue-shared"
	mustEntry(t, h, queries, entryID, creator, "Issue shared key", "sk_live_ISSUE")
	placeInCollection(t, queries, entryID, "coll-issue")
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["api.stripe.com/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("seed ceiling: %v", err)
	}

	capH := setupCapabilityHandler(t, h.db)

	// NOTE: the request field is "secret", not "name". An earlier version of this
	// test sent "name", which json silently ignored, so every request resolved
	// through destination auto-routing instead of the by-name lookup. It still
	// exercised agentCanUse (which is what this test is for, and it did fail
	// correctly at 403 before that fix), but it was not testing the path its own
	// body implied. Both paths are driven explicitly below.
	issueAs := func(t *testing.T, userID string) (int, string) {
		t.Helper()
		body := `{"agent_id":"agent-test","secret":"Issue shared key","destination":"api.stripe.com/v1/charges","method":"POST"}`
		r := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), middleware.UserIDKey, userID))
		w := httptest.NewRecorder()
		capH.Issue(w, r)
		return w.Code, w.Body.String()
	}

	issueByDestination := func(t *testing.T, userID string) (int, string) {
		t.Helper()
		body := `{"agent_id":"agent-test","destination":"api.stripe.com/v1/charges","method":"POST"}`
		r := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), middleware.UserIDKey, userID))
		w := httptest.NewRecorder()
		capH.Issue(w, r)
		return w.Code, w.Body.String()
	}

	// Guard the setup. If the creator cannot mint, every assertion below would
	// pass for the wrong reason and the test would be vacuous.
	if code, body := issueAs(t, creator); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("ABORT: the entry's creator cannot mint by name (%d): %s", code, body)
	}
	if code, body := issueByDestination(t, creator); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("ABORT: the entry's creator cannot mint by destination (%d): %s", code, body)
	}

	// The regression. Each of these resolved the entry fine and was then refused
	// by the ownership ACL behind the lookup.
	for _, tc := range []struct {
		who, role string
	}{
		{editor, "editor"},
		{viewer, "viewer"},
	} {
		code, body := issueAs(t, tc.who)
		if code != http.StatusOK && code != http.StatusCreated {
			t.Errorf("a current collection %s cannot mint for a shared secret (%d): %s\n"+
				"list_secrets advertises this name to them and there is no way to create the grant the error asks for",
				tc.role, code, body)
			continue
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil || out.Token == "" {
			t.Errorf("%s got %d but no usable token: %s", tc.role, code, body)
		}
		if dCode, dBody := issueByDestination(t, tc.who); dCode != http.StatusOK && dCode != http.StatusCreated {
			t.Errorf("a current collection %s cannot mint by destination either (%d): %s", tc.role, dCode, dBody)
		}
	}

	// The other direction must still hold: removing a member ends minting.
	// This is the property three earlier rounds closed, and widening the ACL
	// must not have reopened it.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-issue", UserID: removed,
	}); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if code, body := issueAs(t, removed); code == http.StatusOK || code == http.StatusCreated {
		t.Errorf("a REMOVED collection member still minted a token (%d): %s\n"+
			"rotation is the documented revocation step and it would inject the post-rotation value for them", code, body)
	}

	// And a complete outsider never had access at all.
	if code, body := issueAs(t, stranger); code == http.StatusOK || code == http.StatusCreated {
		t.Errorf("a non-member minted a token for a collection secret (%d): %s", code, body)
	}
}

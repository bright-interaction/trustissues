package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestManagerCanRenameAnEntryStrandedByItsCreator covers the rule chosen for
// collection managers, and proves it did not reopen the oracle it sits next to.
//
// Closing the rename oracle by refusing every non-owner also froze the name of a
// shared entry the moment its creator left the collection: the name is the
// lookup key for service_identities.allowed_secrets and MCP use_secret, and only
// an instance admin could fix a typo in it. A manager should be able to.
//
// The rule (see VaultHandler.Update): a manager may rename an entry whose
// creator has left the collection, and that rename ADOPTS the entry. Adoption is
// what makes it safe. Writing user_id and name in one statement moves the
// UNIQUE(user_id, name) question into the manager's own namespace, so the
// creator's private vault is never consulted and the answer cannot be read as
// "the creator holds that name". It is unconditional on this path, never a
// fallback after a conflict, because a conditional adoption would be the same
// oracle with a slower clock.
func TestManagerCanRenameAnEntryStrandedByItsCreator(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "creator@client-b.example", "user", "")
	manager := mustUser(t, queries, "manager@client-a.example", "user", "")

	mustCollection(t, queries, "coll-team", creator, map[string]string{
		creator: collRoleEditor,
		manager: collRoleManager,
	})

	const sharedID = "entry-team-ci"
	mustEntry(t, h, queries, sharedID, creator, "ci-token", "value-1")
	placeInCollection(t, queries, sharedID, "coll-team")

	// The creator's PRIVATE entry. Nobody else has a read path to it, and its
	// name is what a rename could otherwise probe for.
	mustEntry(t, h, queries, "entry-private", creator, "Acme prod DB", "creator-only")

	rename := func(who, role, name string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+sharedID, who, role, sharedID,
			`{"name":"`+name+`"}`))
		return rec
	}

	// While the creator is still on the team, the manager is refused, and the
	// refusal says the same thing whether or not the creator holds that name.
	t.Run("refused while the creator is still a member", func(t *testing.T) {
		hit := rename(manager, "user", "Acme prod DB")
		miss := rename(manager, "user", "Nothing Named This Anywhere")
		if hit.Code != miss.Code || hit.Body.String() != miss.Body.String() {
			t.Fatalf("a manager's rename answer depends on the creator's PRIVATE vault:\n"+
				"  name the creator holds privately: HTTP %d %s\n"+
				"  name nobody holds:                HTTP %d %s",
				hit.Code, strings.TrimSpace(hit.Body.String()), miss.Code, strings.TrimSpace(miss.Body.String()))
		}
		if hit.Code != http.StatusForbidden {
			t.Fatalf("want 403 while the creator can rename it themselves, got HTTP %d: %s", hit.Code, hit.Body.String())
		}
		if got, _ := queries.GetVaultEntryName(ctx, sharedID); got != "ci-token" {
			t.Fatalf("the entry was renamed anyway: %q", got)
		}
	})

	// The creator leaves. The entry is now stranded: nobody in the collection
	// owns it, and before this rule its name could never be corrected again.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-team", UserID: creator,
	}); err != nil {
		t.Fatalf("creator leaves: %v", err)
	}

	t.Run("the manager can rename it once the creator has left", func(t *testing.T) {
		rec := rename(manager, "user", "ci-token-prod")
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("manager rename of a stranded entry: HTTP %d: %s", rec.Code, rec.Body.String())
		}
		got, err := queries.GetVaultEntryName(ctx, sharedID)
		if err != nil || got != "ci-token-prod" {
			t.Fatalf("the rename did not take: name = %q err = %v", got, err)
		}
		// Adoption: the manager is now the owner, and the entry stayed in the
		// collection (moving it out is a different, separately authorized act).
		access, err := queries.GetVaultEntryAccess(ctx, sharedID)
		if err != nil {
			t.Fatalf("read entry back: %v", err)
		}
		if access.UserID != manager {
			t.Errorf("the renaming manager should own the entry now, owner = %q", access.UserID)
		}
		if !access.CollectionID.Valid || access.CollectionID.String != "coll-team" {
			t.Errorf("adoption must not move the entry out of the collection, got %+v", access.CollectionID)
		}
	})

	// The property that makes adoption safe: the rename does not consult the
	// departed creator's namespace at all, so a name they hold PRIVATELY is
	// accepted exactly like any other. Without adoption this write hits
	// UNIQUE(creator, name) and answers "that name is taken", which is the
	// oracle read one guess at a time.
	t.Run("a name the departed creator holds privately is not an oracle", func(t *testing.T) {
		rec := rename(manager, "user", "Acme prod DB")
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("renaming to a name the CREATOR holds privately answered HTTP %d: %s\n"+
				"that answer is a read of their private vault", rec.Code, rec.Body.String())
		}
		if got, _ := queries.GetVaultEntryName(ctx, sharedID); got != "Acme prod DB" {
			t.Fatalf("the rename did not take: %q", got)
		}
		// And the creator's own entry is untouched: adoption renames the shared
		// entry, it does not reach into anyone else's vault.
		if got, err := queries.GetVaultEntryName(ctx, "entry-private"); err != nil || got != "Acme prod DB" {
			t.Fatalf("the creator's private entry changed: %q err = %v", got, err)
		}
	})

	t.Run("a conflict inside the manager's own namespace is still reported honestly", func(t *testing.T) {
		// A SECOND stranded entry, so the adopt path runs again (the first one
		// is now owned by the manager, which takes the ordinary owner branch).
		const secondID = "entry-team-deploy"
		mustEntry(t, h, queries, secondID, creator, "deploy-key", "value-2")
		placeInCollection(t, queries, secondID, "coll-team")
		mustEntry(t, h, queries, "entry-mgr-personal", manager, "my-own-thing", "v")

		rec := httptest.NewRecorder()
		h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+secondID, manager, "user", secondID,
			`{"name":"my-own-thing"}`))
		if rec.Code != http.StatusConflict {
			t.Fatalf("adopting onto the manager's OWN existing name: HTTP %d, want 409: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "already have") {
			t.Errorf("the manager's conflict should name their own entry, got %s", rec.Body.String())
		}
		// The refused adoption must leave the entry exactly as it was: name and
		// owner both unchanged, or a failed rename would still dispossess.
		access, err := queries.GetVaultEntryAccess(ctx, secondID)
		if err != nil {
			t.Fatalf("read entry back: %v", err)
		}
		if access.UserID != creator {
			t.Errorf("a refused adoption changed the owner to %q", access.UserID)
		}
		if got, _ := queries.GetVaultEntryName(ctx, secondID); got != "deploy-key" {
			t.Errorf("a refused adoption changed the name to %q", got)
		}
	})

	t.Run("an editor still cannot rename a stranded entry", func(t *testing.T) {
		editor := mustUser(t, queries, "editor@client-a.example", "user", "")
		if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
			CollectionID: "coll-team", UserID: editor, Role: collRoleEditor,
			AcceptedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}); err != nil {
			t.Fatalf("add editor: %v", err)
		}
		rec := rename(editor, "user", "editor-renamed-this")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("an editor renamed a shared entry: HTTP %d: %s", rec.Code, rec.Body.String())
		}
	})
}

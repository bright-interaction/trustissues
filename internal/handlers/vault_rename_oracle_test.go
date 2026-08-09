package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRenameDoesNotProbeTheOwnersPrivateVault locks the fix for an existence
// oracle over another user's personal vault.
//
// vault_entries carries UNIQUE(user_id, name) and a shared entry keeps its
// CREATOR's user_id forever, so renaming a shared entry ran a uniqueness check
// against the creator's namespace. An editor in the collection has no read path
// to that namespace, but they could read it one name at a time:
//
//	PUT /api/vault/{shared}  {"name":"AWS root"}
//	  -> 409 "a vault entry with that name already exists"  = the creator has it
//	  -> 204                                                 = the creator does not
//
// On a shared instance the creator is another client, and their private entry
// names are things like "Acme prod DB" or "Client X Stripe live". The answer
// leaks the relationship even though the secret never does.
//
// The invariant: the response to a non-owner's rename is the SAME whether or not
// the owner privately holds that name (it is decided without consulting their
// vault at all), while the owner still gets the useful duplicate-name feedback
// for entries they can see, and everything else on a shared entry stays
// editable.
func TestRenameDoesNotProbeTheOwnersPrivateVault(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	owner := mustUser(t, queries, "owner@client-b.example", "user", "")
	attacker := mustUser(t, queries, "editor@client-a.example", "user", "")

	mustCollection(t, queries, "coll-shared", owner, map[string]string{
		owner:    collRoleManager,
		attacker: collRoleEditor,
	})

	// The shared entry the attacker legitimately has write access to.
	const sharedID = "entry-shared"
	mustEntry(t, h, queries, sharedID, owner, "shared-ci-token", "value-1")
	placeInCollection(t, queries, sharedID, "coll-shared")

	// The owner's PRIVATE entry. The attacker has no read path to it: it is not
	// in any collection, and they are not its owner.
	mustEntry(t, h, queries, "entry-private", owner, "Acme prod DB", "owner-only-value")

	rename := func(who, role, entryID, name string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+entryID, who, role, entryID,
			`{"name":"`+name+`"}`))
		return rec
	}

	// The probe: a name the owner DOES hold privately, and one nobody holds.
	// These two must be indistinguishable, which is the whole property.
	hit := rename(attacker, "user", sharedID, "Acme prod DB")
	miss := rename(attacker, "user", sharedID, "Nothing Named This Anywhere")
	if hit.Code != miss.Code || hit.Body.String() != miss.Body.String() {
		t.Fatalf("the rename answer depends on the owner's PRIVATE vault, which is the oracle:\n"+
			"  name the owner holds privately: HTTP %d %s\n"+
			"  name nobody holds:              HTTP %d %s",
			hit.Code, strings.TrimSpace(hit.Body.String()), miss.Code, strings.TrimSpace(miss.Body.String()))
	}
	if hit.Code != http.StatusForbidden {
		t.Fatalf("a non-owner rename should be refused outright, got HTTP %d: %s", hit.Code, hit.Body.String())
	}
	if strings.Contains(hit.Body.String(), "already exists") {
		t.Errorf("the refusal still asserts the name is taken: %s", hit.Body.String())
	}

	// Nothing was renamed by either attempt.
	if got := entryNamePlain(t, h, queries, sharedID); got != "shared-ci-token" {
		t.Fatalf("the entry was renamed anyway: %q", got)
	}

	// An editor must still be able to edit everything else on a shared entry,
	// including saving the form with the name field unchanged (the edit form
	// resubmits every field, so refusing that would break shared editing).
	t.Run("editor can still save a shared entry with its name unchanged", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+sharedID, attacker, "user", sharedID,
			`{"name":"shared-ci-token","notes":"rotated by the CI runbook"}`))
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("editor could not save the shared entry: HTTP %d: %s", rec.Code, rec.Body.String())
		}
	})

	// And the owner keeps the genuinely useful duplicate-name feedback, because
	// for them the conflicting entry is one they can already see.
	t.Run("owner still gets duplicate-name feedback", func(t *testing.T) {
		rec := rename(owner, "user", sharedID, "Acme prod DB")
		if rec.Code != http.StatusConflict {
			t.Fatalf("owner renaming onto their own existing name: HTTP %d, want 409: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "already exists") {
			t.Errorf("the owner's conflict should say what is wrong, got %s", rec.Body.String())
		}
	})

	t.Run("owner can still rename to a free name", func(t *testing.T) {
		rec := rename(owner, "user", sharedID, "shared-ci-token-v2")
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("owner rename: HTTP %d: %s", rec.Code, rec.Body.String())
		}
		if got := entryNamePlain(t, h, queries, sharedID); got != "shared-ci-token-v2" {
			t.Fatalf("owner rename did not take: name = %q", got)
		}
	})

	t.Run("an instance admin can rename it, and sees every entry anyway", func(t *testing.T) {
		admin := mustUser(t, queries, "admin@client-b.example", "admin", "")
		rec := rename(admin, "admin", sharedID, "shared-ci-token-v3")
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("admin rename: HTTP %d: %s", rec.Code, rec.Body.String())
		}
	})
}

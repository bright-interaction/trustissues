package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestRemovedMemberCannotReadTargets closes the SEVENTH door onto the
// offboarding property, and this one is an actual leak rather than a stale
// config problem.
//
// GET /vault/{id}/targets gated on canRead. entryAccessFor deliberately grants
// a removed creator a residual READ, so they could keep pulling the entry's
// rotation targets after being removed from the collection: other members'
// webhook HMAC signing secrets and forgejo auth_token references, in plaintext,
// including targets configured after they left.
//
// The residual read exists so a creator can recover a secret they own when
// somebody moves it into a collection they are not in. Reading other people's
// delivery credentials is not that. Six earlier rounds closed removal, rotation
// delivery, capability minting, the shared gate, service identities and leaving;
// each one asked a different question of the same property.
func TestRemovedMemberCannotReadTargets(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "tgt-creator@example.com", "user", "")
	manager := mustUser(t, queries, "tgt-manager@example.com", "user", "")
	viewer := mustUser(t, queries, "tgt-viewer@example.com", "user", "")
	// PREMISE CHANGE, round 5. This target used to be configured by the collection
	// MANAGER, because manage was enough to name a delivery destination. It is not
	// any more: adding one is held to the same right as widening
	// destination_patterns, so the principals who can are the entry's creator and
	// an instance admin (see the note in VaultHandler.UpdateTargets).
	//
	// An admin configures it here rather than the creator, because the leak under
	// test is a removed member reading SOMEBODY ELSE'S delivery credentials. If
	// the creator configured it, the HMAC secret would be their own and reading it
	// back would prove nothing. An operator wiring up delivery on a team secret is
	// also what actually happens.
	operator := mustUser(t, queries, "tgt-operator@example.com", "admin", "")

	mustCollection(t, queries, "coll-tgt", manager, map[string]string{
		manager: collRoleManager,
		creator: collRoleEditor,
		viewer:  collRoleViewer,
	})
	const entryID = "entry-tgt"
	mustEntry(t, h, queries, entryID, creator, "Stripe", "sk_live_x")
	placeInCollection(t, queries, entryID, "coll-tgt")

	// A target configured by somebody ELSE, carrying an HMAC secret that exists
	// nowhere else.
	body := `[{"type":"webhook","label":"prod","webhook_url":"https://consumer.example.com/h","webhook_secret":"HMAC-SECRET-NOWHERE-ELSE"}]`
	rec := putTargets(t, h, operator, "admin", entryID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the admin could not set the target: %d %s", rec.Code, rec.Body.String())
	}

	get := func(userID, role string) (int, string) {
		rec := httptest.NewRecorder()
		h.GetTargets(rec, vaultAuthzRequest("GET", "/api/vault/"+entryID+"/targets", userID, role, entryID, ""))
		return rec.Code, rec.Body.String()
	}

	// Guard the setup: the creator is an editor, so they legitimately manage
	// targets right now. If not, the post-removal assertion proves nothing.
	if code, body := get(creator, "user"); code != http.StatusOK || !strings.Contains(body, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Fatalf("ABORT: an active editor cannot read targets (%d): %s", code, body)
	}

	// Remove them from the collection. They remain the entry's user_id, which is
	// exactly the state the residual read covers.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-tgt", UserID: creator,
	}); err != nil {
		t.Fatalf("remove: %v", err)
	}

	code, respBody := get(creator, "user")
	if code == http.StatusOK {
		t.Errorf("a REMOVED member still read the rotation targets (%d)", code)
	}
	if strings.Contains(respBody, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Error("a removed member harvested another member's webhook HMAC signing secret in plaintext")
	}

	// A plain viewer never had a reason to see other people's delivery
	// credentials either.
	if code, body := get(viewer, "user"); code == http.StatusOK && strings.Contains(body, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Error("a collection VIEWER can read another member's webhook HMAC secret")
	}

	// The legitimate case must still work, or this is a break not a fix. Both
	// halves: the admin who configured it, and a current manager of the
	// collection, who can READ delivery config even though round 5 stopped them
	// naming a new destination. Reading is how an operator answers "is that
	// webhook still receiving our key?", and taking it away would make the
	// offboarding story unauditable.
	if code, body := get(operator, "admin"); code != http.StatusOK || !strings.Contains(body, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Errorf("the admin can no longer read the targets they configured (%d): %s", code, body)
	}
	if code, body := get(manager, "user"); code != http.StatusOK || !strings.Contains(body, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Errorf("a current manager can no longer read the entry's targets (%d): %s", code, body)
	}
}

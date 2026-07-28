package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
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

	mustCollection(t, queries, "coll-tgt", manager, map[string]string{
		manager: collRoleManager,
		creator: collRoleEditor,
		viewer:  collRoleViewer,
	})
	const entryID = "entry-tgt"
	mustEntry(t, h, queries, entryID, creator, "Stripe", "sk_live_x")
	placeInCollection(t, queries, entryID, "coll-tgt")

	// A target configured by the MANAGER, carrying an HMAC secret that exists
	// nowhere else.
	body := `[{"type":"webhook","label":"prod","webhook_url":"https://consumer.example.com/h","webhook_secret":"HMAC-SECRET-NOWHERE-ELSE"}]`
	rec := httptest.NewRecorder()
	h.UpdateTargets(rec, vaultAuthzRequest("PUT", "/api/vault/"+entryID+"/targets", manager, "user", entryID, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: manager could not set the target: %d %s", rec.Code, rec.Body.String())
	}

	get := func(userID string) (int, string) {
		rec := httptest.NewRecorder()
		h.GetTargets(rec, vaultAuthzRequest("GET", "/api/vault/"+entryID+"/targets", userID, "user", entryID, ""))
		return rec.Code, rec.Body.String()
	}

	// Guard the setup: the creator is an editor, so they legitimately manage
	// targets right now. If not, the post-removal assertion proves nothing.
	if code, body := get(creator); code != http.StatusOK || !strings.Contains(body, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Fatalf("ABORT: an active editor cannot read targets (%d): %s", code, body)
	}

	// Remove them from the collection. They remain the entry's user_id, which is
	// exactly the state the residual read covers.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-tgt", UserID: creator,
	}); err != nil {
		t.Fatalf("remove: %v", err)
	}

	code, respBody := get(creator)
	if code == http.StatusOK {
		t.Errorf("a REMOVED member still read the rotation targets (%d)", code)
	}
	if strings.Contains(respBody, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Error("a removed member harvested another member's webhook HMAC signing secret in plaintext")
	}

	// A plain viewer never had a reason to see other people's delivery
	// credentials either.
	if code, body := get(viewer); code == http.StatusOK && strings.Contains(body, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Error("a collection VIEWER can read another member's webhook HMAC secret")
	}

	// The legitimate case must still work, or this is a break not a fix.
	if code, body := get(manager); code != http.StatusOK || !strings.Contains(body, "HMAC-SECRET-NOWHERE-ELSE") {
		t.Errorf("the manager can no longer read the targets they configured (%d): %s", code, body)
	}
}

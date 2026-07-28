package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
)

// TestClearingTargetsRequiresIntent covers BOTH directions of the wipe guard,
// because the first version of the fix only had one of them and silently broke
// the legitimate case.
//
// The guard exists because UpdateTargets is a full replace and the panel used to
// render a failed GET identically to "no delivery targets", so a user who added
// one target on top of that empty view deleted the real ones, webhook HMAC
// secrets included, with a success toast and no undo.
//
// But refusing every empty array also removes the only way to delete your last
// target through the UI. A guard that makes a shipped workflow unreachable is
// not a fix; the panel now opts in explicitly with ?clear=1, which it can do
// safely because Save is disabled unless the targets query settled.
func TestClearingTargetsRequiresIntent(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "clear@example.com", "user", "")
	const entryID = "entry-clear"
	mustEntry(t, h, queries, entryID, owner, "Stripe", "sk_live_x")

	seed := func() {
		targets := []RotationTarget{{
			Type: "webhook", Label: "prod", WebhookURL: "https://consumer.example.com/h",
			WebhookSecret: "hmac-secret-that-exists-nowhere-else", ConfiguredBy: owner,
		}}
		encoded, err := json.Marshal(targets)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		enc, err := h.encryptColumn(string(encoded))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if err := queries.UpdateVaultEntryRotationTargets(ctx, db.UpdateVaultEntryRotationTargetsParams{
			RotationTargets: toNullString(enc), ID: entryID,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	count := func() int {
		raw, err := queries.GetVaultEntryTargets(ctx, entryID)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return len(ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", "rotation_targets")))
	}

	seed()
	if count() != 1 {
		t.Fatal("ABORT: fixture did not store a target")
	}

	// An accidental blind wipe must be refused.
	rec := httptest.NewRecorder()
	h.UpdateTargets(rec, vaultAuthzRequest("PUT", "/api/vault/"+entryID+"/targets", owner, "user", entryID, `[]`))
	if rec.Code != http.StatusConflict {
		t.Errorf("a blind empty PUT returned %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if count() != 1 {
		t.Error("the target was deleted by a request that should have been refused")
	}

	// A deliberate clear must succeed, or the user can never remove their last
	// target through the UI.
	rec = httptest.NewRecorder()
	h.UpdateTargets(rec, vaultAuthzRequest("PUT", "/api/vault/"+entryID+"/targets?clear=1", owner, "user", entryID, `[]`))
	if rec.Code != http.StatusOK {
		t.Fatalf("a deliberate clear returned %d, want 200: %s\nthe UI would have no way to delete the last target",
			rec.Code, rec.Body.String())
	}
	if n := count(); n != 0 {
		t.Errorf("deliberate clear left %d target(s)", n)
	}

	// Clearing an ALREADY-empty list needs no ceremony: there is nothing to lose,
	// and refusing it would break saving an entry that simply has no targets.
	rec = httptest.NewRecorder()
	h.UpdateTargets(rec, vaultAuthzRequest("PUT", "/api/vault/"+entryID+"/targets", owner, "user", entryID, `[]`))
	if rec.Code != http.StatusOK {
		t.Errorf("saving an already-empty target list returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// And a non-empty save is never affected by the guard.
	seed()
	rec = httptest.NewRecorder()
	h.UpdateTargets(rec, vaultAuthzRequest("PUT", "/api/vault/"+entryID+"/targets", owner, "user", entryID,
		`[{"type":"webhook","label":"new","webhook_url":"https://other.example.com/h"}]`))
	if rec.Code != http.StatusOK {
		t.Errorf("a normal replace returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if count() != 1 {
		t.Error("a normal replace lost the target")
	}
}

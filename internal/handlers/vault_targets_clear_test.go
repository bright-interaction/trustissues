package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
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
	rec := putTargets(t, h, owner, "user", entryID, `[]`)
	if rec.Code != http.StatusConflict {
		t.Errorf("a blind empty PUT returned %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if count() != 1 {
		t.Error("the target was deleted by a request that should have been refused")
	}

	// A deliberate clear must succeed, or the user can never remove their last
	// target through the UI.
	rec = putTargets(t, h, owner, "user", entryID, `[]`, "clear=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("a deliberate clear returned %d, want 200: %s\nthe UI would have no way to delete the last target",
			rec.Code, rec.Body.String())
	}
	if n := count(); n != 0 {
		t.Errorf("deliberate clear left %d target(s)", n)
	}

	// Clearing an ALREADY-empty list needs no ceremony: there is nothing to lose,
	// and refusing it would break saving an entry that simply has no targets.
	rec = putTargets(t, h, owner, "user", entryID, `[]`)
	if rec.Code != http.StatusOK {
		t.Errorf("saving an already-empty target list returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// And a non-empty save is never affected by the guard.
	seed()
	rec = httptest.NewRecorder()
	rec = putTargets(t, h, owner, "user", entryID,
		`[{"type":"webhook","label":"new","webhook_url":"https://other.example.com/h"}]`)
	if rec.Code != http.StatusOK {
		t.Errorf("a normal replace returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if count() != 1 {
		t.Error("a normal replace lost the target")
	}
}

// TestDamagedTargetsColumnIsNotOverwritten gives rotation_targets the same
// protection Update has for its metadata columns.
//
// decryptColumnOrLog renders a decrypt failure as "[]", so GetTargets answered
// 200 with an empty list and the panel showed "No delivery targets". Saving from
// that view permanently replaced still-recoverable ciphertext, webhook HMAC
// signing secrets included. The ?clear=1 guard does not help: the stored list
// parses as empty, so it is not seen as a wipe at all.
func TestDamagedTargetsColumnIsNotOverwritten(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "damaged-targets@example.com", "user", "")
	const entryID = "entry-dmg-targets"
	mustEntry(t, h, queries, entryID, owner, "Stripe", "sk_live_x")

	sealed, err := h.encryptColumn(`[{"type":"webhook","webhook_url":"https://c.example.com/h","webhook_secret":"HMAC"}]`)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	bad := []byte(sealed)
	bad[len(bad)-3] ^= 0x01
	if _, decErr := h.decryptColumn(string(bad)); decErr == nil {
		t.Fatal("ABORT: the corrupted column still decrypts; the test would be vacuous")
	}
	if err := queries.UpdateVaultEntryRotationTargets(ctx, db.UpdateVaultEntryRotationTargetsParams{
		RotationTargets: toNullString(string(bad)), ID: entryID,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := httptest.NewRecorder()
	rec = putTargets(t, h, owner, "user", entryID,
		`[{"type":"webhook","label":"new","webhook_url":"https://new.example.com/h"}]`)
	if rec.Code != http.StatusConflict {
		t.Errorf("a save over an undecryptable targets column returned %d, want 409: %s", rec.Code, rec.Body.String())
	}

	raw, err := queries.GetVaultEntryTargets(ctx, entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if raw.String != string(bad) {
		t.Error("the still-recoverable targets ciphertext was overwritten; the webhook HMAC secret is unrecoverable now")
	}
}

// TestStalePanelCannotResurrectAPurgedTarget locks the durability of the
// offboarding purge.
//
// UpdateTargets is a full replace and preserves ConfiguredBy only for targets
// STILL stored. So a manager with the rotation panel open across an offboarding
// would resubmit the departed member's webhook; the purge had removed it, so it
// matched nothing and was stamped with the SAVER's id. targetStillAuthorized
// then asked whether that id still has write access, said yes, and plaintext
// delivery to the leaver's address was quietly reopened by someone who thought
// they were adding an unrelated target.
//
// The panel now pins the view with a version and the server refuses a stale one.
func TestStalePanelCannotResurrectAPurgedTarget(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	manager := mustUser(t, queries, "stale-mgr@example.com", "user", "")
	leaver := mustUser(t, queries, "stale-leaver@example.com", "user", "")
	mustCollection(t, queries, "coll-stale", manager, map[string]string{
		manager: collRoleManager,
		leaver:  collRoleEditor,
	})
	const entryID = "entry-stale"
	mustEntry(t, h, queries, entryID, manager, "Stripe", "sk_live_x")
	placeInCollection(t, queries, entryID, "coll-stale")

	// The leaver configures a delivery target.
	body := `[{"type":"webhook","label":"leaver","webhook_url":"https://leaver.example.com/hook"}]`
	rec := putTargets(t, h, leaver, "user", entryID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: leaver could not set a target: %d %s", rec.Code, rec.Body.String())
	}

	// The manager opens the panel and captures the version it was shown.
	rec = httptest.NewRecorder()
	h.GetTargets(rec, vaultAuthzRequest("GET", "/api/vault/"+entryID+"/targets", manager, "user", entryID, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: manager could not load the panel: %d", rec.Code)
	}
	var loaded struct {
		Targets []RotationTarget `json:"targets"`
		Version string           `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loaded); err != nil || loaded.Version == "" {
		t.Fatalf("ABORT: no version returned, the staleness check cannot work: %s", rec.Body.String())
	}

	// The leaver is offboarded and their target purged while the panel is open.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-stale", UserID: leaver,
	}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	ch := &CollectionHandler{queries: queries, vault: h}
	if summary := ch.purgeTargetsConfiguredBy(ctx, "coll-stale", leaver); summary == "" {
		t.Fatal("ABORT: the purge removed nothing, so this no longer tests resurrection")
	}

	// The manager saves the stale panel, adding one of their own on top.
	staleBody := `[{"type":"webhook","label":"leaver","webhook_url":"https://leaver.example.com/hook"},` +
		`{"type":"webhook","label":"mine","webhook_url":"https://mine.example.com/hook"}]`
	rec = httptest.NewRecorder()
	h.UpdateTargets(rec, vaultAuthzRequest("PUT",
		"/api/vault/"+entryID+"/targets?version="+loaded.Version, manager, "user", entryID, staleBody))
	if rec.Code != http.StatusConflict {
		t.Errorf("a stale panel save returned %d, want 409: the purged webhook would be written back "+
			"and re-attributed to the saver, reopening plaintext delivery to the leaver", rec.Code)
	}

	// The purged target must still be gone.
	raw, err := queries.GetVaultEntryTargets(ctx, entryID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, tg := range ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", "rotation_targets")) {
		if tg.WebhookURL == "https://leaver.example.com/hook" {
			t.Error("the offboarded member's webhook was resurrected")
		}
	}

	// A save with the CURRENT version still works, or the panel is unusable.
	rec = httptest.NewRecorder()
	h.GetTargets(rec, vaultAuthzRequest("GET", "/api/vault/"+entryID+"/targets", manager, "user", entryID, ""))
	var fresh struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &fresh)
	rec = httptest.NewRecorder()
	h.UpdateTargets(rec, vaultAuthzRequest("PUT",
		"/api/vault/"+entryID+"/targets?version="+fresh.Version, manager, "user", entryID,
		`[{"type":"webhook","label":"mine","webhook_url":"https://mine.example.com/hook"}]`))
	if rec.Code != http.StatusOK {
		t.Errorf("a save with the current version returned %d: the panel would be unusable", rec.Code)
	}
}

// putTargets does the real GET-then-PUT flow: load the current view, take its
// version, and send it back on save.
//
// The version is REQUIRED on write, because an opt-in staleness check protects
// only the clients that opt in and the point is that an offboarding purge stays
// purged whoever writes next. Tests have to follow the same contract a client
// does, or they stop describing the shipped behaviour.
func putTargets(t *testing.T, h *VaultHandler, userID, role, entryID, body string, extraQuery ...string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.GetTargets(rec, vaultAuthzRequest("GET", "/api/vault/"+entryID+"/targets", userID, role, entryID, ""))
	version := ""
	if rec.Code == http.StatusOK {
		var loaded struct {
			Version string `json:"version"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &loaded)
		version = loaded.Version
	}
	q := "?version=" + version
	for _, e := range extraQuery {
		q += "&" + e
	}
	out := httptest.NewRecorder()
	h.UpdateTargets(out, vaultAuthzRequest("PUT", "/api/vault/"+entryID+"/targets"+q, userID, role, entryID, body))
	return out
}

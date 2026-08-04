package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/middleware"
)

// updateEntry drives the real Update handler for entry id as user uid.
func updateEntry(t *testing.T, h *VaultHandler, uid, id string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/vault/"+id, bytes.NewReader(raw))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserIDKey, uid))
	rr := httptest.NewRecorder()
	h.Update(rr, req)
	return rr
}

// TestUpdateDoesNotResetTheRotationClockOnAnUnchangedValue locks the fix for a
// silent rotation de-scheduling.
//
// Writing the value stamps last_rotated_at = CURRENT_TIMESTAMP, which is right
// for a real change. But the edit form pre-filled the Value input with the
// decrypted secret while its own label said "(leave blank to keep current)", so
// every metadata edit re-submitted the same secret. Renaming an entry or fixing
// a typo in its notes reset the rotation clock, and an overdue auto-rotation
// quietly stopped being due.
//
// The frontend no longer pre-fills, and this guard makes it impossible for any
// client to cause it.
func TestUpdateDoesNotResetTheRotationClockOnAnUnchangedValue(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "u@example.com", "user", "")
	const id = "entry-clock"
	const secret = "the-current-secret"
	mustEntry(t, h, queries, id, owner, "Prod DB", secret)

	// Backdate the rotation clock so any stamp is obvious.
	if _, err := h.db.ExecContext(ctx,
		`UPDATE vault_entries SET last_rotated_at = datetime('now','-100 days'), rotation_interval_days = 30 WHERE id = ?`, id,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	before, err := queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		t.Fatalf("meta before: %v", err)
	}
	// Guard the setup: without a backdated timestamp the assertion is vacuous.
	if !before.LastRotatedAt.Valid || before.LastRotatedAt.Time.IsZero() {
		t.Fatal("ABORT: last_rotated_at was not backdated, the test would prove nothing")
	}

	// A metadata edit that echoes the SAME secret back must not touch the clock.
	rr := updateEntry(t, h, owner, id, map[string]any{
		"name":  "Prod DB renamed",
		"value": secret,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("update returned %d: %s", rr.Code, rr.Body.String())
	}
	after, err := queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		t.Fatalf("meta after: %v", err)
	}
	if !after.LastRotatedAt.Time.Equal(before.LastRotatedAt.Time) {
		t.Fatalf("re-submitting the SAME secret reset the rotation clock: %v -> %v (an overdue rotation would silently stop being due)",
			before.LastRotatedAt.Time, after.LastRotatedAt.Time)
	}
	if after.Name != "Prod DB renamed" {
		t.Fatalf("the metadata edit itself did not apply: name = %q", after.Name)
	}

	// A genuine value change SHOULD stamp it, or manual rotation stops working.
	rr = updateEntry(t, h, owner, id, map[string]any{"value": "a-genuinely-new-secret"})
	if rr.Code != http.StatusOK {
		t.Fatalf("real value change returned %d: %s", rr.Code, rr.Body.String())
	}
	changed, err := queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		t.Fatalf("meta after change: %v", err)
	}
	if !changed.LastRotatedAt.Time.After(before.LastRotatedAt.Time) {
		t.Fatal("a real value change did NOT stamp last_rotated_at: manual rotation no longer records")
	}
}

// TestUpdateRefusesToOverwriteAnUndecryptableSecret locks the other half.
//
// GET /api/vault/unlock renders an entry it cannot decrypt as the literal
// string "[decryption error]". The edit form then submits whatever it was
// showing, so one save persisted that sentinel as the new secret and returned
// 200, destroying a value that was still recoverable once the underlying cause
// (a wrong key, bit rot, a partial write) was fixed. Rotate already refused in
// this situation; Update did not.
func TestUpdateRefusesToOverwriteAnUndecryptableSecret(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "u@example.com", "user", "")
	const id = "entry-corrupt"
	mustEntry(t, h, queries, id, owner, "Corrupt", "original-secret")

	// Corrupt the stored ciphertext so it cannot be decrypted, exactly as a
	// key mismatch or a torn write would leave it.
	if _, err := h.db.ExecContext(ctx,
		`UPDATE vault_entries SET encrypted_value = ? WHERE id = ?`, []byte("not-valid-ciphertext-at-all"), id,
	); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	beforeRow, err := queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	if _, decErr := h.openForTest(beforeRow.EncryptedValue, beforeRow.Nonce); decErr == nil {
		t.Fatal("ABORT: the entry still decrypts, so this test is not exercising the guard")
	}

	rr := updateEntry(t, h, owner, id, map[string]any{"value": "[decryption error]"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("update returned %d, want 409: an undecryptable secret was overwritten (body: %s)", rr.Code, rr.Body.String())
	}

	// The stored ciphertext must be byte-identical: nothing was destroyed.
	afterRow, err := queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(beforeRow.EncryptedValue, afterRow.EncryptedValue) {
		t.Fatal("the refused update still modified the stored value: recovery is now impossible")
	}
}

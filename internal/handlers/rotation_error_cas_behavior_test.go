package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestClearRevokeHalfOfRotationErrorIsCompareAndSwap exercises the last_rotation_error
// CAS end-to-end through the clearer helper the retry/resolve endpoints and the
// provider-change discard all route through.
//
// The bug it closes (the last pending-revoke audit item): the clearers strip the
// revoke half of last_rotation_error after re-reading it, but the write was
// unconditional, so a rotation that recorded a failure between the re-read and the
// write had its alarm erased -- durably, because a manual rotation does not re-run
// to re-record it, leaving the entry reporting clean while a key is live upstream.
//
// The CAS gates on BOTH last_rotation_error AND provider_meta, and each subtest is
// an ablation of one predicate:
//   - the distinct-string race is caught by the text predicate;
//   - the same-string ABA (a concurrent recordRotationOutcome re-arms the bare
//     static revokeStillLiveMsg about a DIFFERENT key, byte-identical) is caught
//     ONLY by the provider_meta predicate, because the alarm always travels with a
//     provider_meta marker change and provider_meta re-nonces on every write.
func TestClearRevokeHalfOfRotationErrorIsCompareAndSwap(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, fmt.Sprintf("caserr-%s@example.com", randomHex(6)), "user", rotationTestPassword)

	setErr := func(t *testing.T, id, v string) {
		t.Helper()
		if err := queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
			LastRotationError: toNullString(v),
			ID:                id,
		}); err != nil {
			t.Fatalf("seed last_rotation_error: %v", err)
		}
	}
	// setMeta writes the provider_meta column through the egress writer (the only
	// path that may). The value is opaque to the clearer -- it is compared as bytes
	// -- so a distinct encrypted blob per call is all a "markers changed" event
	// needs to look like.
	setMeta := func(t *testing.T, id, plaintext string) {
		t.Helper()
		enc, err := h.encryptColumn(plaintext)
		if err != nil {
			t.Fatalf("encrypt provider_meta: %v", err)
		}
		if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
			Provider:     toNullString("cloudflare"),
			ProviderMeta: toNullString(enc),
			AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
			ID:           id,
		}); err != nil {
			t.Fatalf("set provider_meta: %v", err)
		}
	}
	// snapshot reads the two values a real clearer re-reads right before it clears.
	snapshot := func(t *testing.T, id string) (text string, pm sql.NullString) {
		t.Helper()
		row, err := queries.GetVaultEntryMeta(ctx, id)
		if err != nil {
			t.Fatalf("read row: %v", err)
		}
		return row.LastRotationError.String, row.ProviderMeta
	}
	readErr := func(t *testing.T, id string) string {
		t.Helper()
		text, _ := snapshot(t, id)
		return text
	}
	// The helper only uses the request for logging; a bare one is enough.
	req := httptest.NewRequest(http.MethodPost, "/api/vault/x/pending-revoke/retry", nil)

	t.Run("clears the revoke half when the row has not moved, preserving a co-resident failure", func(t *testing.T) {
		id := "caserr-clean-" + randomHex(6)
		mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
		// foldRevokeOutcome's composite shape: a genuine delivery failure joined to
		// the revoke warning. Only the revoke half may go; the delivery error is
		// still true and must survive.
		composite := "target apply failed: HTTP 500; " + revokeStillLiveMsg
		setErr(t, id, composite)

		text, pm := snapshot(t, id)
		h.clearRevokeHalfOfRotationError(ctx, req, "test.clean", id, text, pm)

		if got := readErr(t, id); got != "target apply failed: HTTP 500" {
			t.Fatalf("co-resident failure not preserved / revoke half not cleared: got %q", got)
		}
	})

	t.Run("does not erase a DISTINCT alarm recorded after the caller's snapshot (text predicate)", func(t *testing.T) {
		id := "caserr-race-" + randomHex(6)
		mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
		setErr(t, id, revokeStillLiveMsg)
		text, pm := snapshot(t, id)

		// A concurrent recordRotationFailure records a NEW, distinct failure into the
		// same column between the caller's re-read and this write -- and never touches
		// provider_meta, so only the text predicate can catch it.
		newAlarm := "rotation failed: upstream 503 while minting the replacement key"
		setErr(t, id, newAlarm)

		h.clearRevokeHalfOfRotationError(ctx, req, "test.race", id, text, pm)

		if got := readErr(t, id); got != newAlarm {
			t.Fatalf("clear erased a newer distinct alarm: got %q, want %q", got, newAlarm)
		}
	})

	t.Run("does not erase a SAME-STRING alarm re-armed about a different key (provider_meta predicate)", func(t *testing.T) {
		// This is the ABA the text predicate alone cannot see: revokeStillLiveMsg is a
		// bare static const with no key identity, so a concurrent recordRotationOutcome
		// that re-arms it about a different, still-live key writes byte-identical text.
		// It always moves provider_meta (the new key's markers), which the CAS compares.
		id := "caserr-aba-" + randomHex(6)
		mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
		setMeta(t, id, `{"key_id":"A","markers":"removed-by-resolve"}`)
		setErr(t, id, revokeStillLiveMsg)
		text, pm := snapshot(t, id)

		// Concurrent rotation: re-arms the SAME sentence about key B (byte-identical
		// text) and re-adds B's markers (a fresh provider_meta ciphertext).
		setMeta(t, id, `{"key_id":"B","pending_revoke":"re-armed for a different live key"}`)
		setErr(t, id, revokeStillLiveMsg) // same bytes as the snapshot

		h.clearRevokeHalfOfRotationError(ctx, req, "test.aba", id, text, pm)

		if got := readErr(t, id); got != revokeStillLiveMsg {
			t.Fatalf("clear erased a same-string alarm re-armed about a different live key (ABA): got %q, want it left intact %q",
				got, revokeStillLiveMsg)
		}
	})
}

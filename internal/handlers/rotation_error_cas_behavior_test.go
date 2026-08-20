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
//   - a same-string re-arm with NO accompanying provider_meta write is caught by
//     the KEY IDENTITY the alarm now carries, again through the text predicate;
//   - a re-arm on an OLD-SHAPE row, whose alarm carries no identity to compare,
//     is caught only by the provider_meta predicate.
//
// THE THIRD SUBTEST USED TO MANUFACTURE ITS OWN PRECONDITION, and that is the
// reason this doc is long. It called setMeta before setErr, i.e. it ARRANGED the
// provider_meta write the fix assumed always accompanies the alarm, and then
// observed that the co-gate caught the ABA. It could therefore only ever
// certify the assumption; it could not test it. The assumption was false:
// persistProviderMetaAfterRevoke has four branches that write no provider_meta
// and recordRotationOutcome writes the alarm regardless. (Its error was also
// discarded with `_ =` in revokeOldKeyAndPersistMeta until that was fixed; it is
// now a second warning. The branches still write no provider_meta, so the
// premise this subtest attacks is unchanged.) The subtests below now
// exercise BOTH branches -- the one where provider_meta moves and the one where
// it does not -- and the "does not" case is the one that reproduces the real
// failure, so it is written first.
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
		h.clearRevokeHalfOfRotationError(ctx, req, "test.clean", id, text, pm, []string{"K1"})

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

		h.clearRevokeHalfOfRotationError(ctx, req, "test.race", id, text, pm, []string{"K1"})

		if got := readErr(t, id); got != newAlarm {
			t.Fatalf("clear erased a newer distinct alarm: got %q, want %q", got, newAlarm)
		}
	})

	t.Run("catches a re-arm about a different key with NO provider_meta write (the branch the old guard could not reach)", func(t *testing.T) {
		// THE BRANCH THE PREVIOUS VERSION OF THIS TEST MANUFACTURED AWAY.
		//
		// The co-gate's stated premise was "the revoke alarm always travels with
		// the pending-revoke markers". It does not. persistProviderMetaAfterRevoke
		// returns early without writing provider_meta on four branches (row read
		// error, the provider changed mid-rotation, an egress refusal, and a
		// marshal/encrypt/persist failure) and recordRotationOutcome writes the
		// alarm anyway. revokeOldKeyAndPersistMeta now returns that error as a
		// second warning rather than throwing it away with `_ =`, which changes the
		// recorded STATUS but not this: provider_meta still does not move.
		//
		// So this subtest deliberately does NOT touch provider_meta between the
		// snapshot and the concurrent re-arm. The co-gate is therefore inert here
		// BY CONSTRUCTION, and the only thing that can catch the ABA is the alarm
		// naming its own subject.
		id := "caserr-noprovmeta-" + randomHex(6)
		mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
		setMeta(t, id, `{"key_id":"A"}`)
		setErr(t, id, revokeStillLiveMsgFor([]string{"K2"}))
		text, pm := snapshot(t, id)

		// Concurrent rotation: its revoke of K1 failed and its provider_meta
		// write-back hit one of the four silent branches, so it re-arms the alarm
		// about a DIFFERENT still-live key and provider_meta does not move.
		rearmed := revokeStillLiveMsgFor([]string{"K1"})
		setErr(t, id, rearmed)

		// Our retry settled K2 and clears only K2.
		h.clearRevokeHalfOfRotationError(ctx, req, "test.noprovmeta", id, text, pm, []string{"K2"})

		if got := readErr(t, id); got != rearmed {
			t.Fatalf("the clear erased an alarm re-armed about a DIFFERENT live key while provider_meta "+
				"never moved, so the co-gate could not see it: got %q, want %q.\n"+
				"This is the branch the pre-2026-08-19 guard could not reach because it wrote provider_meta "+
				"itself before writing the alarm.", got, rearmed)
		}
	})

	t.Run("the provider_meta predicate still catches a same-string ABA on an OLD-SHAPE row", func(t *testing.T) {
		// The residual the value-level identity cannot cover: a row written before
		// the alarm carried key ids holds the bare const, so two alarms about two
		// different keys really are byte-identical and the text predicate is blind.
		// provider_meta re-nonces on every write, so when the concurrent rotation
		// DID move the markers, its ciphertext is the witness. This is the case the
		// 2026-08-18 co-gate genuinely closes, and it is why the co-gate stays.
		id := "caserr-aba-" + randomHex(6)
		mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
		setMeta(t, id, `{"key_id":"A","markers":"removed-by-resolve"}`)
		setErr(t, id, revokeStillLiveMsg) // old shape: no key identity
		text, pm := snapshot(t, id)

		// Concurrent rotation: re-arms the SAME sentence about key B (byte-identical
		// text) and re-adds B's markers (a fresh provider_meta ciphertext).
		setMeta(t, id, `{"key_id":"B","pending_revoke":"re-armed for a different live key"}`)
		setErr(t, id, revokeStillLiveMsg) // same bytes as the snapshot

		h.clearRevokeHalfOfRotationError(ctx, req, "test.aba", id, text, pm, []string{"K1"})

		if got := readErr(t, id); got != revokeStillLiveMsg {
			t.Fatalf("clear erased a same-string alarm re-armed about a different live key (ABA): got %q, want it left intact %q",
				got, revokeStillLiveMsg)
		}
	})
}

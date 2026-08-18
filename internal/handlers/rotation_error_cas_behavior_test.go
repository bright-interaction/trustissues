package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
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
// The second subtest is that exact race, and it is an ablation of the fix: revert
// clearRevokeHalfOfRotationError to the unconditional UpdateVaultEntryRotationError
// and it fails, because the clear (of the empty-out kind, since the snapshot IS
// revokeStillLiveMsg) writes "" over the concurrent alarm.
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
	readErr := func(t *testing.T, id string) string {
		t.Helper()
		row, err := queries.GetVaultEntryMeta(ctx, id)
		if err != nil {
			t.Fatalf("read last_rotation_error: %v", err)
		}
		return row.LastRotationError.String
	}
	// The helper only uses the request for logging; a bare one is enough.
	req := httptest.NewRequest(http.MethodPost, "/api/vault/x/pending-revoke/retry", nil)

	t.Run("clears the revoke half when the column has not moved, preserving a co-resident failure", func(t *testing.T) {
		id := "caserr-clean-" + randomHex(6)
		mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
		// foldRevokeOutcome's composite shape: a genuine delivery failure joined to
		// the revoke warning. Only the revoke half may go; the delivery error is
		// still true and must survive.
		composite := "target apply failed: HTTP 500; " + revokeStillLiveMsg
		setErr(t, id, composite)

		h.clearRevokeHalfOfRotationError(ctx, req, id, composite)

		if got := readErr(t, id); got != "target apply failed: HTTP 500" {
			t.Fatalf("co-resident failure not preserved / revoke half not cleared: got %q", got)
		}
	})

	t.Run("does not erase an alarm recorded after the caller's snapshot", func(t *testing.T) {
		id := "caserr-race-" + randomHex(6)
		mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
		// The value the clearer re-read and decided to clear from.
		snapshot := revokeStillLiveMsg
		setErr(t, id, snapshot)

		// A concurrent rotation records a NEW failure into the same column between
		// the caller's re-read and this write -- recordRotationFailure does exactly
		// this, and never touches provider_meta, so no provider_meta CAS covers it.
		newAlarm := "rotation failed: upstream 503 while minting the replacement key"
		setErr(t, id, newAlarm)

		// The clearer runs with its now-STALE snapshot. The CAS must miss and leave
		// the newer, truer alarm in place.
		h.clearRevokeHalfOfRotationError(ctx, req, id, snapshot)

		if got := readErr(t, id); got != newAlarm {
			t.Fatalf("clear erased a newer alarm it knew nothing about: got %q, want the concurrent alarm %q",
				got, newAlarm)
		}
	})
}

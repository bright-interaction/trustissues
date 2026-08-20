package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// The two provider_meta write-back alarms shipped with NO clearer at all.
// revokeStillLiveMsg has three settle paths; these had none, and the only thing
// that removed them was a later rotation blanket-NULLing the column -- which is
// exactly what cannot happen in the case that matters, because on backblaze and
// twilio the stored id is half the credential, so the next mint fails against a
// pair that no longer authenticates.
//
// An alarm an operator cannot discharge is one they learn to ignore.

func TestWithoutMetaWriteClauses(t *testing.T) {
	revoke := revokeStillLiveMsgFor([]string{"K1"})
	for _, tc := range []struct{ name, in, want string }{
		{"the write-back alarm alone", metaWriteBackFailedMsg, ""},
		{"the provider-changed alarm alone", providerChangedMidRotationMsg, ""},
		{"leaves a co-resident revoke alarm alone", revoke + "; " + metaWriteBackFailedMsg, revoke},
		{"leaves a co-resident delivery failure alone", "webhook delivery failed: HTTP 500; " + metaWriteBackFailedMsg, "webhook delivery failed: HTTP 500"},
		{"clears from the middle", "webhook delivery failed: HTTP 500; " + metaWriteBackFailedMsg + "; " + revoke, "webhook delivery failed: HTTP 500; " + revoke},
		{"an unrelated error survives", "webhook delivery failed: HTTP 500", "webhook delivery failed: HTTP 500"},
		{"empty", "", ""},
		{"not at a join boundary is left alone", "a target said " + metaWriteBackFailedMsg, "a target said " + metaWriteBackFailedMsg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := withoutMetaWriteClauses(tc.in); got != tc.want {
				t.Errorf("withoutMetaWriteClauses(%q)\n  got:  %q\n  want: %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestAnOperatorCanClearTheWriteBackAlarmThroughTheUI drives the REAL
// PUT /api/vault/{id} that the RotationManager "save provider" button sends
// (frontend/src/components/RotationManager.tsx:239-244 posts provider +
// provider_meta together), because "there is a clearer" and "an operator can
// reach it" are different claims and only the second one ships.
func TestAnOperatorCanClearTheWriteBackAlarmThroughTheUI(t *testing.T) {
	ctx := context.Background()

	for _, alarm := range []string{metaWriteBackFailedMsg, providerChangedMidRotationMsg} {
		t.Run(alarm[:28], func(t *testing.T) {
			h, queries := newCollectionAuthzEnv(t)
			owner := mustUser(t, queries, fmt.Sprintf("mwc-%s@example.com", randomHex(6)), "user", rotationTestPassword)
			id := "mwc-" + randomHex(6)
			mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
			forceProviderConfig(t, h, id, "backblaze", `{"key_id":"STALE","account_id":"A"}`)

			// The rotation recorded the alarm and could not clear it.
			if err := queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
				LastRotationError: toNullString(alarm),
				ID:                id,
			}); err != nil {
				t.Fatalf("seed alarm: %v", err)
			}

			// THE OPERATOR FIXES THE CONFIGURATION, exactly as the UI sends it.
			rec := putVault(t, h, owner, "user", id, map[string]any{
				"provider":      "backblaze",
				"provider_meta": `{"key_id":"CORRECTED","account_id":"A"}`,
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body.String())
			}

			// The durable record.
			row, err := queries.GetVaultEntryMeta(ctx, id)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if row.LastRotationError.String != "" {
				t.Errorf("the operator corrected the provider configuration and the alarm about that "+
					"configuration survived: %q", row.LastRotationError.String)
			}

			// ...and the response the UI renders from, in the same request. An
			// operator who fixes the config and still sees red has been told
			// their fix did not work.
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if v, ok := body["last_rotation_error"]; ok && v != nil && v != "" {
				t.Errorf("the PUT response still carried the alarm it had just cleared: %v", v)
			}
		})
	}
}

// TestClearingTheWriteBackAlarmLeavesAStillLiveKeyAlarmArmed is the guard that
// stops this becoming a blanket erase. Writing provider_meta does not revoke a
// key that is still live upstream, so that alarm is untouched.
func TestClearingTheWriteBackAlarmLeavesAStillLiveKeyAlarmArmed(t *testing.T) {
	ctx := context.Background()
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, fmt.Sprintf("mwc2-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	id := "mwc2-" + randomHex(6)
	mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
	forceProviderConfig(t, h, id, "backblaze", `{"key_id":"STALE","account_id":"A"}`)

	revoke := revokeStillLiveMsgFor([]string{"K-LIVE"})
	if err := queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString(revoke + "; " + metaWriteBackFailedMsg),
		ID:                id,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := putVault(t, h, owner, "user", id, map[string]any{
		"provider":      "backblaze",
		"provider_meta": `{"key_id":"CORRECTED","account_id":"A"}`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body.String())
	}

	row, err := queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got := row.LastRotationError.String
	if strings.Contains(got, metaWriteBackFailedMsg) {
		t.Errorf("the write-back alarm was not cleared: %q", got)
	}
	if !strings.Contains(got, revokeStillLiveMsg) || !strings.Contains(got, "K-LIVE") {
		t.Errorf("saving provider_meta erased an alarm about a key that is STILL LIVE at the provider "+
			"and that this write did nothing about: %q", got)
	}
}

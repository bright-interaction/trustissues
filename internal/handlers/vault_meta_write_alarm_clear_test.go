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
		// NOT cleared by a provider_meta write: that alarm is about the committed
		// VALUE having been minted at a provider the entry no longer names, which
		// rewriting metadata does not move. Its discharge is a successful rotation.
		{"the provider-changed alarm is NOT dischargeable this way", providerChangedMidRotationMsg, providerChangedMidRotationMsg},
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

	for _, alarm := range []string{metaWriteBackFailedMsg} {
		t.Run("write-back alarm", func(t *testing.T) {
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

// ---------------------------------------------------------------------------
// The five P0s the re-audit found in the first version of this clear. Every one
// of them came from ONE mistake: the trigger tested the SHAPE OF THE REQUEST
// (`req.ProviderMeta != nil`) instead of whether the write improved anything.
// ---------------------------------------------------------------------------

// seedAlarmedEntry returns an entry carrying `alarm`, with provider config set.
func seedAlarmedEntry(t *testing.T, alarm, provider, meta string) (*VaultHandler, *db.Queries, string, string) {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, fmt.Sprintf("p0-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	id := "p0-" + randomHex(6)
	mustEntry(t, h, queries, id, owner, "Entry "+id, "V")
	forceProviderConfig(t, h, id, provider, meta)
	if err := queries.UpdateVaultEntryRotationError(context.Background(), db.UpdateVaultEntryRotationErrorParams{
		LastRotationError: toNullString(alarm), ID: id,
	}); err != nil {
		t.Fatalf("seed alarm: %v", err)
	}
	return h, queries, owner, id
}

func alarmAfterPut(t *testing.T, h *VaultHandler, q *db.Queries, owner, id string, body map[string]any) string {
	t.Helper()
	rec := putVault(t, h, owner, "user", id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT %v returned %d: %s", body, rec.Code, rec.Body.String())
	}
	row, err := q.GetVaultEntryMeta(context.Background(), id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	return row.LastRotationError.String
}

// P0-1: RotationManager has no dirty check, so an operator who opens the entry
// to LOOK at the alarm and presses Save disarms it without changing anything.
func TestANoOpProviderMetaSaveDoesNotClearTheAlarm(t *testing.T) {
	const meta = `{"key_id":"STALE","account_id":"A"}`
	h, q, owner, id := seedAlarmedEntry(t, metaWriteBackFailedMsg, "backblaze", meta)
	got := alarmAfterPut(t, h, q, owner, id, map[string]any{"provider": "backblaze", "provider_meta": meta})
	if got != metaWriteBackFailedMsg {
		t.Errorf("a save that changed NOTHING disarmed the alarm: %q. The operator pressed Save on the "+
			"screen showing the warning, and the warning is what went away, not the cause.", got)
	}
}

// P0-2: the destructive case. Emptying provider_meta DELETES key_id, which is
// half the credential on backblaze, and used to clear the alarm about it in the
// same request -- so the write that broke the entry also silenced the warning.
func TestEmptyingProviderMetaDoesNotClearTheAlarmItCauses(t *testing.T) {
	h, q, owner, id := seedAlarmedEntry(t, metaWriteBackFailedMsg, "backblaze", `{"key_id":"STALE","account_id":"A"}`)
	got := alarmAfterPut(t, h, q, owner, id, map[string]any{"provider": "backblaze", "provider_meta": `{}`})
	if got != metaWriteBackFailedMsg {
		t.Errorf("a write that DELETED key_id (half the credential) cleared the alarm warning about "+
			"the key id: %q", got)
	}
	if stored := entryMetaMap(t, h, q, id); stored["key_id"] != "" {
		t.Logf("note: key_id survived as %q", stored["key_id"])
	}
}

// P0-3: no provider_meta write can honestly discharge this one.
func TestAProviderMetaWriteDoesNotDischargeTheProviderChangedAlarm(t *testing.T) {
	h, q, owner, id := seedAlarmedEntry(t, providerChangedMidRotationMsg, "backblaze", `{"key_id":"STALE","account_id":"A"}`)
	got := alarmAfterPut(t, h, q, owner, id, map[string]any{
		"provider": "backblaze", "provider_meta": `{"key_id":"CORRECTED","account_id":"A"}`,
	})
	if got != providerChangedMidRotationMsg {
		t.Errorf("rewriting metadata discharged an alarm about the committed VALUE having been minted "+
			"at a different provider: %q. Nothing moved the value.", got)
	}
}

// P0-4: the pre-image must come from the transaction, not from a read taken
// after the handler's own commit. With a post-commit re-read, anything a racing
// rotation wrote in that window BECAME the pre-image, so the CAS compared the
// racing writer's values against themselves, matched, and deleted an alarm about
// a failure this request knew nothing about.
//
// The re-read is gone, so the CAS itself is the guard -- and the CAS had no test
// at all: swapping it for an unconditional UPDATE passed the whole package. This
// drives the clearer directly with a STALE pre-image, which is what a racing
// writer leaves behind, and pins that it declines to write.
func TestTheWriteBackClearRefusesOnAStalePreImage(t *testing.T) {
	ctx := context.Background()
	armed := revokeStillLiveMsgFor([]string{"K-NEW"}) + "; " + metaWriteBackFailedMsg
	h, queries, _, id := seedAlarmedEntry(t, armed, "backblaze", `{"key_id":"STALE","account_id":"A"}`)

	row, err := queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// A pre-image from before the racing write: neither half matches the row.
	stale := metaWriteBackFailedMsg
	cleared, applied := h.clearMetaWriteHalfOfRotationError(ctx,
		vaultAuthzRequest(http.MethodPut, "/api/vault/"+id, "u", "user", id, "{}"),
		"test.stale_preimage", id, stale, row.ProviderMeta)

	if applied {
		t.Errorf("the clear wrote against a stale pre-image (returned %q). A rotation that armed an "+
			"alarm after this request decided anything just had it deleted, and the caller was told "+
			"the write succeeded.", cleared)
	}
	after, err := queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if after.LastRotationError.String != armed {
		t.Errorf("the row changed under a refused clear: got %q, want %q", after.LastRotationError.String, armed)
	}
}

// P0-5: the co-resident case. A provider change discards the markers AND this
// handler clears the write-back clause; the discard clear then compared a
// pre-transaction snapshot, saw its own handler's write, concluded a concurrent
// rotation had intervened, and abstained -- stranding the revoke alarm about
// keys whose markers this same request had just thrown away.
func TestAProviderChangeClearsBothHalvesNotJustOne(t *testing.T) {
	revoke := revokeStillLiveMsgFor([]string{"K-OLD"})
	h, q, owner, id := seedAlarmedEntry(t, revoke+"; "+metaWriteBackFailedMsg, "resend",
		`{"key_id":"K2","pending_revoke_url":"https://api.resend.com/api-keys/K-OLD",`+
			`"pending_revoke_method":"DELETE","pending_revoke_auth":"bearer","pending_revoke_key_id":"K-OLD"}`)

	got := alarmAfterPut(t, h, q, owner, id, map[string]any{
		"provider": "sendgrid", "provider_meta": `{"key_id":"K2"}`,
	})
	if strings.Contains(got, revokeStillLiveMsg) {
		t.Errorf("the provider change discarded the markers but left the revoke alarm armed: %q. "+
			"Nothing in the product can revoke K-OLD now, and nothing will name it again.", got)
	}
	if strings.Contains(got, metaWriteBackFailedMsg) {
		t.Errorf("the write-back clause survived: %q", got)
	}
}

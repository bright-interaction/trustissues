package handlers

import (
	"context"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// The write-back half of a rotation had TWO ways to not land, and on both of
// them the rotation recorded itself as a clean success.
//
// These tests are written against the DURABLE RECORD -- the status
// recordRotationOutcome computes and the last_rotation_error it persists --
// rather than against the return value of the write-back, because "the column
// says success" was the actual defect. A test that asserted only on the error
// value would have passed against the broken code on the second case, where
// there was no error value to assert on.
//
// Both cases end with meta["key_id"] in the column naming the PREDECESSOR while
// encrypted_value holds the SUCCESSOR's secret. For backblaze and twilio the id
// is half the credential (backblazeAuthorize sends base64(key_id + ":" + value)),
// so the stored pair authenticates as nobody, and the predecessor is already
// destroyed upstream by the time the write-back runs.

// finaliseRotation runs the shared post-commit path the way both rotation paths
// do: revoke + write-back, then record the outcome. It returns what an operator
// would see afterwards.
func finaliseRotation(t *testing.T, deps rotationDeps, entryID, provider string, passStart map[string]string) (status, stored string) {
	t.Helper()
	ctx := context.Background()
	revokeWarn, metaWarn := revokeOldKeyAndPersistMeta(ctx, deps, entryID, "Entry "+entryID, provider, passStart, secretexit.Plaintext{})
	status, _ = recordRotationOutcome(ctx, deps, rotationRecord{
		EntryID:       entryID,
		EntryName:     "Entry " + entryID,
		Provider:      provider,
		Method:        "manual",
		RevokeWarn:    revokeWarn,
		MetaWriteWarn: metaWarn,
	})
	row, err := deps.queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	return status, row.LastRotationError.String
}

// TestAProviderChangedMidRotationIsNotRecordedAsSuccess is the reproduction of
// the audit's P0-1 as it actually occurs.
//
// The concurrent PUT is an ORDINARY operator action and needs no fault
// injection: it lands inside the mint-then-write window, which spans a real
// network round trip to the provider. persistProviderMetaAfterRevoke then takes
// its "the provider moved under us" branch, which correctly writes nothing --
// and used to return a bare nil, indistinguishable from a write that landed.
func TestAProviderChangedMidRotationIsNotRecordedAsSuccess(t *testing.T) {
	h, deps, entryID := rotationWriteBackEnv(t, "backblaze", `{"key_id":"OLD","account_id":"A"}`)

	// The rotation minted a successor at backblaze and advanced its in-memory map.
	passStart := map[string]string{"key_id": "NEW", "account_id": "A"}

	// THE RACE: the operator repoints the entry while the rotation is out at the
	// provider. Value column untouched, so nothing blocks the value CAS.
	forceProviderConfig(t, h, entryID, "resend", `{"key_id":"OLD","account_id":"A"}`)

	status, stored := finaliseRotation(t, deps, entryID, "backblaze", passStart)

	if status == "success" {
		t.Errorf("a rotation whose key id was never recorded reported status %q. "+
			"The column still names the predecessor, encrypted_value holds the successor, "+
			"and for backblaze that pair is base64(key_id:secret) -- it 401s.", status)
	}
	if stored == "" {
		t.Error("last_rotation_error is empty: the durable record says the rotation was clean, " +
			"which is the whole defect. Nothing else in the product ever names this entry again.")
	}
	if !strings.Contains(stored, "provider changed") {
		t.Errorf("last_rotation_error does not name the actual failure: %q", stored)
	}
	// The no-write decision itself is correct and must NOT have been reverted:
	// resurrecting a previous provider's markers is a separate, worse bug.
	if got := entryMetaMap(t, h, deps.queries, entryID); got["key_id"] != "OLD" {
		t.Errorf("the write-back wrote a previous provider's state into an entry that "+
			"now names a different provider: %+v", got)
	}
}

// TestAFailedWriteBackIsNotRecordedAsSuccess covers the other three branches --
// the row read fails, the egress gate refuses, or marshal/encrypt/persist fails.
// Those DO return an error; it was discarded at the call site with a bare `_ =`.
//
// The egress refusal is the reachable one to drive here: a provider adapter that
// writes a host-influencing key makes the write-back a destination change, which
// egressgate refuses with no principal on the path to authorize it.
func TestAFailedWriteBackIsNotRecordedAsSuccess(t *testing.T) {
	h, deps, entryID := rotationWriteBackEnv(t, "grafana", `{"instance":"acme.grafana.net","key_id":"OLD"}`)

	// The adapter moved the entry's reachable host inside the rotation.
	passStart := map[string]string{"instance": "attacker.grafana.net", "key_id": "NEW"}

	status, stored := finaliseRotation(t, deps, entryID, "grafana", passStart)

	if status == "success" {
		t.Errorf("a rotation whose write-back was refused reported status %q", status)
	}
	if stored == "" {
		t.Error("last_rotation_error is empty: the refusal was logged and then discarded with `_ =`, " +
			"so the durable record said the rotation was clean")
	}
	if got := entryMetaMap(t, h, deps.queries, entryID); got["instance"] != "acme.grafana.net" {
		t.Errorf("the egress gate did not hold: %+v", got)
	}
}

// TestACleanWriteBackIsStillASuccess is the false-positive guard. Neither fold
// may fire on the ordinary path, or every rotation starts alarming and the
// alarm stops meaning anything.
func TestACleanWriteBackIsStillASuccess(t *testing.T) {
	h, deps, entryID := rotationWriteBackEnv(t, "backblaze", `{"key_id":"OLD","account_id":"A"}`)
	passStart := map[string]string{"key_id": "NEW", "account_id": "A"}

	status, stored := finaliseRotation(t, deps, entryID, "backblaze", passStart)

	if status != "success" {
		t.Errorf("an ordinary rotation was downgraded to %q (%q)", status, stored)
	}
	if stored != "" {
		t.Errorf("an ordinary rotation recorded an error: %q", stored)
	}
	if got := entryMetaMap(t, h, deps.queries, entryID); got["key_id"] != "NEW" {
		t.Errorf("the rotation's own key_id did not land: %+v", got)
	}
}

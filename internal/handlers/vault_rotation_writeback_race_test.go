package handlers

import (
	"context"
	"testing"
)

// rotationWriteBackEnv seeds an entry with a provider and a stored
// provider_meta, and hands back the deps the write-back needs.
func rotationWriteBackEnv(t *testing.T, provider, metaJSON string) (*VaultHandler, rotationDeps, string) {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "wb-"+randomHex(6)+"@example.com", "user", "")
	entryID := "wb-" + randomHex(6)
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
	forceProviderConfig(t, h, entryID, provider, metaJSON)
	return h, rotationDeps{queries: queries, vault: h}, entryID
}

// TestTheRotationWriteBackDoesNotEraseAConcurrentOperatorEdit is the reproduced
// data-loss case.
//
// The rotation carries a PASS-START copy of provider_meta across its
// mint-then-write window, which spans a real network round trip to the
// provider. The value CAS upstream guards only encrypted_value -- deliberately,
// because comparing updated_at made unrelated writes fail a rotation that had
// already minted -- so a metadata-only edit by the operator neither blocks the
// rotation nor appears in its map. Treating that map as the target state then
// DELETED the operator's key, and the rotation still reported success.
func TestTheRotationWriteBackDoesNotEraseAConcurrentOperatorEdit(t *testing.T) {
	ctx := context.Background()
	h, deps, entryID := rotationWriteBackEnv(t, "resend", `{"account":"A"}`)

	// What the rotation read at pass start, and has been mutating since.
	passStart := map[string]string{"account": "A", "key_id": "K-NEW"}

	// THE RACE: the operator saves an unrelated meta key while the rotation is
	// out at the provider. Value column untouched, so nothing blocks the CAS.
	forceProviderConfig(t, h, entryID, "resend", `{"account":"A","operator_edit":"KEEP-ME"}`)

	if err := persistProviderMetaAfterRevoke(ctx, deps, entryID, "Entry", "resend", passStart); err != nil {
		t.Fatalf("write-back: %v", err)
	}

	got := entryMetaMap(t, h, deps.queries, entryID)
	if got["operator_edit"] != "KEEP-ME" {
		t.Errorf("the rotation's write-back ERASED an operator edit made during its mint window: %+v. "+
			"The rotation reports success and the operator's change is gone with no diagnostic.", got)
	}
	if got["key_id"] != "K-NEW" {
		t.Errorf("the rotation's own key_id did not land: %+v", got)
	}
	if got["account"] != "A" {
		t.Errorf("an untouched key was lost: %+v", got)
	}
}

// TestTheRotationWriteBackDoesNotResurrectDischargedMarkers is the sibling
// case, and the one that made two of this branch's own fixes fight.
//
// A provider change discharges the pending-revoke markers and writes a
// vault.pending_revoke_discarded activity row. If an in-flight rotation then
// writes its pass-start map back, the markers return, pendingRevokeStatusFrom
// never cross-checks the provider column, and they read as a live stranded key
// at a provider the entry no longer targets -- making the audit row a lie.
func TestTheRotationWriteBackDoesNotResurrectDischargedMarkers(t *testing.T) {
	ctx := context.Background()
	h, deps, entryID := rotationWriteBackEnv(t, "resend",
		`{"key_id":"K2","pending_revoke_url":"https://api.resend.com/api-keys/K-OLD",`+
			`"pending_revoke_method":"DELETE","pending_revoke_auth":"bearer","pending_revoke_key_id":"K-OLD"}`)

	passStart := map[string]string{
		"key_id":            "K2",
		pendingRevokeURL:    "https://api.resend.com/api-keys/K-OLD",
		pendingRevokeMethod: "DELETE",
		pendingRevokeAuth:   "bearer",
		pendingRevokeKeyID:  "K-OLD",
	}

	// THE RACE: the operator changes provider, which discharges the markers.
	forceProviderConfig(t, h, entryID, "sendgrid", `{"key_id":"K2"}`)

	if err := persistProviderMetaAfterRevoke(ctx, deps, entryID, "Entry", "resend", passStart); err != nil {
		t.Fatalf("write-back: %v", err)
	}

	got := entryMetaMap(t, h, deps.queries, entryID)
	for _, k := range pendingRevokeMarkerKeys {
		if _, back := got[k]; back {
			t.Errorf("the rotation RESURRECTED %s after a provider change discharged it: %+v. The "+
				"entry now reports a live stranded key at a provider it no longer targets, and the "+
				"vault.pending_revoke_discarded activity row is a false statement.", k, got)
		}
	}
}

// TestTheRotationWriteBackStillClearsItsOwnMarkers is the positive control for
// both tests above: without it they pass just as well against a write-back that
// has stopped writing anything at all.
func TestTheRotationWriteBackStillClearsItsOwnMarkers(t *testing.T) {
	ctx := context.Background()
	h, deps, entryID := rotationWriteBackEnv(t, "resend",
		`{"account":"A","pending_revoke_url":"https://api.resend.com/api-keys/K-OLD",`+
			`"pending_revoke_method":"DELETE","pending_revoke_auth":"bearer"}`)

	// A confirmed revoke: performPendingRevoke has deleted the markers from the
	// rotation's map in place, and the row must follow.
	passStart := map[string]string{"account": "A", "key_id": "K-NEW"}

	if err := persistProviderMetaAfterRevoke(ctx, deps, entryID, "Entry", "resend", passStart); err != nil {
		t.Fatalf("write-back: %v", err)
	}

	got := entryMetaMap(t, h, deps.queries, entryID)
	for _, k := range pendingRevokeMarkerKeys {
		if _, left := got[k]; left {
			t.Errorf("a confirmed revoke did not clear %s from the row: %+v. The entry still claims a "+
				"key is stranded that was actually deleted.", k, got)
		}
	}
	if got["key_id"] != "K-NEW" || got["account"] != "A" {
		t.Errorf("the write-back stopped writing: %+v", got)
	}
}

package handlers

import (
	"strings"
	"testing"
)

// TestAB2PredecessorWithADotIsStillNameableAndSettleable closes HIGH-3 for the
// arm the first fix missed.
//
// The http shape is rescued by path.Base when the recorded id is dropped for
// failing the charset. b2 cannot use that rescue AT ALL: its "URL" is a bare key
// id, so url.Parse yields Host == "" and the rescue branch is never entered.
// Meanwhile b2's revokeTargetIsNameable bans only "/?#\" and whitespace, so a
// dot passes the gate and is queued. The result was a key live at B2 that
// outstandingRevokeKeyIDs skipped, displacedHeadKeyID queued nameless, and
// ResolvePendingRevoke could never target, because its gate requires a non-empty
// PredecessorKeyID.
//
// The dot is the cheap precondition: an operator writes it into this entry's
// ordinary, unvalidated key_id through PUT /api/vault/{id}. Nothing else is
// needed, which is why this one blocked the ship where the cap-edge findings
// did not.
func TestAB2PredecessorWithADotIsStillNameableAndSettleable(t *testing.T) {
	// The gate must genuinely admit this id, or nothing below is being tested.
	if !revokeTargetIsNameable("abc.def", revokeAuthB2) {
		t.Fatalf("ABORT: the b2 nameability gate now refuses \"abc.def\", so it is never queued and " +
			"this test is measuring nothing. If that refusal was deliberate, this test should be " +
			"replaced by one asserting the refusal instead.")
	}

	meta := map[string]string{}
	deferRevokeOldProviderKey(meta, "DELETE", "abc.def", revokeAuthB2, "abc.def")

	// The precondition the whole finding rests on: the id is dropped from the
	// recorded-id marker, so every reader must derive it from the URL instead.
	if meta[pendingRevokeKeyID] != "" {
		t.Fatalf("ABORT: pending_revoke_key_id is %q, so the recorded id still names the key and the "+
			"derivation under test is never reached", meta[pendingRevokeKeyID])
	}
	if meta[pendingRevokeURL] != "abc.def" {
		t.Fatalf("ABORT: pending_revoke_url is %q, want the bare b2 key id", meta[pendingRevokeURL])
	}

	st := pendingRevokeStatusFromMeta(meta)
	if st == nil || !st.Outstanding {
		t.Fatalf("the row reports nothing outstanding: %+v", st)
	}
	if st.PredecessorKeyID != "abc.def" {
		t.Errorf("the derived predecessor id is %q, want \"abc.def\".\n"+
			"With an empty id the chip shows no key, outstandingRevokeKeyIDs skips the entry, and "+
			"ResolvePendingRevoke refuses every acknowledgement because it compares against this "+
			"exact field. The key stays live at B2 with nothing naming it and no way to settle it.",
			st.PredecessorKeyID)
	}

	// The resolve gate, spelled out the way ResolvePendingRevoke spells it. An
	// empty derived id makes it unsatisfiable for every possible input.
	if st.PredecessorKeyID == "" {
		t.Errorf("ResolvePendingRevoke can never be satisfied for this row: its gate requires " +
			"status.PredecessorKeyID != \"\" and an exact match against it.")
	}

	// And it must not become less nameable by being displaced onto the backlog.
	deferRevokeOldProviderKey(meta, "DELETE", "ghi", revokeAuthB2, "ghi")
	backlog, malformed := parseStrandedRevokes(meta)
	if malformed || len(backlog) != 1 {
		t.Fatalf("ABORT: the displaced head did not reach the backlog: malformed=%v backlog=%+v",
			malformed, backlog)
	}
	if backlog[0].KeyID != "abc.def" {
		t.Errorf("the displaced b2 head was queued with id %q, want \"abc.def\"; a key must not become "+
			"less nameable by being queued than it was while it held the head", backlog[0].KeyID)
	}
	outstanding := outstandingRevokeKeyIDs(meta)
	if !strings.Contains(strings.Join(outstanding, ","), "abc.def") {
		t.Errorf("the row no longer names abc.def: outstanding=%v.\n"+
			"Settling every key this list DOES name clears the alarm while abc.def is live at B2.",
			outstanding)
	}
}

// TestTheB2IDFallbackStillWithholdsAValueThatNamesNothing is the negative half
// of the test above, so the fallback cannot widen into "echo anything".
//
// It also pins that the fallback is scoped to the b2 arm: a non-b2 row whose
// marker URL is neither parseable-with-a-host nor charset-clean keeps the
// pre-change behaviour of reporting outstanding with no id.
func TestTheB2IDFallbackStillWithholdsAValueThatNamesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		meta   map[string]string
		wantID string
	}{
		{
			name:   "a b2 value that names nothing is withheld",
			meta:   map[string]string{pendingRevokeURL: ".", pendingRevokeAuth: revokeAuthB2},
			wantID: "",
		},
		{
			name:   "a charset-clean b2 id still comes back, unchanged by this fallback",
			meta:   map[string]string{pendingRevokeURL: "0021abcDEF_-", pendingRevokeAuth: revokeAuthB2},
			wantID: "0021abcDEF_-",
		},
		{
			name:   "the fallback is b2-only: a bearer row with the same value is unchanged",
			meta:   map[string]string{pendingRevokeURL: "abc.def", pendingRevokeAuth: revokeAuthBearer},
			wantID: "",
		},
		{
			name: "the fallback never overrides a recorded id",
			meta: map[string]string{
				pendingRevokeURL:   "abc.def",
				pendingRevokeAuth:  revokeAuthB2,
				pendingRevokeKeyID: "REAL",
			},
			wantID: "REAL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := pendingRevokeStatusFromMeta(tc.meta)
			if st == nil || !st.Outstanding {
				t.Fatalf("want an outstanding revoke, got %+v", st)
			}
			if st.PredecessorKeyID != tc.wantID {
				t.Errorf("predecessor id = %q, want %q", st.PredecessorKeyID, tc.wantID)
			}
		})
	}
}

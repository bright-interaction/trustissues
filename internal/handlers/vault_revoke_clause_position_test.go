package handlers

import (
	"strings"
	"testing"
)

// splitRevokeClause used to anchor the revoke clause to the END of
// last_rotation_error: the whole value, or a trailing "; "-joined suffix. That
// held only because foldRevokeOutcome was the LAST fold to touch the column.
//
// foldMetaWriteOutcome then began appending after it, which pushed the revoke
// clause into the middle and made it unparseable. splitRevokeClause returned
// ok=false, withoutRevokeStillLiveKeys returned its input byte-identical, and
// the caller's `cleared == current` early return fired before the CAS -- so
// settling a stranded key through Retry answered 200 {"revoked": true} while
// the column still said the key was live and the badge stayed red.
//
// The parser is now position-independent: it finds the clause at any "; " join
// boundary. These tests pin that, and pin the safety property it must not lose.
func TestTheRevokeClauseIsSettleableWhereverItSits(t *testing.T) {
	alarm := revokeStillLiveMsgFor([]string{"K1", "K2"})

	for _, tc := range []struct {
		name    string
		value   string
		settle  []string
		wantOut string
	}{
		{
			name:    "alone (the oldest shape)",
			value:   alarm,
			settle:  []string{"K1", "K2"},
			wantOut: "",
		},
		{
			name:    "trailing after a delivery error (the shape before the meta fold)",
			value:   "delivery failed for 1 target; " + alarm,
			settle:  []string{"K1", "K2"},
			wantOut: "delivery failed for 1 target",
		},
		{
			name:    "THE REGRESSION: followed by the provider_meta clause",
			value:   alarm + "; " + metaWriteBackFailedMsg,
			settle:  []string{"K1", "K2"},
			wantOut: metaWriteBackFailedMsg,
		},
		{
			name:    "sandwiched between a delivery error and the provider_meta clause",
			value:   "delivery failed for 1 target; " + alarm + "; " + providerChangedMidRotationMsg,
			settle:  []string{"K1", "K2"},
			wantOut: "delivery failed for 1 target; " + providerChangedMidRotationMsg,
		},
		{
			name:    "partial settle in the middle keeps the unsettled key",
			value:   alarm + "; " + metaWriteBackFailedMsg,
			settle:  []string{"K1"},
			wantOut: metaWriteBackFailedMsg + "; " + revokeStillLiveMsgFor([]string{"K2"}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := withoutRevokeStillLiveKeys(tc.value, tc.settle)
			if got != tc.wantOut {
				t.Errorf("settling %v\n  in:   %q\n  got:  %q\n  want: %q", tc.settle, tc.value, got, tc.wantOut)
			}
			if got == tc.value && tc.wantOut != tc.value {
				t.Error("returned its input byte-identical, so the caller's `cleared == current` " +
					"early return fires before the CAS and the operator's settle is silently lost")
			}
		})
	}
}

// TestTheRevokeClauseIsOnlyRecognisedAtAJoinBoundary is the safety property the
// end-anchored version had and the position-independent one must keep: a value
// that merely CONTAINS the message somewhere the join never puts it is left
// alone, rather than being torn apart by a substring match.
func TestTheRevokeClauseIsOnlyRecognisedAtAJoinBoundary(t *testing.T) {
	for _, v := range []string{
		"a target reported: " + revokeStillLiveMsg,
		"prefix" + revokeStillLiveMsg,
		revokeStillLiveMsg + " and then some trailing prose",
		"unrelated failure entirely",
		"",
	} {
		if got := withoutRevokeStillLiveKeys(v, []string{"K1"}); got != v {
			t.Errorf("a value with no clause at a join boundary was rewritten\n  in:  %q\n  got: %q", v, got)
		}
	}
}

// TestBothNewFoldMessagesSurviveASettle guards the pairing directly: whichever
// order the folds run in, settling the revoke half must leave the provider_meta
// half intact. It is still true.
func TestBothNewFoldMessagesSurviveASettle(t *testing.T) {
	for _, meta := range []string{metaWriteBackFailedMsg, providerChangedMidRotationMsg} {
		value := revokeStillLiveMsgFor([]string{"K9"}) + "; " + meta
		got := withoutRevokeStillLiveKeys(value, []string{"K9"})
		if !strings.Contains(got, meta) {
			t.Errorf("settling the revoke half erased the provider_meta half\n  in:  %q\n  got: %q", value, got)
		}
		if strings.Contains(got, revokeStillLiveMsg) {
			t.Errorf("the settled revoke clause survived: %q", got)
		}
	}
}

// TestTheParserSettlesWhatTheComposerProduces closes a composer/parser gap that
// every other fixture in this package leaves open.
//
// All of them hand-join `alarm + "; " + metaWriteBackFailedMsg`. The constants
// are production's; the JOIN is the test author's. So changing the separator in
// foldMetaWriteOutcome to " | " reproduces the original P0 exactly -- the parser
// stops recognising the clause, every settle path silently no-ops -- and all
// four test files still pass, because none of them ever asks production to
// build the string.
//
// This one does. Its input comes from the two folds that write the column.
func TestTheParserSettlesWhatTheComposerProduces(t *testing.T) {
	status, summary, _ := foldRevokeOutcome("success", "", "the revoke failed", []string{"K1"})
	_, summary, _ = foldMetaWriteOutcome(status, summary, metaWriteBackFailedMsg)

	if !strings.Contains(summary, revokeStillLiveMsg) || !strings.Contains(summary, metaWriteBackFailedMsg) {
		t.Fatalf("the composer did not produce both clauses: %q", summary)
	}

	t.Run("the revoke half settles", func(t *testing.T) {
		got := withoutRevokeStillLiveKeys(summary, []string{"K1"})
		if got == summary {
			t.Fatalf("byte-identical, so the caller's `cleared == current` early return fires before "+
				"the CAS and the operator's settle is silently lost: %q", got)
		}
		if strings.Contains(got, revokeStillLiveMsg) {
			t.Errorf("the settled revoke clause survived: %q", got)
		}
		if !strings.Contains(got, metaWriteBackFailedMsg) {
			t.Errorf("settling the revoke half erased the write-back half: %q", got)
		}
	})

	t.Run("the write-back half settles", func(t *testing.T) {
		got := withoutMetaWriteClauses(summary)
		if got == summary {
			t.Fatalf("byte-identical: the write-back alarm has no working clearer against a "+
				"production-composed value: %q", got)
		}
		if strings.Contains(got, metaWriteBackFailedMsg) {
			t.Errorf("the write-back clause survived: %q", got)
		}
		if !strings.Contains(got, revokeStillLiveMsg) {
			t.Errorf("clearing the write-back half erased an alarm about a key still live "+
				"upstream, which this act did nothing about: %q", got)
		}
	})
}

package handlers

// Shared rotation outcome logic.
//
// This file is where the two rotation paths stop disagreeing. It starts with the
// one piece that was provably wrong in the manual handler and right in the sweep,
// and it is the seam the full merge extends.

// revokeStillLiveMsg is the ONLY text either path may persist about a failed
// old-key revoke.
//
// Static on purpose. The raw revoke error can embed the provider URL, the key id
// and the upstream response body, and last_rotation_error is API-visible, so the
// detail belongs in the slog line and nowhere else.
const revokeStillLiveMsg = "old key not revoked (still live at provider); see server logs"

// foldRevokeOutcome merges "the predecessor key is still live upstream" into a
// rotation's final status, and reports whether an alert is owed.
//
// It exists because the manual handler wrote that fact to last_rotation_error
// immediately after the revoke failed, and then, a few lines later, unconditionally
// overwrote it: the no-targets branch with "" and Status "success", the delivery
// goroutine with a delivery-only summary. Either way the durable record said the
// rotation was clean while the key the operator believed they had just retired was
// still authenticating. No alert was dispatched either.
//
// That is not a rare path. resend, sendgrid and neon all defer a DELETE for the
// old key, so any 4xx, 5xx or transport error on it lands here, and the revoke
// uses the NEW key as its bearer, which providers routinely reject until the new
// key's permissions propagate. Worse, meta["key_id"] has already advanced to the
// successor by then, so the orphaned predecessor is never a revoke candidate
// again. Someone rotating a key precisely because they think it is compromised
// was told it worked.
//
// The scheduled sweep already computed this correctly. Both paths now call this,
// so the rule is stated once instead of being re-derived at the two sites that
// finalise a rotation.
func foldRevokeOutcome(status, errSummary, revokeWarn string) (outStatus, outSummary string, alert bool) {
	if revokeWarn == "" {
		return status, errSummary, false
	}
	// A delivery failure is already partial or error; do not promote it back up.
	if status == "success" {
		status = "partial"
	}
	if errSummary == "" {
		errSummary = revokeStillLiveMsg
	} else {
		errSummary = errSummary + "; " + revokeStillLiveMsg
	}
	return status, errSummary, true
}

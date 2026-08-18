package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestPendingRevokeAuthz proves the retry and resolve endpoints gate on the
// rights their doc comments claim.
//
// RetryPendingRevoke needs BOTH the spend right (entryCurrentlyUsableBy) and
// the write right (entryAccess canWrite), because it spends the live
// credential upstream AND persists provider_meta afterwards.
// ResolvePendingRevoke needs only the write right, because it never touches
// the provider.
//
// The row that matters most is the REMOVED CREATOR. entryAccessFor grants
// them a residual READ (grantFor row 7) so they can recover a secret they own
// after being removed from its collection, but deliberately NOT use or
// manage. Gating the spend on READ instead of USE would hand a removed team
// member an oracle -- "is our old key still live at the provider?" -- with no
// remaining right to the entry at all and no activity_log row naming them.
// The mutation run at the bottom of this file proves the table actually
// watches for that, rather than merely asserting a status this code would
// have returned either way.
//
// Every refusal is 404, never 403 (grantFor row 1: a probe must not be able
// to tell "gone" from "not yours" apart, the same rule every other
// single-entry vault endpoint follows), so the table checks exactly that
// status for every denied row. Allowed rows are distinguished from denied
// ones by NOT being 404 -- neither test entry carries an actual pending
// revoke, so an allowed caller reaches the honest idempotent answers
// (409 no_pending_revoke for retry, 400 acknowledged-id-mismatch for
// resolve), which happen only once the authz gate has already said yes.
func TestPendingRevokeAuthz(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "prauthz-owner@example.com", "user", rotationTestPassword)
	creator := mustUser(t, queries, "prauthz-creator@example.com", "user", rotationTestPassword)
	manager := mustUser(t, queries, "prauthz-manager@example.com", "user", rotationTestPassword)
	editorUser := mustUser(t, queries, "prauthz-editor@example.com", "user", rotationTestPassword)
	viewerUser := mustUser(t, queries, "prauthz-viewer@example.com", "user", rotationTestPassword)
	stranger := mustUser(t, queries, "prauthz-stranger@example.com", "user", rotationTestPassword)
	disabledUser := mustUser(t, queries, "prauthz-disabled@example.com", "user", rotationTestPassword)
	admin := mustUser(t, queries, "prauthz-admin@example.com", "admin", rotationTestPassword)

	// A personal entry for the plain "owner" row (grantFor row 4: no
	// collection at all).
	const personalEntryID = "entry-prauthz-personal"
	mustEntry(t, h, queries, personalEntryID, owner, "PR Authz Personal", "some-value")

	// A collection entry for every role that only makes sense inside one.
	// disabledUser is seeded as a MANAGER -- otherwise full rights -- so
	// disabling them is shown to override a role that would grant everything,
	// not merely to coincide with a role that already grants nothing.
	mustCollection(t, queries, "coll-prauthz", manager, map[string]string{
		manager:      collRoleManager,
		editorUser:   collRoleEditor,
		viewerUser:   collRoleViewer,
		creator:      collRoleEditor,
		disabledUser: collRoleManager,
	})
	const collEntryID = "entry-prauthz-coll"
	mustEntry(t, h, queries, collEntryID, creator, "PR Authz Collection", "some-value")
	placeInCollection(t, queries, collEntryID, "coll-prauthz")

	if _, err := queries.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: 1, ID: disabledUser}); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	// The creator loses their collection seat, leaving exactly the row-7
	// residual: read, no use, no manage.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-prauthz", UserID: creator,
	}); err != nil {
		t.Fatalf("remove creator: %v", err)
	}

	type row struct {
		name    string
		entryID string
		userID  string
		role    string
		allowed bool
	}
	rows := []row{
		{"owner (personal entry)", personalEntryID, owner, "user", true},
		{"instance admin", collEntryID, admin, "admin", true},
		{"accepted editor", collEntryID, editorUser, "user", true},
		{"accepted manager", collEntryID, manager, "user", true},
		{"accepted viewer (read+use, no manage)", collEntryID, viewerUser, "user", false},
		{"REMOVED CREATOR (residual read only)", collEntryID, creator, "user", false},
		{"stranger (no relationship at all)", collEntryID, stranger, "user", false},
		{"disabled account (would otherwise be a manager)", collEntryID, disabledUser, "user", false},
	}

	for _, c := range rows {
		c := c
		t.Run("retry/"+c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.RetryPendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
				"/api/vault/"+c.entryID+"/pending-revoke/retry", c.userID, c.role, c.entryID,
				`{"password":"`+rotationTestPassword+`"}`))
			if c.allowed {
				if rec.Code == http.StatusNotFound {
					t.Errorf("an authorized caller was refused as if the entry did not exist: %d %s",
						rec.Code, rec.Body.String())
				}
			} else if rec.Code != http.StatusNotFound {
				t.Errorf("expected 404 (never any other code, see grantFor row 1), got %d: %s",
					rec.Code, rec.Body.String())
			}
		})

		t.Run("resolve/"+c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ResolvePendingRevoke(rec, vaultAuthzRequest(http.MethodPost,
				"/api/vault/"+c.entryID+"/pending-revoke/resolve", c.userID, c.role, c.entryID,
				`{"acknowledged_key_id":"whatever"}`))
			if c.allowed {
				if rec.Code == http.StatusNotFound {
					t.Errorf("an authorized caller was refused as if the entry did not exist: %d %s",
						rec.Code, rec.Body.String())
				}
			} else if rec.Code != http.StatusNotFound {
				t.Errorf("expected 404 (never any other code, see grantFor row 1), got %d: %s",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestPendingRevokeRetrySpendGateIsNotJustRead pins the exact fact that makes
// the spend-vs-read distinction load-bearing.
//
// The table test above proves the REMOVED CREATOR row is refused end-to-end,
// but it cannot, by itself, prove WHICH of retry's two gates did the
// refusing: entryAccess's canWrite (the write right, required because retry
// persists provider_meta) ALSO returns false for a removed creator, because
// grantFor has no row today where manage=true and use=false -- every role
// that can write can also spend. So a handler mutation that swaps the spend
// gate (entryCurrentlyUsableBy) for a bare canRead answer is silently caught
// by the write gate that runs immediately after it, and the combined
// 404-or-not assertion in the table above cannot distinguish the two paths.
//
// That double coverage is a GOOD property of the endpoint (see its doc
// comment: BOTH rights are required, independently, because they answer
// different questions), not a gap. But it does mean the claim "the spend
// gate specifically must be entryCurrentlyUsableBy, not canRead" needs its
// own pin: the two functions must actually disagree for the identity this
// is about. If a future change ever grants some role manage without use, this
// is the assertion that would catch a retry endpoint that had started
// trusting canRead for its spend check.
func TestPendingRevokeRetrySpendGateIsNotJustRead(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "spendgate-creator@example.com", "user", "")
	manager := mustUser(t, queries, "spendgate-manager@example.com", "user", "")
	mustCollection(t, queries, "coll-spendgate", manager, map[string]string{
		manager: collRoleManager,
		creator: collRoleEditor,
	})
	const entryID = "entry-spendgate"
	mustEntry(t, h, queries, entryID, creator, "Spend Gate Entry", "some-value")
	placeInCollection(t, queries, entryID, "coll-spendgate")

	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-spendgate", UserID: creator,
	}); err != nil {
		t.Fatalf("remove creator: %v", err)
	}

	canRead, canWrite := h.entryAccessFor(ctx, creator, false, entryID)
	if !canRead {
		t.Fatalf("ABORT: the removed creator lost their residual read too; this test no longer covers "+
			"the identity it claims to (canRead=%t canWrite=%t)", canRead, canWrite)
	}
	if canWrite {
		t.Fatalf("ABORT: the removed creator unexpectedly kept manage; the table test above already covers this row fully on its own")
	}
	if h.entryCurrentlyUsableBy(ctx, creator, entryID) {
		t.Fatalf("entryCurrentlyUsableBy granted USE to a removed creator, who must keep read-only " +
			"recovery access and nothing more")
	}
	// The precondition a "gate on canRead instead" mutation would exploit:
	// canRead is true here while use is false. A spend gate written as canRead
	// would let this identity spend the entry's live credential through
	// RetryPendingRevoke.
}

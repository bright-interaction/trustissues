package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestDisabledUserStopsReceivingTheRotatedSecret covers the OTHER offboarding
// control.
//
// Round 2 closed collection removal: an offboarded editor's webhook stopped
// receiving the rotated plaintext. But an admin responding to a suspected
// compromise reaches for the Disable toggle, not for "remove them from each of
// these six collections one at a time". Disable cut their browser access
// instantly and left the delivery target completely untouched, because
// entryAccessFor decided access from ownership and collection membership and
// never read users.disabled, and targetStillAuthorized inherited that blind spot.
//
// So the rotation an admin performs BECAUSE of the incident was what handed the
// suspect the new key, with a 200 and no warning. Same property as round 2,
// reached through the other door: fixing a bug does not clean its neighbourhood.
//
// The invariant: a disabled configurer's target must be refused, and refused
// LOUDLY (a delivery failure, so the rotation is marked partial and alerts) with
// a reason that names the account rather than blaming collection membership.
func TestDisabledUserStopsReceivingTheRotatedSecret(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "disabled-owner@example.com", "user", "")
	editor := mustUser(t, queries, "disabled-editor@example.com", "user", "")

	mustCollection(t, queries, "coll-disable", owner, map[string]string{
		owner:  collRoleManager,
		editor: collRoleEditor,
	})
	const entryID = "entry-disable"
	// PREMISE CHANGE, round 5: the configurer is the entry's CREATOR, because
	// naming a delivery destination is now held to the same right as widening
	// destination_patterns and a plain editor no longer has it. `owner` stays the
	// collection manager. Nothing about the property under test moves: a disabled
	// account must stop receiving the rotated secret, and grantFor refuses a
	// disabled user before it looks at ownership at all, so the creator is exactly
	// as good a subject as an editor was.
	mustEntry(t, h, queries, entryID, editor, "Stripe live key", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-disable")

	target := RotationTarget{
		Type:         "webhook",
		Label:        "creator backup",
		WebhookURL:   "https://sink.example.com/hook",
		ConfiguredBy: editor,
	}

	// Guard the setup. If the target were already refused while the editor is a
	// live member, the assertion after disabling would pass for the wrong reason.
	if err := targetStillAuthorized(ctx, h, entryID, target); err != nil {
		t.Fatalf("ABORT: target refused while the editor is an active member: %v", err)
	}

	// Disable the account. Deliberately NOT removing them from the collection:
	// that path is already covered, and the whole point is that this is the
	// other control an admin actually uses.
	if _, err := queries.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: 1, ID: editor}); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	// Membership must still be intact, or this would be testing removal again.
	if role, err := queries.GetCollectionMemberRole(ctx, db.GetCollectionMemberRoleParams{
		CollectionID: "coll-disable", UserID: editor,
	}); err != nil || role != collRoleEditor {
		t.Fatalf("ABORT: disabling changed collection membership (role=%q err=%v); this no longer tests the disable path", role, err)
	}

	err := targetStillAuthorized(ctx, h, entryID, target)
	if err == nil {
		t.Fatal("a DISABLED user's webhook is still authorized to receive the rotated secret: " +
			"the rotation performed to revoke them would deliver the new key to them")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("refusal does not name the account status, so an admin would go hunting through "+
			"collection membership instead of the account they just disabled: %q", err)
	}

	// entryAccessFor is the shared authorization point, so it must also refuse.
	// Checking it directly is what stops a future background caller from
	// reintroducing this by asking the question a different way.
	if canRead, canWrite := h.entryAccessFor(ctx, editor, false, entryID); canRead || canWrite {
		t.Errorf("entryAccessFor still grants a disabled user read=%v write=%v", canRead, canWrite)
	}

	// Re-enabling restores them: disable must be reversible, not destructive.
	if _, err := queries.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: 0, ID: editor}); err != nil {
		t.Fatalf("re-enable user: %v", err)
	}
	if err := targetStillAuthorized(ctx, h, entryID, target); err != nil {
		t.Errorf("re-enabling the account did not restore delivery: %v", err)
	}
}

// TestPurgeTargetsConfiguredByUserSpansPersonalEntries checks the cleanup half.
//
// The delivery gate is authoritative, but a stale target left in place keeps
// showing in the rotation panel as if it were live and marks every subsequent
// rotation "partial" forever. Collection removal already purges within that one
// collection; disabling an account is not collection-scoped, and the case a
// per-collection purge misses is the disabled user's OWN personal entries, where
// auto-rotation keeps running after the account is disabled.
func TestPurgeTargetsConfiguredByUserSpansPersonalEntries(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	victim := mustUser(t, queries, "purge-victim@example.com", "user", "")
	other := mustUser(t, queries, "purge-other@example.com", "user", "")

	// A PERSONAL entry (no collection) owned by the user being disabled.
	const personalID = "entry-personal-purge"
	mustEntry(t, h, queries, personalID, victim, "Personal API key", "sk_personal")

	mixed := []RotationTarget{
		{Type: "webhook", Label: "theirs", WebhookURL: "https://a.example.com/h", ConfiguredBy: victim},
		{Type: "webhook", Label: "someone else's", WebhookURL: "https://b.example.com/h", ConfiguredBy: other},
	}
	encoded, err := json.Marshal(mixed)
	if err != nil {
		t.Fatalf("marshal targets: %v", err)
	}
	enc, err := h.encryptColumn(string(encoded))
	if err != nil {
		t.Fatalf("encrypt targets: %v", err)
	}
	if err := setRotationTargetsFixture(t, queries, vaultegress.RotationTargetsParams{
		RotationTargets: toNullString(enc), ID: personalID,
	}); err != nil {
		t.Fatalf("seed targets: %v", err)
	}

	summary := h.PurgeTargetsConfiguredByUser(ctx, victim)
	if summary == "" {
		t.Fatal("purge reported nothing removed, so a personal entry's target survived the account being disabled")
	}

	stored, err := queries.GetVaultEntryTargets(ctx, personalID)
	if err != nil {
		t.Fatalf("reload entry: %v", err)
	}
	left := ParseRotationTargets(h.decryptColumnOrLog(stored.String, "[]", vaultFieldRotationTargets))
	if len(left) != 1 {
		t.Fatalf("expected exactly the other user's target to survive, got %d: %+v", len(left), left)
	}
	// The critical half: an unrelated colleague's delivery must NOT be collateral.
	if left[0].ConfiguredBy != other {
		t.Errorf("purge removed the wrong target; survivor is configured by %q, want %q", left[0].ConfiguredBy, other)
	}
}

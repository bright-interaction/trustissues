package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestOffboardedMemberStopsReceivingTheRotatedSecret locks the fix for the worst
// offboarding hole found in round 2.
//
// A collection editor can configure rotation delivery targets on an entry they
// do not own. Removing them from the collection deleted only the membership
// row: the stored rotation_targets survived, and DeliverRotatedKey never looked
// at who configured them (only forgejo_secret consulted ConfiguredBy, and only
// to resolve its auth_token). So an offboarded editor's webhook kept receiving
// the plaintext secret, and the rotation performed to revoke their access was
// exactly what delivered the new value to them.
//
// The invariant: after removal, a rotation must NOT reach their endpoint, and
// the refusal must be visible as a delivery failure rather than a silent skip.
func TestOffboardedMemberStopsReceivingTheRotatedSecret(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "owner@example.com", "user", "")
	editor := mustUser(t, queries, "editor@example.com", "user", "")

	mustCollection(t, queries, "coll-pay", owner, map[string]string{
		owner:  collRoleManager,
		editor: collRoleEditor,
	})
	const entryID = "entry-stripe"
	// PREMISE CHANGE, round 5: the configurer is the entry's CREATOR. Naming a
	// delivery destination is now held to the same right as widening
	// destination_patterns, so a plain editor cannot configure one at all and
	// targetStillAuthorized asks the same question at delivery. The property is
	// unchanged and still the serious one: someone who could legitimately
	// configure delivery, and is then offboarded, must stop receiving the secret,
	// and the rotation performed to revoke them must not be what hands them the
	// new value.
	mustEntry(t, h, queries, entryID, editor, "Stripe live key", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-pay")

	// The editor's sink. Records anything delivered to it.
	var received []string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = append(received, string(b))
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	targets := []RotationTarget{{
		Type:         "webhook",
		Label:        "backup",
		WebhookURL:   sink.URL,
		ConfiguredBy: editor,
	}}

	// Guard the setup: while the editor IS a member the target must be
	// authorized, otherwise the post-removal refusal below would pass for the
	// wrong reason (e.g. an unattributed target, or a broken entry id).
	//
	// This asserts the authorization decision rather than driving a real HTTP
	// delivery: the outbound guard in alerts blocks loopback addresses, so a
	// httptest sink can never actually be reached from the delivery path. The
	// network leg is not what is under test here; who is allowed to receive is.
	if err := targetStillAuthorized(ctx, h, entryID, targets[0]); err != nil {
		t.Fatalf("ABORT: target not authorized while the editor is still a member: %v", err)
	}

	// Offboard them.
	rm, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-pay", UserID: editor,
	})
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if n, _ := rm.RowsAffected(); n != 1 {
		t.Fatalf("ABORT: removal affected %d rows", n)
	}

	// THE ATTACK: rotate, which is the documented revocation step.
	res := DeliverRotatedKey(ctx, queries, h, entryID, "Stripe live key",
		h.MintedEntrySecret([]byte("old"), entryID, "Stripe live key"),
		h.MintedEntrySecret([]byte("sk_live_ROTATED_NEW"), entryID, "Stripe live key"), targets, owner)

	if len(received) != 0 {
		t.Fatalf("OFFBOARDING FAILED: the removed editor's endpoint received the post-rotation secret: %v", received)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 delivery result, got %d", len(res))
	}
	if res[0].Success {
		t.Fatal("delivery to a removed member's target reported SUCCESS")
	}
	// It must surface, not vanish: a silent skip would hide the offboarding gap.
	if status, summary := summarizeDelivery(res); status != "partial" || summary == "" {
		t.Fatalf("refused target did not surface as a partial rotation: status=%q summary=%q", status, summary)
	}
	// And the refusal reason must not leak the secret.
	if strings.Contains(res[0].Error, "sk_live_ROTATED_NEW") {
		t.Fatalf("the refusal message leaked the secret: %q", res[0].Error)
	}
}

// TestUnattributedTargetIsRefused pins the fail-closed default. Targets predate
// ConfiguredBy, so an unattributed one cannot be shown to belong to anyone with
// current access; delivering to it would ship a live secret to an address nobody
// can vouch for.
func TestUnattributedTargetIsRefused(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "o@example.com", "user", "")
	const entryID = "entry-legacy"
	mustEntry(t, h, queries, entryID, owner, "Legacy", "v")

	var hit bool
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	res := DeliverRotatedKey(ctx, queries, h, entryID, "Legacy",
		h.MintedEntrySecret([]byte("old"), entryID, "Legacy"),
		h.MintedEntrySecret([]byte("new"), entryID, "Legacy"),
		[]RotationTarget{{Type: "webhook", WebhookURL: sink.URL}}, owner)

	if hit {
		t.Fatal("an unattributed target received the secret")
	}
	if len(res) != 1 || res[0].Success {
		t.Fatalf("unattributed target was not refused: %+v", res)
	}
	if !strings.Contains(res[0].Error, "configurer") && !strings.Contains(res[0].Error, "re-save") {
		t.Fatalf("refusal gives the operator no way forward: %q", res[0].Error)
	}
}

// TestPurgeDropsOnlyTheDepartingMembersTargets proves the cleanup half is
// surgical: the leaver's endpoint goes, everyone else's stays.
func TestPurgeDropsOnlyTheDepartingMembersTargets(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "owner@example.com", "user", "")
	leaver := mustUser(t, queries, "leaver@example.com", "user", "")
	mustCollection(t, queries, "coll-x", owner, map[string]string{
		owner: collRoleManager, leaver: collRoleEditor,
	})
	const entryID = "entry-mixed"
	mustEntry(t, h, queries, entryID, owner, "Shared", "v")
	placeInCollection(t, queries, entryID, "coll-x")

	mixed := []RotationTarget{
		{Type: "webhook", Label: "keep", WebhookURL: "https://ok.example.com/h", ConfiguredBy: owner},
		{Type: "webhook", Label: "drop", WebhookURL: "https://leaver.example.com/h", ConfiguredBy: leaver},
	}
	raw, _ := json.Marshal(mixed)
	enc, err := h.encryptColumn(string(raw))
	if err != nil {
		t.Fatalf("encrypt targets: %v", err)
	}
	if err := setRotationTargetsFixture(t, queries, vaultegress.RotationTargetsParams{
		RotationTargets: toNullString(enc), ID: entryID,
	}); err != nil {
		t.Fatalf("store targets: %v", err)
	}

	ch := NewCollectionHandler(queries, h)
	summary := ch.purgeTargetsConfiguredBy(ctx, "coll-x", leaver)
	if summary == "" {
		t.Fatal("purge reported nothing removed")
	}

	row, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("reread: %v", err)
	}
	after := ParseRotationTargets(h.decryptColumnOrLog(row.RotationTargets.String, "[]", vaultFieldRotationTargets))
	if len(after) != 1 {
		t.Fatalf("expected 1 surviving target, got %d: %+v", len(after), after)
	}
	if after[0].Label != "keep" || after[0].ConfiguredBy != owner {
		t.Fatalf("the WRONG target survived: %+v", after[0])
	}
}

package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
)

// TestRemovedMemberCannotResolveSharedSecretByName closes the EIGHTH door onto
// the offboarding property, and this one exfiltrates the live plaintext.
//
// ResolveVaultReference matched on (name, user_id). user_id is the CREATOR
// column, not a statement of current access: removing somebody from a collection
// deletes only their collection_members row, so an entry they created keeps
// their id forever.
//
// So a removed member could put a forgejo_secret target on their OWN personal
// entry (they always have write on a personal entry), set
// auth_token = "the shared secret", point instance at a host they control, and
// rotate their own entry. Delivery resolved the auth_token as them, matched the
// shared entry they had created, and POSTed the CURRENT post-rotation plaintext
// as an Authorization header. The activity log recorded only vault.rotated for
// the carrier entry and never named the secret that left.
//
// The residual-owner READ that entryAccessFor grants does not open this: no HTTP
// surface turns it into plaintext (unlock is membership-scoped, there is no
// per-entry reveal route). This path was the only one that did.
func TestRemovedMemberCannotResolveSharedSecretByName(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	mallory := mustUser(t, queries, "mallory@example.com", "user", "")
	manager := mustUser(t, queries, "ref-manager@example.com", "user", "")

	mustCollection(t, queries, "coll-ref", manager, map[string]string{
		manager: collRoleManager,
		mallory: collRoleEditor,
	})
	// Mallory CREATED the shared secret, so vault_entries.user_id is hers forever.
	const sharedID = "entry-shared-ref"
	mustEntry(t, h, queries, sharedID, mallory, "prod-db", "ORIGINAL-VALUE")
	placeInCollection(t, queries, sharedID, "coll-ref")

	// Guard the setup: while she is a member the reference must resolve, or the
	// post-removal assertion proves nothing.
	if v, err := h.resolveVaultReferenceFor(ctx, "prod-db", mallory); err != nil || string(v) != "ORIGINAL-VALUE" {
		t.Fatalf("ABORT: an active member cannot resolve the shared secret (err=%v)", err)
	}

	// Offboard her. Only the membership row goes; the entry keeps her user_id.
	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-ref", UserID: mallory,
	}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// Confirm the precondition the bug depended on is still true, so this test
	// keeps testing the real shape rather than silently becoming vacuous.
	if owner, err := queries.GetVaultEntryOwner(ctx, sharedID); err != nil || owner != mallory {
		t.Fatalf("ABORT: the entry no longer carries the removed member as user_id (owner=%q err=%v)", owner, err)
	}

	if v, err := h.resolveVaultReferenceFor(ctx, "prod-db", mallory); err == nil {
		t.Errorf("a REMOVED member resolved the shared secret's plaintext: %q\n"+
			"a forgejo_secret auth_token on her own personal entry would deliver this to a host she controls", string(v))
	}

	// The manager, who is still a member, must be unaffected. This is not the
	// creator, so it also proves the gate follows access rather than ownership.
	if _, err := h.resolveVaultReferenceFor(ctx, "prod-db", manager); err != nil {
		t.Errorf("a current collection manager can no longer resolve the shared secret: %v", err)
	}
}

// TestAmbiguousVaultReferenceIsRefused guards the consequence of deciding access
// in Go instead of filtering by the creator column: a name can now match more
// than one entry the caller can reach.
//
// Refusing is the point. Silently picking one means the operator cannot tell
// which credential was spent, and for a rotation target that means a live
// third-party key goes somewhere nobody can audit. Same call the capability
// bridge makes for ambiguous secret names.
func TestAmbiguousVaultReferenceIsRefused(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	user := mustUser(t, queries, "ambig@example.com", "user", "")
	other := mustUser(t, queries, "ambig-other@example.com", "user", "")
	mustCollection(t, queries, "coll-ambig", user, map[string]string{
		user:  collRoleManager,
		other: collRoleEditor,
	})

	// A personal entry, and a same-named one in a collection the user belongs to.
	// UNIQUE(user_id, name) does not prevent this: the collection copy has a
	// different creator.
	mustEntry(t, h, queries, "amb-personal", user, "shared-name", "PERSONAL")
	mustEntry(t, h, queries, "amb-collection", other, "shared-name", "COLLECTION")
	placeInCollection(t, queries, "amb-collection", "coll-ambig")

	v, err := h.resolveVaultReferenceFor(ctx, "shared-name", user)
	if err == nil {
		t.Fatalf("an ambiguous reference silently resolved to %q; the operator cannot tell which credential was spent", string(v))
	}
	if !errors.Is(err, errAmbiguousVaultReference) {
		t.Errorf("ambiguity was reported as %v, which does not tell the operator what to fix", err)
	}

	// `other` reaches only the collection copy (the personal one is not theirs),
	// so their reference is unambiguous and must still resolve.
	got, err := h.resolveVaultReferenceFor(ctx, "shared-name", other)
	if err != nil {
		t.Fatalf("an unambiguous reference stopped resolving: %v", err)
	}
	if string(got) != "COLLECTION" {
		t.Errorf("resolved the wrong entry: %q", string(got))
	}
}

// TestPendingInviteeCannotUseCollectionSecret pins the consent property against
// the newest gate.
//
// entryCurrentlyUsableBy is the right that lets a caller SPEND a credential, and
// it decides collection membership through GetCollectionMemberRole. That query
// filters accepted_at IS NOT NULL, so an unaccepted invite grants nothing. This
// test exists because that is a property of a query the gate merely calls: if
// someone later swaps in a raw membership lookup for speed, consent silently
// stops being enforced on the path that hands out plaintext.
func TestPendingInviteeCannotUseCollectionSecret(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "consent-owner@example.com", "user", "")
	invitee := mustUser(t, queries, "consent-invitee@example.com", "user", "")

	mustCollection(t, queries, "coll-consent", owner, map[string]string{owner: collRoleManager})
	const entryID = "entry-consent"
	mustEntry(t, h, queries, entryID, owner, "team-secret", "TEAM-VALUE")
	placeInCollection(t, queries, entryID, "coll-consent")

	// Invite without accepting: AddCollectionMember leaves accepted_at NULL.
	if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
		CollectionID: "coll-consent", UserID: invitee, Role: collRoleEditor,
	}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	// Guard the fixture: the row must exist, or this passes for the wrong reason.
	if _, err := queries.GetCollectionMembership(ctx, db.GetCollectionMembershipParams{
		CollectionID: "coll-consent", UserID: invitee,
	}); err != nil {
		t.Fatalf("ABORT: no membership row was created, so the pending state is not under test: %v", err)
	}

	if h.entryCurrentlyUsableBy(ctx, invitee, entryID) {
		t.Error("a PENDING invitee can spend a collection secret; adding someone to a collection " +
			"would grant credential use before they ever consented")
	}
	if _, err := h.resolveVaultReferenceFor(ctx, "team-secret", invitee); err == nil {
		t.Error("a PENDING invitee resolved the shared secret's plaintext")
	}

	// After accepting, they can. Otherwise this test would pass on a gate that
	// simply refuses everyone.
	if _, err := queries.AcceptCollectionInvite(ctx, db.AcceptCollectionInviteParams{
		CollectionID: "coll-consent", UserID: invitee,
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !h.entryCurrentlyUsableBy(ctx, invitee, entryID) {
		t.Error("an ACCEPTED member cannot spend the collection secret; the gate refuses everyone")
	}
}

// TestRemovedMemberCannotValidateSharedKey closes the NINTH door.
//
// ValidateKey was the last entryAccess site gated on canRead. It decrypts the
// stored value and authenticates with it against the provider, so it is a live
// USE of the credential rather than a look at metadata. entryAccessFor grants a
// removed creator a residual read, so after removal they kept an oracle: ask
// "is the team's key valid?", have the server spend it upstream on their behalf,
// and learn every rotation, with no activity_log row for it.
func TestRemovedMemberCannotValidateSharedKey(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "val-creator@example.com", "user", "")
	manager := mustUser(t, queries, "val-manager@example.com", "user", "")
	mustCollection(t, queries, "coll-val", manager, map[string]string{
		manager: collRoleManager,
		creator: collRoleEditor,
	})
	const entryID = "entry-val"
	mustEntry(t, h, queries, entryID, creator, "Cloudflare", "cf-token")
	placeInCollection(t, queries, entryID, "coll-val")

	// Guard: while a member, the spend right holds.
	if !h.entryCurrentlyUsableBy(ctx, creator, entryID) {
		t.Fatal("ABORT: an active editor cannot use the entry, so removal proves nothing")
	}

	if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-val", UserID: creator,
	}); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// The residual READ must survive (that is deliberate, for recovery)...
	if canRead, _ := h.entryAccessFor(ctx, creator, false, entryID); !canRead {
		t.Error("the residual recovery read was removed; that is a separate, wanted property")
	}
	// ...but the SPEND right must not.
	if h.entryCurrentlyUsableBy(ctx, creator, entryID) {
		t.Error("a removed member can still spend the shared credential: ValidateKey would " +
			"authenticate upstream with it and hand them a validity oracle")
	}
	// The manager, still a member, is unaffected.
	if !h.entryCurrentlyUsableBy(ctx, manager, entryID) {
		t.Error("a current manager lost the ability to validate the key")
	}
}

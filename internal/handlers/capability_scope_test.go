package handlers

import (
	"context"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestCapabilityLookupIsCollectionScoped locks the THIRD door onto the same
// offboarding property.
//
// entryAccess is documented as "the single authorization point for every
// single-entry operation; do not bypass it with a raw owner check", and two
// earlier rounds closed a residual write right and a surviving rotation webhook
// to make "remove the member, then rotate" actually end their access.
//
// The capability bridge bypassed all of it. lookupSecretByName matched on
// user_id alone, so a member removed from a collection was still the entry's
// user_id and could keep minting tokens; the proxy then injected the CURRENT,
// post-rotation value upstream. They disappeared from the vault UI and from
// unlock while retaining live USE of the credential.
//
// The same raw check broke it in the other direction too: a current viewer or
// editor, who legitimately has access, could not mint at all because they are
// not the user_id.
func TestCapabilityLookupIsCollectionScoped(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "creator@example.com", "user", "")
	editor := mustUser(t, queries, "editor@example.com", "user", "")
	stranger := mustUser(t, queries, "stranger@example.com", "user", "")

	mustCollection(t, queries, "coll-team", editor, map[string]string{
		editor:  collRoleManager,
		creator: collRoleEditor,
	})
	const entryID = "entry-shared"
	mustEntry(t, h, queries, entryID, creator, "Shared prod key", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-team")
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["api.stripe.com/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("seed ceiling: %v", err)
	}

	ch := &CapabilityHandler{db: h.db, vault: h}

	// Guard the setup: while a member, the creator must resolve. If not, the
	// post-removal assertion below would pass for the wrong reason.
	if _, err := ch.lookupSecretByName(ctx, creator, "Shared prod key"); err != nil {
		t.Fatalf("ABORT: creator cannot resolve while still a member: %v", err)
	}
	// A fellow member must also resolve: the raw owner check used to 404 here,
	// which broke the feature for everyone except the creator.
	if _, err := ch.lookupSecretByName(ctx, editor, "Shared prod key"); err != nil {
		t.Fatalf("a current collection member cannot mint for a shared secret: %v", err)
	}
	// A complete outsider must never resolve.
	if _, err := ch.lookupSecretByName(ctx, stranger, "Shared prod key"); err == nil {
		t.Fatal("a non-member resolved a collection secret for minting")
	}

	// Offboard the creator.
	res, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
		CollectionID: "coll-team", UserID: creator,
	})
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("ABORT: removal affected %d rows", n)
	}

	// THE BUG: they are still the user_id, so the old lookup still found it.
	if _, err := ch.lookupSecretByName(ctx, creator, "Shared prod key"); err == nil {
		t.Fatal("REVOCATION FAILED: a removed member can still mint a capability token for the shared secret; " +
			"rotating it would just hand them the new value through the proxy")
	}
	// Destination-based resolution is the same code path and must agree.
	if _, err := ch.lookupSecretByDestination(ctx, creator, "api.stripe.com/v1/charges"); err == nil {
		t.Fatal("REVOCATION FAILED via lookupSecretByDestination")
	}
	// The remaining member keeps working.
	if _, err := ch.lookupSecretByName(ctx, editor, "Shared prod key"); err != nil {
		t.Fatalf("removing one member broke minting for another: %v", err)
	}

	// And MCP must stop advertising it, or the agent is offered a secret it can
	// no longer obtain.
	names, err := queries.ListAccessibleVaultEntryNames(ctx, db.ListAccessibleVaultEntryNamesParams{
		UserID: creator, UserID_2: creator,
	})
	if err != nil {
		t.Fatalf("list accessible names: %v", err)
	}
	for _, n := range names {
		if n == "Shared prod key" {
			t.Fatal("list_secrets still advertises the shared secret to a removed member")
		}
	}
}

// TestPersonalSecretsStillResolve guards the common case: the scoping change
// must not break the ordinary personal-vault path, which is most entries.
func TestPersonalSecretsStillResolve(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "o@example.com", "user", "")
	other := mustUser(t, queries, "x@example.com", "user", "")

	const entryID = "entry-personal"
	mustEntry(t, h, queries, entryID, owner, "My key", "v")
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["api.openai.com/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("seed ceiling: %v", err)
	}

	ch := &CapabilityHandler{db: h.db, vault: h}
	if _, err := ch.lookupSecretByName(ctx, owner, "My key"); err != nil {
		t.Fatalf("owner cannot mint for their own personal secret: %v", err)
	}
	if _, err := ch.lookupSecretByName(ctx, other, "My key"); err == nil {
		t.Fatal("another user resolved someone's personal secret")
	}
	if _, err := ch.lookupSecretByDestination(ctx, owner, "api.openai.com/v1/chat"); err != nil {
		t.Fatalf("owner cannot resolve their personal secret by destination: %v", err)
	}
}

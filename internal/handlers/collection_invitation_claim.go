package handlers

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/emailidentity"
)

// claimCollectionInvitations turns the collection seats recorded for an email
// address into PENDING memberships for a freshly created account.
//
// Why this exists: collection seats are keyed by the invited EMAIL so that a
// pending invitation looks identical whether or not the address has an account
// (see migration 00033). That closed the enumeration oracle and opened a hole at
// the other end. collection_members.user_id is a foreign key, so an invite to an
// address with no account produced a seat and nothing else, and nothing ever
// converted it: the invitee signed up, GET /api/collections/invitations returned
// [], POST /api/collections/{id}/accept answered 404 "no pending invitation for
// this collection", and the manager kept looking at a pending row that could
// never resolve. Reproduced end to end. Invite the client, they register, they
// join IS the onboarding flow this work exists to enable, so a seat that cannot
// be redeemed is worse than the silent drop it replaced: it lies to the manager.
//
// Every account-creation path calls this, and
// TestEveryAccountCreationPathClaimsCollectionInvitations fails when a new one
// does not. It is the same one-property-many-doors shape the capability bridge
// had: a single missed writer puts the product back in the broken state.
//
// The seat row STAYS. It is what ListMembers renders as the pending entry, and
// deleting it here would change that entry's shape the moment the address
// registered, which hands back the account-existence answer by another route.
// AcceptInvite, DeclineInvite, RemoveMember and RescindInvitation clear it when
// the invitation is actually answered.
//
// The membership is created PENDING, never accepted: an invitation must still be
// consented to, and a brand-new account silently joining a stranger's collection
// is exactly what the consent rule refuses.
func claimCollectionInvitations(ctx context.Context, queries *db.Queries, userID, email string) (int, error) {
	// Seats and account identities use one canonical representation. Matching
	// through the shared helper keeps Unicode addresses on the same path as the
	// ASCII addresses SQLite's built-in lower() happens to understand.
	seats, err := queries.ListCollectionInvitationsForEmail(ctx, emailidentity.Canonical(email))
	if err != nil {
		return 0, err
	}
	claimed := 0
	for _, seat := range seats {
		if err := queries.AddCollectionMember(ctx, db.AddCollectionMemberParams{
			CollectionID: seat.CollectionID,
			UserID:       userID,
			Role:         seat.Role,
			AcceptedAt:   sql.NullTime{}, // pending: the new user still has to accept
			InvitedBy:    seat.InvitedBy,
		}); err != nil {
			return claimed, err
		}
		claimed++
	}
	return claimed, nil
}

// claimCollectionInvitationsBestEffort runs the claim and logs a failure without
// taking the account creation down with it.
//
// The account is the important write and it has already succeeded by the time
// this runs; a failed claim leaves the invitation exactly where it was (a seat
// the manager can re-send), which is recoverable, while failing the registration
// is not.
func claimCollectionInvitationsBestEffort(ctx context.Context, queries *db.Queries, userID, email string) {
	n, err := claimCollectionInvitations(ctx, queries, userID, email)
	if err != nil {
		slog.Error("collections: could not claim pending invitations for a new account",
			"user_id", userID, "error", err)
		return
	}
	if n > 0 {
		slog.Info("collections: claimed pending invitations for a new account", "user_id", userID, "seats", n)
	}
}

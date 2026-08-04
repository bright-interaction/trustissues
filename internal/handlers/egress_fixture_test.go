package handlers

import (
	"context"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// FIXTURE WRITES TO THE HOST-CHOOSING COLUMNS.
//
// Test fixtures used to call queries.UpdateVaultEntryDestinationPatterns and
// friends straight off *db.Queries. Those methods do not exist any more: the
// statements that write destination_patterns, provider, provider_meta and
// rotation_targets are generated into internal/vaultegress/internal/egressq,
// which Go's `internal` rule makes unimportable from this package, and the only
// exported way in demands an egressgate.Ticket.
//
// That applies to tests too, deliberately. A fixture that could reach the raw
// query would be a second door held open in the name of convenience, and the
// suite is where a second door is least likely to be noticed.
//
// These helpers are honest about what they are. They act as a principal who IS
// allowed to redirect the secret (the entry's creator, in every fixture that
// uses them), so the oracle is a constant true, written in code, once, here.
// What they cannot do is skip the ticket.
//
// A fixture that means to plant a row the way an older binary or a restored
// backup would writes it with raw SQL instead, and several do. That is not a
// loophole, it is the threat model: those rows are exactly why
// targetStillAuthorized re-asks the authority question at DELIVERY.

// fixtureEgressTicket mints a ticket for a fixture write on one entry and one
// field, with the oracle answering yes.
func fixtureEgressTicket(t *testing.T, entryID, field string) egressgate.Ticket {
	t.Helper()
	tk, err := egressgate.Decide(egressgate.Request{
		EntryID: entryID,
		What:    field,
		// Stated rather than elided: a fixture that seeds a ceiling or a
		// delivery target IS adding a destination, and it says so.
		After:       []string{"fixture:" + field},
		MayRedirect: func() bool { return true },
	})
	if err != nil {
		t.Fatalf("fixture egress ticket for %s on %s: %v", field, entryID, err)
	}
	return tk
}

// setDestinationPatternsFixture is the fixture form of "the owner sets this
// entry's capability ceiling".
func setDestinationPatternsFixture(t *testing.T, q *db.Queries,
	p vaultegress.DestinationPatternsParams) error {

	t.Helper()
	return vaultegress.SetDestinationPatterns(context.Background(), q,
		fixtureEgressTicket(t, p.ID, vaultegress.FieldDestinations), p)
}

// setProviderFixture is the fixture form of "the owner sets this entry's
// provider configuration".
func setProviderFixture(t *testing.T, q *db.Queries, p vaultegress.ProviderParams) error {
	t.Helper()
	return vaultegress.SetProvider(context.Background(), q,
		fixtureEgressTicket(t, p.ID, vaultegress.FieldProvider), p)
}

// setRotationTargetsFixture is the fixture form of "the entry's creator
// configures delivery".
func setRotationTargetsFixture(t *testing.T, q *db.Queries, p vaultegress.RotationTargetsParams) error {
	t.Helper()
	return vaultegress.SetRotationTargets(context.Background(), q,
		fixtureEgressTicket(t, p.ID, vaultegress.FieldRotationTargets), p)
}

// createVaultEntryFixture is the fixture form of "a user creates an entry". The
// row carries the caller's own user_id, so the principal the oracle would name
// is the caller, exactly as in VaultHandler.Create.
//
// SecretOwnerUserID defaults to UserID here for the same reason Create sets them
// equal: at creation the custodian and the owner ARE the same principal, and
// they diverge only when a collection manager later adopts the entry. A fixture
// that left the owner empty would be modelling a row no creating statement in
// the product can produce (TestEveryRowCreatingStatementNamesTheSecretOwner
// proves that), so tests built on it would be testing a state that cannot exist.
func createVaultEntryFixture(t *testing.T, q *db.Queries, p vaultegress.CreateEntryParams) error {
	t.Helper()
	if p.SecretOwnerUserID == "" {
		p.SecretOwnerUserID = p.UserID
	}
	return vaultegress.CreateEntry(context.Background(), q,
		fixtureEgressTicket(t, p.ID, vaultegress.FieldProvider), p)
}

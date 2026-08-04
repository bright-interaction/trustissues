// Package forgeaticket builds an authorization instead of earning one.
//
// egressgate.Ticket has no exported fields and one constructor, so "I forgot to
// ask" and "I asked and was allowed" cannot be spelled the same way. A composite
// literal naming its fields does not compile outside package egressgate.
package forgeaticket

import (
	"context"
	"database/sql"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

func Bypass(ctx context.Context, q *db.Queries, entryID, targets string) error {
	forged := egressgate.Ticket{
		entryID: entryID,
		what:    vaultegress.FieldRotationTargets,
		granted: true,
	}
	return vaultegress.SetRotationTargets(ctx, q, forged, vaultegress.RotationTargetsParams{
		RotationTargets: sql.NullString{String: targets, Valid: true},
		ID:              entryID,
	})
}

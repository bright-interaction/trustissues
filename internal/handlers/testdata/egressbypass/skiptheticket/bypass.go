// Package skiptheticket calls the chokepoint wrapper and declines to ask
// anybody for permission first.
//
// The Ticket is a parameter, not a convention, so this is an arity error.
package skiptheticket

import (
	"context"
	"database/sql"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

func Bypass(ctx context.Context, q *db.Queries, entryID, targets string) error {
	return vaultegress.SetRotationTargets(ctx, q, vaultegress.RotationTargetsParams{
		RotationTargets: sql.NullString{String: targets, Valid: true},
		ID:              entryID,
	})
}

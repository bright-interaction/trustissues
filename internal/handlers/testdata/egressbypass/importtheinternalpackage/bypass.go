// Package importtheinternalpackage reaches for the generated egress queries
// directly, which is the shortest possible bypass: skip the wrapper, skip the
// ticket, call the statement.
//
// Go's `internal` rule refuses it. That rule is the reason the queries live at
// internal/vaultegress/internal/egressq rather than in internal/db.
package importtheinternalpackage

import (
	"context"
	"database/sql"

	"github.com/bright-interaction/trustissues/internal/vaultegress/internal/egressq"
)

func Bypass(ctx context.Context, conn *sql.DB, entryID, targets string) error {
	return egressq.New(conn).UpdateVaultEntryRotationTargets(ctx,
		egressq.UpdateVaultEntryRotationTargetsParams{
			RotationTargets: sql.NullString{String: targets, Valid: true},
			ID:              entryID,
		})
}

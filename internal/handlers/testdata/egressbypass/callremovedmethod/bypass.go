// Package callremovedmethod is the round-5 defect written out literally.
//
// VaultHandler.UpdateTargets called exactly this, with no authority check, and a
// vault_only account holding an accepted EDITOR seat on somebody else's shared
// entry pointed a rotation webhook at a host it controlled. The next scheduled
// rotation POSTed the freshly minted plaintext there.
//
// *db.Queries no longer has the method.
package callremovedmethod

import (
	"context"
	"database/sql"

	"github.com/bright-interaction/trustissues/internal/db"
)

func Bypass(ctx context.Context, q *db.Queries, entryID, targets string) error {
	return q.UpdateVaultEntryRotationTargets(ctx, db.UpdateVaultEntryRotationTargetsParams{
		RotationTargets: sql.NullString{String: targets, Valid: true},
		ID:              entryID,
	})
}

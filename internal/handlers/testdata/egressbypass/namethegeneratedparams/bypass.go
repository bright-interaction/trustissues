// Package namethegeneratedparams tries to route around the wrapper's own
// parameter type by naming the generated one, which is the shape a developer
// reaches for when the two structs look redundant.
//
// The generated params live in the internal package, so they are unnameable
// here for the same reason the queries are uncallable.
package namethegeneratedparams

import (
	"database/sql"

	"github.com/bright-interaction/trustissues/internal/vaultegress/internal/egressq"
)

var Params = egressq.UpdateVaultEntryRotationTargetsParams{
	RotationTargets: sql.NullString{String: "[]", Valid: true},
	ID:              "entry",
}

package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

// LoginAttemptRetention is how long a login_attempts row is kept.
//
// Nothing reads one older than 15 minutes. The per-email and per-IP lockout
// counts both use `datetime('now', '-15 minutes')`, vault.reauthLocked reuses
// the per-email count, and ListRecentLoginAttemptsByEmail has no callers.
// TestLoginAttemptRetentionOutlivesEveryReader derives those windows from the
// query file and fails if this constant ever stops exceeding the longest one,
// so adding a query that looks back further is caught rather than silently
// starved of rows.
//
// 24 hours rather than the 15 minutes correctness alone would allow, because an
// operator looking at a suspected credential-stuffing run wants the day's shape,
// not the last quarter hour. Rather than 30 days, because the rows are plaintext
// email plus source IP, they are the one thing an unauthenticated caller can
// write into this database, and a keyless backup reveals them (THREAT-MODEL R8).
// The real audit trail for logins is activity_log, which is append-only and
// unaffected by this sweep.
const LoginAttemptRetention = 24 * time.Hour

// loginAttemptSweepInterval is how often the sweep runs. Well under the
// retention window, so a row outlives its usefulness by at most an hour.
const loginAttemptSweepInterval = time.Hour

// PruneLoginAttempts deletes login_attempts rows older than
// LoginAttemptRetention and returns how many went.
func PruneLoginAttempts(ctx context.Context, queries *db.Queries) (int64, error) {
	// SQLite datetime modifier, negative so it reaches into the past. Minutes
	// rather than hours so the unit matches the readers this is checked against.
	modifier := fmt.Sprintf("-%d minutes", int(LoginAttemptRetention.Minutes()))
	res, err := queries.PruneLoginAttempts(ctx, modifier)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// RunLoginAttemptRetention sweeps expired login_attempts rows until ctx is
// cancelled. Runs once at startup so a deployment that has been accumulating
// rows since before this existed is cleaned on the first boot that has it,
// rather than an hour later.
func RunLoginAttemptRetention(ctx context.Context, queries *db.Queries) {
	sweep := func() {
		n, err := PruneLoginAttempts(ctx, queries)
		if err != nil {
			slog.Error("login-attempt janitor: sweep failed", "error", err)
			return
		}
		if n > 0 {
			slog.Info("login-attempt janitor: pruned expired rows",
				"count", n, "retention", LoginAttemptRetention.String())
		}
	}

	sweep()

	ticker := time.NewTicker(loginAttemptSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

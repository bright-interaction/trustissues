package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/brightinteraction/trustissues/internal/alerts"
	"github.com/brightinteraction/trustissues/internal/db"
)

// expiryCheckInterval is how often the reminder worker looks for secrets
// approaching their expires_at. Daily: one reminder per day per entry is
// signal, hourly repeats would be noise.
const expiryCheckInterval = 24 * time.Hour

// expiryInitialDelay is the pause before the first check after boot.
const expiryInitialDelay = 2 * time.Minute

// RunExpiryReminders is the background worker that dispatches
// vault.secret_expiring alerts for entries whose expires_at falls within the
// admin-configured rotation_reminder_days window. Call from main.go:
//
//	go handlers.RunExpiryReminders(ctx, queries, dispatcher)
//
// where ctx is the server's shutdown context. A rotation_reminder_days
// setting of 0 disables reminders.
func RunExpiryReminders(ctx context.Context, queries *db.Queries, dispatcher *alerts.ChannelDispatcher) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(expiryInitialDelay):
	}
	checkExpiringSecrets(ctx, queries, dispatcher)

	ticker := time.NewTicker(expiryCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkExpiringSecrets(ctx, queries, dispatcher)
		}
	}
}

func checkExpiringSecrets(ctx context.Context, queries *db.Queries, dispatcher *alerts.ChannelDispatcher) {
	checkCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	windowDays := settingInt(checkCtx, queries, "rotation_reminder_days", defaultRotationReminderDays)
	if windowDays <= 0 {
		return
	}

	rows, err := queries.ListExpiringVaultEntries(checkCtx, fmt.Sprintf("%d", windowDays))
	if err != nil {
		slog.Error("expiry reminders: query failed", "error", err)
		return
	}

	for _, row := range rows {
		expires := ""
		if row.ExpiresAt.Valid {
			expires = row.ExpiresAt.Time.UTC().Format(time.RFC3339)
		}
		slog.Warn("vault secret expiring soon", "entry", row.Name, "expires_at", expires)
		dispatcher.Dispatch(alerts.EventSecretExpiring, row.Name, "", map[string]string{
			"expires_at":  expires,
			"window_days": fmt.Sprintf("%d", windowDays),
		})
	}
}

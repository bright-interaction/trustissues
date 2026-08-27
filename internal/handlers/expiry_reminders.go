package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
)

// expiryCheckInterval is how often the reminder worker looks for secrets
// approaching their expires_at. Daily: one reminder per day per entry is
// signal, hourly repeats would be noise.
const expiryCheckInterval = 24 * time.Hour

// expiryInitialDelay is the pause before the first check after boot.
const expiryInitialDelay = 2 * time.Minute

// entryNameOpener opens a stored vault_entries.name. *VaultHandler satisfies it
// via EntryNamePlain.
//
// The worker takes this rather than the whole vault handler because opening the
// label is the only vault-key-derived thing it does, and an expiry reminder must
// never be a door to an entry's VALUE.
type entryNameOpener interface {
	EntryNamePlain(stored string) string
}

// alertDispatcher is the send seam. *alerts.ChannelDispatcher satisfies it.
// It exists so a test can observe what an expiry reminder actually PUTS on the
// wire, which is the only way to catch a name that was never opened: the bug is
// invisible from the database and from the return value, and shows up only in
// the payload an operator's webhook receives.
type alertDispatcher interface {
	DispatchGuarded(event, source, host string, data map[string]string, guard alerts.DeliveryGuard)
}

// RunExpiryReminders is the background worker that dispatches
// vault.secret_expiring alerts for entries whose expires_at falls within the
// admin-configured rotation_reminder_days window. Call from main.go:
//
//	go handlers.RunExpiryReminders(ctx, queries, vaultHandler, dispatcher)
//
// where ctx is the server's shutdown context. A rotation_reminder_days
// setting of 0 disables reminders.
func RunExpiryReminders(ctx context.Context, queries *db.Queries, names entryNameOpener, dispatcher *alerts.ChannelDispatcher) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(expiryInitialDelay):
	}
	checkExpiringSecrets(ctx, queries, names, dispatcher)

	ticker := time.NewTicker(expiryCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkExpiringSecrets(ctx, queries, names, dispatcher)
		}
	}
}

func checkExpiringSecrets(ctx context.Context, queries *db.Queries, names entryNameOpener, dispatcher alertDispatcher) {
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
		// Opened once, before either sink. The stored column has been enc:v1:
		// ciphertext since 00040, and this name is the ENTIRE identifying content
		// of the alert: the payload carries no entry id, so an operator whose
		// webhook received the raw column had no way to tell which of their
		// secrets was about to expire. It read as "some secret expires Tuesday".
		name := row.Name
		if names != nil {
			name = names.EntryNamePlain(row.Name)
		}
		slog.Warn("vault secret expiring soon", "entry", name, "expires_at", expires)
		if !entryAllowsExternalNotificationMetadata(checkCtx, queries, row.ID) {
			slog.Info("expiry reminders: external notification suppressed by fully-private policy",
				"entry_id", row.ID)
			continue
		}
		dispatcher.DispatchGuarded(alerts.EventSecretExpiring, name, "", map[string]string{
			"expires_at":  expires,
			"window_days": fmt.Sprintf("%d", windowDays),
		}, entryExternalNotificationDeliveryGuard(queries, row.ID))
	}
}

package handlers

import (
	"context"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
)

// entryExternalNotificationDeliveryGuard closes the queue-to-delivery policy
// race. Notification dispatch is asynchronous, so a collection can be promoted
// to fully_private after the caller's initial suppression check but before a
// channel goroutine sends its payload. Re-read at the final delivery boundary;
// the dispatcher does not hold a database transaction across network I/O.
func entryExternalNotificationDeliveryGuard(queries *db.Queries, entryID string) alerts.DeliveryGuard {
	return func(ctx context.Context) bool {
		return entryAllowsExternalNotificationMetadata(ctx, queries, entryID)
	}
}

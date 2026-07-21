-- name: ListEnabledNotificationChannels :many
SELECT id, name, type, config, config_nonce, encryption_version, events
FROM notification_channels
WHERE enabled = 1;

-- name: ListNotificationChannels :many
SELECT id, name, type, enabled, events, encryption_version, created_at, updated_at
FROM notification_channels
ORDER BY created_at ASC;

-- name: GetNotificationChannel :one
SELECT id, name, type, enabled, config, config_nonce, encryption_version, events
FROM notification_channels
WHERE id = ?;

-- name: CreateNotificationChannel :one
INSERT INTO notification_channels (name, type, enabled, config, config_nonce, encryption_version, events)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: UpdateNotificationChannelEnabled :execresult
UPDATE notification_channels
SET enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteNotificationChannel :execresult
DELETE FROM notification_channels WHERE id = ?;

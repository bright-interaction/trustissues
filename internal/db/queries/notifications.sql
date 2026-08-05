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

-- name: ListNotificationChannelConfigsForRekey :many
-- Channel configs are raw AES-GCM under the vault value key, with the nonce in
-- its own column and NO marker in the payload. encryption_version 0 means the
-- config was written before at-rest encryption and is plain JSON; the sweep must
-- see those rows too so it can report them rather than silently treat a
-- cleartext webhook URL (which can carry a bearer token) as already converted.
SELECT id, name, config, config_nonce, encryption_version
FROM notification_channels
ORDER BY id;

-- name: RekeyNotificationChannelConfig :exec
UPDATE notification_channels
SET config = ?, config_nonce = ?, encryption_version = ?
WHERE id = ?;

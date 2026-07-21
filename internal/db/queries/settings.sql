-- name: GetSetting :one
SELECT value FROM settings WHERE key = ?;

-- name: UpsertSetting :exec
INSERT INTO settings (key, value, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP;

-- name: GetSessionDurationSetting :one
SELECT value FROM settings WHERE key = 'session_duration_hours';

-- name: GetVaultAutoLockMaxMinutes :one
SELECT value FROM settings WHERE key = 'vault_auto_lock_max_minutes';

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

-- name: GetSessionIdleSetting :one
-- The HTTP session idle window, in minutes. Distinct from
-- vault_auto_lock_max_minutes, which governs how long a DECRYPTED vault stays
-- open in the browser: those are different security properties and sharing one
-- knob meant widening the vault auto-lock silently widened every session.
SELECT value FROM settings WHERE key = 'session_idle_minutes';

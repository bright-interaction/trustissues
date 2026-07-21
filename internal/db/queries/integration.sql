-- Integration-owned queries: activity export and admin user listing with
-- vault entry counts. Kept out of the platform-owned query files per the
-- CONTRACT.md rule (new queries go in new files).

-- name: ExportActivityEntries :many
SELECT a.id, a.user_id, u.email AS user_email, a.action, a.detail,
       a.ip_address, a.user_agent, a.created_at
FROM activity_log a
LEFT JOIN users u ON u.id = a.user_id
WHERE (CAST(@user_filter AS TEXT) = '' OR a.user_id = @user_filter)
  AND (CAST(@action_filter AS TEXT) = '' OR a.action = @action_filter)
ORDER BY a.created_at DESC;

-- name: ListUsersWithEntryCount :many
SELECT u.id, u.email, u.name, u.role, u.disabled, u.totp_enabled, u.created_at,
       (SELECT COUNT(*) FROM vault_entries v WHERE v.user_id = u.id) AS entry_count
FROM users u
ORDER BY u.created_at ASC;

-- name: CountVaultEntriesForUser :one
SELECT COUNT(*) FROM vault_entries WHERE user_id = ?;

-- name: SeedVaultEntryCapabilityDefaults :exec
-- Seeds the capability-bridge columns from the provider defaults at
-- enrollment time. Only fills untouched rows so explicit per-entry
-- patterns are never overwritten.
UPDATE vault_entries
SET destination_patterns = ?, injection_spec = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND destination_patterns = '[]' AND injection_spec = '{}';

-- name: ListExpiringVaultEntries :many
SELECT id, name, user_id, expires_at
FROM vault_entries
WHERE expires_at IS NOT NULL
  AND expires_at > datetime('now')
  AND expires_at <= datetime('now', '+' || CAST(@window_days AS TEXT) || ' days')
ORDER BY expires_at ASC;

-- name: InsertActivity :exec
INSERT INTO activity_log (user_id, action, detail, ip_address, user_agent)
VALUES (?, ?, ?, ?, ?);

-- name: ListActivityEntries :many
SELECT a.id, a.user_id, u.email AS user_email, a.action, a.detail,
       a.ip_address, a.user_agent, a.created_at
FROM activity_log a
LEFT JOIN users u ON a.user_id = u.id
ORDER BY a.created_at DESC, a.id DESC
LIMIT ? OFFSET ?;

-- name: ListActivityEntriesByAction :many
SELECT a.id, a.user_id, u.email AS user_email, a.action, a.detail,
       a.ip_address, a.user_agent, a.created_at
FROM activity_log a
LEFT JOIN users u ON a.user_id = u.id
WHERE a.action = ?
ORDER BY a.created_at DESC, a.id DESC
LIMIT ? OFFSET ?;

-- name: ListActivityEntriesByActionPrefix :many
-- See CountActivityEntriesByActionPrefix. Same ordering as the other list
-- queries so paging behaves identically.
SELECT a.id, a.user_id, u.email AS user_email, a.action, a.detail,
       a.ip_address, a.user_agent, a.created_at
FROM activity_log a
LEFT JOIN users u ON a.user_id = u.id
WHERE a.action LIKE ? ESCAPE '\'
ORDER BY a.created_at DESC, a.id DESC
LIMIT ? OFFSET ?;

-- name: ListActivityEntriesByUser :many
SELECT a.id, a.user_id, u.email AS user_email, a.action, a.detail,
       a.ip_address, a.user_agent, a.created_at
FROM activity_log a
LEFT JOIN users u ON a.user_id = u.id
WHERE a.user_id = ?
ORDER BY a.created_at DESC, a.id DESC
LIMIT ? OFFSET ?;

-- name: CountActivityEntries :one
SELECT COUNT(*) FROM activity_log;

-- name: CountActivityEntriesByAction :one
SELECT COUNT(*) FROM activity_log WHERE action = ?;

-- name: CountActivityEntriesByActionPrefix :one
-- Backs the "vault.*" style category filters. The UI has always offered them,
-- but the only filter query was an exact match, so every wildcard option
-- returned zero rows and looked like "nothing ever happened".
-- The caller passes the prefix WITHOUT the star (e.g. "vault."), and escapes
-- any LIKE metacharacters in it.
SELECT COUNT(*) FROM activity_log WHERE action LIKE ? ESCAPE '\';

-- name: CountActivityEntriesByUser :one
SELECT COUNT(*) FROM activity_log WHERE user_id = ?;

-- name: ListActivityEntriesFiltered :many
-- One query for all three filters, mirroring ExportActivityEntries.
--
-- The list endpoint used a switch whose FIRST arm was "a user is selected", so
-- picking a user silently discarded the action filter. The export twin already
-- combined them, which meant the table and the CSV of the same view returned
-- DIFFERENT rows: for an audit surface, two disagreeing answers is worse than
-- one wrong one.
SELECT a.id, a.user_id, u.email AS user_email, a.action, a.detail,
       a.ip_address, a.user_agent, a.created_at
FROM activity_log a
LEFT JOIN users u ON u.id = a.user_id
WHERE (CAST(@user_filter AS TEXT) = '' OR a.user_id = @user_filter)
  AND (
        (CAST(@action_filter AS TEXT) = '' AND CAST(@action_prefix AS TEXT) = '')
     OR (CAST(@action_prefix AS TEXT) != ''
         AND substr(a.action, 1, length(CAST(@action_prefix AS TEXT))) = CAST(@action_prefix AS TEXT))
     OR (CAST(@action_prefix AS TEXT) = '' AND a.action = @action_filter)
  )
-- Named params throughout. Mixing @named with positional ? made sqlc emit ELEVEN
-- placeholders for a call that passes five arguments, so every request to
-- GET /api/activity failed with "sql: expected 11 arguments, got 5" and the
-- admin audit log was entirely dead. Never mix the two styles in one query.
ORDER BY a.created_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: CountActivityEntriesFiltered :one
SELECT COUNT(*) FROM activity_log a
WHERE (CAST(@user_filter AS TEXT) = '' OR a.user_id = @user_filter)
  AND (
        (CAST(@action_filter AS TEXT) = '' AND CAST(@action_prefix AS TEXT) = '')
     OR (CAST(@action_prefix AS TEXT) != ''
         AND substr(a.action, 1, length(CAST(@action_prefix AS TEXT))) = CAST(@action_prefix AS TEXT))
     OR (CAST(@action_prefix AS TEXT) = '' AND a.action = @action_filter)
  );

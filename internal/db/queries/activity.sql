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

-- name: CountActivityEntriesByUser :one
SELECT COUNT(*) FROM activity_log WHERE user_id = ?;

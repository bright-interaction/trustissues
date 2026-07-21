-- name: CreateAPIKeyForUser :exec
INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListAPIKeysByUser :many
SELECT id, name, key_prefix, last_used_at, expires_at, created_at
FROM api_keys
WHERE user_id = ?
ORDER BY created_at DESC;

-- name: DeleteAPIKey :execresult
DELETE FROM api_keys WHERE id = ? AND user_id = ?;

-- name: DeleteAPIKeysByUser :exec
DELETE FROM api_keys WHERE user_id = ?;

-- name: CreateAPIKeyForUser :exec
INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListAPIKeysByUser :many
SELECT id, name, key_prefix, last_used_at, expires_at, revoked_at, created_at
FROM api_keys
WHERE user_id = ?
ORDER BY created_at DESC;

-- name: DeleteAPIKey :execresult
DELETE FROM api_keys WHERE id = ? AND user_id = ?;

-- name: DeleteAPIKeysByUser :exec
DELETE FROM api_keys WHERE user_id = ?;

-- Revocation by flag, not by DELETE, so the audit trail survives the incident.
-- COALESCE keeps the call idempotent: revoking an already-revoked key does not
-- move its timestamp and still reports a row, so a repeated incident-response
-- click cannot come back as a confusing 404.

-- name: RevokeAPIKey :execresult
UPDATE api_keys
SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
WHERE id = ? AND user_id = ?;

-- name: RevokeAPIKeysByUser :exec
UPDATE api_keys
SET revoked_at = CURRENT_TIMESTAMP
WHERE user_id = ? AND revoked_at IS NULL;

-- name: CreateLoginAttempt :exec
INSERT INTO login_attempts (email, ip_address, success)
VALUES (?, ?, ?);

-- name: CountRecentFailedLoginAttemptsByEmail :one
SELECT COUNT(*) FROM login_attempts
WHERE email = ? AND success = 0
  AND created_at > datetime('now', '-15 minutes');

-- name: CountRecentFailedLoginAttemptsByIP :one
SELECT COUNT(*) FROM login_attempts
WHERE ip_address = ? AND success = 0
  AND created_at > datetime('now', '-15 minutes');

-- name: ListRecentLoginAttemptsByEmail :many
SELECT id, email, ip_address, success, created_at
FROM login_attempts
WHERE email = ?
ORDER BY created_at DESC
LIMIT 20;

-- Server-side session records. A JWT carries the session id as its jti claim;
-- the auth middleware rejects any token whose session row is missing, revoked,
-- or idle past the configured window. This turns stateless JWTs into revocable
-- sessions so logout and inactivity kill a leaked token immediately.

-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, expires_at)
VALUES (?, ?, ?);

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
WHERE id = ? AND revoked_at IS NULL;

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
WHERE user_id = ? AND revoked_at IS NULL;

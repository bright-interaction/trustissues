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

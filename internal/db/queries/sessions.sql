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

-- name: PruneLoginAttempts :execresult
-- Retention sweep for login_attempts.
--
-- Nothing purged this table, so it accumulated a plaintext email and source IP
-- per attempt for the life of the deployment. It is the one table an
-- UNAUTHENTICATED caller can put a row of their choosing into, and since the
-- 2026-08-05 enumeration fix an address with no account writes a row too, so it
-- grows faster than it used to.
--
-- Deleting old rows costs nothing, because this table is a rate-limiting
-- mechanism and not an audit trail. Every live reader (the per-email and per-IP
-- lockout counts, and vault.reauthLocked which reuses the per-email one) looks
-- back exactly 15 minutes; ListRecentLoginAttemptsByEmail has no callers at all.
-- The actual audit trail for logins is activity_log, which is append-only and
-- tamper-evident and is not touched by this.
--
-- The window is passed in rather than baked here so one Go constant is the
-- single source of truth, and TestLoginAttemptRetentionOutlivesEveryReader can
-- derive the readers' windows from this file and prove the constant exceeds all
-- of them.
DELETE FROM login_attempts WHERE created_at < datetime('now', ?);

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

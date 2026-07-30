-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: CreateUser :one
INSERT INTO users (email, password_hash, name, role)
VALUES (?, ?, ?, ?)
RETURNING id, email, name, role, created_at;

-- name: CreateFirstAdmin :one
-- The first-run admin, created ONLY while the users table is empty.
--
-- Register used to read CountUsers, then decode the request body, then INSERT, with
-- no transaction and no recheck. The gap between the check and the write is not
-- instantaneous and it is ATTACKER-EXTENDABLE: the body decode sits inside it and the
-- server's ReadTimeout is 30s, so a client that trickles its body holds the window
-- open for as long as it likes.
--
-- Proven, not theorised: a request that passed the count==0 gate and then stalled
-- mid-body still created an account after a legitimate operator completed setup,
-- giving 2 users / 2 admins. Register is UNAUTHENTICATED and mints an ADMIN, so that
-- is a full takeover of a fresh instance by anyone who can reach it during setup.
--
-- The check and the insert are now one statement, so there is no window at all.
-- A caller that affects zero rows must treat that as "setup already completed".
INSERT INTO users (email, password_hash, name, role)
SELECT ?, ?, ?, 'admin'
WHERE NOT EXISTS (SELECT 1 FROM users)
RETURNING id, email, name, role, created_at;

-- name: GetUserByEmail :one
SELECT id, email, password_hash, name, role, disabled, created_at
FROM users WHERE email = ?;

-- name: GetUserByID :one
SELECT id, email, name, role, disabled, totp_enabled, created_at
FROM users WHERE id = ?;

-- name: ListUsers :many
SELECT id, email, name, role, disabled, totp_enabled, created_at
FROM users ORDER BY created_at ASC;

-- name: GetPasswordHashByUserID :one
SELECT password_hash FROM users WHERE id = ?;

-- name: GetUserEmailByID :one
SELECT email FROM users WHERE id = ?;

-- name: UpdatePasswordHash :exec
UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: InvalidateUserSessions :exec
UPDATE users SET sessions_valid_after = ? WHERE id = ?;

-- name: UpdateUserName :exec
UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateUserRole :execresult
UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: SetUserDisabled :execresult
UPDATE users SET disabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeleteUser :execresult
DELETE FROM users WHERE id = ?;

-- name: CountAdmins :one
SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0;

-- name: GetUserTOTPState :one
SELECT totp_enabled, totp_secret, totp_recovery_codes
FROM users WHERE id = ?;

-- name: GetTOTPSecret :one
SELECT totp_secret FROM users WHERE id = ?;

-- name: StoreTOTPSecret :exec
UPDATE users SET totp_secret = ? WHERE id = ?;

-- name: EnableTOTP :exec
UPDATE users SET totp_enabled = 1, totp_recovery_codes = ? WHERE id = ?;

-- name: DisableTOTP :exec
UPDATE users SET totp_enabled = 0, totp_secret = '', totp_recovery_codes = '' WHERE id = ?;

-- name: UpdateRecoveryCodes :exec
UPDATE users SET totp_recovery_codes = ? WHERE id = ?;

-- name: ListUsersWithTOTPSecret :many
SELECT id, totp_secret FROM users WHERE totp_secret != '';

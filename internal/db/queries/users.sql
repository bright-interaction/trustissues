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
-- Rewrites the hash only. Its one caller outside SetPasswordHash is the
-- transparent bcrypt-to-argon2id rehash on a successful login: that rewrites
-- the hash of a password the owner just typed, it does not set a new one, so
-- it must not touch password_set. See SetPasswordHash for the paths that do.
UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: SetPasswordHash :exec
-- Same write as UpdatePasswordHash, plus marking password_set so TOTPVerify
-- knows this account's owner can actually supply a password. Use this from
-- every path where a HUMAN is choosing the new password: change-password,
-- admin reset-password, and invitation redemption when a password was
-- supplied. See migration 00043.
UPDATE users SET password_hash = ?, password_set = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: SetInitialPasswordHash :execresult
-- Atomic one-time bootstrap. The handler's early password_set read is only a
-- cheap way to avoid hashing an already-initialized account; it cannot be the
-- authority because two holders of the invitation-minted API key can both read
-- zero before either expensive hash finishes. This compare-and-set makes one
-- request the winner and prevents the later request overwriting its password.
UPDATE users
SET password_hash = ?, password_set = 1, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND password_set = 0;

-- name: GetUserPasswordSet :one
-- 1 when a human has ever set a password this account's owner could supply;
-- 0 when the stored hash is a server-minted, immediately-discarded value
-- (password-less invitation redemption) that nobody, including the owner,
-- knows. See migration 00043 and TOTPVerify.
SELECT password_set FROM users WHERE id = ?;

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

-- name: CASRecoveryCodes :execresult
-- Compare-and-swap on the recovery-code list.
--
-- Consumption was a read-modify-write: read the JSON array, drop the used code, write
-- the whole column back. With a plain UPDATE that is a lost update, and each code is a
-- standalone 64-bit 2FA bypass, so a code the user has already redeemed and crossed off
-- their printed list stays a working second factor.
--
-- Two ways in: two concurrent logins each carrying a code both read before either
-- writes, and a failed persist that still completed the login. Comparing the column
-- itself means the second writer loses and retries against the winner's list.
UPDATE users SET totp_recovery_codes = ?
WHERE id = ? AND COALESCE(totp_recovery_codes, '') = ?;

-- name: ListUsersWithTOTPSecret :many
SELECT id, totp_secret FROM users WHERE totp_secret != '';

-- name: ClaimTOTPStep :execresult
-- Spend a TOTP time step, monotonically.
--
-- Affects zero rows when the step has already been used (or an older one is being
-- replayed), which is how a captured code stops being reusable inside its own window.
UPDATE users SET totp_last_step = ?
WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?);

-- name: UpdateUserRoleIfNotLastAdmin :execresult
-- Role change that REFUSES to remove the last active admin, atomically.
--
-- ensureNotLastAdmin was a check-then-act: COUNT(*) in one statement, the write
-- in another, with no transaction and no CAS between them. Two admins demoting
-- each other concurrently (or one admin demoted twice by two tabs) both saw
-- count = 2, both proceeded, and the instance was left with zero admins. Nothing
-- in the product can create one back: CreateFirstAdmin is gated on the users
-- table being empty, and every admin route needs an admin. The recovery is
-- hand-editing the database.
--
-- The guard travels WITH the write here, so the count and the update see the
-- same snapshot. RowsAffected = 0 means it was refused.
UPDATE users SET role = ?
WHERE users.id = ?
  AND (
    ? = 'admin'
    OR users.role != 'admin'
    OR users.disabled = 1
    OR (SELECT COUNT(*) FROM users AS a WHERE a.role = 'admin' AND a.disabled = 0) > 1
  );

-- name: SetUserDisabledIfNotLastAdmin :execresult
-- Disable that refuses to disable the last active admin. Same reasoning as
-- UpdateUserRoleIfNotLastAdmin.
UPDATE users SET disabled = ?
WHERE users.id = ?
  AND (
    ? = 0
    OR users.role != 'admin'
    OR users.disabled = 1
    OR (SELECT COUNT(*) FROM users AS a WHERE a.role = 'admin' AND a.disabled = 0) > 1
  );

-- name: UserHasProtectedCollectionImpact :one
-- Hard delete removes memberships and reassigns shared rows held by the target.
-- This cheap preflight avoids doing credential-revocation side effects before
-- the authoritative conditional DELETE below refuses a public request.
SELECT EXISTS (
  SELECT 1
  FROM collection_members cm
  JOIN collections c ON c.id = cm.collection_id
  WHERE cm.user_id = sqlc.arg('user_id') AND c.private_access_policy != 'standard'
  UNION ALL
  SELECT 1
  FROM vault_entries e
  JOIN collections c ON c.id = e.collection_id
  WHERE e.user_id = sqlc.arg('user_id') AND c.private_access_policy != 'standard'
);

-- name: DeleteUserIfNotLastAdmin :execresult
-- Hard delete refuses both the last active admin and, on public ingress, a user
-- whose removal would mutate protected collection authority or custody. The
-- policy predicate is on the DELETE itself so a concurrent policy promotion
-- cannot slip between a handler preflight and this destructive write.
DELETE FROM users
WHERE users.id = sqlc.arg('id')
  AND (
    users.role != 'admin'
    OR users.disabled = 1
    OR (SELECT COUNT(*) FROM users AS a WHERE a.role = 'admin' AND a.disabled = 0) > 1
  )
  AND (
    sqlc.arg('private_ingress') = 1
    OR NOT EXISTS (
      SELECT 1
      FROM collection_members cm
      JOIN collections c ON c.id = cm.collection_id
      WHERE cm.user_id = users.id AND c.private_access_policy != 'standard'
      UNION ALL
      SELECT 1
      FROM vault_entries e
      JOIN collections c ON c.id = e.collection_id
      WHERE e.user_id = users.id AND c.private_access_policy != 'standard'
    )
  );

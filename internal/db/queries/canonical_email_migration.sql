-- name: ListLoginAttemptEmailIdentitiesForCanonicalMigration :many
-- Migration 00046 must preserve every attempt row while bringing its lockout
-- key onto the same canonical representation as account login lookup.
SELECT id, email
FROM login_attempts
ORDER BY id;

-- name: UpdateLoginAttemptEmailForCanonicalMigration :exec
UPDATE login_attempts
SET email = @email
WHERE id = @id;

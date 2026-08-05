-- name: CreateInvitation :one
-- code holds the vault-key ciphertext (resend has to email the original), and
-- code_hash is what redemption looks up. See migration 00030.
INSERT INTO invitations (code, code_hash, email, name, target_role, created_by, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, code, email, name, status, target_role, expires_at, created_at;

-- name: ListInvitations :many
SELECT id, code, email, name, status, target_role, expires_at, created_at
FROM invitations
ORDER BY created_at DESC;

-- name: DeletePendingInvitation :execresult
DELETE FROM invitations WHERE id = ? AND status = 'pending';

-- name: GetInvitationForResend :one
SELECT id, code, email, name, status FROM invitations WHERE id = ?;

-- name: GetPendingInvitationByCode :one
-- Lookup is by HASH, never by the code itself: a leaked database must not
-- contain anything redeemable. Constant-shape and still O(1) via the unique
-- index on code_hash.
SELECT id, code, email, name, target_role, expires_at
FROM invitations
WHERE code_hash = ? AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP;

-- name: ExpireStaleInvitations :exec
UPDATE invitations SET status = 'expired'
WHERE status = 'pending' AND expires_at <= CURRENT_TIMESTAMP;

-- name: MarkInvitationRedeemed :exec
UPDATE invitations
SET status = 'redeemed', redeemed_by = ?, redeemed_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: GetUserIDByEmailForInvite :one
SELECT id FROM users WHERE email = ?;

-- name: CreateInvitedUser :one
INSERT INTO users (email, password_hash, name, role)
VALUES (?, ?, ?, ?)
RETURNING id;

-- name: ListInvitationCodesForRekey :many
-- Pending invitation codes are encrypted at rest with the vault handler's
-- enc:v1: column scheme so "resend invitation" can mail the original code. A
-- master-key rotation that skipped this column would leave every pending invite
-- unresendable, which reads as a broken feature rather than as a rotation bug.
SELECT id, code FROM invitations WHERE code != '' ORDER BY id;

-- name: RekeyInvitationCode :exec
UPDATE invitations SET code = ? WHERE id = ?;

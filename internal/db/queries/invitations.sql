-- name: CreateInvitation :one
INSERT INTO invitations (code, email, name, target_role, created_by, expires_at)
VALUES (?, ?, ?, ?, ?, ?)
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
SELECT id, code, email, name, target_role, expires_at
FROM invitations
WHERE code = ? AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP;

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

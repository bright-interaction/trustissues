-- +goose Up
-- +goose StatementBegin

-- Invitation codes were the ONLY live bearer credential stored in cleartext in
-- the database. Every sibling is protected: api_keys stores a SHA-256 hash,
-- service_identities stores key_hash, sessions store only a jti while the real
-- bearer is a JWT signed with a secret that never touches the DB.
--
-- That mattered because THREAT-MODEL.md tells operators a stolen .db without the
-- vault key "is safe to back up off-host". It was not: /api/invitations/redeem is
-- unauthenticated by design, so anyone holding a keyless backup taken while an
-- invite was pending could read the code out of it and redeem it against the live
-- server. If the invite was for an admin, that is a real account, and an admin can
-- reset another user's password and then unlock their vault. A copy documented as
-- inert became a path to every secret.
--
-- Two columns instead of one, because both properties are needed:
--   code_hash  SHA-256 of the code. Lookup is by hash, so a leaked database
--              yields no redeemable value and no preimage.
--   code       now holds the code encrypted under the vault key, because the
--              "resend invitation" feature has to email the original code and a
--              hash cannot be reversed.
ALTER TABLE invitations ADD COLUMN code_hash TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_code_hash
    ON invitations(code_hash) WHERE code_hash != '';

-- Every pending code that exists right now is already sitting in cleartext in
-- whatever backups have been taken, so it has to be treated as burned. Expiring
-- rather than deleting keeps the audit trail: an admin can see the invite existed
-- and re-issue it.
UPDATE invitations SET status = 'expired' WHERE status = 'pending';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_invitations_code_hash;
ALTER TABLE invitations DROP COLUMN code_hash;
-- +goose StatementEnd

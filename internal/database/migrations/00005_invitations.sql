-- +goose Up
-- Invitations for user onboarding (including vault_only extension users).
-- created_by/redeemed_by use ON DELETE SET NULL so deleting a user never
-- orphans historical invitation rows (copied from dockyard migration 00072).
CREATE TABLE invitations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    code TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'redeemed', 'expired')),
    target_role TEXT NOT NULL DEFAULT 'vault_only' CHECK(target_role IN ('admin', 'user', 'vault_only')),
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    redeemed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    redeemed_at DATETIME,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_invitations_code ON invitations(code);

-- +goose Down
DROP INDEX IF EXISTS idx_invitations_code;
DROP TABLE IF EXISTS invitations;

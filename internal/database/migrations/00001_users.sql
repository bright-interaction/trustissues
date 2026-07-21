-- +goose Up
-- Single-team user accounts. Roles:
--   admin      full access, sees every vault entry
--   user       regular member, owns their vault entries
--   vault_only locked to the vault UI (browser extension users)
CREATE TABLE users (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user', 'vault_only')),
  disabled INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT DEFAULT '',
  totp_enabled INTEGER DEFAULT 0,
  totp_recovery_codes TEXT DEFAULT '',
  -- Session revocation: a JWT whose iat (issued-at) is older than
  -- sessions_valid_after is rejected by the auth middleware. Bumped to the
  -- current time on a password change so a stolen token cannot outlive the
  -- password it was minted under. 0 means "no revocation point".
  sessions_valid_after INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down
DROP TABLE IF EXISTS users;

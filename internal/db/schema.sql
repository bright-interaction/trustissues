-- sqlc schema for Trustissues.
--
-- This file mirrors the embedded goose migrations in
-- internal/database/migrations/ (same pattern as dockyard). It exists so sqlc
-- can typecheck queries without parsing goose annotations or triggers.
--
-- RULE: when you add a migration (feature agents: 00010+), append the same
-- table/column definitions here in the SAME commit, then run `sqlc generate`.

-- 00001_users.sql
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
  sessions_valid_after INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 00002_sessions_api_keys.sql
CREATE TABLE login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  success INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  last_used_at DATETIME,
  expires_at DATETIME,
  -- 00026_api_key_revocation.sql
  revoked_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 00003_activity_log.sql
CREATE TABLE activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  detail TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 00004_settings.sql
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 00005_invitations.sql
CREATE TABLE invitations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    -- Vault-key ciphertext of the invite code (resend must email the original).
    -- Redemption looks up code_hash, never this. See migration 00030.
    code TEXT UNIQUE NOT NULL,
    code_hash TEXT NOT NULL DEFAULT '',
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

-- 00006_notification_channels.sql
CREATE TABLE notification_channels (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('webhook', 'slog')),
  enabled INTEGER DEFAULT 1,
  config TEXT NOT NULL DEFAULT '{}',
  config_nonce BLOB DEFAULT NULL,
  encryption_version INTEGER DEFAULT 0,
  events TEXT NOT NULL DEFAULT 'vault.rotation_partial,vault.rotation_failed,vault.secret_expiring',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 00023_collections.sql (shared team vaults; defined before vault_entries for
-- the collection_id foreign key).
CREATE TABLE collections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE collection_members (
  collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('viewer', 'editor', 'manager')),
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  accepted_at TIMESTAMP,
  -- Who actually sent this invitation (see migration 00031). Distinct from
  -- collections.created_by, which is who created the COLLECTION.
  invited_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (collection_id, user_id)
);
CREATE INDEX idx_collection_members_user ON collection_members(user_id);

-- 00010_vault.sql
CREATE TABLE vault_entries (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  encrypted_value BLOB NOT NULL,
  nonce BLOB NOT NULL,
  category TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  rotation_interval_days INTEGER,
  expires_at DATETIME,
  last_rotated_at DATETIME,
  url TEXT DEFAULT '',
  username TEXT DEFAULT '',
  encryption_version INTEGER DEFAULT 2,
  alias_url TEXT DEFAULT '',
  auto_login INTEGER NOT NULL DEFAULT 0,
  provider TEXT DEFAULT '',
  provider_meta TEXT DEFAULT '{}',
  auto_rotate INTEGER DEFAULT 0,
  rotation_log TEXT DEFAULT '[]',
  last_rotation_error TEXT DEFAULT '',
  rotation_targets TEXT DEFAULT '[]',
  destination_patterns TEXT NOT NULL DEFAULT '[]',
  injection_spec TEXT NOT NULL DEFAULT '{}',
  url_bidx TEXT NOT NULL DEFAULT '',
  alias_url_bidx TEXT NOT NULL DEFAULT '',
  collection_id TEXT REFERENCES collections(id) ON DELETE CASCADE,
  custom_fields TEXT NOT NULL DEFAULT '[]',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, name)
);

CREATE INDEX idx_vault_entries_url ON vault_entries(url) WHERE url != '';
CREATE INDEX idx_vault_entries_user ON vault_entries(user_id);
CREATE INDEX idx_vault_entries_collection ON vault_entries(collection_id) WHERE collection_id IS NOT NULL;

-- 00011_metadata_at_rest.sql (url/alias_url/username/category/notes encrypted at
-- rest; url_bidx/alias_url_bidx hold the keyed HMAC blind index for autofill).
CREATE INDEX idx_vault_entries_url_bidx ON vault_entries(url_bidx) WHERE url_bidx != '';
CREATE INDEX idx_vault_entries_alias_url_bidx ON vault_entries(alias_url_bidx) WHERE alias_url_bidx != '';

-- 00020_capability.sql (accessed via raw parameterized SQL in
-- internal/handlers/capability.go; mirrored here to keep this file a
-- faithful copy of the migrations)
CREATE TABLE capability_grants (
    agent_id    TEXT NOT NULL,
    secret_id   TEXT NOT NULL REFERENCES vault_entries(id) ON DELETE CASCADE,
    granted_by  TEXT NOT NULL DEFAULT '',
    granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at  TEXT,
    notes       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (agent_id, secret_id)
);
CREATE INDEX idx_capability_grants_secret ON capability_grants(secret_id);

CREATE TABLE capability_log (
    id           TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    secret_id    TEXT,
    secret_name  TEXT NOT NULL DEFAULT '',
    destination  TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT '',
    event        TEXT NOT NULL,
    status_code  INTEGER,
    error        TEXT NOT NULL DEFAULT '',
    nonce        TEXT NOT NULL DEFAULT '',
    issued_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_capability_log_agent ON capability_log(agent_id, issued_at DESC);
CREATE INDEX idx_capability_log_secret ON capability_log(secret_id, issued_at DESC);
CREATE INDEX idx_capability_log_nonce ON capability_log(nonce);

CREATE TABLE capability_spent_nonces (
    nonce       TEXT PRIMARY KEY,
    expires_at  TEXT NOT NULL
);
CREATE INDEX idx_capability_spent_nonces_expires ON capability_spent_nonces(expires_at);

-- 00021_service_identities.sql
CREATE TABLE service_identities (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,
    description        TEXT NOT NULL DEFAULT '',
    allowed_secrets    TEXT NOT NULL DEFAULT '[]',
    key_hash           TEXT NOT NULL,
    key_prefix         TEXT NOT NULL,
    last_used_at       DATETIME,
    expires_at         DATETIME,
    revoked_at         DATETIME,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_user_id TEXT
);
CREATE INDEX idx_service_identities_hash ON service_identities(key_hash);
CREATE INDEX idx_service_identities_name ON service_identities(name);

CREATE TABLE service_secret_audit (
    id                    TEXT PRIMARY KEY,
    service_identity_id   TEXT,
    service_name          TEXT NOT NULL DEFAULT '',
    event                 TEXT NOT NULL,
    secret_names          TEXT NOT NULL DEFAULT '[]',
    error                 TEXT NOT NULL DEFAULT '',
    remote_ip             TEXT NOT NULL DEFAULT '',
    occurred_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_service_secret_audit_identity ON service_secret_audit(service_identity_id, occurred_at DESC);
CREATE INDEX idx_service_secret_audit_event ON service_secret_audit(event, occurred_at DESC);

-- 00022_sessions.sql
-- Per-token server-side session records. A JWT carries its session id as the jti
-- claim; the auth middleware rejects any token whose session row is missing,
-- revoked, or idle past the configured window. expires_at is nullable so sqlc
-- types CreateSessionParams.ExpiresAt as sql.NullTime.
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME,
  revoked_at DATETIME
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

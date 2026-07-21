-- +goose Up
-- Consolidated vault_entries schema. This is the flattened equivalent of
-- dockyard's vault_entries after migrations 00009 (base table) + 00013
-- (url, username + partial url index) + 00014 (encryption_version) + 00015
-- (vault columns only: user_id, per-user UNIQUE(user_id, name), user index,
-- last_rotated_at default dropped, encryption_version default 2) + 00019
-- (alias_url) + 00023 (auto_login) + 00063 (provider, provider_meta,
-- auto_rotate, rotation_log, last_rotation_error) + 00064 (rotation_targets)
-- + 00069 (vault_entries columns only: destination_patterns, injection_spec).
--
-- encrypted_value/nonce hold the AES-256-GCM secret; encryption_version 2 is
-- the PBKDF2-SHA256 (600k) derived key, version 1 the legacy single-pass
-- SHA-256 key. provider_meta and rotation_targets are additionally encrypted
-- at rest with the enc:v1: column scheme (see vault_column_crypto.go).
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
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, name)
);

CREATE INDEX idx_vault_entries_url ON vault_entries(url) WHERE url != '';
CREATE INDEX idx_vault_entries_user ON vault_entries(user_id);

-- +goose Down
DROP INDEX IF EXISTS idx_vault_entries_user;
DROP INDEX IF EXISTS idx_vault_entries_url;
DROP TABLE IF EXISTS vault_entries;

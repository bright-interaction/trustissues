-- +goose Up
-- Notification channels for rotation and vault alerts. Trustissues ships two
-- channel types: webhook (HMAC-signed POST) and slog (structured log line,
-- always available, useful as a default sink). Config is encrypted at rest
-- when encryption_version > 0 (config_nonce carries the AES-GCM nonce).
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

-- +goose Down
DROP TABLE IF EXISTS notification_channels;

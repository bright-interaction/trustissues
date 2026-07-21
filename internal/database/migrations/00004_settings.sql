-- +goose Up
-- Global key/value settings (vault policy, SMTP for invitation emails,
-- session duration).
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vault policy: maximum minutes the vault stays unlocked before auto-lock.
INSERT INTO settings (key, value) VALUES ('vault_auto_lock_max_minutes', '15');

-- Session duration for issued JWTs, in hours (default 7 days).
INSERT INTO settings (key, value) VALUES ('session_duration_hours', '168');

-- SMTP settings for invitation emails (empty host disables email sending).
INSERT INTO settings (key, value) VALUES ('smtp_host', '');
INSERT INTO settings (key, value) VALUES ('smtp_port', '587');
INSERT INTO settings (key, value) VALUES ('smtp_from', '');
INSERT INTO settings (key, value) VALUES ('smtp_username', '');
INSERT INTO settings (key, value) VALUES ('smtp_password', '');
INSERT INTO settings (key, value) VALUES ('smtp_use_tls', 'true');

-- +goose Down
DROP TABLE IF EXISTS settings;

-- +goose Up
-- Login attempt tracking for lockout (5 failures per email / 15 min) and
-- per-IP credential stuffing limits.
CREATE TABLE login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  success INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_login_attempts_email ON login_attempts(email, created_at);
CREATE INDEX idx_login_attempts_ip ON login_attempts(ip_address, created_at);
CREATE INDEX idx_login_attempts_email_success_created
    ON login_attempts(email, success, created_at);

-- API keys for external API access (browser extension, CI, integrations).
-- Only a SHA-256 hash of the key is stored; the plaintext is shown once.
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  last_used_at DATETIME,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- +goose Down
DROP INDEX IF EXISTS idx_api_keys_hash;
DROP INDEX IF EXISTS idx_api_keys_user;
DROP TABLE IF EXISTS api_keys;
DROP INDEX IF EXISTS idx_login_attempts_email_success_created;
DROP INDEX IF EXISTS idx_login_attempts_ip;
DROP INDEX IF EXISTS idx_login_attempts_email;
DROP TABLE IF EXISTS login_attempts;

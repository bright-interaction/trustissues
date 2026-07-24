-- +goose Up
-- Shield: LLM-boundary tokenization. When an agent (Claude/ChatGPT) reaches the
-- vault through the AI gateway or the MCP boundary, PII in the data crossing to
-- the external model is replaced with opaque markers and resolved back to
-- plaintext server-side. These tables hold the per-connection token vault: one
-- shield_sessions row per MCP/gateway connection, and one shield_tokens row per
-- tokenized value, its ciphertext AES-256-GCM encrypted under TRUSTISSUES_SHIELD_KEY.
-- Accessed by internal/shield/store_sql.go via raw parameterized SQL (not sqlc).
-- Off by default: with no TRUSTISSUES_SHIELD_KEY set, shield is bypassed and
-- these tables stay empty.
CREATE TABLE shield_sessions (
  id          TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL
);
CREATE INDEX idx_shield_sessions_expires ON shield_sessions(expires_at);

CREATE TABLE shield_tokens (
  token       TEXT PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES shield_sessions(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  hint        TEXT NOT NULL DEFAULT '',
  ciphertext  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_shield_tokens_session ON shield_tokens(session_id);

-- +goose Down
DROP INDEX IF EXISTS idx_shield_tokens_session;
DROP TABLE IF EXISTS shield_tokens;
DROP INDEX IF EXISTS idx_shield_sessions_expires;
DROP TABLE IF EXISTS shield_sessions;

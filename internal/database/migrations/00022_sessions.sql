-- +goose Up
-- Per-token server-side session records. Sessions were previously pure stateless
-- JWT (only a coarse users.sessions_valid_after cutoff existed), so a leaked
-- token could not be revoked before its natural expiry. Each JWT now carries its
-- session id as the jti claim; the auth middleware rejects any token whose
-- session row is missing, revoked, or idle past the configured window, turning
-- stateless JWTs into revocable sessions so logout and inactivity kill a leaked
-- token immediately. expires_at is intentionally NULLABLE so sqlc types
-- CreateSessionParams.ExpiresAt as sql.NullTime (which is what auth.go passes).
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME,
  revoked_at DATETIME
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- +goose Down
DROP INDEX IF EXISTS idx_sessions_user;
DROP TABLE IF EXISTS sessions;

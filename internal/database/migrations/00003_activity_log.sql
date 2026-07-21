-- +goose Up
-- +goose StatementBegin
CREATE TABLE activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  detail TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

CREATE INDEX idx_activity_log_created ON activity_log(created_at);
CREATE INDEX idx_activity_log_action ON activity_log(action, created_at);
CREATE INDEX idx_activity_log_user ON activity_log(user_id, created_at);

-- +goose StatementBegin
-- Append-only audit trail at the database level. Any UPDATE or DELETE against
-- the log (buggy handler, compromised process, or a SQLite shell session)
-- raises and the transaction rolls back. Copied from dockyard's audited
-- activity_log hardening.
CREATE TRIGGER activity_log_no_update
BEFORE UPDATE ON activity_log
BEGIN
  SELECT RAISE(ABORT, 'activity_log is append-only; UPDATE is not permitted');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER activity_log_no_delete
BEFORE DELETE ON activity_log
BEGIN
  SELECT RAISE(ABORT, 'activity_log is append-only; DELETE is not permitted');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS activity_log_no_delete;
DROP TRIGGER IF EXISTS activity_log_no_update;
DROP INDEX IF EXISTS idx_activity_log_user;
DROP INDEX IF EXISTS idx_activity_log_action;
DROP INDEX IF EXISTS idx_activity_log_created;
DROP TABLE IF EXISTS activity_log;

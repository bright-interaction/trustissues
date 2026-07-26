-- +goose Up
-- The append-only UPDATE trigger on activity_log aborted EVERY update, including
-- the one SQLite itself performs for the `user_id REFERENCES users(id) ON DELETE
-- SET NULL` foreign key. Deleting a user therefore always failed: the FK action
-- fired the trigger, the trigger raised, and the whole delete rolled back. An
-- admin could disable an account but never remove it, so offboarding a departing
-- or compromised teammate left their row (and their audit identity) in place.
--
-- Replace the blanket trigger with one that permits EXACTLY the FK's
-- anonymization (user_id going from a value to NULL while every other column
-- stays byte-identical) and still aborts any other UPDATE. `IS` is used rather
-- than `=` so NULL columns compare correctly. Append-only integrity is
-- preserved: action, detail, ip_address, user_agent, created_at and id can never
-- be rewritten, and the DELETE trigger is untouched, so no audit row can be
-- removed or edited. The only permitted mutation is dropping the actor link,
-- which is the intended semantics of ON DELETE SET NULL.
-- +goose StatementBegin
DROP TRIGGER IF EXISTS activity_log_no_update;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER activity_log_no_update
BEFORE UPDATE ON activity_log
WHEN NOT (
  NEW.user_id IS NULL
  AND OLD.user_id IS NOT NULL
  AND NEW.id IS OLD.id
  AND NEW.action IS OLD.action
  AND NEW.detail IS OLD.detail
  AND NEW.ip_address IS OLD.ip_address
  AND NEW.user_agent IS OLD.user_agent
  AND NEW.created_at IS OLD.created_at
)
BEGIN
  SELECT RAISE(ABORT, 'activity_log is append-only; only actor anonymization on user delete is permitted');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS activity_log_no_update;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER activity_log_no_update
BEFORE UPDATE ON activity_log
BEGIN
  SELECT RAISE(ABORT, 'activity_log is append-only; UPDATE is not permitted');
END;
-- +goose StatementEnd

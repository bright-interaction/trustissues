-- +goose Up
-- activity_log has been append-only at the database level since 00003, but the
-- two audit tables that record credential access have never had the same
-- protection. capability_log answers "did this key get issued, used or denied;
-- from where; by which agent", and service_secret_audit answers "which service
-- pulled which secrets and when". Both are the record an operator would consult
-- after a suspected compromise, and until now a buggy handler, a compromised
-- process or a `sqlite3` shell could rewrite or erase either one silently.
--
-- The same append-only pair as activity_log, applied to both tables. Neither
-- needs the anonymization carve-out that 00027 had to add: activity_log has
-- `user_id REFERENCES users(id) ON DELETE SET NULL`, so SQLite itself performed
-- an UPDATE the blanket trigger aborted, which is what made deleting a user
-- impossible. Neither table here declares a foreign key at all. Both instead
-- denormalise the actor (capability_log.secret_name, service_secret_audit
-- .service_name, each commented "audit-after-delete" at the point of
-- definition), precisely so that deleting the referenced row leaves the audit
-- row intact and untouched. No FK action can fire, so no carve-out is needed
-- and the blanket form is the correct one.
--
-- Verified before writing this: every statement in the tree that names either
-- table is an INSERT or a SELECT. There is no retention sweep to break. That
-- does mean both tables grow without bound, which is the same trade activity_log
-- already makes and is deliberately left alone here rather than resolved by a
-- migration whose stated job is to make the rows immutable.

-- +goose StatementBegin
CREATE TRIGGER capability_log_no_update
BEFORE UPDATE ON capability_log
BEGIN
  SELECT RAISE(ABORT, 'capability_log is append-only; UPDATE is not permitted');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER capability_log_no_delete
BEFORE DELETE ON capability_log
BEGIN
  SELECT RAISE(ABORT, 'capability_log is append-only; DELETE is not permitted');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER service_secret_audit_no_update
BEFORE UPDATE ON service_secret_audit
BEGIN
  SELECT RAISE(ABORT, 'service_secret_audit is append-only; UPDATE is not permitted');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER service_secret_audit_no_delete
BEFORE DELETE ON service_secret_audit
BEGIN
  SELECT RAISE(ABORT, 'service_secret_audit is append-only; DELETE is not permitted');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS service_secret_audit_no_delete;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TRIGGER IF EXISTS service_secret_audit_no_update;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TRIGGER IF EXISTS capability_log_no_delete;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TRIGGER IF EXISTS capability_log_no_update;
-- +goose StatementEnd

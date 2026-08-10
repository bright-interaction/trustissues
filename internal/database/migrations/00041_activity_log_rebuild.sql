-- +goose Up
-- REBUILDING THE AUDIT LOG, ON PURPOSE, ONCE.
--
-- 00040 encrypted vault_entries.name and the pass that added activity_detail_crypto.go
-- sealed the name inside every activity line that names one. Neither could touch
-- the rows already written: activity_log has been append-only at the database
-- level since 00003, and the application may not rewrite an audit row. That
-- guarantee is the point, not an obstacle to route around, because an
-- application that can rewrite audit history is indistinguishable from an
-- attacker with application access covering their tracks.
--
-- On the instance this ships to, nine of twenty-eight rows still named a vault
-- secret in the clear, which is most of a five-entry inventory and is exactly
-- what the encrypted columns exist to withhold from a stolen file. The operator
-- chose to clear the log rather than keep it.
--
-- WHY THIS IS A MIGRATION AND NOT A FEATURE. A migration is reviewed code that
-- runs once, at a deploy, under an operator who asked for it, and it does not
-- hand the running server any new capability: after this file finishes, the
-- triggers are back and the handlers still cannot rewrite or delete a single
-- row. Nothing here is reachable from the API, then or later.
--
-- WHAT IS LOST, STATED PLAINLY. Every activity row, not only the nine. The audit
-- history for this instance ends here and begins again empty. The deploy takes a
-- verified snapshot BEFORE migrations run (trustissuesBackupVaultDB,
-- /app/data/backups/pre-deploy-<stamp>.db), so the old log is recoverable from
-- that file if this turns out to be the wrong call.
--
-- WHAT IS DELIBERATELY CARRIED ACROSS. One thing: the backfill's withheld-owner
-- notice. Migrations 00034/00035/00036 leave secret_owner_user_id empty on any
-- entry whose depositor they could not prove, and write an activity row so the
-- operator knows to repair it at Settings -> Ownership. That row is the only
-- pointer to a real, still-outstanding piece of work, and deleting it would
-- quietly close a ticket instead of a log line. It is not preserved by exempting
-- it from the DELETE (which would make this file a selective rewrite of audit
-- history, the thing it must not be); it is RE-DERIVED below from the current
-- contents of vault_entries, which is where the fact actually lives.
--
-- WHAT THIS DOES NOT DISTURB. Ownership attribution itself. 00034/00035/00036
-- read this log to decide whose authority governs a secret, and they have
-- already run: secret_owner_user_id is materialised on vault_entries and is not
-- re-derived from the log again.
--
-- DELETE rather than DROP TABLE: the table keeps its schema, its indexes and its
-- foreign key to users, so nothing downstream has to be recreated correctly from
-- memory. Only the rows go.

-- The prior count has to be captured BEFORE the delete, because "was there a log
-- to clear" is knowable from nowhere else, and a fresh install must come up with
-- an empty activity log rather than a notice about a history it never had.
-- +goose StatementBegin
CREATE TEMP TABLE activity_log_rebuild_prior AS SELECT COUNT(*) AS n FROM activity_log;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TRIGGER IF EXISTS activity_log_no_delete;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TRIGGER IF EXISTS activity_log_no_update;
-- +goose StatementEnd

DELETE FROM activity_log;

-- The id sequence restarts too, so the new log does not open at id 29 and imply
-- twenty-eight rows a reader cannot find.
DELETE FROM sqlite_sequence WHERE name = 'activity_log';

-- Recreated verbatim from 00027, NOT from 00003. 00027 narrowed the UPDATE
-- trigger to permit exactly the FK's actor anonymization (user_id going to NULL
-- while every other column stays byte-identical), because the blanket version
-- aborted the ON DELETE SET NULL that deleting a user performs, which made
-- offboarding impossible. Restoring 00003's blanket trigger here would silently
-- reintroduce that bug. Both triggers are back in place before the first INSERT
-- below, so the new log is append-only from its very first row.
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

-- +goose StatementBegin
CREATE TRIGGER activity_log_no_delete
BEFORE DELETE ON activity_log
BEGIN
  SELECT RAISE(ABORT, 'activity_log is append-only; DELETE is not permitted');
END;
-- +goose StatementEnd

-- The first row of the new log says why the old one is not there, so an auditor
-- reading a log that starts mid-life is not left to guess. Conditional, so a
-- fresh install does not announce the clearing of a log that never existed.
-- +goose StatementBegin
INSERT INTO activity_log (user_id, action, detail)
SELECT NULL, 'admin.activity_log_rebuilt',
       'The activity log was cleared by migration 00041, discarding ' ||
       (SELECT n FROM activity_log_rebuild_prior) || ' row(s). Rows written before the entry name ' ||
       'was sealed at rest (00040, then activity_detail_crypto.go) named vault secrets in ' ||
       'cleartext, and append-only means the application could not rewrite them. The ' ||
       'pre-migration snapshot under /app/data/backups holds the previous log.'
WHERE (SELECT n FROM activity_log_rebuild_prior) > 0;
-- +goose StatementEnd

-- Re-derived from vault_entries, not preserved from the old log. Same predicate
-- and same operator instruction as 00034/00035/00036, so an instance that still
-- has withheld entries still has the row that tells somebody to go and fix them.
-- +goose StatementBegin
INSERT INTO activity_log (user_id, action, detail)
SELECT NULL, 'vault.owner_backfill_withheld',
       'After the activity log was rebuilt by migration 00041, ' || COUNT(*) ||
       ' vault entry/entries are still recorded with no recorded secret owner. This is re-derived ' ||
       'from vault_entries rather than carried over from the discarded log, so it reflects the ' ||
       'state right now. These entries still open, reveal and rotate; they refuse NEW delivery ' ||
       'destinations until an instance admin claims them at Settings -> Ownership.'
FROM vault_entries
WHERE secret_owner_user_id = ''
HAVING COUNT(*) > 0;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE activity_log_rebuild_prior;
-- +goose StatementEnd

-- +goose Down
-- Deliberately empty. The rows are gone and a Down cannot invent them; restoring
-- them means restoring the pre-deploy snapshot. Recreating the triggers is not
-- needed either, since Up leaves them exactly as it found them.
SELECT 1;

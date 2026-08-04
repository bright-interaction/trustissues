-- +goose Up
-- +goose StatementBegin
-- THE TABLES, FOR AN INSTANCE THAT IS ALREADY PAST THE MIGRATIONS THAT ADD THEM.
--
-- secret_owner_backfill and secret_ownership_claims are created by 00034, and
-- by 00035 and 00036 as well, so every path that runs any of those ends up with
-- them. An instance already recorded at version 36 runs none of the three ever
-- again, and would carry the schema without the two tables the handler now
-- writes on every ownership claim.
--
-- That is the whole job of this file. It is deliberately CREATE IF NOT EXISTS
-- and nothing else.
--
-- IT DOES NOT POPULATE secret_owner_backfill, and that is the important part.
-- On a fresh database 00034 has already recorded exactly the rows it decided
-- about, and adding to it here would be wrong. On an instance that ran an
-- earlier cut, the honest answer to "which rows did the backfill decide about"
-- is that nothing recorded it, and an EMPTY table means no future repair may
-- withdraw anybody's ownership there. That fails in the direction that costs an
-- operator a repair they may never need, rather than the direction that stops
-- every shared secret rotating.
CREATE TABLE IF NOT EXISTS secret_owner_backfill (
  entry_id      TEXT PRIMARY KEY,
  decided_owner TEXT NOT NULL DEFAULT '',
  decided_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS secret_ownership_claims (
  entry_id       TEXT PRIMARY KEY,
  claimed_by     TEXT NOT NULL DEFAULT '',
  claimed_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  withdrawn_json TEXT NOT NULL DEFAULT '{}'
);
-- +goose StatementEnd

-- +goose StatementBegin
-- The claims an admin already made through the product, read ANCHORED at
-- position 1 rather than with instr().
--
-- The handler writes the repaired entry's id first and always, so position 1 is
-- the one part of that sentence no caller can move. 00034 does the same read for
-- a fresh database; this is the copy for an instance that is already past it.
-- After this, nothing in the system reads a prose sentence to decide who owns a
-- secret.
INSERT OR IGNORE INTO secret_ownership_claims (entry_id, claimed_by)
SELECT ve.id, ''
FROM vault_entries ve
WHERE EXISTS (
  SELECT 1 FROM activity_log al
  WHERE al.action = 'vault.ownership_claimed'
    AND substr(al.detail, 1, length('Entry ' || ve.id || ':')) = 'Entry ' || ve.id || ':'
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Not dropped. The claims table records deliberate admin decisions and the
-- backfill table records what a migration was allowed to undo; losing either
-- turns a later repair loose on rows it must not touch.
SELECT 1;
-- +goose StatementEnd

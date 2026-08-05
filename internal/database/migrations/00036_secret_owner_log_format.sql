-- +goose Up
-- +goose StatementBegin
-- THE PREDICATE COULD NOT READ THE LOG FORMAT WRITTEN BY THE COMMIT IT CITED.
--
-- 00034 and 00035 both operationalise "a vault.entry_moved row naming this
-- entry" as
--
--   instr(al.detail, '(id: ' || vault_entries.id || ',') > 0
--
-- and both justify it by saying SetVaultEntryCollection has logged the entry id
-- since 4e9bd5ec, the commit that introduced collections. The citation is right
-- and the predicate does not match what that commit writes. At 4e9bd5ec the
-- handler logs
--
--   "Vault entry moved to collection (id: %s)"
--
-- which renders "(id: X)" with a CLOSING PAREN. The comma form is the CURRENT
-- format, "Vault entry moved: NAME (id: X, from: A, to: B)", and it arrived
-- later. Five commits shipped the paren form (4e9bd5ec, 725dd0df, d7cfa0a5,
-- 4528ef77, 6acf64ff, 2026-07-24 to 2026-07-26), so any instance that ran a
-- binary from that window has entry_moved rows the predicate cannot see.
--
-- What that costs is exactly the laundering path 00034 is about. An entry
-- created personal, moved INTO a collection by a paren-era binary, adopted by a
-- manager while vault.entry_adopted did not yet exist (it was added 2026-08-02),
-- and moved back OUT to personal, looks to the predicate like an entry that has
-- never been in a collection. It is personal now, its two move rows are
-- invisible, it has no adoption row, so 00034 stamps its custodian: THE
-- MANAGER, not the creator, promoted to owner in the one column nothing below an
-- instance admin can move.
--
-- ===========================================================================
-- A LOG FORMAT IS NOT AN API, SO THIS ONE STOPS READING IT AS ONE
-- ===========================================================================
--
-- The fix is not the comma-or-paren regex. Matching a prose format means the
-- migration is coupled to a string a handler is free to reword, and it has
-- already been reworded once with nobody noticing. The question the backfill
-- actually needs answered is
--
--   does any vault.entry_moved row MENTION this entry?
--
-- and the entry id is an opaque unique token (lower(hex(randomblob(16))), 32
-- hex characters, fixed width, so no id can be a substring of another). Asking
-- whether the detail CONTAINS that token assumes nothing about the format at
-- all: it matches the paren era, the comma era, and any future wording that
-- still mentions the entry.
--
-- The one thing it does assume is that the detail mentions the id somehow, and
-- that assumption is no longer hidden. TestEveryEntryScopedActivityDetailNames
-- TheEntryID reads the source and fails if a writer of vault.entry_moved,
-- vault.entry_adopted or vault.ownership_claimed formats a detail without the
-- entry id in it. A dependency on a log format is fine as long as somebody is
-- told when the format changes, and nobody was.
--
-- WHY THE THREE CLAUSES ARE NOT ALL LOOSENED
--
-- They fail in opposite directions, so they get opposite strictness.
--
--   entry_moved, entry_adopted   WITHHOLD an owner. A false positive costs an
--                                admin one click at Settings -> Ownership; a
--                                false negative stamps an attacker. Loosened to
--                                bare containment, deliberately.
--   ownership_claimed            PRESERVES an owner, so a false positive keeps
--                                one this migration means to withdraw. Kept
--                                STRICT, and it can be: that action has had
--                                exactly one format in its whole existence
--                                because it shipped with the repair surface.
--
-- The residual, stated: an entry NAMED with another entry's 32-hex id would be
-- withheld by the loosened clause, because the move detail carries the moved
-- entry's name. That is a self-inflicted denial of service on one row, repaired
-- by an admin claim, and it is the safe direction. Trading it for independence
-- from a prose format is the whole point.
--
-- Corrected in place in 00034 and 00035 for a fresh database. This migration
-- exists because a corrected file is worth nothing to a database that already
-- ran the broken one: goose records the version and never reads the file again.
-- It is idempotent, and a no-op on a database whose owners are already correct.
-- SELF-SUFFICIENT for the same reason 00035 is: an instance may sit at a
-- version whose 00034 never created these, and goose will not re-read it.
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
UPDATE vault_entries
SET secret_owner_user_id = ''
WHERE secret_owner_user_id != ''
  -- ROWS THAT EXISTED WHEN 00034 RAN, asked of the clock rather than of a table.
  --
  -- This clause used to be
  --
  --   AND EXISTS (SELECT 1 FROM secret_owner_backfill b WHERE b.entry_id = vault_entries.id)
  --
  -- and that was a STRICT REGRESSION, proved by running the real chain: the same
  -- v34 database IS repaired by the pre-00037 code and is NOT repaired with that
  -- clause in place. secret_owner_backfill is populated by exactly one INSERT,
  -- inside 00034. This migration only ever runs on a database that ALREADY
  -- applied a broken 00034, goose never re-reads a recorded file, so 00034 never
  -- runs there and the table is created EMPTY by this file's own CREATE IF NOT
  -- EXISTS. The gate matched nothing, both repairs became no-ops on the only
  -- population they exist for, and a laundered manager ownership survived
  -- permanently with no operator notice.
  --
  -- goose_db_version.tstamp is recorded on every instance that ran 00034,
  -- including the ones with no provenance table, so it answers the same question
  -- without depending on bookkeeping that may never have been written.
  --
  -- BOTH AMBIGUITIES RESOLVE TOWARD REPAIRING. A missing tstamp and a row created
  -- in the same second as the migration both count as "existed then", so the row
  -- is in scope and its unprovable ownership is withdrawn. Withholding an owner
  -- costs an admin one click at Settings -> Ownership; leaving a laundered one
  -- standing cannot be undone at all. CURRENT_TIMESTAMP is second-granular, so
  -- that second of overlap is real and is spent in the recoverable direction.
  AND (
    vault_entries.created_at IS NULL
    OR vault_entries.created_at <= COALESCE(
         (SELECT tstamp FROM goose_db_version
          WHERE version_id = 34 AND is_applied = 1
          ORDER BY id DESC LIMIT 1),
         vault_entries.created_at)
  )
  AND NOT (
    (collection_id IS NULL OR collection_id = '')
    AND NOT EXISTS (
      SELECT 1 FROM activity_log al
      WHERE al.action = 'vault.entry_moved'
        AND instr(al.detail, vault_entries.id) > 0
    )
    AND NOT EXISTS (
      SELECT 1 FROM activity_log al
      WHERE al.action = 'vault.entry_adopted'
        AND instr(al.detail, vault_entries.id) > 0
    )
  )
  -- THE CLAIM IS A ROW, not a sentence with the previous holder's bytes in it.
  AND NOT EXISTS (
    SELECT 1 FROM secret_ownership_claims c WHERE c.entry_id = vault_entries.id
  );
-- +goose StatementEnd

-- +goose StatementBegin
-- The other direction, for completeness rather than for safety, and it is the
-- same statement 00034 runs on a fresh database.
UPDATE vault_entries
SET secret_owner_user_id = user_id
WHERE secret_owner_user_id = ''
  AND user_id != ''
  AND (collection_id IS NULL OR collection_id = '')
  AND NOT EXISTS (
    SELECT 1 FROM activity_log al
    WHERE al.action = 'vault.entry_moved'
      AND instr(al.detail, vault_entries.id) > 0
  )
  AND NOT EXISTS (
    SELECT 1 FROM activity_log al
    WHERE al.action = 'vault.entry_adopted'
      AND instr(al.detail, vault_entries.id) > 0
  );
-- +goose StatementEnd

-- +goose StatementBegin
-- Say so, durably, and only when there is something to say.
INSERT INTO activity_log (user_id, action, detail)
SELECT NULL, 'vault.owner_backfill_withheld',
       'Migration 00036 re-derived secret ownership against the activity log without parsing its ' ||
       'wording, and left ' || COUNT(*) || ' vault entry/entries with no recorded owner. The earlier ' ||
       'backfills matched one phrasing of the vault.entry_moved detail and could not see the ' ||
       'phrasing shipped between 2026-07-24 and 2026-07-26, so an entry moved through a collection ' ||
       'in that window could have been stamped with a custodian who did not deposit its secret. ' ||
       'These entries still open, reveal and rotate; they refuse NEW delivery destinations until an ' ||
       'instance admin claims them at Settings -> Ownership.'
FROM vault_entries
WHERE secret_owner_user_id = ''
HAVING COUNT(*) > 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- There is no down. Restoring an ownership this migration withdrew means
-- copying user_id back into secret_owner_user_id, which is the defect itself.
SELECT 1;
-- +goose StatementEnd

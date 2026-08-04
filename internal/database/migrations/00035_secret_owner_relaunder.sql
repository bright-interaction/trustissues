-- +goose Up
-- +goose StatementBegin
-- UN-LAUNDERING, for any database that already applied the FIRST cut of 00034.
--
-- 00034 originally ended with
--
--   UPDATE vault_entries SET secret_owner_user_id = user_id WHERE secret_owner_user_id = '';
--
-- and that one statement handed the round back. user_id is the column a
-- collection MANAGER moves to their own id with two ordinary product calls
-- (remove the creator from the collection, then rename the entry, which fires
-- managerMayAdoptOrphanedEntry). Copying it into secret_owner_user_id promotes
-- an attacker who had already done that from custodian to OWNER, durably, into
-- the one column nothing below an instance admin can move, and the exit then
-- authorises their deliveries correctly forever. THE FIX BOOTSTRAPPED ITS
-- AUTHORITY FROM THE COLUMN IT EXISTS TO DISTRUST.
--
-- 00034 is corrected in place, which is what a fresh database gets. This
-- migration exists because a corrected file is worth NOTHING to a database that
-- already ran the broken one: goose records 34 as applied and never looks at
-- the file again. So the rule is re-derived here, and it is the same rule.
--
-- It is idempotent and a no-op on a database that ran the corrected 00034: the
-- provably-safe class keeps the owner it already has, and every other row is
-- already empty.
--
-- WHAT IT CLEARS
--
-- Every entry NOT in the class 00034 can prove: personal now, no
-- vault.entry_moved row naming it (so it has never been in a collection, so
-- adoption was never reachable for it), and no vault.entry_adopted row naming
-- it. An empty owner DENIES at mayDirectSecretEgress, which is the safe
-- direction, and Settings -> Ownership is where an admin takes it back
-- deliberately through vaultegress.AuthorizeTransfer.
--
-- THE ONE THING IT PRESERVES, and the one it deliberately does not
--
-- An entry whose ownership was moved by the product's sanctioned transfer since
-- the broken migration ran is left alone: POST /api/admin/vault/{id}/ownership/claim
-- writes a vault.ownership_claimed row naming the entry, and clearing an owner
-- an admin had just chosen would undo a decision rather than an accident.
--
-- The hard-delete re-owning path (admin.entries_reassigned) is NOT preserved,
-- because its audit row carries a count and a set of names rather than entry
-- ids, so there is nothing to match on. Those entries are cleared with the rest
-- and the admin re-claims them from the Ownership page. That costs an
-- afternoon; the alternative is leaving a laundered attacker in place because
-- an unrelated offboarding might have touched the same row, which is guessing
-- in the attacker's favour to save a click.
--
-- HOW THE MOVE EVIDENCE IS MATCHED, corrected in place
--
-- The first cut of this file, like 00034's, asked for '(id: ' || id || ',',
-- which is the CURRENT wording of the vault.entry_moved detail and not the one
-- shipped between 2026-07-24 and 2026-07-26 ("Vault entry moved to collection
-- (id: X)", closing paren, no comma). A migration that reads a prose format is
-- coupled to a string a handler may reword, and this one had been. It now asks
-- whether the detail CONTAINS THE ID, which is wording-independent: the id is
-- 32 fixed-width hex characters, so it cannot be a substring of another id.
-- The ownership_claimed clause stays delimited on purpose, because it PRESERVES
-- rather than withholds and its failure direction is therefore the unsafe one.
-- Migration 00036 applies the same correction to databases that already ran
-- this file.
-- SELF-SUFFICIENT, because an instance may already have run an earlier cut of
-- 00034 that did not create these. Goose will never re-read that file for them,
-- so this migration cannot assume the tables exist. An EMPTY
-- secret_owner_backfill here is the safe reading, not a broken one: it means
-- this repair touches nothing, which is the correct outcome on an instance
-- whose backfill was never recorded.
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
  -- ONLY ROWS 00034 DECIDED ABOUT. A repair undoes the backfill's work, never
  -- the creating statement's. Without this line every SHARED entry created
  -- between the two deploys loses the owner its own creator was stamped with,
  -- stops rotating, and can only be recovered by a claim that deletes its
  -- recorded destinations. See the table's comment in 00034.
  AND EXISTS (SELECT 1 FROM secret_owner_backfill b WHERE b.entry_id = vault_entries.id)
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
  -- THE CLAIM IS A ROW. It used to be instr() over a prose sentence that
  -- carried the previous holder's own bytes, so the holder of entry A could
  -- spare a laundered ownership on entry B. See 00034.
  AND NOT EXISTS (
    SELECT 1 FROM secret_ownership_claims c WHERE c.entry_id = vault_entries.id
  );
-- +goose StatementEnd

-- +goose StatementBegin
-- The other direction, for completeness rather than for safety: a row in the
-- provably-safe class that somehow has no owner gets one. On a database that
-- ran the corrected 00034 this changes nothing, and on one that ran neither it
-- is the same statement 00034 runs.
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
       'Migration 00035 re-derived secret ownership and left ' || COUNT(*) || ' vault entry/entries ' ||
       'with no recorded owner. If this instance ever ran the first cut of migration 00034, an ' ||
       'ownership it copied out of vault_entries.user_id has just been withdrawn: user_id is a column ' ||
       'a collection manager can move to themselves. These entries still open, reveal and rotate; ' ||
       'they refuse NEW delivery destinations until an instance admin claims them at ' ||
       'Settings -> Ownership.'
FROM vault_entries
WHERE secret_owner_user_id = ''
HAVING COUNT(*) > 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- There is no down. Restoring an ownership this migration withdrew means
-- copying user_id back into secret_owner_user_id, which is the defect itself.
-- An operator who wants a specific entry owned again does it through
-- Settings -> Ownership, where the decision is attributable.
SELECT 1;
-- +goose StatementEnd

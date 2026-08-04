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
UPDATE vault_entries
SET secret_owner_user_id = ''
WHERE secret_owner_user_id != ''
  AND NOT (
    (collection_id IS NULL OR collection_id = '')
    AND NOT EXISTS (
      SELECT 1 FROM activity_log al
      WHERE al.action = 'vault.entry_moved'
        AND instr(al.detail, '(id: ' || vault_entries.id || ',') > 0
    )
    AND NOT EXISTS (
      SELECT 1 FROM activity_log al
      WHERE al.action = 'vault.entry_adopted'
        AND instr(al.detail, 'Entry ' || vault_entries.id || ' ') > 0
    )
  )
  AND NOT EXISTS (
    SELECT 1 FROM activity_log al
    WHERE al.action = 'vault.ownership_claimed'
      AND instr(al.detail, 'Entry ' || vault_entries.id || ':') > 0
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
      AND instr(al.detail, '(id: ' || vault_entries.id || ',') > 0
  )
  AND NOT EXISTS (
    SELECT 1 FROM activity_log al
    WHERE al.action = 'vault.entry_adopted'
      AND instr(al.detail, 'Entry ' || vault_entries.id || ' ') > 0
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

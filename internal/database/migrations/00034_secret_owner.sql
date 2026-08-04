-- +goose Up
-- +goose StatementBegin
-- WHOSE SECRET THIS IS, for the purposes of the exit, in a column no member can
-- move.
--
-- Round 7 put every decrypted secret through one gate and asked one question:
-- did the OWNER of the secret being sent authorise this destination. It
-- resolved "owner" from vault_entries.user_id, and user_id is a column an
-- ordinary product route lets a collection MANAGER write to their own id:
-- AdoptAndRenameVaultEntry, reached by PUT /api/vault/{id} with a new name once
-- the entry's creator is no longer an accepted member of the collection. A
-- manager can bring that precondition about themselves with
-- DELETE /api/collections/{id}/members/{creator}, which is manager-gated too. So
-- two ordinary calls made the attacker the owner, and the exit then authorised
-- the exact round-6 delivery it exists to refuse.
--
-- An authority derived from data the attacker can write is not an authority.
--
-- The fix is not to take adoption away: adoption is what moves the
-- UNIQUE(user_id, name) question into the renamer's own namespace, which is what
-- keeps a rename from being an existence oracle over a colleague's private
-- vault. The fix is that user_id was carrying TWO meanings at once, the
-- namespace this row occupies and the principal whose authority governs its
-- plaintext, and the attack is exactly that conflation. They are two columns now.
--
--   user_id               the CUSTODIAN. Uniqueness scope, listing, ownership
--                         for grantFor. Adoption moves it, deliberately.
--   secret_owner_user_id  the OWNER, and only the exit asks about it. Written
--                         when the row is created, and afterwards only by the
--                         one statement in internal/vaultegress/internal/egressq
--                         that exists to transfer it.
--
-- ===========================================================================
-- THE BACKFILL DOES NOT TRUST user_id, BECAUSE user_id IS WHAT IT DISTRUSTS
-- ===========================================================================
--
-- The first version of this migration ended with
--
--   UPDATE vault_entries SET secret_owner_user_id = user_id;
--
-- and that one statement handed the whole round back. On an instance where a
-- manager had ALREADY run the two calls above, user_id was the attacker. The
-- migration would have promoted them from custodian to OWNER, durably, into the
-- one column nothing below an instance admin can move afterwards, and the exit
-- would then have authorised their deliveries CORRECTLY, forever. A fix whose
-- backfill bootstraps its authority from the column it exists to distrust is
-- not a fix, it is a laundering step with a comment on it.
--
-- So the backfill stamps an owner only where the custodian is PROVABLY still
-- the creator, and leaves the column EMPTY everywhere else. An empty owner
-- denies (VaultHandler.mayDirectSecretEgress refuses rather than falling back
-- to user_id), which is the safe direction. An entry that denies until an admin
-- repairs it is a bad afternoon; an entry silently owned by an attacker is the
-- round.
--
-- WHAT ACTUALLY DISTINGUISHES THE TWO ON A LIVE DATABASE
--
-- After creation, exactly two statements in the module write
-- vault_entries.user_id:
--
--   AdoptAndRenameVaultEntry        the attack. It can only fire on an entry
--                                   whose collection_id is NOT NULL, because
--                                   managerMayAdoptOrphanedEntry returns false
--                                   for a personal entry before it reads
--                                   anything else.
--   TransferVaultEntrySecretOwner   internal/vaultegress, which did not exist
--                                   before this migration and which moves BOTH
--                                   columns together.
--
-- collection_id itself is written in exactly two places: at creation
-- (VaultHandler.Create places a new shared entry immediately, logging only
-- vault.entry_created), and by SetVaultEntryCollection behind
-- PUT /api/vault/{id}/collection, which logs vault.entry_moved with the ENTRY
-- ID in it, and has done since the commit that introduced collections at all
-- (4e9bd5ec). activity_log is append-only at the DATABASE level: migrations
-- 00003 and 00027 put triggers on it that abort every UPDATE except the foreign
-- key's actor anonymization, and every DELETE without exception, and no query in
-- the module deletes from it.
--
-- WHAT THE PREDICATE MATCHES, AND WHAT IT DELIBERATELY DOES NOT
--
-- The detail is prose and has been reworded once already. 4e9bd5ec wrote
-- "Vault entry moved to collection (id: X)"; the current handler writes "Vault
-- entry moved: NAME (id: X, from: A, to: B)". The first cut of this migration
-- matched '(id: ' || id || ',', which reads the SECOND wording and is blind to
-- the first, so an entry moved through a collection by a binary from
-- 2026-07-24 to 2026-07-26 looked as though it never had been. See migration
-- 00036, which is the same correction for databases that already applied this
-- file.
--
-- So it matches the ID ALONE. The id is lower(hex(randomblob(16))): 32 hex
-- characters, fixed width, so no id is a substring of another. Asking whether
-- the detail CONTAINS that token assumes nothing about the wording, which is
-- the property a migration wants from a log it did not write.
-- TestEveryEntryScopedActivityDetailNamesTheEntryID pins the one assumption
-- that is left, that a writer of these actions puts the entry id in the detail
-- at all.
--
-- Therefore an entry that is PERSONAL NOW and has NO vault.entry_moved row
-- naming it has never been in a collection, so adoption was never reachable for
-- it, so its user_id is still the principal who deposited the plaintext. That
-- is the class this migration is willing to stamp.
--
-- WHAT DOES NOT DISTINGUISH THEM, SAID PLAINLY
--
-- For an entry that is in a collection NOW, nothing in the database separates
-- "the creator still holds it" from "a manager adopted it". Both states are one
-- row whose user_id is an accepted member of the collection. The
-- vault.entry_adopted audit row checked below is real, but it was only added on
-- 2026-08-02, so an adoption performed by an older binary left no record naming
-- the entry: vault.entry_updated carries the NEW name and the ADOPTER's id,
-- which is indistinguishable from an owner renaming their own entry. Membership
-- history does not close it either, because an admin can move a non-member's
-- personal entry into a collection, which satisfies "the creator is not a
-- member" with no removal ever recorded.
--
-- So every collection entry lands in the ambiguous class and is left EMPTY.
-- That is deliberately the expensive answer: on a team instance it means every
-- shared entry stops accepting NEW delivery destinations, and existing webhook
-- and forgejo targets configured by a non-admin stop contributing hosts at
-- delivery time, until an admin claims the entry. Reading, revealing, rotating
-- in place, narrowing and CLEARING targets all stay open, and clearing is the
-- lever that matters for a secret nobody is left to own. The repair surface is
-- GET /api/admin/vault/ownership and POST /api/admin/vault/{id}/ownership/claim,
-- reachable in the UI at Settings -> Ownership, and it goes through
-- vaultegress.AuthorizeTransfer like every other ownership move.
--
-- RESIDUAL, stated rather than hidden: the evidence is an activity_log row, and
-- LogActivityFromRequest is best effort. A vault.entry_moved insert that failed
-- at the time (a write error the handler logged and carried on from) leaves an
-- entry that WAS in a collection looking as though it never was. That is one
-- failed insert on a route that had to succeed first, and it is why the
-- vault.entry_adopted clause is kept even though the collection_id clause
-- already implies it: two independent rows have to be missing, not one.
ALTER TABLE vault_entries ADD COLUMN secret_owner_user_id TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose StatementBegin
UPDATE vault_entries
SET secret_owner_user_id = user_id
WHERE user_id != ''
  -- Adoption cannot reach a personal entry: managerMayAdoptOrphanedEntry
  -- returns false when collection_id is NULL or empty.
  AND (collection_id IS NULL OR collection_id = '')
  -- ... and this one has never been in a collection either, because the only
  -- post-creation writer of collection_id logs the entry id when it runs.
  -- instr() on the bare id rather than on a phrasing: see the note above.
  AND NOT EXISTS (
    SELECT 1 FROM activity_log al
    WHERE al.action = 'vault.entry_moved'
      AND instr(al.detail, vault_entries.id) > 0
  )
  -- The direct record, for the era that has one.
  AND NOT EXISTS (
    SELECT 1 FROM activity_log al
    WHERE al.action = 'vault.entry_adopted'
      AND instr(al.detail, vault_entries.id) > 0
  );
-- +goose StatementEnd

-- +goose StatementBegin
-- Tell the operator, durably, in the surface they already read. A fail-closed
-- migration that strands secrets silently is its own outage; this row is what
-- makes the Activity page say so on the first login after the deploy, and it
-- names the page that repairs it.
INSERT INTO activity_log (user_id, action, detail)
SELECT NULL, 'vault.owner_backfill_withheld',
       'Migration 00034 left ' || COUNT(*) || ' vault entry/entries with no recorded secret owner, ' ||
       'because the database cannot prove their current custodian is the principal who deposited the ' ||
       'secret. They still open, reveal and rotate; they refuse NEW delivery destinations until an ' ||
       'instance admin claims them at Settings -> Ownership.'
FROM vault_entries
WHERE secret_owner_user_id = ''
HAVING COUNT(*) > 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE vault_entries DROP COLUMN secret_owner_user_id;
-- +goose StatementEnd

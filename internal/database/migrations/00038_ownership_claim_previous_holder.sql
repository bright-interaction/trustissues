-- +goose Up
-- +goose StatementBegin
-- WHO HELD THE ROW BEFORE THE CLAIM, so the claim can be undone.
--
-- POST /api/admin/vault/{id}/ownership/claim is irreversible today, and the
-- states that make a row claimable are not. An entry becomes claimable the
-- moment its recorded owner loses manage, and manage is lost by:
--
--   a collection manager removing the owner from the collection
--   a collection manager changing the owner's role to viewer
--   an admin demoting the owner's INSTANCE role from admin to user
--   an admin disabling the owner's account
--
-- Every one of those is a routine, reversible call, and three of them can be
-- made by somebody who is not an instance admin and who never touches the entry.
-- Put the role back and the row stays claimed: ownership moved, the custodian
-- moved with it, and the ceiling the owner had configured was withdrawn. So a
-- collection manager converts a reversible demotion into a permanent transfer by
-- waiting for an admin to do the helpful thing on the Ownership page.
--
-- The fix is not to refuse the claim. An operator looking at a stranded secret
-- needs to be able to act, and the page exists because the alternative is
-- sqlite3. The fix is for the claim to be UNDOABLE, which means recording what
-- it displaced.
--
-- THESE COLUMNS ARE NOT CALLER-CONTROLLED AND MUST NEVER BECOME SO. They are
-- written by ClaimSecretOwnership from the entry's own row, and read by
-- RestoreSecretOwnership as the ONLY permitted recipient of a restore. That is
-- what keeps the restore from being a second transfer path: the admin cannot
-- name who gets the entry back, they can only put it back where the product
-- recorded it was.
--
-- Both default to the empty string, which reads as "nothing recorded to restore"
-- and is the correct answer for every claim taken before this migration and for
-- every claim on a row the backfill withheld (those had no previous owner at
-- all). Restore refuses on empty rather than guessing at the custodian.
ALTER TABLE secret_ownership_claims ADD COLUMN previous_owner_user_id TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE secret_ownership_claims ADD COLUMN previous_custodian_user_id TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Not dropped, for the same reason 00037 does not drop the tables: these record
-- a displaced holder, and losing them turns a claim that was undoable into one
-- that is not, silently, on rows an operator may already be relying on.
SELECT 1;
-- +goose StatementEnd

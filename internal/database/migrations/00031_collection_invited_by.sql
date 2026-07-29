-- +goose Up
-- +goose StatementBegin

-- The collection consent card said "Invited by <email>", and that email came
-- from collections.created_by, i.e. whoever CREATED the collection, not whoever
-- sent the invitation. collection_members had no inviter column at all, so the
-- field could not be right by construction.
--
-- That matters because the consent step is the only control against the attack
-- migration 00029 was written for: a low-trust account planting a credential
-- that lands in a colleague's vault list and autofill. The invitee's whole
-- decision rests on who is asking, and any manager of a collection created by a
-- trusted person inherited that person's name on the card. Separately, once the
-- creator's account was deleted the card rendered "Invited by " with nobody
-- named, so a legitimate invitee could not tell who was asking either.
ALTER TABLE collection_members ADD COLUMN invited_by TEXT REFERENCES users(id) ON DELETE SET NULL;

-- Backfill from the creator so live pending invites keep an attribution rather
-- than going blank on upgrade. It is the same value they were already being
-- shown, so this changes nothing the invitee sees today; new invites record the
-- real sender.
UPDATE collection_members
SET invited_by = (SELECT c.created_by FROM collections c WHERE c.id = collection_members.collection_id)
WHERE invited_by IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE collection_members DROP COLUMN invited_by;
-- +goose StatementEnd

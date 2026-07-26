-- +goose Up
-- Collection membership had no consent step: any authenticated user could
-- create a collection, add anyone else to it, and drop entries into it. The
-- victim's vault list, their /vault/match autofill and their unlock payload
-- immediately carried attacker-controlled entries, so the lowest-trust account
-- could plant a fake "Okta SSO" credential in front of an admin on a real
-- company domain, or wait for the victim to store a real secret in what looked
-- like a legitimate shared collection and then read it as its manager.
--
-- Membership is now an invitation: accepted_at NULL means pending, and a
-- pending membership grants NOTHING. Every read and authorization path filters
-- on accepted_at IS NOT NULL.
--
-- Existing rows are backfilled as accepted. They were created by the operator
-- before this feature existed, and forcing a re-accept on upgrade would silently
-- drop live shared access.
ALTER TABLE collection_members ADD COLUMN accepted_at TIMESTAMP;

-- +goose StatementBegin
UPDATE collection_members SET accepted_at = CURRENT_TIMESTAMP WHERE accepted_at IS NULL;
-- +goose StatementEnd

CREATE INDEX idx_collection_members_pending ON collection_members(user_id) WHERE accepted_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_collection_members_pending;
ALTER TABLE collection_members DROP COLUMN accepted_at;

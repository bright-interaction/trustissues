-- +goose Up
-- vault_entries.name was the last cleartext column on the entry, and it is the
-- one that describes the entry best. 00011 encrypted url, alias_url, username,
-- category and notes precisely so a stolen database FILE is not a readable one,
-- and left "Stripe live key" and "GitHub production PAT" sitting beside them in
-- the clear, which gives a keyless reader the whole inventory anyway. Encrypting
-- the name is what makes 00011's work mean what it says.
--
-- THE UNIQUENESS PROBLEM, and why this migration does NOT rebuild the table.
--
-- vault_entries carries UNIQUE(user_id, name) declared inline in 00010, and
-- SQLite cannot drop an inline constraint: the documented way to change one is
-- to rebuild the table. Rebuilding the table that holds every secret, to change
-- a constraint, is a large risk for a small reason.
--
-- It is not necessary. The column crypto is AES-256-GCM with a fresh random
-- nonce per seal, so two entries with the SAME name encrypt to different
-- ciphertext, and the inline constraint simply stops firing. It becomes vacuous
-- rather than wrong. The real per-user uniqueness moves to the partial UNIQUE
-- index below, over the keyed blind index of the name, which IS deterministic
-- and therefore does collide when two names are equal.
--
-- The one case where the old constraint still bites is two rows whose name is
-- EMPTY for the same user, which both store as '' because the column crypto
-- passes empty through. That is exactly what the old constraint did before this
-- migration too, so the behaviour is unchanged.
--
-- WHY THE INDEX IS PARTIAL. Between this migration and the boot backfill that
-- fills it, every row has name_bidx = ''. A total unique index would read those
-- as duplicates and refuse to be created at all. Excluding '' means the index
-- constrains exactly the rows that have been backfilled, and the backfill can
-- run row by row without a window where writes are rejected.
--
-- WHY THE SCOPE IS THE USER AND NOT bidxScope(). The url blind index is keyed
-- per SCOPE (collection or owner) so a shared collection still autofills for
-- every member. This index answers a different question: it enforces
-- UNIQUE(user_id, name), where user_id is the CUSTODIAN (see 00034), and that
-- constraint is per user whether or not the entry sits in a collection. Keying
-- it by collection would silently change which renames are legal. The user id is
-- mixed into the HMAC input as well as being the leading index column, so the
-- stored token is unlinkable across users the same way the url index is.
ALTER TABLE vault_entries ADD COLUMN name_bidx TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX idx_vault_entries_user_name_bidx
  ON vault_entries(user_id, name_bidx) WHERE name_bidx != '';

-- +goose Down
DROP INDEX IF EXISTS idx_vault_entries_user_name_bidx;
ALTER TABLE vault_entries DROP COLUMN name_bidx;

-- +goose Up
-- Arbitrary per-entry custom fields (Bitwarden-style): a JSON array of
-- {label, value, secret} objects, so an entry can carry extra labelled data
-- beyond the fixed schema (e.g. a database entry's host/port/db-name, a recovery
-- PIN, a second token). The whole blob is AES-256-GCM encrypted at rest via the
-- columncrypto helper (it may hold secret values), same as provider_meta and the
-- other metadata columns. Default '[]' is plaintext and reads cleanly (the
-- decrypt path passes through unmarked values); it becomes ciphertext on first
-- write. Detail-level: returned on GET single entry and on unlock, not in the
-- bulk list.
ALTER TABLE vault_entries ADD COLUMN custom_fields TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE vault_entries DROP COLUMN custom_fields;

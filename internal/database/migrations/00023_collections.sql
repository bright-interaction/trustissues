-- +goose Up
-- Shared team vaults. A collection is a named container of vault entries that
-- multiple teammates can access via a per-collection role. This turns the
-- product from a per-user vault (personal ownership + admin-all) into a team
-- password manager without touching the encryption model: a collection entry is
-- encrypted with the same server VAULT_KEY as a personal one, and sharing is a
-- pure authorization layer (any authorized member decrypts server-side). Roles:
--   viewer  - read + reveal entries
--   editor  - viewer + create/update/delete entries in the collection
--   manager - editor + manage members and rename/delete the collection
CREATE TABLE collections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE collection_members (
  collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('viewer', 'editor', 'manager')),
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (collection_id, user_id)
);
CREATE INDEX idx_collection_members_user ON collection_members(user_id);

-- collection_id NULL means a personal entry (owned by user_id, existing
-- behaviour). A non-NULL collection_id means the entry lives in a shared
-- collection; user_id stays the creator for audit + the UNIQUE(user_id, name)
-- constraint. ON DELETE CASCADE so deleting a collection removes its entries.
ALTER TABLE vault_entries ADD COLUMN collection_id TEXT REFERENCES collections(id) ON DELETE CASCADE;
CREATE INDEX idx_vault_entries_collection ON vault_entries(collection_id) WHERE collection_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_vault_entries_collection;
ALTER TABLE vault_entries DROP COLUMN collection_id;
DROP INDEX IF EXISTS idx_collection_members_user;
DROP TABLE IF EXISTS collection_members;
DROP TABLE IF EXISTS collections;

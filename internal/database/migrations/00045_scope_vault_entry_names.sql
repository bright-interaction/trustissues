-- +goose Up
-- Vault entry names are unique inside the vault where an operator sees them:
-- one personal vault or one shared collection. 00040 keyed name_bidx by the
-- custodian and constrained (user_id, name_bidx), which accidentally joined a
-- user's personal vault to every collection entry they happened to custody.
-- Besides rejecting useful duplicate labels across unrelated vaults, that made
-- create/import/rename a blind-index oracle for a fully-private collection.
--
-- Application writes from this migration onward key name_bidx by the same
-- explicit u:<user>/c:<collection> scope as the URL indexes. The two indexes
-- below state the storage invariant directly. They are partial so legacy rows
-- whose index could not be backfilled remain readable and repairable.
DROP INDEX IF EXISTS idx_vault_entries_user_name_bidx;

CREATE UNIQUE INDEX idx_vault_entries_personal_name_bidx
  ON vault_entries(user_id, name_bidx)
  WHERE name_bidx != '' AND (collection_id IS NULL OR collection_id = '');

CREATE UNIQUE INDEX idx_vault_entries_collection_name_bidx
  ON vault_entries(collection_id, name_bidx)
  WHERE name_bidx != '' AND collection_id IS NOT NULL AND collection_id != '';

-- +goose Down
DROP INDEX IF EXISTS idx_vault_entries_collection_name_bidx;
DROP INDEX IF EXISTS idx_vault_entries_personal_name_bidx;

CREATE UNIQUE INDEX idx_vault_entries_user_name_bidx
  ON vault_entries(user_id, name_bidx) WHERE name_bidx != '';

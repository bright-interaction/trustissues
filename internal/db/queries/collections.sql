-- collections.sql: shared team vaults (collections) + membership, plus the
-- collection-aware vault-entry queries that replace the per-user-only lookups so
-- a member sees personal entries AND entries in collections they belong to.

-- ============================================================================
-- Collections CRUD
-- ============================================================================

-- name: CreateCollection :exec
INSERT INTO collections (id, name, description, created_by) VALUES (?, ?, ?, ?);

-- name: GetCollection :one
SELECT id, name, description, created_by, created_at, updated_at FROM collections WHERE id = ?;

-- name: UpdateCollection :exec
UPDATE collections SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeleteCollection :exec
DELETE FROM collections WHERE id = ?;

-- name: ListCollectionsForUser :many
SELECT c.id, c.name, c.description, c.created_by, c.created_at, c.updated_at, cm.role
FROM collections c
JOIN collection_members cm ON cm.collection_id = c.id
WHERE cm.user_id = ?
ORDER BY c.name ASC;

-- name: ListAllCollections :many
SELECT id, name, description, created_by, created_at, updated_at FROM collections ORDER BY name ASC;

-- name: CountCollectionEntries :one
SELECT COUNT(*) FROM vault_entries WHERE collection_id = ?;

-- ============================================================================
-- Membership
-- ============================================================================

-- name: AddCollectionMember :exec
INSERT INTO collection_members (collection_id, user_id, role) VALUES (?, ?, ?)
ON CONFLICT(collection_id, user_id) DO UPDATE SET role = excluded.role;

-- name: RemoveCollectionMember :execresult
DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?;

-- name: GetCollectionMemberRole :one
SELECT role FROM collection_members WHERE collection_id = ? AND user_id = ?;

-- name: ListCollectionMembers :many
SELECT cm.user_id, cm.role, cm.added_at, u.email, u.name
FROM collection_members cm
JOIN users u ON u.id = cm.user_id
WHERE cm.collection_id = ?
ORDER BY u.email ASC;

-- name: CountCollectionManagers :one
SELECT COUNT(*) FROM collection_members WHERE collection_id = ? AND role = 'manager';

-- ============================================================================
-- Collection-aware vault-entry access
-- ============================================================================

-- name: GetVaultEntryAccess :one
-- Returns the owner and collection of an entry so the handler can authorize a
-- single-entry operation (personal: owner-or-admin; collection: member role).
SELECT user_id, collection_id FROM vault_entries WHERE id = ?;

-- name: SetVaultEntryCollection :exec
UPDATE vault_entries SET collection_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: ListAccessibleVaultEntries :many
SELECT e.id, e.user_id, e.collection_id, e.name, e.url, e.alias_url, e.username, e.category, e.notes, e.auto_login, e.rotation_interval_days, e.expires_at, e.last_rotated_at, e.provider, e.provider_meta, e.auto_rotate, e.last_rotation_error, e.created_at, e.updated_at
FROM vault_entries e
WHERE (e.collection_id IS NULL AND e.user_id = ?)
   OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ?)
ORDER BY e.name ASC;

-- name: ListAccessibleVaultEntriesWithSecrets :many
SELECT e.id, e.user_id, e.collection_id, e.name, e.url, e.alias_url, e.username, e.category, e.notes, e.auto_login, e.rotation_interval_days, e.expires_at, e.last_rotated_at, e.provider, e.provider_meta, e.auto_rotate, e.last_rotation_error, e.created_at, e.updated_at, e.encrypted_value, e.nonce
FROM vault_entries e
WHERE (e.collection_id IS NULL AND e.user_id = ?)
   OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ?)
ORDER BY e.name ASC;

-- name: MatchAccessibleVaultEntriesByURL :many
SELECT e.id, e.user_id, e.collection_id, e.name, e.url, e.alias_url, e.username, e.category, e.notes, e.auto_login, e.rotation_interval_days, e.expires_at, e.last_rotated_at, e.provider, e.provider_meta, e.auto_rotate, e.last_rotation_error, e.created_at, e.updated_at
FROM vault_entries e
WHERE ((e.collection_id IS NULL AND e.user_id = ?)
       OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ?))
  AND ((e.url_bidx != '' AND e.url_bidx = ?) OR (e.alias_url_bidx != '' AND e.alias_url_bidx = ?))
ORDER BY e.name ASC;

-- name: ListAccessibleVaultEntryNames :many
-- Names visible to the user (personal + collections) for import conflict checks.
SELECT e.name FROM vault_entries e
WHERE (e.collection_id IS NULL AND e.user_id = ?)
   OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ?);

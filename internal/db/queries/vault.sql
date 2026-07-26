-- vault.sql: Secrets vault queries - CRUD, encryption migration, unlock,
-- per-field updates, rotation, URL matching, reference resolution, import.
-- Source: internal/handlers/vault.go, internal/handlers/vault_import.go
-- Copied verbatim from dockyard so generated method names stay identical.

-- ============================================================================
-- Encryption migration (v1 SHA-256 -> v2 PBKDF2)
-- ============================================================================

-- name: CountVaultEntriesV1 :one
SELECT COUNT(*) FROM vault_entries WHERE encryption_version = 1;

-- name: ListVaultEntriesV1 :many
SELECT id, encrypted_value, nonce FROM vault_entries WHERE encryption_version = 1;

-- name: MigrateVaultEntryEncryption :exec
UPDATE vault_entries SET encrypted_value = ?, nonce = ?, encryption_version = 2 WHERE id = ?;

-- ============================================================================
-- Ownership check
-- ============================================================================

-- name: GetVaultEntryOwner :one
SELECT user_id FROM vault_entries WHERE id = ?;

-- ============================================================================
-- List entries (metadata only)
-- ============================================================================

-- name: ListAllVaultEntries :many
SELECT id, user_id, collection_id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, created_at, updated_at
FROM vault_entries ORDER BY name ASC;

-- name: ListVaultEntriesByUser :many
SELECT id, user_id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, created_at, updated_at
FROM vault_entries WHERE user_id = ? ORDER BY name ASC;

-- ============================================================================
-- Create entry
-- ============================================================================

-- name: CreateVaultEntry :exec
INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, provider, provider_meta, auto_rotate, url_bidx, alias_url_bidx, encryption_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2);

-- name: GetVaultEntryMeta :one
SELECT id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, custom_fields, created_at, updated_at
FROM vault_entries WHERE id = ?;

-- name: UpdateVaultEntryCustomFields :exec
UPDATE vault_entries SET custom_fields = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- ============================================================================
-- Update entry - encrypted value (re-encrypt + rotate timestamp)
-- ============================================================================

-- name: UpdateVaultEntryValue :exec
UPDATE vault_entries SET encrypted_value = ?, nonce = ?, encryption_version = 2, last_rotated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- ============================================================================
-- Update entry - individual metadata fields
-- ============================================================================

-- name: UpdateVaultEntryName :exec
UPDATE vault_entries SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryCategory :exec
UPDATE vault_entries SET category = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryNotes :exec
UPDATE vault_entries SET notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryRotationInterval :exec
UPDATE vault_entries SET rotation_interval_days = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryExpiresAt :exec
UPDATE vault_entries SET expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryURL :exec
UPDATE vault_entries SET url = ?, url_bidx = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryAliasURL :exec
UPDATE vault_entries SET alias_url = ?, alias_url_bidx = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryUsername :exec
UPDATE vault_entries SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryAutoLogin :exec
UPDATE vault_entries SET auto_login = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- ============================================================================
-- Delete entry
-- ============================================================================

-- name: GetVaultEntryName :one
SELECT name FROM vault_entries WHERE id = ?;

-- name: DeleteVaultEntry :execresult
DELETE FROM vault_entries WHERE id = ?;

-- ============================================================================
-- Unlock (password re-entry) - returns entries with encrypted data for decryption
-- ============================================================================

-- name: GetUserPasswordHash :one
SELECT password_hash FROM users WHERE id = ?;

-- name: ListVaultEntriesWithSecrets :many
SELECT id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, custom_fields, created_at, updated_at, encrypted_value, nonce
FROM vault_entries WHERE user_id = ? ORDER BY name ASC;

-- ============================================================================
-- Rotate (generate new secret value)
-- ============================================================================

-- name: RotateVaultEntryValue :execresult
UPDATE vault_entries SET encrypted_value = ?, nonce = ?, encryption_version = 2, last_rotated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- ============================================================================
-- URL matching (browser extension autofill)
-- ============================================================================

-- name: MatchVaultEntriesByURL :many
-- Autofill lookup by blind index. url/alias_url are encrypted at rest and cannot
-- be LIKE-matched, so the handler computes HMAC-SHA256(normalized_host) from the
-- requested url (see vault.go urlBlindIndex) and matches it against the stored
-- url_bidx / alias_url_bidx. Both bind params carry the SAME computed index.
SELECT id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, created_at, updated_at
FROM vault_entries WHERE user_id = ? AND ((url_bidx != '' AND url_bidx = ?) OR (alias_url_bidx != '' AND alias_url_bidx = ?)) ORDER BY name ASC;

-- ============================================================================
-- Resolve {{vault:NAME}} references (scoped to requesting user's vault)
-- ============================================================================

-- name: ResolveVaultReference :one
SELECT encrypted_value, nonce FROM vault_entries
WHERE vault_entries.name = ? AND user_id = ?;

-- ============================================================================
-- Import - conflict detection
-- ============================================================================

-- name: ListVaultEntryNamesByUser :many
SELECT name FROM vault_entries WHERE user_id = ?;

-- ============================================================================
-- Import - bulk insert (used inside transaction)
-- ============================================================================

-- name: ImportVaultEntry :exec
INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, url, username, category, notes, url_bidx, encryption_version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, datetime('now'), datetime('now'));

-- ============================================================================
-- Provider integration (API key rotation)
-- ============================================================================

-- name: UpdateVaultEntryProvider :exec
UPDATE vault_entries SET provider = ?, provider_meta = ?, auto_rotate = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryProviderMeta :exec
UPDATE vault_entries SET provider_meta = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: ListVaultEntriesForMetaBackfill :many
SELECT id, provider_meta, rotation_targets FROM vault_entries;

-- ============================================================================
-- Metadata-at-rest backfill (encrypt url/alias_url/username/category/notes,
-- compute url_bidx/alias_url_bidx). Runs once at boot via
-- VaultHandler.BackfillMetadataAtRest; idempotent (enc:v1: prefix guards it).
-- ============================================================================

-- name: ListVaultEntriesForMetaAtRestBackfill :many
-- user_id and collection_id are needed because the URL blind index is keyed per
-- SCOPE (personal vs a specific collection), so recomputing it requires knowing
-- which scope the row currently lives in.
SELECT id, user_id, collection_id, url, alias_url, username, category, notes, url_bidx, alias_url_bidx FROM vault_entries;

-- name: UpdateVaultEntryMetaAtRest :exec
UPDATE vault_entries
SET url = ?, alias_url = ?, username = ?, category = ?, notes = ?, url_bidx = ?, alias_url_bidx = ?
WHERE id = ?;

-- name: UpdateVaultEntryRotationError :exec
UPDATE vault_entries SET last_rotation_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryRotationLog :exec
UPDATE vault_entries SET rotation_log = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryRotationTargets :exec
UPDATE vault_entries SET rotation_targets = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: ListVaultEntriesNeedingRotation :many
SELECT id, user_id, name, encrypted_value, nonce, encryption_version, provider, provider_meta, rotation_interval_days, last_rotated_at, rotation_log, rotation_targets
FROM vault_entries
WHERE auto_rotate = 1
  AND provider != ''
  AND rotation_interval_days > 0
  AND (
    last_rotated_at IS NULL
    OR (julianday('now') - julianday(last_rotated_at)) >= rotation_interval_days
  )
ORDER BY last_rotated_at ASC;

-- name: GetVaultEntryForRotation :one
-- On-demand path: fetch a single entry (with its secret + rotation fields) by
-- id, with NO auto_rotate filter. This backs the manual Rotate and ValidateKey
-- handlers plus the rotation-log re-fetches, all of which are user-triggered
-- operations that MUST work for every entry regardless of auto_rotate (this is
-- an on-demand rotation product). The scheduled sweep uses a separate query,
-- ListVaultEntriesNeedingRotation, which keeps its own auto_rotate = 1 gate.
-- Do NOT re-add "AND auto_rotate = 1" here: it makes manual rotate panic
-- (empty row -> nil nonce -> GCM) and validate 404 for every entry that is not
-- auto-rotating.
SELECT id, user_id, name, encrypted_value, nonce, encryption_version, provider, provider_meta, rotation_interval_days, last_rotated_at, rotation_log, rotation_targets
FROM vault_entries WHERE id = ?;

-- name: GetVaultEntryTargets :one
SELECT rotation_targets FROM vault_entries WHERE id = ?;

-- name: ListProviderEntries :many
SELECT id, user_id, name, provider, provider_meta, auto_rotate, rotation_interval_days, expires_at, last_rotated_at, last_rotation_error, rotation_log, rotation_targets, created_at, updated_at
FROM vault_entries WHERE provider != '' ORDER BY provider ASC, name ASC;

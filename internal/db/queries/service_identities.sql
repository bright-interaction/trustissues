-- service_identities.sql: scope-limited API keys for production services
-- to fetch their declared secrets at boot. Source:
-- internal/handlers/service_secrets.go

-- ============================================================================
-- Resolve by hashed key (auth middleware lookup)
-- ============================================================================

-- name: GetServiceIdentityByKeyHash :one
SELECT id, name, description, allowed_secrets, key_prefix,
       last_used_at, expires_at, revoked_at, created_at, created_by_user_id
FROM service_identities
WHERE key_hash = ?;

-- name: TouchServiceIdentityLastUsed :exec
UPDATE service_identities
SET last_used_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- ============================================================================
-- Admin CRUD
-- ============================================================================

-- name: ListServiceIdentities :many
SELECT id, name, description, allowed_secrets, key_prefix,
       last_used_at, expires_at, revoked_at, created_at
FROM service_identities
ORDER BY created_at DESC;

-- name: GetServiceIdentityByID :one
SELECT id, name, description, allowed_secrets, key_prefix,
       last_used_at, expires_at, revoked_at, created_at
FROM service_identities
WHERE id = ?;

-- name: CreateServiceIdentity :exec
INSERT INTO service_identities
  (id, name, description, allowed_secrets, key_hash, key_prefix,
   expires_at, created_by_user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: RevokeServiceIdentity :execresult
UPDATE service_identities
SET revoked_at = CURRENT_TIMESTAMP
WHERE id = ? AND revoked_at IS NULL;

-- name: DeleteServiceIdentity :execresult
DELETE FROM service_identities WHERE id = ?;

-- ============================================================================
-- Vault lookup for service-side resolution (owner-scoped, name-keyed)
-- ============================================================================

-- name: GetVaultEntryForServiceFetch :one
-- Scoped to the OWNING user: vault_entries.name is unique only per user, so a
-- name-only lookup would return whichever user's same-named secret SQLite
-- returns first and decrypt it (cross-owner plaintext exfil). A service identity
-- may only resolve secrets owned by its creating user.
--
-- Also restricted to PERSONAL entries (collection_id IS NULL). A service
-- identity's allowed_secrets is a NAME whitelist, and any editor of a shared
-- collection can rewrite the value of an entry that lives in that collection
-- even when the creating user still owns the row. Without this predicate an
-- editor could therefore control what a machine identity fetches (or swap it for
-- a value of their choosing) purely by editing a shared entry. Machine
-- identities resolve only secrets their creator holds privately.
SELECT id, name, encrypted_value, nonce, encryption_version
FROM vault_entries
WHERE name = ? AND user_id = ? AND collection_id IS NULL
LIMIT 1;

-- ============================================================================
-- Audit log
-- ============================================================================

-- name: InsertServiceSecretAudit :exec
INSERT INTO service_secret_audit
  (id, service_identity_id, service_name, event, secret_names, error, remote_ip)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListRecentServiceSecretAudit :many
SELECT id, service_identity_id, service_name, event, secret_names,
       error, remote_ip, occurred_at
FROM service_secret_audit
ORDER BY occurred_at DESC
LIMIT ?;

-- name: ListAuditForServiceIdentity :many
SELECT id, service_identity_id, service_name, event, secret_names,
       error, remote_ip, occurred_at
FROM service_secret_audit
WHERE service_identity_id = ?
ORDER BY occurred_at DESC
LIMIT ?;

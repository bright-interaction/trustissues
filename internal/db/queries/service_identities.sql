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

-- name: RevokeServiceIdentitiesByUser :execresult
-- Offboarding: revoke every still-live service key a departing user minted.
-- FetchOwnSecrets resolves secrets as the identity's created_by_user_id, so an
-- un-revoked key outlives its owner and keeps reading their personal vault.
-- The runtime gate in FetchOwnSecrets refuses those anyway; revoking here is
-- what makes the revocation VISIBLE in the identities list instead of the key
-- silently 401ing at the next boot.
UPDATE service_identities
SET revoked_at = CURRENT_TIMESTAMP
WHERE created_by_user_id = ? AND revoked_at IS NULL;

-- name: ListServiceIdentitiesByUser :many
SELECT id, name FROM service_identities
WHERE created_by_user_id = ? AND revoked_at IS NULL;

-- name: DeleteServiceIdentity :execresult
DELETE FROM service_identities WHERE id = ?;

-- ============================================================================
-- Vault lookup for service-side resolution (owner-scoped)
-- ============================================================================

-- name: ListPersonalVaultEntriesForServiceFetch :many
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
--
-- THE NAME PREDICATE IS GONE FROM THE SQL, and it had to be. Since 00040 this
-- column holds randomized AES-GCM ciphertext, so `WHERE name = ?` against the
-- whitelist's cleartext matched NOTHING: every service-identity secret fetch
-- missed, and the handler answered 200 with an empty secrets map, so containers
-- booted credential-less believing they had succeeded.
--
-- It is deliberately NOT replaced with `WHERE name_bidx = ?`. The boot sweep in
-- vault.go leaves a row whose sealed name would collide on UNIQUE(user_id,
-- name_bidx) cleartext with an EMPTY name_bidx, forever, on purpose. A bidx
-- lookup silently strands exactly those rows, which is a worse failure than the
-- one being fixed because it is invisible. The name is matched in Go instead,
-- on the decrypted value, which resolves swept and unswept rows alike.
--
-- BOTH AUTHORIZATION PREDICATES STAY IN SQL. user_id is what stops a service
-- identity reaching another owner's secret and collection_id IS NULL is what
-- stops a collection editor choosing what a machine identity fetches. Neither
-- may move into the Go filter: a name match that runs after a widened query is
-- not an authorization check.
SELECT id, name, encrypted_value, nonce, encryption_version
FROM vault_entries
WHERE user_id = ? AND collection_id IS NULL;

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

-- collections.sql: shared team vaults (collections) + membership, plus the
-- collection-aware vault-entry queries that replace the per-user-only lookups so
-- a member sees personal entries AND entries in collections they belong to.

-- ============================================================================
-- Collections CRUD
-- ============================================================================

-- name: CreateCollection :exec
-- Legacy/internal creation paths intentionally take the schema default. This
-- keeps native documents from older versions compatible without allowing an
-- empty string to masquerade as a policy.
INSERT INTO collections (id, name, description, created_by) VALUES (?, ?, ?, ?);

-- name: CreateCollectionWithPolicy :exec
-- The live API validates this value with privateaccess.ParseOrDefault before
-- invoking the query. SQLite's CHECK remains the final closed-vocabulary gate.
INSERT INTO collections (id, name, description, created_by, private_access_policy)
VALUES (?, ?, ?, ?, ?);

-- name: GetCollection :one
SELECT id, name, description, created_by, private_access_policy, created_at, updated_at
FROM collections WHERE id = ?;

-- name: UpdateCollection :exec
-- NULL means the caller omitted the policy. Preserving it here, in the same
-- statement, avoids both old-client downgrades and a read/modify/write race.
UPDATE collections
SET name = sqlc.arg('name'),
    description = sqlc.arg('description'),
    private_access_policy = COALESCE(sqlc.narg('private_access_policy'), private_access_policy),
    updated_at = CURRENT_TIMESTAMP
WHERE id = sqlc.arg('id');

-- name: RestoreNativeImportedCollectionTimestamps :exec
-- Native imports create a private copy with a fresh id and fresh authority, but
-- retain the source document's content timestamps for portable history.
UPDATE collections SET created_at = ?, updated_at = ? WHERE id = ?;

-- name: DeleteCollection :exec
DELETE FROM collections WHERE id = ?;

-- name: ListCollectionsForUser :many
-- Accepted memberships only. A pending invitation must not surface the
-- collection (or its entries) until the invitee opts in.
SELECT c.id, c.name, c.description, c.created_by, c.private_access_policy,
       c.created_at, c.updated_at, cm.role
FROM collections c
JOIN collection_members cm ON cm.collection_id = c.id
WHERE cm.user_id = ? AND cm.accepted_at IS NOT NULL
ORDER BY c.name ASC;

-- name: ListPendingCollectionInvitesForUser :many
-- Invitations awaiting the user's decision. These grant no access.
SELECT c.id, c.name, c.description, cm.role, cm.added_at, u.email AS invited_by_email
FROM collections c
JOIN collection_members cm ON cm.collection_id = c.id
LEFT JOIN users u ON u.id = cm.invited_by
WHERE cm.user_id = ? AND cm.accepted_at IS NULL
ORDER BY cm.added_at DESC;

-- name: AcceptCollectionInvite :execresult
UPDATE collection_members SET accepted_at = CURRENT_TIMESTAMP
WHERE collection_id = ? AND user_id = ? AND accepted_at IS NULL;

-- name: ListAllCollections :many
SELECT id, name, description, created_by, private_access_policy, created_at, updated_at
FROM collections ORDER BY name ASC;

-- name: CountCollectionEntries :one
SELECT COUNT(*) FROM vault_entries WHERE collection_id = ?;

-- name: ListCollectionVaultEntryNamesSample :many
-- A bounded sample of the entries a collection holds, read by DeleteCollection
-- right before the FK cascade destroys them, so activity_log can name what was
-- lost instead of just noting that something was. Capped by LIMIT (the caller
-- passes it) rather than returned in full: a collection with hundreds of
-- entries would otherwise write an unbounded blob into the one append-only
-- trail this product has, and the exact count from CountCollectionEntries
-- already sits beside the sample in the log line for anything past the cap.
--
-- ORDER BY id, not name. name is ciphertext since 00040, so ordering by it
-- ordered by nonce: WHICH 25 of 30 entries got named in the permanent log was
-- random per delete, and re-running the same delete would have named a different
-- set. The caller sorts the DECRYPTED names before writing the line, so the log
-- still reads alphabetically; only the choice of which rows fall inside the cap
-- is made here, and it is now stable.
SELECT id, name FROM vault_entries WHERE collection_id = ? ORDER BY id ASC LIMIT ?;

-- ============================================================================
-- Membership
-- ============================================================================

-- name: AddCollectionMember :exec
-- accepted_at is passed explicitly: NULL for an invitation another user must
-- accept, set for a self-membership (the creator of a collection). On conflict
-- only the role changes, so re-inviting never silently re-grants access and a
-- role change never revokes an existing acceptance.
--
-- invited_by records who actually SENT this invitation, which the consent card
-- shows. On conflict it is only rewritten while the row is still pending: a role
-- change on an already-accepted member must not rewrite the history of who
-- brought them in.
INSERT INTO collection_members (collection_id, user_id, role, accepted_at, invited_by) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(collection_id, user_id) DO UPDATE SET
  role = excluded.role,
  invited_by = CASE WHEN collection_members.accepted_at IS NULL THEN excluded.invited_by ELSE collection_members.invited_by END;

-- name: RemoveCollectionMember :execresult
DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?;

-- name: GetCollectionMemberRole :one
-- Authorization lookup: a PENDING membership returns no row, so it grants
-- neither read nor write anywhere entryAccess or canWriteCollection is used.
SELECT role FROM collection_members
WHERE collection_id = ? AND user_id = ? AND accepted_at IS NOT NULL;

-- name: GetCollectionMembership :one
-- EXISTENCE lookup, acceptance-agnostic. Deliberately separate from
-- GetCollectionMemberRole: that one is the authorization gate and must keep
-- ignoring pending rows, but management operations need to see a pending
-- invitation too. RemoveMember used the authorization query as its existence
-- check, so rescinding an invitation that had not been accepted 404'd with
-- "member not found" and the invite stayed acceptable forever, with no way for
-- anyone to withdraw it. Never use this to decide access.
SELECT role, accepted_at FROM collection_members
WHERE collection_id = ? AND user_id = ?;

-- name: ListCollectionMembers :many
SELECT cm.user_id, cm.role, cm.added_at, cm.accepted_at, u.email, u.name
FROM collection_members cm
JOIN users u ON u.id = cm.user_id
WHERE cm.collection_id = ?
ORDER BY u.email ASC;

-- ============================================================================
-- Pending invitations, keyed by the invited EMAIL
-- ============================================================================
--
-- These exist so a pending seat is recorded whether or not the address matches
-- an account. collection_members can only hold a row for an address that HAS an
-- account (user_id is a foreign key), so listing pending memberships told any
-- collection manager, including a vault_only user who just created a throwaway
-- collection, exactly which addresses are registered. See migration 00033.

-- name: UpsertCollectionInvitation :exec
-- Re-inviting the same address updates the seat's role rather than adding a
-- second one, which is also how the members UI sends a role change.
INSERT INTO collection_invitations (collection_id, email, role, invited_by) VALUES (?, ?, ?, ?)
ON CONFLICT(collection_id, email) DO UPDATE SET
  role = excluded.role,
  invited_by = excluded.invited_by;

-- name: ListCollectionInvitations :many
SELECT collection_id, email, role, invited_by, created_at FROM collection_invitations
WHERE collection_id = ? ORDER BY email ASC;

-- name: ListCollectionInvitationsForEmail :many
-- Every seat waiting for one address, read at ACCOUNT CREATION.
--
-- Recording the seat by email fixed the enumeration oracle but broke redemption:
-- a seat for an address with no account never became a membership, so the
-- invitee could not accept it after signing up and the manager stared at a
-- pending row that would never resolve. That is the exact client-onboarding flow
-- (invite the client, they register, they join) this work exists to enable.
--
-- The seat row is deliberately NOT deleted when it is claimed. The seat is what
-- ListMembers renders, so removing it would change the pending entry's shape the
-- moment the address registered, which is the account-existence answer again by
-- another route.
SELECT collection_id, role, invited_by FROM collection_invitations
WHERE email = ? ORDER BY collection_id ASC;

-- name: DeleteCollectionInvitation :execresult
DELETE FROM collection_invitations WHERE collection_id = ? AND email = ?;

-- name: CountCollectionManagers :one
-- Accepted managers only: a pending invitee cannot be the manager that keeps a
-- collection from being orphaned.
SELECT COUNT(*) FROM collection_members
WHERE collection_id = ? AND role = 'manager' AND accepted_at IS NOT NULL;

-- ============================================================================
-- Collection-aware vault-entry access
-- ============================================================================

-- name: GetVaultEntryAccess :one
-- Returns the custodian, the SECRET OWNER and the collection of an entry so the
-- handler can authorize a single-entry operation (personal: owner-or-admin;
-- collection: member role).
--
-- Two owner columns, because they answer two questions and conflating them is
-- what made round 7's gate decorative on one path:
--
--   user_id               the CUSTODIAN. grantFor's isCreator and the personal
--                         listing/name scope. A collection MANAGER moves it to
--                         themselves by adopting an orphaned shared entry; the
--                         shared name scope remains c:<collection>.
--   secret_owner_user_id  the OWNER the EXIT asks about (mayDirectSecretEgress).
--                         Adoption does not move it, and nothing else in the
--                         module can: see internal/vaultegress.
SELECT user_id, secret_owner_user_id, collection_id FROM vault_entries WHERE id = ?;

-- name: SetVaultEntryCollection :exec
-- collection_id and name_bidx are one scope fact since 00045. Updating one
-- without the other either enforces the source vault on the destination or
-- briefly exposes a destination name to the source scope's uniqueness check.
UPDATE vault_entries
SET collection_id = ?, name_bidx = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ListAccessibleVaultEntries :many
SELECT e.id, e.user_id, e.collection_id, e.name, e.url, e.alias_url, e.username, e.category, e.notes, e.auto_login, e.rotation_interval_days, e.expires_at, e.last_rotated_at, e.provider, e.provider_meta, e.auto_rotate, e.last_rotation_error, e.created_at, e.updated_at
FROM vault_entries e
-- The disabled-account clause matches grantFor's row 2. Without it, disabling an
-- account left the unlock screen returning every shared secret's plaintext to
-- it, which is the widest of the offboarding doors because it is bulk rather
-- than one entry. Bind params: userID three times.
WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.disabled = 0)
  AND ((e.collection_id IS NULL AND e.user_id = ?)
   OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ? AND cm.accepted_at IS NOT NULL))
ORDER BY e.name ASC;

-- name: CountAccessibleVaultEntries :one
-- Export preflight twin of ListAccessibleVaultEntries. Keep the disabled-user
-- and accepted-membership predicate byte-identical so the cheap count never
-- promises a bulk reveal whose row query has a different scope. The caller
-- passes the first disallowed count (currently 5,001), so this preflight cannot
-- scan an attacker-sized vault just to learn that it is over the export cap.
--
-- minimum_portable_bytes is deliberately a LOWER bound, not an estimate. For
-- the entry value AES-GCM adds exactly a 16-byte tag. A sealed metadata column
-- is enc:v1: + base64(nonce || ciphertext); base64 can carry at most two padding
-- bytes, so floor(encoded/4)*3 - 30 is no greater than its plaintext byte count
-- (12-byte nonce + 16-byte tag + at most 2 padding bytes). JSON never represents
-- a string in fewer bytes than its UTF-8 input. Fields export may redact or
-- reserialize smaller (provider_meta, custom_fields, destination_patterns) are
-- intentionally excluded. Therefore a result over the native file ceiling can
-- be refused before any row is decrypted without rejecting a document that
-- could fit.
WITH accessible AS (
  SELECT e.id FROM vault_entries e
  WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.disabled = 0)
    AND ((e.collection_id IS NULL AND e.user_id = ?)
     OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ? AND cm.accepted_at IS NOT NULL))
    AND (sqlc.arg(private_ingress) = 1
      OR e.collection_id IS NULL
      OR EXISTS (
        SELECT 1 FROM collections c
        WHERE c.id = e.collection_id AND c.private_access_policy = 'standard'
      ))
  LIMIT sqlc.arg(max_rows)
), accessible_rows AS (
  SELECT e.id, e.collection_id, e.encrypted_value, e.name, e.url,
         e.alias_url, e.username, e.category, e.notes, e.provider
  FROM vault_entries e
  WHERE e.id IN (SELECT id FROM accessible)
), entry_stats AS (
  SELECT COUNT(*) AS entry_count,
    COALESCE(SUM(
      length(CAST(e.id AS BLOB)) +
      length(CAST(COALESCE(e.collection_id, '') AS BLOB)) +
      MAX(length(e.encrypted_value) - 16, 0) +
      CASE WHEN substr(e.name, 1, 7) = 'enc:v1:'
        THEN MAX(((length(e.name) - 7) / 4) * 3 - 30, 0)
        ELSE length(CAST(e.name AS BLOB)) END +
      CASE WHEN substr(COALESCE(e.url, ''), 1, 7) = 'enc:v1:'
        THEN MAX(((length(e.url) - 7) / 4) * 3 - 30, 0)
        ELSE length(CAST(COALESCE(e.url, '') AS BLOB)) END +
      CASE WHEN substr(COALESCE(e.alias_url, ''), 1, 7) = 'enc:v1:'
        THEN MAX(((length(e.alias_url) - 7) / 4) * 3 - 30, 0)
        ELSE length(CAST(COALESCE(e.alias_url, '') AS BLOB)) END +
      CASE WHEN substr(COALESCE(e.username, ''), 1, 7) = 'enc:v1:'
        THEN MAX(((length(e.username) - 7) / 4) * 3 - 30, 0)
        ELSE length(CAST(COALESCE(e.username, '') AS BLOB)) END +
      CASE WHEN substr(COALESCE(e.category, ''), 1, 7) = 'enc:v1:'
        THEN MAX(((length(e.category) - 7) / 4) * 3 - 30, 0)
        ELSE length(CAST(COALESCE(e.category, '') AS BLOB)) END +
      CASE WHEN substr(COALESCE(e.notes, ''), 1, 7) = 'enc:v1:'
        THEN MAX(((length(e.notes) - 7) / 4) * 3 - 30, 0)
        ELSE length(CAST(COALESCE(e.notes, '') AS BLOB)) END +
      length(CAST(COALESCE(e.provider, '') AS BLOB))
    ), 0) AS minimum_portable_bytes
  FROM accessible_rows e
), collection_stats AS (
  SELECT COALESCE(SUM(
    length(CAST(c.id AS BLOB)) +
    length(CAST(c.name AS BLOB)) +
    length(CAST(COALESCE(c.description, '') AS BLOB))
  ), 0) AS minimum_portable_bytes
  FROM collections c
  WHERE c.id IN (
    SELECT DISTINCT collection_id FROM accessible_rows WHERE collection_id IS NOT NULL
  )
)
SELECT entry_stats.entry_count AS entry_count,
       entry_stats.minimum_portable_bytes + collection_stats.minimum_portable_bytes AS minimum_portable_bytes
FROM entry_stats CROSS JOIN collection_stats;

-- name: ListAccessibleVaultEntriesWithSecrets :many
SELECT e.id, e.user_id, e.collection_id, e.name, e.url, e.alias_url, e.username, e.category, e.notes, e.auto_login, e.rotation_interval_days, e.expires_at, e.last_rotated_at, e.provider, e.provider_meta, e.auto_rotate, e.last_rotation_error, e.custom_fields, e.destination_patterns, e.created_at, e.updated_at, e.encrypted_value, e.nonce
FROM vault_entries e
-- The disabled-account clause matches grantFor's row 2; see
-- ListAccessibleVaultEntries above. Bind params: userID three times.
WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.disabled = 0)
  AND ((e.collection_id IS NULL AND e.user_id = ?)
   OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ? AND cm.accepted_at IS NOT NULL))
  AND (sqlc.arg(private_ingress) = 1
    OR e.collection_id IS NULL
    OR EXISTS (
      SELECT 1 FROM collections c
      WHERE c.id = e.collection_id AND c.private_access_policy = 'standard'
    ))
ORDER BY e.name ASC;

-- name: MatchAccessibleVaultEntriesByURL :many
SELECT e.id, e.user_id, e.collection_id, e.name, e.url, e.alias_url, e.username, e.category, e.notes, e.auto_login, e.rotation_interval_days, e.expires_at, e.last_rotated_at, e.provider, e.provider_meta, e.auto_rotate, e.last_rotation_error, e.created_at, e.updated_at
FROM vault_entries e
-- The disabled-account clause matches grantFor's row 2. This one feeds
-- browser-extension autofill, so a disabled account kept getting entry
-- suggestions for collections it had been cut from.
WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.disabled = 0)
  AND ((e.collection_id IS NULL AND e.user_id = ?)
       OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ? AND cm.accepted_at IS NOT NULL))
  AND ((e.url_bidx != '' AND e.url_bidx = ?) OR (e.alias_url_bidx != '' AND e.alias_url_bidx = ?))
ORDER BY e.name ASC;

-- name: MatchPersonalVaultEntriesByURL :many
-- Autofill within the caller's PERSONAL scope. The blind index is keyed per
-- scope, so a personal entry and a collection entry for the same host produce
-- different index values and a stolen database no longer reveals that two users
-- hold entries for the same site.
SELECT e.id, e.user_id, e.collection_id, e.name, e.url, e.alias_url, e.username, e.category, e.notes, e.auto_login, e.rotation_interval_days, e.expires_at, e.last_rotated_at, e.provider, e.provider_meta, e.auto_rotate, e.last_rotation_error, e.created_at, e.updated_at
FROM vault_entries e
WHERE e.collection_id IS NULL AND e.user_id = ?
  AND ((e.url_bidx != '' AND e.url_bidx = ?) OR (e.alias_url_bidx != '' AND e.alias_url_bidx = ?))
ORDER BY e.name ASC;

-- name: MatchCollectionVaultEntriesByURL :many
-- Autofill within one collection the caller has ACCEPTED. Callers must check
-- membership before calling; the collection id is the index scope.
SELECT e.id, e.user_id, e.collection_id, e.name, e.url, e.alias_url, e.username, e.category, e.notes, e.auto_login, e.rotation_interval_days, e.expires_at, e.last_rotated_at, e.provider, e.provider_meta, e.auto_rotate, e.last_rotation_error, e.created_at, e.updated_at
FROM vault_entries e
WHERE e.collection_id = ?
  AND ((e.url_bidx != '' AND e.url_bidx = ?) OR (e.alias_url_bidx != '' AND e.alias_url_bidx = ?))
ORDER BY e.name ASC;

-- name: ListAccessibleVaultEntryNames :many
-- Names visible to the user (personal + collections) for import conflict checks.
SELECT e.name FROM vault_entries e
WHERE ((e.collection_id IS NULL AND e.user_id = ?)
   OR e.collection_id IN (SELECT cm.collection_id FROM collection_members cm WHERE cm.user_id = ? AND cm.accepted_at IS NOT NULL))
  AND (sqlc.arg(private_ingress) = 1
    OR e.collection_id IS NULL
    OR EXISTS (
      SELECT 1 FROM collections c
      WHERE c.id = e.collection_id AND c.private_access_policy = 'standard'
    ));

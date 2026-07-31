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
SELECT id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, custom_fields, destination_patterns, created_at, updated_at
FROM vault_entries WHERE id = ?;

-- name: UpdateVaultEntryCustomFields :exec
UPDATE vault_entries SET custom_fields = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- ============================================================================
-- Update entry - encrypted value (re-encrypt + rotate timestamp)
-- ============================================================================

-- name: UpdateVaultEntryValue :exec
UPDATE vault_entries SET encrypted_value = ?, nonce = ?, encryption_version = 2, last_rotated_at = CURRENT_TIMESTAMP, last_rotation_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

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
SELECT id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, custom_fields, destination_patterns, created_at, updated_at, encrypted_value, nonce
FROM vault_entries WHERE user_id = ? ORDER BY name ASC;

-- ============================================================================
-- Rotate (generate new secret value)
-- ============================================================================

-- name: RotateVaultEntryValueUnchecked :execresult
-- "Unchecked" means unchecked BY THIS QUERY: it will happily bind an empty
-- token and match zero rows. Call persistRotatedValue instead, which refuses a
-- missing token. TestRotateValueHasOneCallSite enforces that this name appears
-- in exactly one non-test file.
-- Compare-and-swap on updated_at.
--
-- The scheduled sweep snapshots every due entry at pass start and writes back
-- minutes later, so a value a user saved during the pass was silently
-- overwritten by the stale one. The extra predicate makes that a no-op instead:
-- the caller checks RowsAffected and treats 0 as "someone else changed it,
-- leave it alone and pick it up next pass". It also stops a rotation landing on
-- an entry that was deleted mid-pass.
-- The comparison is on TEXT, deliberately. The column is DATETIME but SQLite
-- stores it as the literal string CURRENT_TIMESTAMP produced
-- ("2026-07-29 13:06:22"), while Go's driver scans it into a time.Time and binds
-- it back in a different layout. So `updated_at = ?` with a time.Time NEVER
-- matched: the first version of this CAS made every scheduled rotation report a
-- conflict and persist nothing, turning a rare lost-update into a total silent
-- outage of auto-rotation. Compare the raw text both ways.
UPDATE vault_entries SET encrypted_value = ?, nonce = ?, encryption_version = 2, last_rotated_at = CURRENT_TIMESTAMP, last_rotation_error = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND CAST(updated_at AS TEXT) = CAST(@updated_at_text AS TEXT);

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

-- name: ResolveVaultReference :many
-- Resolves a {{vault:NAME}} / auth_token reference to its ciphertext.
--
-- Returns id so the CALLER can run the resolved row through entryAccessFor
-- rather than trusting this predicate. user_id is the CREATOR column, not a
-- statement of current access: removing someone from a collection deletes only
-- the collection_members row, so a name+user_id match kept resolving a shared
-- secret for a member who had been removed from the collection holding it.
--
-- :many, not :one, so an ambiguous name is refused by the caller instead of
-- SQLite silently picking a row.
SELECT id, user_id, collection_id, encrypted_value, nonce FROM vault_entries
WHERE vault_entries.name = ?;

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

-- name: GetVaultEntryRotationLog :one
SELECT COALESCE(rotation_log, '') FROM vault_entries WHERE id = ?;

-- name: CASVaultEntryRotationLog :execresult
-- Compare-and-swap on the rotation_log column itself.
--
-- rotation_log is read-modify-written: the caller unmarshals the array, appends one
-- entry, trims to 50 and writes the whole column back. With a plain UPDATE that is a
-- lost update. The sweep takes its snapshot at pass start and can be up to 90s per
-- earlier entry behind, so a user clicking Rotate on the same entry mid-pass had
-- their successful rotation ERASED from history and replaced by the sweep's
-- conflict error, complete with an alert about a rotation that had actually
-- succeeded.
--
-- Comparing the column rather than updated_at is deliberate: updated_at is bumped by
-- every neighbouring write, so it would spuriously fail here, and it is stored as
-- literal text which has already caused three rounds of CAS bugs on this table.
UPDATE vault_entries SET rotation_log = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND COALESCE(rotation_log, '') = ?;

-- name: UpdateVaultEntryRotationTargets :exec
UPDATE vault_entries SET rotation_targets = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: ListVaultEntriesNeedingRotation :many
SELECT id, user_id, name, encrypted_value, nonce, encryption_version, provider, provider_meta, rotation_interval_days, last_rotated_at, rotation_log, rotation_targets, CAST(updated_at AS TEXT) AS updated_at_text
FROM vault_entries
WHERE auto_rotate = 1
  AND provider != ''
  AND rotation_interval_days > 0
  -- Age from created_at when the entry has never been rotated, NOT "NULL means
  -- due now". last_rotated_at has no DEFAULT and CreateVaultEntry never sets
  -- it, so every newly enrolled secret was NULL and the old predicate made it
  -- due on the very next pass (1 minute after boot, then hourly). An operator
  -- who stored a Cloudflare token, ticked auto-rotate and chose 365 days had it
  -- rolled at the provider within the hour, killing the value they had just
  -- deployed, while the UI showed the entry as "fresh". created_at is always
  -- populated (DEFAULT CURRENT_TIMESTAMP), so the clock starts at enrolment: a
  -- genuinely old entry still comes due immediately, a fresh one waits out its
  -- interval. computeRotationStatus uses the same fallback so the UI and the
  -- scheduler agree.
  AND (julianday('now') - julianday(COALESCE(last_rotated_at, created_at))) >= rotation_interval_days
  -- The entry must still have a live owner, or live in a shared collection.
  --
  -- vault_entries.user_id has no foreign key (every other user-owned table has
  -- one), and deleting a user does not touch the table, so a departed person's
  -- personal entries survive with a dangling user_id. Nothing can READ them
  -- afterwards: unlock, the capability lookups and the service fetch are all
  -- scoped to a real user. But this sweep had no owner filter at all, so it
  -- kept rotating those secrets AT THE PROVIDER forever: invalidating whatever
  -- was deployed with the old value, writing the new value into a row nobody
  -- can decrypt, then failing delivery and firing a rotation_partial alert on
  -- every pass, from an account that no longer exists.
  --
  -- Disabled owners are excluded for the same reason offboarding revokes their
  -- delivery targets: a suspended account's credentials should stop moving.
  AND (
    (collection_id IS NOT NULL AND collection_id != '')
    OR EXISTS (SELECT 1 FROM users u WHERE u.id = vault_entries.user_id AND u.disabled = 0)
  )
ORDER BY COALESCE(last_rotated_at, created_at) ASC;

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
SELECT CAST(updated_at AS TEXT) AS updated_at_text, id, user_id, name, encrypted_value, nonce, encryption_version, provider, provider_meta, rotation_interval_days, last_rotated_at, rotation_log, rotation_targets
FROM vault_entries WHERE id = ?;

-- name: GetVaultEntryTargets :one
SELECT rotation_targets FROM vault_entries WHERE id = ?;

-- name: ListProviderEntries :many
SELECT id, user_id, name, provider, provider_meta, auto_rotate, rotation_interval_days, expires_at, last_rotated_at, last_rotation_error, rotation_log, rotation_targets, created_at, updated_at
FROM vault_entries WHERE provider != '' ORDER BY provider ASC, name ASC;

-- name: AnyEncryptedVaultEntry :many
-- Boot-time vault-key probe. Returns EVERY sealed secret, with its version, so
-- VerifyVaultKey can test whether the configured key actually opens this
-- database BEFORE writing the sentinel.
--
-- Two things here were wrong and both ended in the same unrecoverable state.
--
-- It filtered `encryption_version = 2`, which is defensible for deciding
-- "opens" (a v1 row is sealed under the legacy SHA-256 derivation) but not for
-- deciding "hasCiphertext". A database whose vault rows are ALL v1, which
-- vault_rotation_cas.go documents as a supported carried-over input and which
-- MigrateEncryption exists to handle, answered "no ciphertext at all". The gate
-- then sealed the sentinel under whatever key was configured, and afterwards
-- refused the CORRECT key permanently. The caller now tests v1 rows under the
-- legacy derivation instead of pretending they are not there.
--
-- It was also `:one` with LIMIT 1, sampling ONE arbitrary row while probes 2
-- and 3 both iterate. One row sealed under an older key, or one bit flip, made
-- the gate refuse a key that opens every other row in the table. Returning the
-- set lets the caller answer "does this key open ANY of them", which is the
-- question the gate is actually asking.
SELECT encrypted_value, nonce, encryption_version FROM vault_entries
WHERE length(encrypted_value) > 0;

-- name: ListVaultEntryTargetsInCollection :many
-- Offboarding sweep: every entry in a collection that has rotation targets, so
-- targets configured by a departing member can be purged when they lose access.
SELECT id, name, rotation_targets FROM vault_entries
WHERE collection_id = ? AND rotation_targets IS NOT NULL AND rotation_targets != '' AND rotation_targets != '[]';

-- name: ListAllVaultEntryTargets :many
-- Estate-wide variant of the sweep above, for offboarding that is not scoped to
-- one collection: disabling an account has to detach that person's delivery
-- endpoints wherever they sit, including on entries they own personally, since
-- auto-rotation keeps running on those after the account is disabled.
SELECT id, name, rotation_targets FROM vault_entries
WHERE rotation_targets IS NOT NULL AND rotation_targets != '' AND rotation_targets != '[]';

-- name: UpdateVaultEntryDestinationPatterns :exec
-- The capability ceiling: which hosts/paths an agent token minted for this
-- secret may ever reach. Until this existed the column had exactly one writer
-- (the provider preset seed), so a secret created without a recognised provider
-- could never mint a capability token at all and the MCP feature was unusable.
UPDATE vault_entries SET destination_patterns = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeletePersonalVaultEntriesForUser :execresult
-- Hard user delete: their PERSONAL entries go with them.
--
-- The alternative is what used to happen: the rows survived with a dangling
-- user_id and no read path anywhere (unlock, the capability lookups and the
-- service fetch are all scoped to a real user), so they were unrecoverable
-- ciphertext held forever. Deleting them therefore loses nothing that could
-- ever have been read again, makes the confirmation dialog's promise true, and
-- gives the product an actual erasure path.
DELETE FROM vault_entries WHERE user_id = ? AND (collection_id IS NULL OR collection_id = '');

-- name: ListCollectionVaultEntriesForUser :many
-- The rows ReassignCollectionVaultEntryOwner will walk, one at a time.
--
-- A single blanket UPDATE was all-or-nothing: vault_entries still carries
-- UNIQUE(user_id, name), so if the leaver and the new owner both had an entry
-- called "GitHub" (generic names collide constantly in a password manager) the
-- statement aborted and EVERY shared entry kept the deleted user's id, silently,
-- while the confirmation dialog promised the team would keep them.
SELECT id, name FROM vault_entries
WHERE user_id = ? AND collection_id IS NOT NULL AND collection_id != '';

-- name: ReassignCollectionVaultEntryOwner :execresult
-- Re-own ONE entry, so a single name collision cannot block the rest.
UPDATE vault_entries SET user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: RenameVaultEntry :execresult
-- Used only to de-duplicate on re-ownership when the new owner already has an
-- entry by that name.
UPDATE vault_entries SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: AnyEncryptedColumnSample :many
-- Boot key-gate probe 3: every OTHER columncrypto surface.
--
-- Probes 1 and 2 cover v2 vault secrets and marked TOTP seeds. A database whose
-- only ciphertext is an SMTP password, an invitation code or a notification
-- channel config satisfied neither, so the gate reported "no ciphertext", sealed
-- the sentinel under whatever key was configured, and then permanently refused
-- the CORRECT key. Cheap to close: one row from each surface is enough.
-- Each surface is bounded by its OWN subquery. A trailing LIMIT on a compound
-- SELECT applies to the WHOLE result, so the first version returned only the
-- settings row and never probed an invitation code at all: a database whose only
-- ciphertext was an invite code still fell through the gate, which is the exact
-- hole this probe exists to close.
-- Each row carries its crypto FAMILY, because the three surfaces do not share one.
-- settings.smtp_password is columncrypto ("tienc:v1:"), invitations.code is the
-- vault handler's own column crypto ("enc:v1:"), and a notification config is raw
-- AES-GCM bytes with its nonce in a separate column and NO marker at all.
--
-- Probe 3 used to run columncrypto.IsEncrypted over all three, so it recognised
-- exactly one and silently skipped the other two: a database whose only ciphertext
-- was an invite code or a channel config still reported "no ciphertext", the gate
-- sealed a sentinel under whatever key was configured, and the CORRECT key was
-- refused from then on. That is the data loss this probe exists to prevent, and it
-- was inert for two thirds of its own surface area.
SELECT family, blob FROM (SELECT 'columncrypto' AS family, value AS blob FROM settings WHERE key = 'smtp_password' AND value != '' LIMIT 1)
UNION ALL
SELECT family, blob FROM (SELECT 'vaultcolumn' AS family, code AS blob FROM invitations WHERE code != '' LIMIT 1)
UNION ALL
SELECT family, blob FROM (SELECT 'rawgcm' AS family, config AS blob FROM notification_channels WHERE config != '' AND encryption_version > 0 LIMIT 1);

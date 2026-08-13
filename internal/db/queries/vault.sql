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
FROM vault_entries ORDER BY id ASC;

-- name: ListVaultEntriesByUser :many
SELECT id, user_id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, created_at, updated_at
FROM vault_entries WHERE user_id = ? ORDER BY id ASC;

-- ============================================================================
-- Create entry
-- ============================================================================

-- name: GetVaultEntryMeta :one
-- collection_id is SELECTed here on purpose. It was missing, so every response
-- built from this row (PUT /vault/{id}, POST /{id}/rotate, PUT /{id}/schedule)
-- reported collection_id: null no matter which shared collection the entry was
-- actually in. Clients that merge a write response into a cached entry then
-- moved every shared entry back to "Personal" on save. Adding a column to this
-- projection is cheap; the clients working around its absence was not.
--
-- name_bidx joins the projection for the same reason: the two callers that
-- rewrite the scope-keyed indexes after a move pass every OTHER column of this
-- row straight back into UpdateVaultEntryMetaAtRest unchanged, and a column they
-- cannot read is a column they would write as empty. A move changes
-- collection_id, never user_id, so the name index is genuinely unchanged and
-- passing it through is the correct thing rather than merely the safe one.
SELECT id, collection_id, name, name_bidx, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, custom_fields, destination_patterns, created_at, updated_at
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
-- name_bidx moves with name, always. They are one fact in two columns, and a
-- rename that updated only the ciphertext would leave the old name's token
-- enforcing uniqueness and the new name's unconstrained.
UPDATE vault_entries SET name = ?, name_bidx = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: AdoptAndRenameVaultEntry :exec
-- Rename an ORPHANED shared entry and take ownership of it in one statement.
--
-- Uniqueness is UNIQUE(user_id, name), scoped to the entry's creator, so any
-- rename by somebody else asks a question about the creator's private namespace
-- and the answer (409 or 200) is readable by the person asking. Writing the new
-- owner and the new name together moves the uniqueness question into the
-- renamer's OWN namespace, where a conflict is with an entry they can see and
-- saying so leaks nothing. See the rule in vault.go's Update.
--
-- IT DOES NOT TOUCH secret_owner_user_id, AND THAT IS THE POINT.
--
-- This statement is how a collection MANAGER used to make themselves the owner
-- for the purposes of the exit: remove the creator from the collection (also
-- manager-gated), then rename the entry. Two ordinary calls and the exit
-- authorised the cross-entry delivery it exists to refuse, because it resolved
-- "owner" from the column this statement writes.
--
-- Adoption is still right and still happens: it moves the UNIQUE(user_id, name)
-- question into the renamer's namespace, which is a NAMESPACE concern. Whose
-- authority governs the plaintext is a different question and lives in a
-- different column, which only internal/vaultegress can write.
--
-- name_bidx is written here too, and it MUST be derived under the NEW user_id.
-- The index is keyed by the custodian, so an adoption that carried the old
-- owner's token across would enforce the departing owner's namespace on a row
-- that now lives in the adopter's, which is the opposite of what this statement
-- exists to do.
UPDATE vault_entries SET user_id = ?, name = ?, name_bidx = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

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
FROM vault_entries WHERE user_id = ? ORDER BY id ASC;

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
-- The token also carries the PRIOR CIPHERTEXT, because a timestamp cannot see a
-- same-second write. updated_at is CURRENT_TIMESTAMP, which SQLite renders at
-- whole-second resolution, so two writes committed inside one second leave the
-- column byte-identical and a snapshot taken between them still matches: the CAS
-- reports applied=true for exactly the lost update it exists to refuse.
-- Demonstrated against the real schema (token 17:06:04, competing write at
-- 17:06:04, replayed stale CAS -> rows changed = 1).
--
-- encrypted_value is AES-GCM under a fresh random nonce, so two different writes
-- essentially never produce the same bytes, and it is precisely the column whose
-- loss matters here: a concurrent name or schedule edit touches other columns and
-- is not lost by this statement. Comparing it makes the guard independent of clock
-- granularity.
UPDATE vault_entries SET encrypted_value = ?, nonce = ?, encryption_version = 2, last_rotated_at = CURRENT_TIMESTAMP, last_rotation_error = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
  AND CAST(updated_at AS TEXT) = CAST(@updated_at_text AS TEXT)
  AND encrypted_value = @prev_encrypted_value;

-- ============================================================================
-- URL matching (browser extension autofill)
-- ============================================================================

-- name: MatchVaultEntriesByURL :many
-- Autofill lookup by blind index. url/alias_url are encrypted at rest and cannot
-- be LIKE-matched, so the handler computes HMAC-SHA256(normalized_host) from the
-- requested url (see vault.go urlBlindIndex) and matches it against the stored
-- url_bidx / alias_url_bidx. Both bind params carry the SAME computed index.
SELECT id, name, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, last_rotated_at, provider, provider_meta, auto_rotate, last_rotation_error, created_at, updated_at
FROM vault_entries WHERE user_id = ? AND ((url_bidx != '' AND url_bidx = ?) OR (alias_url_bidx != '' AND alias_url_bidx = ?)) ORDER BY id ASC;

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
--
-- IT NO LONGER FILTERS BY NAME, and cannot. Since 00040 the name column holds
-- randomized ciphertext, and the blind index that replaced it for equality is
-- keyed per USER, so there is no single token to look a name up by across the
-- users whose entries a caller may legitimately reach through a shared
-- collection. The name comparison therefore moves into Go, against the decrypted
-- name, in resolveVaultReferenceFor.
--
-- The REACHABILITY filter is untouched and still runs afterwards, which is what
-- keeps seven rounds of scope fixes intact: this statement never authorised
-- anything, it only narrowed. Returning the name lets the caller narrow on
-- exactly what it narrowed on before.
SELECT id, user_id, collection_id, name, encrypted_value, nonce FROM vault_entries;

-- ============================================================================
-- Import - conflict detection
-- ============================================================================

-- name: ListVaultEntryNamesByUser :many
SELECT name FROM vault_entries WHERE user_id = ?;

-- ============================================================================
-- Import - bulk insert (used inside transaction)
-- ============================================================================

-- name: ImportVaultEntry :exec
-- secret_owner_user_id is written HERE, on the INSERT, alongside user_id.
--
-- Every statement that creates a vault entry has to name both, and
-- TestEveryRowCreatingStatementNamesTheSecretOwner proves it against SQLite
-- rather than against a reviewer: a row inserted with the column left at its ''
-- default has no owner at all, so mayDirectSecretEgress refuses everyone and the
-- importer silently loses the ability to configure delivery for what they just
-- imported. Forgetting must be a red test, not a feature that quietly stops.
INSERT INTO vault_entries (id, user_id, secret_owner_user_id, name, encrypted_value, nonce, url, username, category, notes, url_bidx, name_bidx, encryption_version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, datetime('now'), datetime('now'));

-- ============================================================================
-- Provider integration (API key rotation)
-- ============================================================================

-- name: ListVaultEntriesForMetaBackfill :many
-- provider is selected alongside the two columns being re-encrypted because the
-- egress write gate derives the entry's reachable host set from the
-- (provider, provider_meta) pair. A backfill must be able to show that its write
-- moves that set nowhere, and it cannot show that without the provider name.
SELECT id, provider, provider_meta, rotation_targets FROM vault_entries;

-- ============================================================================
-- Metadata-at-rest backfill (encrypt url/alias_url/username/category/notes,
-- compute url_bidx/alias_url_bidx). Runs once at boot via
-- VaultHandler.BackfillMetadataAtRest; idempotent (enc:v1: prefix guards it).
-- ============================================================================

-- name: ListVaultEntriesForMetaAtRestBackfill :many
-- user_id and collection_id are needed because the URL blind index is keyed per
-- SCOPE (personal vs a specific collection), so recomputing it requires knowing
-- which scope the row currently lives in. name and name_bidx joined them in
-- 00040: the name index is keyed by user_id alone, which user_id already covers.
SELECT id, user_id, collection_id, name, url, alias_url, username, category, notes, url_bidx, alias_url_bidx, name_bidx FROM vault_entries;

-- name: UpdateVaultEntryMetaAtRest :exec
UPDATE vault_entries
SET name = ?, url = ?, alias_url = ?, username = ?, category = ?, notes = ?, url_bidx = ?, alias_url_bidx = ?, name_bidx = ?
WHERE id = ?;

-- name: UpdateVaultEntryRotationError :exec
UPDATE vault_entries SET last_rotation_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: GetVaultEntryRotationLog :one
SELECT COALESCE(rotation_log, '') FROM vault_entries WHERE id = ?;

-- name: CASVaultEntryRotationLog :execresult
-- Compare-and-swap on the rotation_log column itself. THE ONLY WRITER OF THIS
-- COLUMN. There is deliberately no unconditional `SET rotation_log = ?` sibling.
--
-- There was one, and everything below was already written next to it. Three call
-- sites used the plain writer anyway (the reminder branch of the sweep, the
-- reminder branch of the manual handler, and recordRotationFailure), each
-- appending to a caller-supplied snapshot: precisely the lost update this query
-- was added to prevent, still live on three of five paths. Deleting the plain
-- query is what makes appendRotationLog the only reachable writer, because a
-- future caller cannot name a method sqlc does not generate.
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
-- ORDER BY id, not name: name is ciphertext since 00040 and sorting it would
-- order rows by nonce, which is random. Callers that present entries to a human
-- sort by the DECRYPTED name in Go (sortEntriesByName).
FROM vault_entries WHERE provider != '' ORDER BY provider ASC, id ASC;

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

-- Re-owning ONE entry (so a single name collision cannot block the rest) is
-- vaultegress.TransferSecretOwnership now. The statement moved to
-- internal/vaultegress/queries because it writes secret_owner_user_id, the
-- column the exit resolves "whose secret is this" from, and that column has
-- exactly one post-creation writer by construction rather than by convention.

-- RenameVaultEntry is GONE, deliberately.
--
-- It wrote name WITHOUT name_bidx, which 00040 made a contradiction: the two are
-- one fact in two columns, and a rename that moves only the ciphertext leaves the
-- OLD name's token enforcing uniqueness and the new name's unconstrained. Its one
-- caller (the offboard de-duplication) now uses UpdateVaultEntryName, which takes
-- both. Removed rather than left unused, because the next person to need a rename
-- would have found a ready-made statement that silently does the wrong half.

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

-- ============================================================================
-- THE OPERATOR SURFACE FOR THE FAIL-CLOSED BACKFILL (migration 00034)
-- ============================================================================

-- name: ListVaultEntriesWithNoRecordedOwner :many
-- Every entry whose secret_owner_user_id is empty, which is every entry the
-- 00034 backfill refused to stamp because the database could not prove the
-- current custodian is the principal who deposited the plaintext.
--
-- An empty owner DENIES at mayDirectSecretEgress, so this list is exactly the
-- set of secrets that cannot accept a new delivery destination. A fail-closed
-- migration with no way to see what it closed is its own outage, which is why
-- this exists and why it is joined to something an admin can act on: the
-- custodian's address and the collection name.
--
-- Admin-only at the route. It names entries across every user's vault, which is
-- a thing only an instance admin may enumerate, and it deliberately returns NO
-- ciphertext and no encrypted metadata: repairing ownership does not require
-- seeing the secret.
SELECT e.id, e.name, e.user_id, e.collection_id, e.created_at, e.updated_at,
       u.email AS custodian_email,
       c.name AS collection_name
FROM vault_entries e
LEFT JOIN users u ON u.id = e.user_id
LEFT JOIN collections c ON c.id = e.collection_id
WHERE e.secret_owner_user_id = ''
ORDER BY e.created_at ASC, e.id ASC;

-- name: CountRecordedAdoptionsForEntry :one
-- Whether the append-only audit trail records this entry being ADOPTED by a
-- collection manager, i.e. its custodian moving without its owner moving.
--
-- It is shown next to each unowned entry so an admin repairing ownership can
-- tell "this one is merely ambiguous" from "this one was demonstrably taken
-- over". It is not a security decision: the vault.entry_adopted row only exists
-- for adoptions performed by a binary from 2026-08-02 onward, so an empty
-- answer proves nothing and the migration never treats it as proof on its own.
SELECT COUNT(*) FROM activity_log
WHERE action = 'vault.entry_adopted' AND instr(detail, 'Entry ' || sqlc.arg(entry_id) || ' ') > 0;

-- ============================================================================
-- Master-key rotation (VaultHandler.RekeyVault, see vault_rekey.go).
--
-- One list + one write per keyed surface. The list queries are deliberately
-- UNFILTERED: the sweep has to SEE every row to answer "does this open under the
-- current key", and a WHERE clause that excludes a row excludes it from the
-- rotation too. The boot key gate has already been burned twice by a probe query
-- that filtered away the rows that mattered (encryption_version = 2 only, then a
-- trailing LIMIT on a compound SELECT), and both times the result was a store
-- that silently reported "nothing to protect here". Filtering happens in Go,
-- where the reason for skipping a row can be reported.
-- ============================================================================

-- name: ListVaultEntriesForRekey :many
-- Every vault_entries column that holds material derived from the master key, in
-- one read: the secret value (+ its nonce and derivation version), the eight
-- enc:v1: metadata columns, and the two blind indexes. user_id and collection_id
-- come along because the blind index is keyed PER SCOPE, so recomputing it needs
-- to know which scope the row lives in.
--
-- provider comes along although it is not keyed and is never rewritten here. The
-- write this feeds is a host-choosing one and therefore takes an egressgate
-- ticket, and providerDestinations needs the provider NAME as well as the meta
-- to say which hosts a provider binding can reach. Without it the sweep would
-- have to mint its ticket on an empty comparison, which is the shape the
-- chokepoint guards call decorative.
SELECT id, user_id, collection_id, encrypted_value, nonce, encryption_version,
       name, url, alias_url, username, category, notes,
       provider, provider_meta, rotation_targets, custom_fields,
       url_bidx, alias_url_bidx, name_bidx
FROM vault_entries
ORDER BY id;

-- RekeyVaultEntry USED TO LIVE HERE and is now in
-- internal/vaultegress/queries/vault_egress.sql.
--
-- It writes provider_meta and rotation_targets, which are HOST-CHOOSING
-- columns, and nothing outside internal/vaultegress may write one of those
-- without an egressgate.Ticket. Generated into this package the statement was
-- reachable as h.queries.RekeyVaultEntry, i.e. a way to set a delivery target
-- with no decision behind it, and TestNoStatementOutsideTheEgressPackageWrites
-- AHostChoosingColumn refuses it: SQLite will not even prepare the statement
-- against a schema where those columns are GENERATED.
--
-- Moving it kept BOTH properties the merge had to hold together. The sweep
-- still writes every keyed column of a row in ONE statement, so a row can never
-- be half-converted, and the write still goes through the ticket chokepoint.
-- The ticket it takes is the re-encryption kind: same destinations in, same
-- destinations out.

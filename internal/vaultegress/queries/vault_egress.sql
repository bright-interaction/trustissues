-- EVERY STATEMENT THAT WRITES A HOST-CHOOSING COLUMN OF vault_entries.
--
-- These used to live in internal/db/queries alongside every other query, which
-- meant sqlc put them on *db.Queries, which meant any handler could call one.
-- Five rounds of the same defect ended the same way: a write path that never
-- asked who was allowed to redirect the secret, sitting next to a table that
-- said the column was dangerous.
--
-- They generate into internal/vaultegress/internal/egressq. Go's `internal`
-- rule means that package is importable ONLY from inside internal/vaultegress,
-- so the exported wrappers in internal/vaultegress/writes.go, which demand an
-- egressgate.Ticket, are the only way for the rest of the module to reach them.
-- A handler that tries to call one directly does not fail a test, it fails to
-- compile.
--
-- ADD A NEW ONE HERE, not in internal/db/queries, whenever the statement writes
-- destination_patterns, provider, provider_meta or rotation_targets, or any new
-- column classified egressChoosesHost. TestNoStatementOutsideTheEgressPackage-
-- WritesAHostChoosingColumn proves that rule against the real SQLite engine
-- rather than against a regular expression, so putting one in the wrong file is
-- caught rather than merely discouraged.

-- name: CreateVaultEntry :exec
INSERT INTO vault_entries (id, user_id, secret_owner_user_id, name, encrypted_value, nonce, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, provider, provider_meta, auto_rotate, url_bidx, alias_url_bidx, name_bidx, collection_id, encryption_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2);

-- name: TransferVaultEntrySecretOwner :execresult
-- THE ONLY STATEMENT IN THE MODULE THAT MOVES secret_owner_user_id AFTER
-- CREATION, and it lives here for the same reason the host-choosing writes do:
-- so that "change whose authority governs this plaintext" is not something a
-- handler can express.
--
-- It writes BOTH ownership columns, deliberately. A transfer that moved the
-- exit's owner and left the custodian behind would put listing/recovery rights
-- in one person's hands and the widening right in another's, which is the split
-- this column exists to make impossible to create by accident.
--
-- Its one caller is the hard-delete offboarding path: an instance admin deleting
-- a user re-owns the entries that person created inside shared collections, so
-- the team keeps them. An instance admin already holds the widening right on
-- every entry (grantFor row 3), so this hands them nothing they did not have,
-- and the activity log names the transfer.
--
-- name_bidx is supplied with user_id. Personal entries move to u:<new user>;
-- collection entries remain c:<collection>, but supplying a freshly derived
-- token also upgrades pre-00045 custodian-scoped rows.
--
-- 00040's name token was keyed by CUSTODIAN. Since 00045, shared rows instead
-- use c:<collection>; an UPDATE that changes user_id and leaves a legacy token
-- alone keeps the row outside the collection namespace, so a duplicate can land
-- without either row's token colliding.
--
-- Offboarding renames an incoming entry only when that collection already has
-- the name. A same-named PERSONAL entry is a different scope and must not make
-- the shared entry rename or reveal that personal name through an error.
UPDATE vault_entries SET user_id = ?, secret_owner_user_id = ?, name_bidx = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryProvider :exec
UPDATE vault_entries SET provider = ?, provider_meta = ?, auto_rotate = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryProviderMeta :exec
UPDATE vault_entries SET provider_meta = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: CASVaultEntryProviderMeta :execresult
-- Compare-and-swap on provider_meta itself, for the pending-revoke retry
-- endpoint. Both rotation paths still hold providerMeta in memory across the
-- mint and write it back wholesale (see revokeOldKeyAndPersistMeta /
-- persistProviderMetaAfterRevoke), so a retry landing in that window would
-- otherwise be silently lost AND the rotation's stale in-memory map would
-- RESURRECT the markers the retry just cleared when it writes moments later.
--
-- The stored value is randomly-nonced ciphertext (a fresh seal per write), so
-- comparing it as an opaque token has no ABA problem: two writes of the
-- "same" plaintext never produce the same bytes, which is exactly the
-- property a compare-and-swap token needs and updated_at (whole-second
-- resolution, bumped by neighbouring writes) does not have.
--
-- `IS`, not `=`, because the previous value can legitimately be NULL (an
-- entry with no provider_meta yet), and NULL = NULL is NULL in SQL, which
-- would never match and would make the CAS unusable for that row.
UPDATE vault_entries SET provider_meta = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND provider_meta IS ?;

-- name: UpdateVaultEntryRotationTargets :exec
UPDATE vault_entries SET rotation_targets = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryDestinationPatterns :exec
-- The capability ceiling: which hosts/paths an agent token minted for this
-- secret may ever reach. Until this existed the column had exactly one writer
-- (the provider preset seed), so a secret created without a recognised provider
-- could never mint a capability token at all and the MCP feature was unusable.
UPDATE vault_entries SET destination_patterns = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: SeedVaultEntryCapabilityDefaults :exec
-- Seeds the capability-bridge columns from the provider defaults at
-- enrollment time. Only fills untouched rows so explicit per-entry
-- patterns are never overwritten.
UPDATE vault_entries
SET destination_patterns = ?, injection_spec = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND destination_patterns = '[]' AND injection_spec = '{}';

-- name: RekeyVaultEntry :exec
-- Writes every keyed column of one entry at once, for the master-key sweep.
--
-- One statement rather than per-column updates on purpose: a row must never be
-- half-converted, with (say) the value on the new key and notes still on the old
-- one. The sweep also runs inside a transaction, so this is belt and braces, but
-- the single statement is what makes the invariant local to the row.
--
-- It lives in THIS package because it assigns provider_meta and
-- rotation_targets. A re-encryption is not a redirection, but "it does not
-- change the destinations" is a property of the caller, not of the statement,
-- and this package exists precisely because that distinction cannot be enforced
-- by reading SQL. So it takes a ticket like every other host-choosing write, and
-- vaultegress.RekeyEntry is the only way to reach it.
--
-- updated_at is deliberately NOT touched. Re-encryption is not a user edit, and
-- bumping it would make every entry look freshly modified in the UI right after
-- an incident, which is the worst possible moment to lose that signal.
UPDATE vault_entries
SET encrypted_value = ?, nonce = ?, encryption_version = ?,
    name = ?, url = ?, alias_url = ?, username = ?, category = ?, notes = ?,
    provider_meta = ?, rotation_targets = ?, custom_fields = ?,
    url_bidx = ?, alias_url_bidx = ?, name_bidx = ?
WHERE id = ?;

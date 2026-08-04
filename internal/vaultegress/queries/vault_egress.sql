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
INSERT INTO vault_entries (id, user_id, secret_owner_user_id, name, encrypted_value, nonce, url, alias_url, username, category, notes, auto_login, rotation_interval_days, expires_at, provider, provider_meta, auto_rotate, url_bidx, alias_url_bidx, encryption_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2);

-- name: TransferVaultEntrySecretOwner :execresult
-- THE ONLY STATEMENT IN THE MODULE THAT MOVES secret_owner_user_id AFTER
-- CREATION, and it lives here for the same reason the host-choosing writes do:
-- so that "change whose authority governs this plaintext" is not something a
-- handler can express.
--
-- It writes BOTH columns, deliberately. A transfer that moved the exit's owner
-- and left the custodian behind would put UNIQUE(user_id, name) in one person's
-- namespace and the widening right in another's, which is the split this column
-- exists to make impossible to create by accident.
--
-- Its one caller is the hard-delete offboarding path: an instance admin deleting
-- a user re-owns the entries that person created inside shared collections, so
-- the team keeps them. An instance admin already holds the widening right on
-- every entry (grantFor row 3), so this hands them nothing they did not have,
-- and the activity log names the transfer.
UPDATE vault_entries SET user_id = ?, secret_owner_user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryProvider :exec
UPDATE vault_entries SET provider = ?, provider_meta = ?, auto_rotate = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateVaultEntryProviderMeta :exec
UPDATE vault_entries SET provider_meta = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

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

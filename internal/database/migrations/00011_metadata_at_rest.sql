-- +goose Up
-- Encrypt-at-rest for the free-text vault metadata columns (notes, username,
-- alias_url, category) plus the display url. Those columns previously sat in
-- cleartext next to the encrypted secret, so a raw DB-file leak exposed which
-- sites a user has logins for and their usernames. They are now stored with the
-- same enc:v1: AES-256-GCM column scheme used for provider_meta/rotation_targets
-- (see vault_column_crypto.go).
--
-- url cannot be matched with a LIKE once encrypted, so autofill matching moves
-- to a blind index: url_bidx / alias_url_bidx hold HMAC-SHA256(normalized_host,
-- bidx-key-derived-from-TRUSTISSUES_VAULT_KEY). GET /api/vault/match computes the
-- same HMAC from the requested url and looks up by equality (see vault.go
-- urlBlindIndex + Match). The HMAC key never leaves the process, so the index
-- reveals nothing about the host to a DB reader.
--
-- This migration only adds the columns + lookup indexes. The one-time crypto
-- backfill of existing rows (encrypt the cleartext metadata, compute the blind
-- indexes) runs in Go at boot via VaultHandler.BackfillMetadataAtRest, which is
-- idempotent (the enc:v1: prefix marks already-encrypted values), exactly like
-- the existing MigrateEncryption / BackfillMetadataEncryption precedent.
ALTER TABLE vault_entries ADD COLUMN url_bidx TEXT NOT NULL DEFAULT '';
ALTER TABLE vault_entries ADD COLUMN alias_url_bidx TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_vault_entries_url_bidx ON vault_entries(url_bidx) WHERE url_bidx != '';
CREATE INDEX idx_vault_entries_alias_url_bidx ON vault_entries(alias_url_bidx) WHERE alias_url_bidx != '';

-- +goose Down
DROP INDEX IF EXISTS idx_vault_entries_alias_url_bidx;
DROP INDEX IF EXISTS idx_vault_entries_url_bidx;
ALTER TABLE vault_entries DROP COLUMN alias_url_bidx;
ALTER TABLE vault_entries DROP COLUMN url_bidx;

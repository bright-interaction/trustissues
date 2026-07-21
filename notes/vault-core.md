# vault-core notes

## What was built

Vault core extracted from dockyard into the files I own:

- `internal/handlers/vault.go`: VaultHandler (AES-256-GCM, PBKDF2-SHA256
  600k key derivation, legacy SHA-256 v1 support + MigrateEncryption),
  List/Create/Update/Delete, Unlock (account-password re-verify),
  Rotate/ValidateKey/Providers (delegating to the rotation agent's
  ProviderRegistry), GetTargets/UpdateTargets (reduced to webhook,
  forgejo_secret, notify), UpdateSchedule, Match (?url= autofill with LIKE
  escaping), ResolveReferences ({{vault:NAME}}, per-user scoped).
- `internal/handlers/vault_column_crypto.go`: enc:v1: at-rest encryption for
  provider_meta / rotation_targets + startup BackfillMetadataEncryption.
  Copied from dockyard unchanged apart from imports.
- `internal/handlers/vault_import.go`: VaultImportHandler with CSV format
  detection + parsers for 1Password, Bitwarden (skips non-login rows),
  LastPass; conflict preview; transactional confirm via sqlc ImportVaultEntry.
- `internal/handlers/vault_ssrf.go`: hardenedOutboundClient (no redirects,
  dial-time private-IP re-check) + isPrivateIP (moved here from dockyard's
  servers.go, which this product does not carry) + the allowPrivateOutbound
  test-only override var.
- `internal/db/queries/vault.sql`: copied VERBATIM from dockyard (method
  names identical). All rotation-related vault_entries queries live here too
  (ListVaultEntriesNeedingRotation, GetVaultEntryForRotation, rotation
  log/error/targets updates); the rotation agent compiles against them.
- `internal/database/migrations/00010_vault.sql`: ONE consolidated
  vault_entries table equal to dockyard 00009 + 00013 + 00014 + 00015 (vault
  columns only) + 00019 + 00023 + 00063 + 00064 + 00069 (vault columns only:
  destination_patterns, injection_spec), with the partial url index and the
  user_id index, per-user UNIQUE(user_id, name).
- Tests: `vault_test.go` (encrypt/decrypt round trip + wrong-key reject,
  MigrateEncryption v1 to v2 against a real DB, computeRotationStatus state
  machine, shared helper converters, ResolveReferences per-user scoping),
  `vault_column_crypto_test.go` (ported from dockyard: round trip +
  idempotence + backfill dry run), `vault_import_test.go` (format detection,
  per-format CSV parsing, quoted fields, mismatched-column error),
  `vault_ssrf_test.go` (isPrivateIP table, dial-time block, redirect refusal).

## Verified (scratchpad dry run, real tree untouched)

Full-tree dry run in the session scratchpad with vault_entries + the other
agents' tables appended to schema.sql: `sqlc generate` clean, `go build
./...` green, `go vet ./...` clean, `go test ./internal/handlers/` ALL PASS
(mine plus the rotation and capability agents' suites together), and a
fresh-DB goose boot migrates cleanly to version 21 with vault_entries at 25
columns. The 00010/00020 duplicate-column conflict the rotation agent
flagged is already resolved: the current 00020_capability.sql no longer
ALTERs vault_entries (it depends on my 00010 columns). Nothing to do there.

## Deliberate adaptations (not straight copies)

- PBKDF2 salt is `trustissues:vault:v2` (dockyard used `dockyard:vault:v2`).
  Fresh product, fresh keyspace; a dockyard DB file is NOT drop-in
  decryptable and that is intended.
- NewVaultHandler(dbConn, queries, cfg) takes *config.Config and keys off
  cfg.VaultKey (no JWT-secret fallback; config.Load already hard-fails
  without TRUSTISSUES_VAULT_KEY).
- Activity actions renamed to the contract's noun.verb_past style:
  vault.entry_created, vault.entry_updated, vault.entry_deleted,
  vault.unlocked, vault.rotated, vault.targets_updated, vault.imported.
  FRONTEND + anyone filtering /api/activity: use these, not dockyard's
  vault.create/update/delete/unlock/rotate/import.
- UpdateTargets validates only webhook / forgejo_secret / notify; env_var,
  file_write, reload_endpoint are gone (unknown types 400). The rotation
  agent's TestUpdateTargetsValidationSetMatchesDelivery pins this set.
- The duplicate legacy import methods that dockyard kept on VaultHandler
  (ImportPreview/ImportConfirm inside vault.go + parseCSVLine/getCSVField)
  are NOT ported. VaultImportHandler in vault_import.go is the single import
  surface; unlike the dockyard vault.go variant it detects 1Password.
- Import preview does NOT mask values (dockyard's unwired vault_import.go
  masked them). The frontend round-trips preview entries into confirm, so
  masking would import literal "********" strings; the client already holds
  the raw CSV, nothing extra is exposed.
- vault_import.go's raw tx.Exec / db.Query SQL was replaced with sqlc
  (ImportVaultEntry via queries.WithTx, ListVaultEntryNamesByUser) per the
  contract's no-raw-SQL rule. Behavior identical, still one transaction.
- Import category allowlist keeps dockyard's set but swaps "note" for
  "login" so imported rows match the Create endpoint's category vocabulary.
- Dockyard preserved quirk, do not "fix" silently: GetVaultEntryForRotation
  filters auto_rotate = 1, so a manual Rotate of a non-auto entry sees empty
  oldValue/targets (provider rotate and delivery need auto_rotate on). Same
  as dockyard.

## Shared package symbols I define (do not redefine elsewhere)

vault.go: nullTimePtr, stringPtrToNullTime, nullInt64ToIntPtr,
intPtrToNullInt64, boolToInt64, generateToken.
vault_ssrf.go: hardenedOutboundClient, allowPrivateOutbound, isPrivateIP.
The platform helpers.go does not carry these; if backend-platform later
adds them to helpers.go, delete them from my vault.go in the same commit.

Symbols I consume from the rotation agent (all present in the tree):
ProviderRegistry, ListProviders, ParseProviderMeta, RotationTarget,
ParseRotationTargets, RotationLogEntry, AppendRotationLog, DeliverRotatedKey,
summarizeDelivery, dispatchRotationAlert.

## Env vars

None added, none read directly. Everything goes through cfg.VaultKey.

## Vault auto-lock policy

Unlock is stateless server-side (no unlock session), so
vault_auto_lock_max_minutes is enforced client-side: the frontend reads
GET /api/settings/vault-policy (platform-wired) and re-locks its decrypted
state on that timer. Nothing for the server to enforce beyond serving the
policy; documented in the Unlock handler comment.

## Requests to other agents / integration (I do not own these files)

1. `internal/db/schema.sql` (platform): append EXACTLY this block, then run
   `sqlc generate`:

   ```sql
   -- 00010_vault.sql
   CREATE TABLE vault_entries (
     id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
     user_id TEXT NOT NULL DEFAULT '',
     name TEXT NOT NULL,
     encrypted_value BLOB NOT NULL,
     nonce BLOB NOT NULL,
     category TEXT DEFAULT '',
     notes TEXT DEFAULT '',
     rotation_interval_days INTEGER,
     expires_at DATETIME,
     last_rotated_at DATETIME,
     url TEXT DEFAULT '',
     username TEXT DEFAULT '',
     encryption_version INTEGER DEFAULT 2,
     alias_url TEXT DEFAULT '',
     auto_login INTEGER NOT NULL DEFAULT 0,
     provider TEXT DEFAULT '',
     provider_meta TEXT DEFAULT '{}',
     auto_rotate INTEGER DEFAULT 0,
     rotation_log TEXT DEFAULT '[]',
     last_rotation_error TEXT DEFAULT '',
     rotation_targets TEXT DEFAULT '[]',
     destination_patterns TEXT NOT NULL DEFAULT '[]',
     injection_spec TEXT NOT NULL DEFAULT '{}',
     created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
     updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
     UNIQUE(user_id, name)
   );

   CREATE INDEX idx_vault_entries_url ON vault_entries(url) WHERE url != '';
   CREATE INDEX idx_vault_entries_user ON vault_entries(user_id);
   ```

2. `cmd/server/main.go` (platform): construct + boot in this order, right
   after queries are built:

   ```go
   vaultHandler := handlers.NewVaultHandler(dbConn, queries, cfg)
   if err := vaultHandler.MigrateEncryption(); err != nil {
       slog.Error("vault encryption migration failed", "error", err)
       os.Exit(1)
   }
   if _, err := vaultHandler.BackfillMetadataEncryption(); err != nil {
       slog.Error("vault metadata backfill failed", "error", err)
   }
   vaultImportHandler := handlers.NewVaultImportHandler(dbConn, vaultHandler)
   ```

3. `cmd/server/main.go` (platform): mount inside the FEATURE ROUTES block
   (all roles including vault_only; ownership is enforced in-handler):

   ```go
   r.Route("/vault", func(r chi.Router) {
       r.Get("/", vaultHandler.List)
       r.Post("/", vaultHandler.Create)
       r.Get("/providers", vaultHandler.Providers)
       r.Get("/match", vaultHandler.Match)
       r.With(timw.RateLimit(sensitiveOpLimiter)).Post("/unlock", vaultHandler.Unlock)
       r.Put("/{id}", vaultHandler.Update)
       r.Delete("/{id}", vaultHandler.Delete)
       r.With(timw.RateLimit(sensitiveOpLimiter)).Post("/{id}/rotate", vaultHandler.Rotate)
       r.With(timw.RateLimit(sensitiveOpLimiter)).Post("/{id}/validate", vaultHandler.ValidateKey)
       r.Get("/{id}/targets", vaultHandler.GetTargets)
       r.Put("/{id}/targets", vaultHandler.UpdateTargets)
       r.Put("/{id}/schedule", vaultHandler.UpdateSchedule)
       r.Post("/import/preview", vaultImportHandler.ImportPreview)
       r.Post("/import/confirm", vaultImportHandler.ImportConfirm)
   })
   ```

4. `cmd/server/main.go` (platform): the global timw.MaxBodySize(1MB) caps
   CSV imports at 1MB even though the import handler allows 10MB multipart.
   Either accept the 1MB cap (fine for most exports) or mount the two
   /vault/import/* routes with a larger per-route body limit. My handlers
   work either way.
5. Pass vaultHandler as the alerts.ConfigDecrypter when constructing
   dispatchers (DecryptValue satisfies the interface).
6. Frontend vault agent: preview response is `{format, entries, conflicts,
   total}` with UNMASKED values; round-trip `entries` (minus skipped) into
   confirm. Activity action names are the new noun.verb_past set above.
7. Rotation agent: nothing needed from you; your reconciliation (UpdateTargets
   and GetTargets staying in my vault.go, queries in my vault.sql) matches
   what I shipped.

## TODOs / open questions

- Once schema.sql + sqlc generate land, `go test ./internal/handlers/` runs
  my DB-backed tests for real (verified green in the scratch dry run).
- destination_patterns / injection_spec are carried in the schema per spec
  (00069 vault columns) and used by the capability agent's files; my
  handlers do not touch them.

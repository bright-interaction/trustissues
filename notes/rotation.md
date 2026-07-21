# rotation notes

## What was built

Rotation engine extracted from dockyard into the files I own:

- `internal/handlers/vault_providers.go`: full external-SaaS provider
  registry (KeyProvider interface, ProviderRegistry, ListProviders,
  revokeOldProviderKey, RotationLogEntry/AppendRotationLog,
  ParseProviderMeta). 14 auto-rotate providers + 17 validate-only providers
  + 2 local generators. The five dockyard `internal:*` agent-dispatched
  providers are NOT ported (see cred_rotation.go below).
- `internal/handlers/vault_targets.go`: RotationTarget (reduced to webhook,
  forgejo_secret, notify), ParseRotationTargets, DeliverRotatedKey,
  summarizeDelivery (delivery-gated partial status), dispatchRotationAlert
  (adapted to the platform alerts API: one fewer argument, uses
  alerts.EventRotationPartial), deliverToForgejoSecret, deliverToWebhook.
- `internal/handlers/vault_rotation.go`: RotateVaultKeys (single pass, copied
  from dockyard with store->db and 4-arg LogActivity adaptations) plus the
  new RunScheduledRotations background worker.
- `internal/handlers/cred_rotation.go`: doc-only file recording that the
  internal-credential agent bridge is deliberately not ported (no agent
  fleet, no agent_commands table in this product).
- Tests: `vault_targets_test.go` (delivery semantics, retired-type
  regression guard, webhook HMAC + payload, forgejo validation, and a full
  DB-backed UpdateTargets handler test) and `vault_providers_test.go`
  (registry reduced-set guard, generator providers, rotation log,
  provider meta).

Verified in a scratchpad copy of the tree (sqlc generate + go build + go vet
+ go test, all green; the real tree's generated code and schema.sql were NOT
touched per contract). The UpdateTargets test passes once the migration
conflict below is fixed.

## Exact worker invocation for main.go (platform, please wire)

```go
// inside the startup sequence, after vaultHandler is constructed;
// ctx is the server's shutdown context
go handlers.RunScheduledRotations(ctx, dbConn, queries, vaultHandler)
```

The worker runs a first pass 1 minute after boot, then hourly, and returns
when ctx is cancelled. `handlers.RotateVaultKeys(dbConn, queries,
vaultHandler)` runs a single pass directly if ever needed.

## What was cut (per spec)

- Target types env_var, file_write, reload_endpoint: struct fields, delivery
  functions, the two-pass grace/verify machinery, and every queries.* call
  touching services/servers/agents/envs (UpdateEnvVarValue,
  GetServerIDByServiceID, GetServerOrgID, CheckMemberExists,
  EnqueueEncryptedAgentCommand, GetServerIDByName) are gone. Retired types
  now fail closed: rejected with 400 at set time (UpdateTargets) and
  produce a failed DeliveryResult (rotation status "partial") if present in
  stored data. Regression-guarded by tests.
- isMultiTenantMode checks: single-team build, nothing to scope.
- internal:* providers + the agent command queue/poll bridge
  (cred_rotation.go documents the rationale).

## Deliberate adaptations (not straight copies)

- providerHTTP is `alerts.GuardedWebhookClient(15 * time.Second)` instead of
  dockyard's local hardenedOutboundClient (same SSRF shape: no redirects,
  dial-time private-IP block). Tests swap the package var to reach httptest
  loopback servers; production default stays guarded.
- Provider renames for the standalone product: `dockyard-shared-secret` ->
  `shared-secret`, `shield-key-32` -> `generated-key-32`. Rotation logic
  unchanged (32-byte hex, 32-char alphanumeric with rejection sampling).
  FRONTEND: use these names, not the dockyard ones.
- Zitadel provider no longer defaults instance to auth.example.com;
  `instance` is now required in provider_meta. Cloudflare's cfResponse/
  cloudflareAPIBase are defined locally in vault_providers.go (dockyard kept
  them in the DNS handler, which this product does not carry).
- DeliverRotatedKey keeps the dockyard signature including oldValue even
  though only the cut reload_endpoint flow consumed it, so the manual Rotate
  handler in vault.go ports without change.
- Webhook delivery signature header stays `X-Vault-Signature: sha256=<hmac>`
  (raw-body HMAC, dockyard rotation convention). Note this differs from the
  alerts channel headers (X-Trustissues-Signature over "timestamp.body");
  both are documented behavior, do not "unify" them silently.

## Coordination with the vault agent (already reconciled)

- UpdateTargets: the vault agent's vault.go already carries an UpdateTargets
  with exactly the reduced validation set, so I removed my duplicate from
  vault_targets.go to avoid a redeclaration. The reduced set is pinned by
  TestUpdateTargetsValidationSetMatchesDelivery, which drives their handler;
  if vault.go's switch drifts from {webhook, forgejo_secret, notify} the
  suite fails. GetTargets also stays in vault.go.
- My code compiles against these vault-agent-owned symbols (all present in
  the current tree): NewVaultHandler/VaultHandler with queries field,
  EncryptValue, DecryptValue, encryptColumn, decryptColumnOrLog, ownsEntry;
  queries ListVaultEntriesNeedingRotation, UpdateVaultEntryRotationLog,
  UpdateVaultEntryRotationError, RotateVaultEntryValue,
  UpdateVaultEntryProviderMeta, ResolveVaultReference, GetVaultEntryTargets,
  UpdateVaultEntryRotationTargets, CreateVaultEntry (test only).

## CRITICAL cross-agent finding: migration 00010 vs 00020 conflict

`00010_vault.sql` creates vault_entries WITH destination_patterns and
injection_spec, and `00020_capability.sql` then does
`ALTER TABLE vault_entries ADD COLUMN` for the same two columns. Goose
aborts at 00020 with "duplicate column name" on every fresh database, so
the app cannot boot. Fix belongs to the owner of those migrations: drop the
two ADD COLUMN statements from 00020 (or the two columns from 00010). My
TestUpdateTargetsValidationSetMatchesDelivery fails on exactly this today
and passes the moment it is fixed (verified in scratch).

Also still pending from the same owner: vault_entries (+ capability +
service_identities tables) are not yet appended to `internal/db/schema.sql`,
so `sqlc generate` fails on vault.sql/service_identities.sql until that
lands.

## Route wiring (platform, at integration)

Rotation surfaces live on the vault router (per-entry ownership inside
handlers). The vault agent's notes cover their routes; from my side make
sure these exist and that manual rotate/validate sit behind
sensitiveOpLimiter:

- `GET  /api/vault/{id}/targets` -> vaultHandler.GetTargets (vault.go)
- `PUT  /api/vault/{id}/targets` -> vaultHandler.UpdateTargets (vault.go)
- providers listing for the frontend: handlers.ListProviders() needs a tiny
  GET handler if the vault agent has not wired one (dockyard exposed it as
  /api/vault/providers).

## Env vars

None added, none read. No os.Getenv anywhere in my files.

## TODOs for integration

1. Wire `go handlers.RunScheduledRotations(ctx, dbConn, queries,
   vaultHandler)` in main.go (invocation above).
2. Fix the 00010/00020 duplicate-column migration conflict (blocker, owner:
   vault agent).
3. Append feature tables to internal/db/schema.sql + run `sqlc generate`
   (owner: vault agent / platform).
4. Pass vaultHandler as the alerts.ConfigDecrypter when the platform
   constructs dispatchers elsewhere; my dispatchRotationAlert already
   receives it per call.

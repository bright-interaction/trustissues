# frontend-vault notes

Agent: frontend-vault. Owned files, all delivered and green under
`bunx tsc --noEmit` and `bun run build`:

- `frontend/src/pages/Vault.tsx` (default-exports the page, renders inside Layout)
- `frontend/src/components/RotationManager.tsx`
- `frontend/src/components/VaultImportModal.tsx`
- `frontend/src/lib/vault-types.ts`

## What was done

Copied dockyard's Vault.tsx, RotationManager.tsx, VaultImportModal.tsx and the
vault types, adapted to the Trustissues shell:

- Types moved to `src/lib/vault-types.ts` (VaultEntry, RotationTarget,
  ImportEntry, VaultImportPreview, ServiceIdentity family). Per
  FRONTEND-CONTRACT.md the API wrappers also live there (`vaultApi`,
  `serviceIdentitiesApi`) built on `request<T>()` from `src/lib/api.ts`,
  since api.ts is platform-owned.
- Query keys: vault queries use the reserved `queryKeys.vault.*`
  (list/targets/all). RotationManager now uses `queryKeys.vault.targets(id)`
  instead of dockyard's ad-hoc `['vault-targets', id]`. Service-identity keys
  are exported from vault-types.ts as `serviceIdentityKeys` because
  query-keys.ts is platform-owned.
- RotationManager: target types reduced to webhook / forgejo_secret / notify.
  All env_var, file_write, reload_endpoint UI and type fields removed.
  forgejo_secret got a UI it never had in dockyard (instance, repo,
  secret_name, auth_token as a vault entry name) with field names matching the
  Go struct in dockyard's `internal/handlers/vault_targets.go`. webhook got an
  optional `webhook_secret` field (HMAC signing) matching the same struct.
- Vault.tsx keeps: unlock flow, add/edit/delete forms, metadata-only locked
  table, entries list with category chips, provider chips, rotation status
  badges, auto-rotate badge, rotation error badge, per-entry rotate with
  password, rotation delivery panel, import modal, SecretBridgeCard
  (capability mode) and ServiceIdentitiesCard (admin only).
- SecretBridgeCard rebranded Dockyard -> Trustissues (trustissues-secret-bridge,
  Trustissues API key, /settings link). Dropped dockyard-only links: /docs
  anchor, /api/mcp, the claude-code CLI hint with the ~/.dockyard path.
- Removed dockyard's `{{vault:SECRET_NAME}}` deploy-time injection hint card
  (Trustissues has no deploy system).
- No SSHKeyVault anywhere (dockyard's Vault.tsx did not import it either; its
  users were Server.tsx and InstallWizard.tsx which are not ported).
- Removed em dashes from copied strings (rotated-value banner, empty category
  placeholder). Fixed dockyard's "entryies" pluralization bug in the import
  modal conflict warning.

## Endpoints the backend must expose (dockyard shapes, verbatim)

- `GET/POST /api/vault`, `PUT/DELETE /api/vault/{id}`
- `POST /api/vault/unlock` `{password}` -> VaultEntry[] with values
- `POST /api/vault/{id}/rotate` `{password}` -> entry + plaintext `value`
- `GET/PUT /api/vault/{id}/targets` -> RotationTarget[]
- `PUT /api/vault/{id}/schedule` `{rotation_interval_days, auto_rotate}`
- `POST /api/vault/import/preview` (multipart: file, format) -> VaultImportPreview
- `POST /api/vault/import/confirm` `{entries}` -> `{imported}`
- `GET/POST /api/service-identities`, `POST .../{id}/revoke`,
  `DELETE .../{id}`, `GET .../{id}/audit?limit=N`
  (plus `/api/service-identities/me/secrets` for machines)

## Integration requests / TODOs (files I do not own)

1. main.go: wire `/api/vault` (all roles) and the service-identities routes
   (AdminOnly for management) at the FEATURE ROUTES block. Vault delivery
   targets and schedule editing should sit behind VaultOnlyBlock or per-role
   checks as backend-vault decides.
2. main.go body limit: the global chain caps bodies at 1MB but the import
   modal accepts CSVs up to 10MB. Raise the limit on
   `/api/vault/import/preview` (e.g. MaxBodySize(10MB) on that route) or the
   effective import cap is 1MB.
3. Sensitive-op limiter: contract puts unlock/rotate behind 5 req/15min/IP.
   The UI re-locks the vault after every create/update/delete (dockyard
   behavior, kept), so an admin doing a handful of edits re-unlocks each time
   and will hit 429 fast. Consider a higher unlock budget (e.g. 15/15min) or
   only rate-limiting failed unlocks.
4. SecretBridgeCard links to `GET /downloads/install-secret-bridge.sh`. If the
   secret-bridge installer is not ported to Trustissues, either serve that
   script or tell me and I will drop the card.
5. ServiceIdentitiesCard says keys are presented to
   `/api/service-identities/me/secrets` and start with `sk_`. If backend-vault
   picked a different path or prefix, tell me and I will update the copy.
6. Optional cleanup for frontend-platform: adopt an `api.vault` /
   `api.serviceIdentities` namespace in api.ts and `queryKeys.serviceIdentities`
   in query-keys.ts; the wrappers and keys in vault-types.ts can then be
   re-exported or removed. Not blocking.
7. Settings page: the SecretBridgeCard's "Mint a Trustissues API key" step
   links to `/settings`. If API keys live under a specific tab, a
   `?tab=keys`-style deep link would be nicer; tell me the param and I will
   update.

## Assumptions

- Unlock/rotate take the user's login password (dockyard semantics); the
  backend-vault agent copies dockyard's handlers so request/response shapes
  match the dockyard frontend contract exactly.
- `vault_auto_lock_max_minutes` enforcement is server-side (unlock response
  scope/TTL); the UI holds decrypted entries only in memory and drops them on
  lock, navigation away, or any mutation.

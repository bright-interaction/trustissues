# capability agent notes

## What was built

Extracted the capability bridge + service identities from dockyard into
trustissues. All files compile and the tests pass when verified against a
sqlc-generated build (see "Verification" below).

Files owned and written:

- `internal/capability/token.go` + `token_test.go`: copied from dockyard.
  Only change: HKDF salt/info labels renamed from `dockyard:capability:v1:*`
  to `trustissues:capability:v1:*` (fresh product, fresh DB, no token
  compatibility to preserve) and doc comments rebranded. 11 tests pass.
- `internal/handlers/capability.go`: Issue (POST /api/secrets/issue), Proxy
  (/proxy/{host}/*), agentCanUse grants, replay-nonce spend, capability_log
  audit, PruneSpentNonces. All dockyard defense-in-depth kept: dests ceiling
  narrowing only, proxy-time re-check against the CURRENT allow-list, method
  match, single-use nonces, plaintext wipe after forward, 16 MiB body cap,
  auth/hop-by-hop header stripping both directions.
- `internal/handlers/capability_providers.go`: InjectionSpec,
  DefaultInjection, CapabilityDefaults, MarshalCapabilityDefaults.
- `internal/handlers/service_secrets.go`: FetchOwnSecrets (X-Service-Key),
  admin mint/list/revoke/delete/audit. Owner-scoped fetch kept (dockyard
  CRIT-1 fix): identities without created_by_user_id are refused, and vault
  lookups are (name, user_id) pairs.
- `internal/db/queries/service_identities.sql`: annotations copied VERBATIM
  from dockyard so generated method names are identical.
- `internal/database/migrations/00020_capability.sql`,
  `00021_service_identities.sql`.
- Tests: `capability_test.go` (unit + e2e: happy path incl. real TLS
  upstream, destination mismatch, auto-route), `capability_providers_test.go`,
  `service_secrets_test.go` (17 tests incl. cross-owner isolation, scope
  whitelist, revoke/expiry lockout, audit survival after delete).

## Choices made (as instructed, stated explicitly)

1. **DB pattern for capability.go: kept raw parameterized SQL via `*sql.DB`**
   (the smaller faithful change). Dockyard's capability.go already talks
   straight to `*sql.DB` with parameterized queries for the capability tables
   and the minimal vault_entries projections; its `store.Queries` field was
   unused. I dropped that dead field instead of porting a store shim.
   service_secrets.go, which genuinely used sqlc in dockyard, was converted
   to the platform `*db.Queries` pattern.
2. **Vault decoupling: both handlers depend on `alerts.ConfigDecrypter`**
   (`DecryptValue(ciphertext, nonce []byte, encVersion int) ([]byte, error)`)
   instead of a concrete `*VaultHandler`. CONTRACT.md section 7 already
   states the vault handler satisfies this interface, so integration passes
   the vault handler directly. This let my files compile and be tested
   without owning or referencing vault files.
3. **Outbound client: `alerts.GuardedWebhookClient(60 * time.Second)`**
   replaces dockyard's `hardenedOutboundClient`. Identical behavior (no
   redirects + dial-time private-IP re-check) and it is the platform's
   blessed egress client. Tests inject their own client via SetHTTPClient
   exactly as dockyard's do. Note: the vault agent has since ported
   `hardenedOutboundClient` into `vault_ssrf.go`; the two coexist without
   collision. If you prefer one blessed shape, that is a one-line swap in
   NewCapabilityHandler.
4. **Migration 00020 has NO ALTER TABLE statements.** The vault agent's
   consolidated `00010_vault.sql` already includes `destination_patterns`
   and `injection_spec` on vault_entries (it flattened dockyard 00069's
   columns into the base table). My 00020 therefore only creates
   capability_grants, capability_log, capability_spent_nonces; its Down
   drops only those three. Re-adding the ALTERs would break migration at
   boot with duplicate-column errors.
5. **Provider defaults: two Bright-specific entries adjusted.** Dockyard's
   map hardcoded `auth.example.com` (zitadel) and
   `code.example.com` (forgejo). Trustissues is a standalone
   product, so `zitadel` was removed (self-hosted, no safe global default)
   and `forgejo` now defaults to `code.forgejo.org/*` only. Owners of
   self-hosted instances set destination_patterns per entry. Everything
   else is verbatim.
6. **Signing key source is `cfg.VaultKey`.** No new env var needed; no bare
   os.Getenv anywhere in my files (zero env reads at all).
7. **Key prefixes:** service keys keep dockyard's `sk_` prefix; the comment
   contrast is now against trustissues user keys (`ti_`).

## Route list + middleware placement for main.go (integration)

Mirrors dockyard main.go:668-669 (proxy outside everything), :754 (service
fetch outside session auth), :864-868 (admin CRUD inside auth group),
:894-896 (issue inside auth group behind sensitiveOpLimiter).

Constructors (after vaultHandler exists; both take the vault handler as the
alerts.ConfigDecrypter):

```go
capabilityHandler, err := handlers.NewCapabilityHandler(dbConn, vaultHandler, cfg.VaultKey)
if err != nil { slog.Error("capability handler init failed", "error", err); os.Exit(1) }
serviceSecretsHandler := handlers.NewServiceSecretsHandler(queries, vaultHandler)
```

Routes OUTSIDE the session-auth group:

```go
// 1. On the ROOT router r (sibling of /health, NOT under /api): the
// capability proxy. Auth is the signed token verified inside the handler;
// session middleware must NOT wrap it (external HTTP clients call it).
r.HandleFunc("/proxy/{host}/*", capabilityHandler.Proxy)
r.HandleFunc("/proxy/{host}", capabilityHandler.Proxy)

// 2. Inside r.Route("/api", ...) (so the 500/min apiLimiter applies) but
// OUTSIDE the JWTOrAPIKeyAuth group: service fetch-on-boot. X-Service-Key
// auth lives inside the handler; service containers call it from arbitrary
// IPs with no session and no Origin header.
r.Post("/service-identities/me/secrets", serviceSecretsHandler.FetchOwnSecrets)
```

Routes INSIDE the authenticated group (the FEATURE ROUTES block). The
handlers enforce admin themselves (middleware.IsAdmin) exactly like
dockyard, so AdminOnly wrapping is optional but harmless; do wrap the
non-vault surfaces in VaultOnlyBlock per the contract:

```go
// Service identities (admin-only mint + list + revoke + delete + audit).
r.Route("/service-identities", func(r chi.Router) {
    r.Use(timw.VaultOnlyBlock())
    r.Get("/", serviceSecretsHandler.ListServiceIdentities)
    r.Post("/", serviceSecretsHandler.CreateServiceIdentity)
    r.Post("/{id}/revoke", serviceSecretsHandler.RevokeServiceIdentity)
    r.Delete("/{id}", serviceSecretsHandler.DeleteServiceIdentity)
    r.Get("/{id}/audit", serviceSecretsHandler.GetServiceIdentityAudit)
})

// Capability bridge: mint a short-lived token. Sensitive op, rate limit it.
r.Route("/secrets", func(r chi.Router) {
    r.With(timw.RateLimit(sensitiveOpLimiter)).Post("/issue", capabilityHandler.Issue)
})
```

Note the chi ordering constraint: the public
`r.Post("/service-identities/me/secrets", ...)` and the authenticated
`r.Route("/service-identities", ...)` coexist fine (chi routes the literal
`me/secrets` path before the `{id}` params) but keep the public one
registered on the /api router directly, not inside the auth group.

Optional (dockyard never wired it either): a background sweep for expired
nonces, e.g. a 10-minute ticker goroutine calling
`capabilityHandler.PruneSpentNonces(ctx)`.

## Integration requests (files I do not own)

1. **`internal/db/schema.sql`**: append the following AFTER the vault
   agent's vault_entries block (my queries reference vault_entries), then
   run `sqlc generate`. I could not edit this file (not mine; it was also
   being concurrently rewritten during my run):

```sql
-- 00021_service_identities.sql
CREATE TABLE service_identities (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,
    description        TEXT NOT NULL DEFAULT '',
    allowed_secrets    TEXT NOT NULL DEFAULT '[]',
    key_hash           TEXT NOT NULL,
    key_prefix         TEXT NOT NULL,
    last_used_at       DATETIME,
    expires_at         DATETIME,
    revoked_at         DATETIME,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_user_id TEXT
);

CREATE TABLE service_secret_audit (
    id                    TEXT PRIMARY KEY,
    service_identity_id   TEXT,
    service_name          TEXT NOT NULL DEFAULT '',
    event                 TEXT NOT NULL,
    secret_names          TEXT NOT NULL DEFAULT '[]',
    error                 TEXT NOT NULL DEFAULT '',
    remote_ip             TEXT NOT NULL DEFAULT '',
    occurred_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

   The capability tables (capability_grants/log/spent_nonces) are accessed
   via raw SQL only, so sqlc does not strictly need them in schema.sql, but
   appending them keeps the file a faithful mirror of the migrations (the
   platform rule). Copy the three CREATE TABLE blocks from
   `internal/database/migrations/00020_capability.sql` if you want the
   mirror complete.

2. **`sqlc generate`** must run after (1). My service_secrets.go compiles
   against the generated `db.Queries` methods from
   `internal/db/queries/service_identities.sql`. I verified the exact
   generated names/types by running sqlc + go build + go test on a scratch
   copy outside the worktree; no surprises left, it will compile as long as
   schema.sql contains vault_entries + the two tables above.

3. **`cmd/server/main.go`**: wire constructors + routes as in the section
   above; remove the `_ = sensitiveOpLimiter` blank assignment when the
   /secrets/issue route takes it.

4. **Vault agent**: no changes requested. Confirmed their 00010_vault.sql
   already carries destination_patterns + injection_spec and their
   VaultHandler.DecryptValue matches alerts.ConfigDecrypter. One optional
   hook: when an entry is enrolled with a known provider, seed the two
   columns via `handlers.MarshalCapabilityDefaults(provider)` (dockyard
   does this in its enroll path); store `'[]'` / `'{}'` when it returns
   empty strings.

5. **Frontend/docs agents**: the plaintext service key is returned exactly
   once from POST /api/service-identities (response field `key`, prefix
   `sk_`); the issue response fields are token, proxy_url, secret,
   expires_at, nonce_length. Proxy auth header is
   `Authorization: Capability <token>`.

## Verification

Could not build inside the worktree (generated sqlc code for my queries
must not be committed by me, and schema.sql is contested by concurrent
agents). Instead: full tree copied to the session scratchpad, schema.sql
extended there with vault_entries (the vault agent's real DDL) + my two
tables, then `sqlc generate`, `go build ./...`, `go vet`, gofmt check, and
`go test` for internal/capability (11 tests) and my handlers tests (30 run
targets, 60 RUN/PASS lines): all green, including the e2e proxy test
against a real TLS upstream asserting the secret is injected, the
capability token never leaks upstream, and replay returns 403.

## TODOs / open items

- PruneSpentNonces sweep is defined but unwired (same as dockyard). Cheap
  to add at integration; see route section.
- `grafana`, `auth0`, `supabase` defaults use a leading `*.` wildcard that
  the pattern matcher does not support (single trailing `/*` only). This is
  dockyard-faithful (same latent quirk there); those three providers
  effectively require per-entry patterns. Left untouched because changing
  matcher semantics is a security-sensitive edit that should be its own
  reviewed change.
- No env vars were added; nothing bypasses internal/config.

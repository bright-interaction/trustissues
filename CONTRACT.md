# Trustissues platform contract

This document is the integration contract between the backend-platform
skeleton and the feature agents (vault, rotation, frontend). Everything below
compiles and is smoke-tested on the branch. Build against these exports; if
you need a change in a platform-owned file, request it in your notes file
instead of editing.

Module: `github.com/brightinteraction/trustissues`, Go 1.26.

## 1. Config (`internal/config`)

```go
cfg, err := config.Load()   // hard-fails without required secrets
```

`config.Config` fields (all read from `TRUSTISSUES_*` env vars, no bare
`os.Getenv` anywhere else):

| Field | Env var | Default | Notes |
|---|---|---|---|
| `Port` | `TRUSTISSUES_PORT` | `8080` | |
| `JWTSecret` | `TRUSTISSUES_JWT_SECRET` | required, >= 32 chars | startup fails if missing |
| `VaultKey` | `TRUSTISSUES_VAULT_KEY` | required, >= 32 chars | startup fails if missing; key for every encrypted column |
| `BaseURL` | `TRUSTISSUES_BASE_URL` | `http://localhost:8080` | |
| `DataDir` | `TRUSTISSUES_DATA_DIR` | `./data` | SQLite lives at `<DataDir>/trustissues.db` |
| `FrontendDir` | `TRUSTISSUES_FRONTEND_DIR` | `./frontend/dist` | |
| `LogLevel` | `TRUSTISSUES_LOG_LEVEL` | `info` | debug/info/warn/error |

If you need a new env var, add it as a `Config` field + `TRUSTISSUES_*` read
inside `config.Load` (request via notes if you do not own the file).

## 2. Database access pattern

- `database.Connect(cfg.DataDir)` opens SQLite (WAL, foreign keys, busy
  timeout, pool of 10). Returns `*sql.DB`.
- `database.RunMigrations(dbConn)` runs the embedded goose migrations at boot.
- `queries := db.New(dbConn)` constructs the sqlc `*db.Queries`. Handlers
  receive `*db.Queries` (and `*sql.DB` only where middleware needs it) via
  their constructors: `handlers.NewXxxHandler(queries, cfg)`.

sqlc setup (`sqlc.yaml`): engine sqlite, queries in
`internal/db/queries/*.sql`, generated package `db` in `internal/db/`,
schema at `internal/db/schema.sql`.

RULES for feature agents:
- Add your queries as new files in `internal/db/queries/` (do not edit the
  platform-owned files `users.sql`, `sessions.sql`, `api_keys.sql`,
  `activity.sql`, `settings.sql`, `invitations.sql`, `notifications.sql`).
- When you add a migration you MUST append the same table definitions to
  `internal/db/schema.sql` in the same commit, then run `sqlc generate`.
- Parameterized SQL only. No string-concatenated SQL anywhere.

## 3. Migration numbering map

Migrations live in `internal/database/migrations/` and are embedded via
`go:embed`. Goose format, `-- +goose Up` / `-- +goose Down`, use
`-- +goose StatementBegin/End` around triggers.

| Range | Owner | Contents |
|---|---|---|
| 00001 | platform | users (role CHECK admin/user/vault_only, disabled, totp_*, sessions_valid_after) |
| 00002 | platform | login_attempts + api_keys |
| 00003 | platform | activity_log (+ append-only triggers) |
| 00004 | platform | settings (vault_auto_lock_max_minutes=15, session_duration_hours=168, smtp_*) |
| 00005 | platform | invitations (target_role, ON DELETE SET NULL FKs) |
| 00006 | platform | notification_channels (types: webhook, slog) |
| 00007-00009 | platform | reserved, do not use |
| 00010+ | feature agents | vault entries, rotation targets, etc. |

## 4. Middleware (`internal/middleware`, import alias `timw`)

Context keys and helpers (all on `r.Context()`):

```go
timw.GetUserID(ctx) string      // "" when unauthenticated
timw.GetUserRole(ctx) string    // "admin" | "user" | "vault_only"
timw.IsAdmin(ctx) bool
timw.IsVaultOnly(ctx) bool
```

Router middleware:

```go
timw.JWTOrAPIKeyAuth(cfg.JWTSecret, dbConn)  // auth: Bearer JWT, session cookie, or X-API-Key
timw.AdminOnly()                             // 403 unless role == admin
timw.VaultOnlyBlock()                        // 403 when role == vault_only
timw.RateLimit(timw.NewRateLimiter(n, window))
timw.SecurityHeaders                         // CSP, HSTS, nosniff, frame deny
timw.MaxBodySize(bytes)                      // http.MaxBytesReader wrapper
```

Auth accepts, in order: `Authorization: Bearer <jwt>`, the
`trustissues_session` cookie (`timw.SessionCookieName`, HttpOnly + Secure +
SameSite=Strict), or `X-API-Key` (SHA-256 hash looked up in `api_keys`).
Disabled users are rejected on every request; JWTs older than the user's
`sessions_valid_after` are revoked. API keys are prefixed `ti_`.

Exposed context keys (typed, package-private type): `timw.UserIDKey`,
`timw.UserRoleKey`. Always use the getters.

## 5. Route wiring in `cmd/server/main.go`

Global chain: RequestID, Logger, Recoverer, Compress, SecurityHeaders,
MaxBodySize(1MB). `/api` is wrapped in a 500 req/min/IP limiter. Public
endpoints (`/api/auth/login`, `/api/auth/register`, `/api/auth/status`,
`/api/invitations/redeem`) additionally sit behind a 30 req/15min/IP limiter.

Feature routes are mounted inside the authenticated group at the clearly
marked block:

```go
// FEATURE ROUTES WIRED AT INTEGRATION
```

Conventions there: vault under `/api/vault` (all roles, per-entry ownership
inside handlers), rotation under `/api/rotation` behind
`timw.VaultOnlyBlock()`, sensitive operations (unlock, rotate, export) behind
the pre-built `sensitiveOpLimiter` (5 req/15min/IP), currently assigned to
`_` in main.go until a feature route uses it.

Platform-wired routes (do not re-wire): `/health`, `/api/auth/*`,
`/api/settings/vault-policy`, `/api/activity`, `/api/admin/users*`,
`/api/admin/invitations*`, `/api/invitations/redeem`, static frontend with
SPA fallback from `cfg.FrontendDir`.

## 6. Activity log helpers (`internal/handlers`)

```go
handlers.LogActivity(q *db.Queries, userID *string, action, detail string)
handlers.LogActivityFromRequest(q *db.Queries, r *http.Request, action, detail string)
```

Fire-and-forget (background ctx, 5s timeout), never returns an error to the
caller. `LogActivityFromRequest` records user ID from context plus client IP
and user agent. Action naming style: `noun.verb_past` (`vault.entry_created`,
`rotation.completed`). The table is append-only (DB triggers), so never plan
an UPDATE/DELETE against `activity_log`.

`GET /api/activity` (admin only) supports `?action=`, `?user_id=`,
`?limit=` (max 500), `?offset=`.

## 7. Alerts dispatcher (`internal/alerts`)

Mirrors dockyard's `ChannelDispatcher` surface minus the org parameter, so
rotation code copied from dockyard's `vault_targets.go` needs one-argument
adaptation:

```go
d := alerts.NewChannelDispatcher(ctx, queries, decrypter) // decrypter may be nil
d.Dispatch(event, source, host string, data map[string]string) // non-blocking
d.DispatchTest(row db.GetNotificationChannelRow) error         // synchronous
alerts.GuardedWebhookClient(timeout)  // SSRF-guarded client for ANY user-URL POST
alerts.SignPayload(secret, body)      // HMAC-SHA256 over "timestamp.body"
```

`alerts.ConfigDecrypter` interface:
`DecryptValue(ciphertext, nonce []byte, encVersion int) ([]byte, error)`.
The vault handler should satisfy it (dockyard pattern) and be passed in at
integration. Events defined: `vault.rotation_partial`,
`vault.rotation_failed`, `vault.secret_expiring`, `test.notification`.
Channel types: `webhook` (HMAC-signed generic POST, signature headers
`X-Trustissues-Signature` / `X-Trustissues-Timestamp`) and `slog`.

Rotation target types kept from dockyard: `webhook`, `forgejo_secret`,
`notify`. The control-plane types `env_var`, `file_write`,
`reload_endpoint` are CUT; do not port them.

## 8. Settings access

`settings` is a key/value table. Via `*db.Queries`:

```go
q.GetSetting(ctx, key) (string, error)          // sql.ErrNoRows when absent
q.UpsertSetting(ctx, db.UpsertSettingParams{Key, Value})
q.GetVaultAutoLockMaxMinutes(ctx)               // seeded "15"
q.GetSessionDurationSetting(ctx)                // seeded "168" (hours)
```

Vault policy endpoint: `GET /api/settings/vault-policy` (any authenticated
role) and `PUT` (admin) with body `{"auto_lock_max_minutes": 1..1440}`. The
vault feature must read `vault_auto_lock_max_minutes` and enforce it.

## 9. Column crypto (`internal/columncrypto`)

Shared at-rest encryption for string columns, keyed by `cfg.VaultKey`:

```go
columncrypto.EncryptString(plaintext, cfg.VaultKey) (string, error)
columncrypto.DecryptString(encrypted, cfg.VaultKey) (string, error)
```

AES-256-GCM with a PBKDF2-SHA256 (600k) derived key, output
base64(nonce||ciphertext). Used by the platform for TOTP seeds. The vault
feature may use its own binary BLOB scheme (dockyard's encrypted_value +
nonce columns); both key off `cfg.VaultKey`.

## 10. Handler response helpers (`internal/handlers`)

Package-private but available to any feature handler placed in
`internal/handlers`: `writeJSON`, `writeBadRequest`, `writeUnauthorized`,
`writeForbidden`, `writeNotFound`, `writeConflict`, `writeInternalError`,
`writeValidationError`, `writeRateLimited`, `logError(r, msg, args...)`,
`clientIP(r)`, `mustMarshalJSON`, null helpers, `ValidateEmail`,
`ValidateRequired`, `ValidateStringLength`, `validatePassword`,
`generateID()`. Client errors stay generic; put detail in `logError`.

## 11. Roles, first run, invitations

- First run: `POST /api/auth/register` creates the admin while `users` is
  empty, then permanently 409s. `GET /api/auth/status` reports
  `setup_required`.
- Lockout: 5 failed logins per email / 15 min locks the account (429); 20
  per IP blocks credential stuffing. TOTP 2FA on login (`totp_code` field,
  `{"totp_required":true}` signal) with recovery codes.
- Invitations carry `target_role` (default `vault_only`). Public redeem at
  `POST /api/invitations/redeem` `{code, password?}`; `vault_only`
  redemptions receive a `ti_`-prefixed API key for the extension.
- vault_only semantics: locked to the vault UI. Platform admin routes
  already exclude them via `AdminOnly`; feature agents must wrap every
  non-vault route in `timw.VaultOnlyBlock()`.

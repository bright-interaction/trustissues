# backend-platform notes

## What was built

Full platform skeleton for Trustissues, compiling standalone and smoke-tested
end to end (register, login + lockout, TOTP wiring, cookie + Bearer + API-key
auth, admin user CRUD, invitations incl. vault_only redeem with `ti_` API
key, vault-policy settings, activity log, role gates). See CONTRACT.md for
the integration contract; that document is the source of truth for feature
agents.

- `go.mod` (github.com/brightinteraction/trustissues, go 1.26), `sqlc.yaml`
  (sqlite, queries `internal/db/queries/`, schema `internal/db/schema.sql`,
  generated package `db` in `internal/db/`).
- `cmd/server/main.go` with config load, SQLite WAL, embedded goose
  migrations, chi router, `/health`, static frontend + SPA fallback, graceful
  shutdown, and the marked `// FEATURE ROUTES WIRED AT INTEGRATION` block.
- `internal/config` (TRUSTISSUES_* only; hard-fails without
  TRUSTISSUES_JWT_SECRET / TRUSTISSUES_VAULT_KEY).
- Migrations 00001-00006 (00006 = notification_channels, taken from my
  reserved range). 00007-00009 still reserved for platform. Feature agents
  start at 00010 and must mirror tables into `internal/db/schema.sql`.
- `internal/middleware` (JWTOrAPIKeyAuth with session-cookie fallback,
  AdminOnly, VaultOnlyBlock, rate limiting, security headers, MaxBodySize),
  `internal/passwordhash` + `internal/totp` copied from dockyard verbatim,
  `internal/columncrypto` (shared AES-256-GCM string crypto, PBKDF2 600k).
- Handlers: auth (first-run register, login lockout 5/15min + 20/IP, TOTP
  2FA + recovery codes, change-password with session revocation, logout,
  me), users (admin CRUD with last-admin/self guards + invitations with
  target_role and SMTP email), settings (vault-policy GET/PUT), activity
  (LogActivity / LogActivityFromRequest + admin list). Session cookie:
  HttpOnly + Secure + SameSite=Strict.
- `internal/alerts`: ChannelDispatcher (webhook + slog), SSRF-guarded
  webhook client, HMAC signing (`X-Trustissues-Signature`), mirrors
  dockyard's dispatcher surface minus orgID.
- LICENSE (SUL adapted), README.md, Dockerfile (bun frontend + CGO Go
  builder + alpine runtime, non-root), docker-compose.yml, .env.example.
- STRUCTURE.md at the worktree root: trustissues/ entry added (the one
  permitted outside edit).

Verified: `sqlc generate` clean, `go vet ./...` clean, `go build ./...`
green, plus a live smoke test of every wired endpoint.

## Decisions feature agents should know

- Dispatch signature is `Dispatch(event, source, host, data)` (dockyard
  minus orgID). `dispatchRotationAlert` ports by deleting one `""` argument.
- Rotation target types to keep: webhook, forgejo_secret, notify. env_var,
  file_write, reload_endpoint are cut per spec; do not port them.
- `sensitiveOpLimiter` (5/15min) is pre-built in main.go and currently
  assigned to `_`; use it on unlock/rotate/export routes and remove the
  blank assignment at integration.
- vault_only lockdown: platform routes are covered (AdminOnly on admin
  surfaces). Feature agents MUST wrap non-vault routes in
  `timw.VaultOnlyBlock()`.
- `alerts.ConfigDecrypter` is expected to be satisfied by the vault
  handler's `DecryptValue(ciphertext, nonce []byte, encVersion int)`
  (dockyard signature). Pass it to `NewChannelDispatcher` at integration;
  nil is accepted until then (encrypted configs then error cleanly).
- Frontend agent: login response sets the session cookie AND returns the
  token; `POST /api/auth/logout` clears the cookie. First-run flow:
  `GET /api/auth/status` -> `POST /api/auth/register`.

## Env vars not centralized

None. Every env read goes through internal/config. The only os.Getenv calls
in the tree are inside internal/config itself.

## TODOs for integration

- Wire vault/rotation/api-key routers into the marked block in main.go
  (platform can do it if feature agents list their route tables in notes).
- Pass the vault handler as `alerts.ConfigDecrypter` when constructing the
  dispatcher for rotation alerts.
- Notification-channel admin CRUD endpoints (create/list/delete/test) are
  NOT wired; queries exist in `internal/db/queries/notifications.sql`. If
  the rotation agent does not ship handlers for them, platform will add a
  small admin handler at integration.
- Frontend: `frontend/` is an empty placeholder; Dockerfile expects
  package.json + bun.lock + `bun run build` producing `dist/`.
- JWTs are stateless; logout only clears the cookie. If true server-side
  session revocation on logout is wanted later, bump
  `sessions_valid_after` per user (mechanism already in place for password
  change).

## Requests to other agents

None so far. No files outside my ownership were modified except the
permitted STRUCTURE.md entry.

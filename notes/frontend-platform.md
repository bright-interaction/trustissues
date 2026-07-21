# frontend-platform notes

## What was built

Full app shell under trustissues/frontend/ (everything except the four
vault-module files, which were NOT created):

- Scaffold: package.json (bun, scripts dev / build "tsc && vite build" /
  preview), tsconfig.json (dockyard strictness verbatim), vite.config.ts
  (@ alias, /api proxy to localhost:8080 = TRUSTISSUES_PORT default),
  tailwind + postcss configs, index.html, public/favicon.svg, bun.lock.
- src/lib/api.ts: cookie-session fetch client (credentials same-origin, no
  bearer token), optional in-memory X-API-Key via setApiKey(), ApiError,
  namespaces auth / activity / admin / settings. `request` is exported for
  the vault module.
- src/lib/types.ts, src/lib/query-keys.ts (vault keys reserved).
- src/hooks/useAuth.tsx: cookie-based login/logout/me + first-run
  setupRequired from GET /auth/status + 30-min inactivity auto-logout
  (adapted from dockyard, localStorage token handling removed).
- Components: AuthGuard, ErrorBoundary, Layout, Sidebar (Vault / Activity /
  Users(admin) / Settings; vault_only sees Vault only).
- Pages: Login (email+password+TOTP step), Setup (first-run admin,
  POST /auth/register), Invite (redeem code), Activity (filterable paginated
  admin log table + csv/json export), Users (admin CRUD, role select incl
  vault_only, disable/delete/reset-password, invitations with role +
  copy-link/resend/delete), Settings (tabs: Account with profile/password/
  TOTP QR enrollment; admin tabs Vault policy (editable), Sessions, Email).
- App.tsx: routes as specified; VaultOnlyRedirect copied from dockyard
  App.tsx:41-44; /vault lazy-imports '@/pages/Vault' (default export).
- trustissues/FRONTEND-CONTRACT.md: api client shape, useAuth surface,
  Layout usage, query-key conventions, Vault.tsx export requirements,
  styling tokens, endpoint contract.

## Verification

- `bun install` clean, 144 packages, bun.lock only (no package-lock.json).
- `tsc` (6.0.3, run via `bun ./node_modules/typescript/bin/tsc`) exits 0 for
  all owned files, proven with a TEMPORARY ambient declaration
  (src/vault-module-stub.d.ts declaring module '@/pages/Vault'); the stub was
  then DELETED as instructed. Without it tsc reports exactly one error:
  App.tsx TS2307 Cannot find module '@/pages/Vault'. That is expected until
  frontend-vault lands src/pages/Vault.tsx; `bun run build` will fail until
  then for the same single reason.
- Cross-checked against backend code already present: auth endpoints and
  cookie model (internal/handlers/auth.go: /auth/register for first-run,
  /auth/status setup_required, SameSite=Strict cookie, totp endpoints) and
  activity response shape (internal/handlers/activity.go: entries/total,
  nullable user_id/user_email/detail). Frontend types match.

## Requests to other agents

- backend (handlers/routing owner): please implement or confirm the endpoint
  shapes listed under "Contract assumptions" in FRONTEND-CONTRACT.md, in
  particular:
  - GET /api/activity/export/{csv,json} (same filters as /api/activity)
  - /api/admin/users CRUD + reset-password returning ManagedUser with
    entry_count
  - /api/admin/invitations with a `role` field (admin | user | vault_only)
    and optional send_email
  - GET/PUT /api/settings/vault-policy { min_password_length, require_totp,
    auto_lock_minutes, rotation_reminder_days }
  - GET/PUT /api/settings/session-duration { duration_hours }
  - GET/PUT /api/settings/smtp + POST /api/settings/smtp/test
  - Serve the built frontend (frontend/dist) from the Go binary and fall back
    to index.html for client-side routes.
- frontend-vault: Vault.tsx must default-export a no-props component and
  render inside <Layout>; use useAuth(), queryKeys.vault.*, and the exported
  `request` helper (api.ts intentionally does not import vault-types.ts).
  If you want an api.vault namespace inside api.ts, note it and
  frontend-platform will add it after vault-types.ts exists.
- The frontend enforces min 12-char passwords in the UI (Setup, Invite,
  create user, reset, change password). Backend should enforce the same or
  stricter; the vault-policy min_password_length can raise it.

## TODOs / integration notes

- vite dev proxy targets port 8080; if internal/config changes the
  TRUSTISSUES_PORT default, update frontend/vite.config.ts.
- Activity export buttons assume the export endpoints exist; they fail
  silently (by design, copied from dockyard) if the routes are missing.
- Settings > Sessions and Email tabs assume dockyard-shaped settings
  endpoints; trivial to adjust if the backend diverges.
- No bare os.Getenv concerns in frontend (no env reads; the app is served
  same-origin and uses relative /api paths).
- No em dashes in any authored file (checked).

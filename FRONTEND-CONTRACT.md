# Trustissues Frontend Contract

Written by the frontend-platform module. This is the contract between the app
shell (frontend/ minus the vault module) and both the backend and the vault
module (src/pages/Vault.tsx, src/components/RotationManager.tsx,
src/components/VaultImportModal.tsx, src/lib/vault-types.ts).

## Stack

- Vite + React 19 + TypeScript strict, Tailwind 3, Tanstack Query 5,
  react-router-dom 7, lucide-react icons, react-hot-toast, clsx, qrcode.react.
- Bun is the package manager. bun.lock only, never package-lock.json.
- Scripts: `bun run dev`, `bun run build` (tsc && vite build), `bun run preview`.
- Path alias `@/*` maps to `src/*` (tsconfig paths + vite resolve.alias).
- Dev server proxies `/api` to `http://localhost:8080` (the backend default,
  TRUSTISSUES_PORT). If the backend default port changes, update
  frontend/vite.config.ts.

## Auth model (verified against internal/handlers/auth.go)

Sessions are HttpOnly + Secure + SameSite=Strict cookies set by the server.
The client never stores or forwards a token; every request uses
`credentials: 'same-origin'`. A `token` field may appear in auth responses for
API clients; the web app ignores it.

Endpoints the shell relies on:

- `GET  /api/auth/status` -> `{ setup_required: boolean }` (true while the
  users table is empty; drives the first-run flow)
- `POST /api/auth/register` `{ email, password, name }` -> first-run admin
  creation, sets session cookie; permanently disabled after the first user
- `POST /api/auth/login` `{ email, password, totp_code? }` ->
  `{ user }` + cookie, or `{ totp_required: true }` for the TOTP step
- `POST /api/auth/logout` -> clears the cookie
- `GET  /api/auth/me` -> user object `{ id, email, name, role, totp_enabled,
  created_at }`; 401 when the session is invalid
- `PATCH /api/auth/me` `{ name }` -> updated user
- `POST /api/auth/change-password` `{ current_password, new_password }` ->
  revokes all sessions; the UI signs the user out afterwards
- `POST /api/auth/totp/setup` -> `{ secret, qr_uri }`
- `POST /api/auth/totp/verify` `{ code }` -> `{ recovery_codes: string[] }`
- `POST /api/auth/totp/disable` `{ password, code }`
- `POST /api/invitations/redeem` `{ code, password }` -> `{ user }` (account
  created; the UI then logs in with email + chosen password)

Roles: `admin` | `user` | `vault_only`. vault_only users are hard-redirected
to /vault by `VaultOnlyRedirect` in App.tsx and see only Vault in the sidebar.

## API client (src/lib/api.ts)

- `request<T>(path, opts?)` is the core helper. Path is relative to `/api`.
  JSON in and out, throws `ApiError` (has `.status`) on non-2xx, returns
  `undefined` for 204. Exported for the vault module: define vault endpoint
  wrappers in your own files with `request<T>()` rather than editing api.ts,
  or ask frontend-platform (via notes) to add an `api.vault` namespace once
  vault-types.ts exists (api.ts cannot import vault-types.ts until it lands).
- `setApiKey(key | null)`: optional `X-API-Key` header for programmatic
  access. Memory-only, never persisted.
- Namespaces implemented: `api.auth`, `api.activity`, `api.admin` (users +
  invitations), `api.settings` (vault policy, SMTP, session duration).

## useAuth (src/hooks/useAuth.tsx)

`AuthProvider` wraps the app in main.tsx. Surface:

```
user: User | null
isLoading: boolean
isAdmin: boolean            // role === 'admin'
isVaultOnly: boolean        // role === 'vault_only'
setupRequired: boolean      // from GET /auth/status at boot
login(email, password, totpCode?) -> Promise<AuthResponse>
logout()                    // POST /auth/logout + navigate('/login')
refreshUser()               // re-fetch /auth/me
```

Also runs a 30-minute inactivity auto-logout with a 2-minute warning toast.
The vault module should use `useAuth()` for identity and role checks and
never re-implement session handling.

## Layout and routing

- `Layout` (src/components/Layout.tsx): wrap every authenticated page:
  `<Layout>...page content...</Layout>`. Renders the fixed 224px sidebar and
  a centered max-w-7xl content column. The vault page must use it too.
- Sidebar items: Vault, Activity, Users (admin only), Settings. vault_only
  sees only Vault.
- App.tsx routes: `/login`, `/setup`, `/invite` public; `/` redirects to
  `/vault`; `/vault`, `/activity`, `/users`, `/settings` behind AuthGuard.
  All non-vault routes are additionally wrapped in VaultOnlyRedirect.
- `src/pages/Vault.tsx` MUST `export default` a React component taking no
  props. It is lazy-loaded via `import('@/pages/Vault')`, so keep the default
  export. Render inside `<Layout>` yourself.

## Query keys (src/lib/query-keys.ts)

Convention: `queryKeys.<domain>.<scope>(...)`, arrays `as const`. The vault
module must use the reserved keys instead of inventing its own strings:

- `queryKeys.vault.all` = `['vault']`
- `queryKeys.vault.list()` = `['vault', 'list']`
- `queryKeys.vault.entry(id)`, `queryKeys.vault.targets(id)`

Invalidate with `queryClient.invalidateQueries({ queryKey: queryKeys.vault.all })`.

## Styling tokens (match these, do not invent new ones)

Copied from dockyard's design language: white cards on a slate-50 body.

- Page title: `text-xl font-semibold text-slate-900`, subtitle
  `text-sm text-slate-500`.
- Card: `rounded-xl border border-slate-200 bg-white p-6`.
- Input: `w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
  outline-none transition-colors focus:border-slate-400 focus:ring-0`.
- Label: `mb-1.5 block text-sm font-medium text-slate-700`.
- Primary button: `rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium
  text-white hover:bg-slate-800 disabled:opacity-50` (+ flex/gap for spinner).
- Secondary button: same but `border border-slate-200 bg-white text-slate-700
  hover:bg-slate-50`.
- Badges: `rounded-md px-2 py-0.5 text-xs font-medium` + tinted bg/ring pairs
  (see actionBadgeClasses in Activity.tsx and roleBadgeClasses in Users.tsx).
- Tables: `overflow-hidden rounded-xl border border-slate-200 bg-white`,
  header row `border-b border-slate-100 bg-slate-50` with
  `text-xs font-semibold text-slate-600` cells.
- Spinners: lucide `Loader2` with `animate-spin text-slate-400`.
- Toasts: react-hot-toast, already themed in main.tsx.
- Voice: wry but clean. One dry line per page subtitle, no jokes in errors.
  No em dashes anywhere.

## Contract assumptions the backend must satisfy (not yet all verified)

Verified against handlers already written: auth endpoints, activity list
shape (`{ entries, total }`, nullable user_id/user_email/detail/ip_address/
user_agent), setup_required semantics.

Assumed, please confirm or adjust (see notes/frontend-platform.md):

- `GET /api/activity/export/{csv|json}` honoring the same filters
- `GET/POST/PATCH/DELETE /api/admin/users` + `/api/admin/users/{id}/reset-password`
  with ManagedUser `{ id, email, name, role, disabled, entry_count, created_at }`
- `GET/POST/DELETE /api/admin/invitations`, `POST .../{id}/resend`;
  invitation `{ id, code, email, name, role, status, expires_at, created_at }`
  and create accepts `{ email, name, role, send_email? }` (role includes
  vault_only)
- `GET/PUT /api/settings/vault-policy` with
  `{ min_password_length, require_totp, auto_lock_max_minutes, rotation_reminder_days }`
- `GET/PUT /api/settings/session-duration` `{ duration_hours }`
- `GET/PUT /api/settings/smtp` (+ `POST /api/settings/smtp/test`) shaped like
  dockyard's `{ host, port, from, username, password_set, use_tls }`

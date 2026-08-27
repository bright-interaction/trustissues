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
  created; the UI then logs in with email + chosen password). A `vault_only`
  invitee continues to `/client-onboarding`; no response API key is consumed or
  persisted.

Roles: `admin` | `user` | `vault_only`. `vault_only` users can reach Vault and
Settings (Account + API keys only); `VaultOnlyRedirect` keeps them out of the
activity, credential-access, and user-management pages. Server middleware is
the authorization boundary.

## API client (src/lib/api.ts)

- `request<T>(path, opts?)` is the core helper. Path is relative to `/api`.
  JSON in and out, throws `ApiError` (has `.status`) on non-2xx, returns
  `undefined` for 204. Exported for the vault module: define vault endpoint
  wrappers in your own files with `request<T>()` rather than editing api.ts,
  or ask frontend-platform (via notes) to add an `api.vault` namespace once
  vault-types.ts exists (api.ts cannot import vault-types.ts until it lands).
- `setApiKey(key | null)`: optional `X-API-Key` header for programmatic
  access. Memory-only, never persisted.
- `setUnauthorizedHandler(fn | undefined)`: invoked once per `401` so the app
  can drop session state. `AuthProvider` registers it. A caller that
  legitimately expects a `401` (the startup `/auth/me` probe on the public
  `/setup` and `/invite` pages) opts out with `skipAuthRedirect`.
- `setEnrollmentRequiredHandler(fn | undefined)`: invoked when any request is
  refused by the TOTP enrolment gate. `AuthProvider` registers it, refreshes
  the user so the banner becomes truthful, and redirects to
  `/settings?tab=account`.

### The enrolment gate's 403 (cross-cutting, applies to EVERY route except `/api/auth`)

While the `require_totp` vault policy is on and the caller has not enrolled,
`internal/middleware/totp_enrollment.go` refuses every route outside
`/api/auth`:

| status | `code` | when |
|---|---|---|
| 403 | `totp_enrollment_required` | the vault policy requires 2FA and this account has not enrolled |

Exported from `src/lib/api.ts` as `TOTP_ENROLLMENT_REQUIRED_CODE`, and pinned
equal to the Go constant by
`src/test/enrollment-gate-surface.test.tsx`.

Two rules for anything that renders server data:

1. **Route on the `code`, never on the bare `403`.** An ordinary authorization
   refusal is also a `403` and must not drag the user to the enrolment page.
2. **A refused list is not an empty list.** Destructure `error` from the query
   and give it its own branch. Vault.tsx did neither, so the gate's `403` left
   the list at its `[]` default and the page told the owner of five credentials
   *"No secrets stored."* See `src/test/vault-refusal-is-not-emptiness.test.tsx`.

This section exists because the gate's code was declared part of the API
contract in a Go comment while no frontend file read `.code` off an `ApiError`
at all, and this table did not list it.
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
- Sidebar items: Vault, Activity, Users (admin only), Settings. `vault_only`
  sees Vault and Settings so a password-authenticated session can manage its
  own account and mint/revoke a named extension API key.
- App.tsx routes: `/login`, `/setup`, `/invite` public; `/` redirects to
  `/vault`; `/client-onboarding`, `/vault`, `/activity`, `/users`, `/settings`
  behind AuthGuard. The client checklist redirects non-`vault_only` users back
  to Vault.
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

## Pending revoke: retry + resolve (new 2026-08-18, being implemented now)

Closes the gap where an on-demand entry (`auto_rotate: false`) whose last
rotation left a predecessor key un-revoked at the provider never retries that
revoke and never surfaces it, because the only consumer of the stored retry
markers is the rotation path itself. This is the operator-visible fix: a field
on every vault entry response, plus two buttons' worth of endpoint.

### New field on every vault entry object (`vaultEntryMeta`)

Every response that already returns a vault entry (list, get-one, unlock,
create, update, rotate, validate's entry echo where applicable) gains one more
top-level key, **always present, never omitted**, same discipline as
`custom_fields`:

```jsonc
"pending_revoke": null
```

or, when the row has a revoke outstanding:

```jsonc
"pending_revoke": {
  "outstanding": true,
  "predecessor_key_id": "key-1"
}
```

`predecessor_key_id` is a best-effort label for display only (e.g. "the key
ending in `key-1` is still live upstream"); never treat it as a full
credential id you can round-trip elsewhere except back into
`acknowledged_key_id` on the resolve call below. It can be `""` (empty string)
while `outstanding` is still `true`, for a predecessor id the backend could not
safely characterize; render that as "an older key" or similar, not as a blank.
Concretely, it is withheld when the marker is a bare key id that fails the
server's conservative charset check, and when the marker is a URL whose path
reduces to nothing nameable (no path, or a bare `/`); the server will not
invent an id out of punctuation just to have something to show.

Since 2026-08-18 the server RECORDS the predecessor id at the moment it queues
the revoke, rather than deriving it from the marker URL afterwards. For any
entry stranded from that point on, `predecessor_key_id` is the provider's exact
key id: safe to show verbatim, and safe to require back on resolve. The
derivation described above is now only the fallback for rows stranded before
that change. The practical consequence: Twilio entries used to report
`<sid>.json` and now report the bare `SK...` sid that the Twilio console shows,
so an operator copying the id from the provider is no longer refused.

There is one further shape, and note it is the opposite of the empty-id case
above: `outstanding: true` with a POPULATED `predecessor_key_id` on an entry
whose retry coordinates are gone. Retry answers `409 no_pending_revoke` for it,
because retry needs the URL; resolve still works, because it matches on the id.
So when the server reports outstanding and retry 409s, offer resolve, not retry.

(An earlier revision of this paragraph said "empty `predecessor_key_id`", which
was backwards and would have sent an implementer to wire resolve onto the
empty-id case, where the server hard-400s every click. The server reports this
shape only when the id passes its charset check, which an empty string does
not. No known writer can currently produce the shape at all: the only writer of
the recorded id sets the URL three lines earlier, and the markers are deleted
as a group. The reader handles it defensively so a future writer, or a
hand-repaired row, cannot create a stranded key the product can neither see nor
clear.)

This field is a **derived read-only fact**, computed fresh from the encrypted
markers on every response. It is never accepted on `PUT /api/vault/{id}` (same
as `provider_meta`'s other reserved keys. Sending it back is harmless, the
backend ignores/redacts it, but do not wire it into the edit form's dirty
tracking).

### `POST /api/vault/{id}/pending-revoke/retry`

The "retry this revoke now" button. Requires password re-auth, same UX as
Rotate/Unlock/Validate (prompt for password, same 429/403 handling).

Request:

```jsonc
{ "password": "the user's account password" }
```

Response `200` (the attempt was actually performed, check `revoked`, not just
the status code, to know whether it worked):

```jsonc
{
  "revoked": true,
  "detail": "",
  "pending_revoke": null
}
```

or, when the upstream is still refusing the revoke:

```jsonc
{
  "revoked": false,
  "detail": "old key not revoked (still live at provider); see server logs",
  "pending_revoke": { "outstanding": true, "predecessor_key_id": "key-1" }
}
```

`detail` is always that exact static sentence on failure (never the raw
upstream error, which only goes to the server log), so it is safe to render
verbatim.

Failure responses (all the existing `{ "error", "code", "request_id" }` shape
already used everywhere else in this API):

| status | `code` | when |
|---|---|---|
| 400 | `BAD_REQUEST` | missing password |
| 401 | `UNAUTHORIZED` | user lookup failed |
| 403 | `FORBIDDEN` | wrong password |
| 403 | `destination_pinned` | this secret is pinned to the AI gateway; spending it here is refused |
| 404 | `NOT_FOUND` | entry does not exist, or caller lacks read/spend/write rights (removed creator, stranger, disabled account, same as every other vault endpoint, refusals never distinguish "gone" from "not yours") |
| 409 | `unknown_provider` | entry's provider isn't one this server can talk to (same wording as Rotate) |
| 409 | `decrypt_failed` | the stored value could not be decrypted |
| 409 | `no_pending_revoke` | nothing outstanding; calling retry on a clean entry is a safe no-op you'll see as this, not as success |
| 429 | `RATE_LIMITED` | too many recent failed re-auths, try again in 15 minutes |

A `429` from the sensitive-op rate limiter itself (distinct from the
reauth-lockout `429` above) is also possible under heavy use; treat any `429`
the same way (backoff, "try again shortly").

Note there is no `500` documented for "revoke failed": a failed revoke is a
successful *attempt* (`revoked: false`), not a server *error*. That is a
statement about HTTP status handling, **not** a licence to render it quietly:
`revoked: false` means a credential the operator believes is dead is still
live at the provider, which is the most alarming outcome this endpoint has.

Render it as BOTH:

- the persistent inline state, keep the "an older key is still live" banner
  up, driven by the `pending_revoke` you got back, and
- an explicit notification that the click did not work (the shipped UI fires
  an error toast carrying `detail`).

What the "not a server error" rule actually forbids is treating it like a
transport failure: do not show a generic "something went wrong", do not
retry it automatically, and do not clear or hide the banner. An earlier
revision of this document said to render `revoked: false` "instead of an
error", which read as "do not alarm the operator" and would have removed the
only signal that a live orphaned credential is still out there, the exact
regression `pending-revoke-affordance.test.tsx` pins.

### `POST /api/vault/{id}/pending-revoke/resolve`

The "I dealt with this a different way, stop showing it" button, the
terminal escape hatch for a predecessor key that can never be revoked through
this UI (provider changed, key already gone, etc). No password required (same
as delete, which also needs none). The caller must know and type/paste the
predecessor key id shown by `pending_revoke.predecessor_key_id`, this is a
confirmation, not just a click, precisely because it discards the record with
no upstream verification.

Request:

```jsonc
{ "acknowledged_key_id": "key-1" }
```

Response `200` on success:

```jsonc
{
  "resolved": true,
  "pending_revoke": null
}
```

Response `400` (`BAD_REQUEST`) when `acknowledged_key_id` is missing, empty,
or does not exactly match the current `predecessor_key_id`, markers are left
untouched on the row, so it's safe to just re-show the confirmation and let
the user retry. There is intentionally no way to resolve a marker "blind"
(empty predecessor id resolves nothing); if `predecessor_key_id` renders empty
in the UI, resolve is not offered, only retry, or contacting an admin.

`404` (`NOT_FOUND`) under the same authz conditions as every other vault
endpoint (entry access via `canWrite` only here, no spend right needed, this
never touches the provider).

### UI notes

- Surface `pending_revoke` wherever an entry's rotation status is already
  shown (list row, detail panel). It is **independent** of
  `rotation_status`/`last_rotation_error`, an entry can read
  `rotation_status: "success"` and still carry `pending_revoke.outstanding:
  true`; do not fold the two into one badge.
- Suggested copy: "An older key at this provider may still be live" with a
  "Retry revoke" button (→ POST .../retry) and, once the user has confirmed
  out-of-band that it's handled, a secondary "Mark resolved" action (→ POST
  .../resolve) that requires re-typing/pasting the shown
  `predecessor_key_id`.
- On-demand entries (`auto_rotate: false`) are the whole point of this
  feature, they never get picked up by the scheduled sweep, so this UI is
  the *only* way that class of entry's stranded key ever gets retried. Do not
  gate visibility of the retry button on `auto_rotate`.

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

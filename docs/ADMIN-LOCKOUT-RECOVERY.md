# Recovering a locked-out administrator

There is no in-product recovery path, and that is deliberate. This document
exists because the alternative to a runbook is inventing an authentication
bypass, and on a credential vault a break-glass endpoint is a permanent attack
surface that exists for a rare event. It would become the softest target in the
system.

The existing recovery requires shell access to the host holding the database.
That is a real authorization boundary, and a stronger one than anything that
could be added in code.

Read [Prevention](#prevention) first. It is cheaper than every procedure below.

## What is NOT a lockout

Check these before touching the database.

**An un-enrolled admin under `require_totp` is not locked out.** The gate leaves
`/api/auth` reachable precisely so enrolment stays possible. Sign in normally and
finish 2FA setup at Settings > Account. If the banner does not appear, reload
once; if it still does not, that is a bug worth reporting, not a lockout.

**A `429` is not permanent.** The per-email lockout is 5 failures in 15 minutes
and it expires on its own. Wait it out before escalating. Note that it trips on
the *sixth* request, because the counter is read before the failure is recorded.

**Someone else can lock your login without touching your account.** The
`password_login` counter is keyed on email alone, so anyone who knows the address
can spray the public login endpoint and hold that door shut, renewably. This is a
known limitation, pre-existing and not introduced by the enrolment gate. It does
NOT affect an already-signed-in session: since the counter was split by scope, a
stranger's failures at the login door cannot refuse your enrolment, your vault
unlock, or your re-auth. If you are already signed in, you are not stuck.

## The genuine lockouts

| Situation | Recovery |
|---|---|
| Enrolled, lost the authenticator, still have a recovery code | Use the recovery code at login. Then disable and re-enrol 2FA. No DB access needed. |
| Enrolled, lost the authenticator, recovery codes gone | [Procedure A](#procedure-a-clear-2fa-for-one-account) |
| `require_totp` is on and you need 2FA off | `TOTPDisable` refuses with `409` while the policy is on. Turn the policy off first (needs a working admin session), or [Procedure B](#procedure-b-turn-off-require_totp). |
| Password unknown, and you are the only admin | [Procedure C](#procedure-c-set-a-password) |
| Login answers `429` and will not clear | [Procedure D](#procedure-d-clear-the-lockout-counter) |

There is no forgot-password flow, no admin unlock endpoint, and no route that
resets another user's 2FA. `POST /api/admin/users/{id}/reset-password` exists but
refuses the caller's own account, so it cannot rescue a sole admin. Confirmed by
audit: the only `DisableTOTP` call site in the codebase is inside the
`TOTPDisable` handler.

## Before any procedure

**Take a backup.** These are direct writes to a live credential vault.

```sh
docker compose -f docker-compose.prod.yml exec trustissues \
  sqlite3 /data/trustissues.db "VACUUM INTO '/data/pre-recovery.db'"
```

`VACUUM INTO` refuses to overwrite an existing file. Move the snapshot out of
the container (and remove any stale `/data/pre-recovery.db`) before repeating a
recovery attempt. It is WAL-safe and, unlike SQLite's page-copy `.backup`, does
not carry freelist residue into the break-glass snapshot.

The database lives under `TRUSTISSUES_DATA_DIR` (default `./data`). The container
is named `trustissues` (`docker-compose.prod.yml:35`). Adjust paths to your
deployment.

**Record who did this and why.** These writes bypass the product's own controls
and leave no application audit trail, so the operational record is the only one
that will exist.

## Procedure A: clear 2FA for one account

Leaves the password intact. The user can enrol again afterwards.

```sql
UPDATE users
   SET totp_enabled = 0,
       totp_secret = '',
       totp_recovery_codes = '',
       totp_last_step = NULL
 WHERE email = 'admin@example.com';
```

Clear `totp_last_step` too. It is the replay guard that records the last spent
time step; leaving a stale value behind can refuse the first codes from a freshly
enrolled authenticator.

If `require_totp` is on, the account is now un-enrolled and gated: it can reach
`/api/auth` to enrol, which is the intended path. Sign in and enrol immediately.

## Procedure B: turn off `require_totp`

```sql
UPDATE settings SET value = 'false' WHERE key = 'require_totp';
```

Prefer doing this through the UI with a working admin session. Direct edits skip
the guard that refuses to enable the policy unless the acting admin is enrolled,
and that guard is the reason a half-configured instance cannot lock itself out.

## Procedure C: set a password

Password hashes are argon2id and cannot be hand-written. Two options:

1. **Another admin resets it.** `POST /api/admin/users/{id}/reset-password`. Note
   this also revokes that user's API keys in the same request, so any browser
   extension will need re-provisioning.
2. **No other admin exists.** Mark the account as having no password and let it
   set one through the product:

```sql
UPDATE users SET password_set = 0 WHERE email = 'admin@example.com';
```

The account can then call `POST /api/auth/set-initial-password` with a live
session or API key. That endpoint refuses any account where `password_set = 1`,
so it cannot be used to take over an account that already has a password. Setting
the marker to 0 by hand deliberately opens that door for one account; close it by
completing the flow promptly.

## Procedure D: clear the lockout counter

```sql
-- one account, login door only
DELETE FROM login_attempts
 WHERE email = 'admin@example.com' AND scope = 'password_login';
```

Deleting and recreating the user does NOT clear this. `login_attempts` has no
foreign key to `users` and is keyed on the email string, so the rows outlive the
account.

Scopes are `password_login` (written by the public login endpoint) and
`session_reauth` (written only by an already-authenticated caller). If re-auth or
enrolment is being refused rather than login, the relevant rows are
`session_reauth`, and their presence means something authenticated as that user
was guessing. Investigate before deleting.

## After any procedure

1. Sign in and confirm the account works.
2. Re-enrol 2FA if you cleared it.
3. Rotate anything the recovery exposed. Restoring access to a credential vault
   is not the same as containing whatever caused the lockout.
4. Delete the pre-recovery backup once you are satisfied. It is a full copy of the
   vault.
5. Do the prevention step below, so the next occurrence is not another one of
   these.

## Prevention

**Keep at least two enrolled administrators.** Every procedure here exists only
because a single-admin deployment has no second path. With two, `reset-password`
covers Procedure C and Procedure A becomes a support task rather than a shell
session on the production host.

**Check before enabling `require_totp`.** `GET /api/service-identities` reports
`owner_email` and `owner_totp_enabled`, so an operator can see which automation
will start failing before the policy is switched on rather than after. Service
identities are refused while their owning human is un-enrolled.

**Store recovery codes somewhere that is not the vault.** Codes kept only inside
TrustIssues are unreachable in exactly the situation they exist for.

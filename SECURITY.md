# Security Policy

Trustissues holds credentials, API keys, and 2FA seeds for a whole team. We take
its security seriously and we are honest about its limits. Read THREAT-MODEL.md
alongside this file.

## Reporting a vulnerability

If you find a security issue, report it privately. Do not open a public issue
and do not post details anywhere public until it is fixed.

- Email: security@brightinteraction.com
- Include: what you found, how to reproduce it, and the impact you think it has.
- We aim to acknowledge within 3 business days and to agree on a disclosure
  timeline with you. Please give us a reasonable window to ship a fix before any
  public disclosure.

Do not run scans or tests against a Trustissues instance you do not own.

## Security posture (what is true today)

**Encryption at rest.** All secret values, TOTP seeds, notification configs, and
rotation targets are encrypted with AES-256-GCM. The key is derived from
`TRUSTISSUES_VAULT_KEY` via PBKDF2-SHA256 (600k iterations) with a fresh random
96-bit nonce per value. The key is held only in process memory from the
environment; it is never stored in the database.

**This is server-side encryption, not end-to-end.** The operator of the server,
and anyone with root on the host, can decrypt everything, because they control
the key. Trustissues is not a zero-knowledge system. If your threat model
requires that even the operator cannot read secrets, this is the wrong tool.

**Authentication.** Argon2id password hashing (bcrypt auto-upgraded on login),
per-email lockout and per-IP throttling on login, constant-time handling of
unknown accounts, optional TOTP 2FA with hashed single-use recovery codes,
admin-enforceable team-wide 2FA.

**Sessions.** Stateless HS256 JWT signed with `TRUSTISSUES_JWT_SECRET`, delivered
as an `HttpOnly; Secure; SameSite=Strict` cookie. Password change revokes all
prior sessions.

**Transport.** The app expects to run behind a TLS-terminating proxy. Session
cookies are `Secure`, so they will not be sent over plain HTTP to a non-loopback
host. This is intentional.

**HTTP hardening.** Security headers are set on every response: a strict
Content-Security-Policy (`default-src 'self'`), `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`,
`Permissions-Policy` locking off camera/mic/geolocation. No CORS is enabled
(same-origin only). Request bodies are size-capped.

**Refuse-to-start.** The process exits non-zero at boot if
`TRUSTISSUES_JWT_SECRET` or `TRUSTISSUES_VAULT_KEY` is missing or shorter than 32
characters. Auth and at-rest encryption are never optional.

**Audit log.** Auth events, admin actions, invitations, and service-identity
secret fetches are recorded and exportable (CSV / JSON) by an admin.

## Key custody (the most important operational rule)

- Generate `TRUSTISSUES_VAULT_KEY` and `TRUSTISSUES_JWT_SECRET` with
  `openssl rand -hex 32`. Never use the placeholder from `.env.example`.
- Store `TRUSTISSUES_VAULT_KEY` in a separate secret store from your database
  backups. Backup + key in the same place cancels the encryption.
- Losing `TRUSTISSUES_VAULT_KEY` is permanent, total data loss. There is no
  recovery path. Back it up once, deliberately, and protect it like a root
  password.
- Losing `TRUSTISSUES_JWT_SECRET` only forces re-login. It does not threaten
  stored data.

## Rotating the vault key (manual, do this carefully)

This build has no automatic key rotation and no dual-key read. Changing
`TRUSTISSUES_VAULT_KEY` in place will make all existing data unreadable. If you
must rotate the key (suspected compromise, policy), do it as an explicit
migration while the old key still works:

1. Announce a short maintenance window. Take a backup first (see README).
2. With the server running under the OLD key, export every secret in plaintext
   through the authenticated API or the vault UI (unlock, reveal, record). There
   is no bulk re-key command, so this is a manual export/re-import.
3. Stand up a fresh data directory with the NEW key.
4. Re-create the entries (and re-enroll TOTP) under the new instance.
5. Verify you can unlock and read every secret under the new key, then retire the
   old data directory and destroy the old key.

Do not simply restart with a new env value and expect the data to migrate. It
will not. Until a code-side dual-key rotation ships, treat key rotation as a
supervised re-import, never an env edit.

## Supported versions

Trustissues is pre-1.0. Security fixes land on `main`. Run a recent build.

## Known gaps tracked for the next hardening pass

See THREAT-MODEL.md "Residual risks" (R1 through R7) and DEFERRED.md. The
operator-visible ones: backups are manual (WAL-safe `scripts/backup.sh`, see
docs/BACKUP.md; scheduling is deferred), the DB file and its `-wal`/`-shm` are
chmodded to 0600 on boot with the data dir 0700 (still, keep
`TRUSTISSUES_DATA_DIR` off a shared mount), the app must bind loopback
(`TRUSTISSUES_BIND_HOST=127.0.0.1`) behind TLS with
`TRUSTISSUES_TRUSTED_PROXY_HOPS` set to the real proxy count, and a wrong
`TRUSTISSUES_VAULT_KEY` now stops the server at boot rather than serving blank
entries (override with `TRUSTISSUES_ALLOW_KEY_MISMATCH=1` only when the original
key is gone for good and losing every secret is accepted).

Any user, including `vault_only`, mints their own browser-extension API key from
Settings > API keys. It is displayed once and stored only as a hash.

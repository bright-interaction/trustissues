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

## Rotating the vault key

Rotation is a supported, in-place operation. It has two halves:

- a **dual-key read**: with `TRUSTISSUES_VAULT_KEY_PREVIOUS` set to the old key,
  every decrypt tries the current key and then the previous one, so a store that
  has not been re-encrypted yet keeps serving normally;
- a **re-encrypt sweep**: one transaction that moves every keyed column in the
  database onto the current key, verifies the result before committing, and
  refuses outright if any stored value opens under neither key.

Two columns are deliberately NOT re-encrypted by that sweep, and they are the
audit trail: `capability_log.secret_name` and `service_secret_audit.secret_names`
are sealed under a separate audit key, which is itself stored wrapped under the
master key. Those tables are append-only, so no sweep can rewrite them; the
rotation rewraps the audit key instead, and the rows stay exactly as written.
Nothing extra to do, but if you are auditing the sweep's report, that is why
those two columns never appear in it.

Take a backup first (see `docs/BACKUP.md`). Then:

1. Generate the new key: `openssl rand -hex 32`.
2. Move the current value of `TRUSTISSUES_VAULT_KEY` into
   `TRUSTISSUES_VAULT_KEY_PREVIOUS`, and put the new value in
   `TRUSTISSUES_VAULT_KEY`.
3. Restart. The instance boots and serves normally. The boot log and
   **Settings -> Encryption** both say the store is still on the previous key.
4. Run the sweep. Any of:
   - **Settings -> Encryption -> "Re-encrypt everything with the current key"**
     (the normal path; it shows you what moved and what, if anything, refused),
   - `POST /api/admin/vault-key/rekey` as an admin,
   - `TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT=1` plus a restart, for headless
     deploys where nobody logs in.
5. Confirm **Settings -> Encryption** reports everything on the current key.
6. **Remove `TRUSTISSUES_VAULT_KEY_PREVIOUS` and restart.** Until you do, the
   key you are retiring is still loaded and still opens all of this data, which
   defeats the point of rotating after a compromise.

`GET /api/admin/vault-key` returns the same report as the UI: a per-column count
of how many values are on the current key, on the previous key, stale, or
unreadable. It needs no configuration, so it is also the fastest way to check the
state of an instance somebody else deployed.

Two notes on the environment while a rotation is in flight:

- The old key is accepted as `TRUSTISSUES_VAULT_KEY_PREVIOUS` even if it is short
  or looks weak, with a warning. It describes data that already exists, so
  refusing it would protect nothing and would block the one rotation that matters
  most: away from a bad key. Setting it to the SAME value as
  `TRUSTISSUES_VAULT_KEY` is still refused, because that reads as a configured
  rotation while converting nothing.
- Once the sweep is done, every boot warns that the retired key is still loaded,
  until you remove it. Not once: every boot, because on a headless deploy that
  log line is the only surface anyone sees.

### What the sweep covers

Every column that holds material derived from the master key, across all four
crypto schemes in use: the vault secret values (both derivation versions), the
eight `enc:v1:` metadata columns on `vault_entries`, the two URL blind indexes,
invitation codes, TOTP seeds, the SMTP password, the boot key sentinel, and
notification-channel configs.

The blind indexes are worth calling out because their failure is silent: they are
keyed HMACs, not ciphertext, so a stale one does not fail to decrypt, it just
stops matching and browser autofill quietly returns nothing. The sweep recomputes
them, and autofill looks up under both keys while a rotation is configured.

Because they are recomputed from cleartext rather than decrypted, a stale index
is repaired with **no previous key at all**. That state is reachable without any
rotation (a metadata backfill that ran out of budget leaves it), so the status
page reports it as needing a sweep and the button stays available.

Two tests enforce this list. One walks the real database schema and fails when
any column is neither registered as a keyed surface nor explicitly classified as
unkeyed, so a new encrypted column cannot ship without a decision about rotation.
The other states each crypto family's on-disk format as a pair, and asserts in
both directions that the sweep's reader accepts what the production writer
produces AND that the production reader accepts what the sweep writes. The second
half is the one that matters: a sweep that reads correctly and writes a shape the
product cannot parse has already re-encrypted the original away.

### If the sweep refuses

A refusal means the store holds ciphertext that neither configured key opens: a
row restored from an older backup, or a previous rotation that was never
finished. **Nothing is written** when this happens, and the report names the
table, column and row id of every such value (never the value itself).

Do not treat a refusal as "close enough". The one genuinely destructive action
available at that moment is deleting the old key while some rows still need it.
Find the key those values were sealed under, set it as
`TRUSTISSUES_VAULT_KEY_PREVIOUS`, restart, and run the sweep again.

### If you already changed the key with no previous key set

The boot gate refuses to start, which is correct: the data is still recoverable.
Put the ORIGINAL key back in `TRUSTISSUES_VAULT_KEY` and restart, then follow the
procedure above. `TRUSTISSUES_ALLOW_KEY_MISMATCH=1` boots anyway and is a
last-resort tool that accepts losing the data; it is not part of rotation.

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

# Trustissues Threat Model

Read this before you deploy. It tells you, in plain terms, what Trustissues
protects, what it does not, and the handful of ways you can lose all your data.
It is written for the person running the server, not just the person who wrote
it.

Last reviewed: 2026-07-21 (operator-surface hardening pass).

## What this system holds

Trustissues is a shared vault for a single team. It stores some of the most
sensitive data an organization has:

- Human login credentials (usernames + passwords for other systems).
- API keys and machine tokens for third-party services.
- TOTP / 2FA seeds (the shared secret behind an authenticator app).
- SMTP credentials, notification-channel configs, rotation delivery targets.
- Account password hashes (Argon2id) for every Trustissues user.

If this data leaks, an attacker can log into everything your team logs into.
Treat the server the way you would treat a safe.

## The one thing you must never lose: TRUSTISSUES_VAULT_KEY

Every secret value in the database is encrypted with a key derived from the
environment variable `TRUSTISSUES_VAULT_KEY` (AES-256-GCM, key stretched with
PBKDF2-SHA256 at 600k iterations). The key itself is never written to the
database. It lives only in the environment you give the process.

This has two consequences you must internalize:

1. **Lose the key, lose everything.** There is no reset, no recovery, no
   support backdoor. If you regenerate `.env`, wipe the environment, or restore
   a database against a different key, every vault value, every TOTP seed, and
   every rotation target becomes permanently unreadable. This was verified: a
   database booted under a different key returns `[decryption error]` for every
   secret and the plaintext cannot be recovered by any means.
2. **Change the key the wrong way and you also lose everything.** There is no
   built-in key-rotation routine and no dual-key read path in this build.
   Swapping `TRUSTISSUES_VAULT_KEY` for a new value is identical to losing the
   old one. Do not rotate the key by editing the env var. See SECURITY.md for
   the manual re-key procedure (export, re-import under the new key) if you ever
   must.

Back the key up, once, in a password manager or secret store that is physically
and logically separate from where the database backup lives. If the backup and
the key ever sit in the same place, you have defeated the encryption.

## Trust boundaries

```
[ Browser / Extension ]  --HTTPS-->  [ TLS proxy ]  --HTTP(loopback)-->  [ Trustissues ]  ---->  [ SQLite file ]
        untrusted network                 you own                            you own                  you own
```

- **The network between a user and the server is untrusted.** Everything on it
  must be HTTPS. Trustissues sets its session cookie `Secure`, so over plain
  HTTP the cookie is silently dropped and login "mysteriously" fails. That is
  the app refusing to send credentials in cleartext, not a bug. Terminate TLS
  in front of it.
- **The server host is the trust anchor.** Anyone who can read the process
  environment (`/proc`, a debugger, a container inspect) can read
  `TRUSTISSUES_VAULT_KEY` and therefore decrypt everything. Anyone with root on
  the host owns the vault. Limit who can SSH to the box.
- **The SQLite file is trusted-at-rest only in the sense that it is
  ciphertext.** Secret values, TOTP seeds, notification configs, rotation
  targets, and entry metadata (URL, alias URL, username, category, notes) are
  encrypted at rest under the vault key. A stolen `.db` file without the key
  exposes the schema and the Argon2 password hashes, plus AES-GCM ciphertext, but
  no plaintext secret values. It is safe to back up off-host **as long as the key
  is stored elsewhere.**

  This claim was false until 2026-07-29: invitation codes were stored in
  cleartext, and `POST /api/invitations/redeem` is unauthenticated by design, so
  a keyless backup taken while an invite was pending could be read for the code
  and redeemed against the live server. An admin-role invite produced a real
  admin account, and an admin can reset another user's password and then unlock
  their vault. Codes are now stored as vault-key ciphertext with a SHA-256 lookup
  hash (migration 00030), matching how `api_keys` and `service_identities` have
  always stored their bearer credentials. Any pending invite that predates that
  migration was expired, because its code is already sitting in older backups.
- **The entry NAME is stored in cleartext, and so is the inventory it implies.**
  `vault_entries.name` carries the `UNIQUE(user_id, name)` constraint, the
  by-name capability lookup and every `ORDER BY name`, so it is not encrypted
  today. A leaked `.db` therefore does reveal the list of services the team keeps
  entries for ("AWS root account", "Klarna prod DB", and any customer name an
  operator puts in a title), even though no value decrypts. The same strings are
  mirrored into `activity_log.detail`, `capability_log.secret_name` and
  `service_identities.allowed_secrets`. Treat a backup as revealing WHAT you
  hold, never the secrets themselves. Encrypting it behind a blind index is
  designed and deferred, see DEFERRED.md.
- **URL matching for the browser extension uses a keyed blind index, not the
  plaintext URL.** So the extension can ask "do we have an entry for this
  domain?" without the server storing the URL in the clear. The blind index
  leaks equality and existence (two entries for the same URL share an index
  value) but not the URL itself. Because the index is keyed off the vault key, it
  is part of what a key rotation must re-derive.

## What the encryption does and does NOT protect against

Be honest with yourself about this. Trustissues does **server-side** encryption,
not end-to-end. That is a deliberate design choice for a self-hosted team vault,
and it has clear limits.

**It protects against:**

- A stolen database file or backup (ciphertext is useless without the key).
- A stolen disk / volume snapshot.
- Casual read of the DB by another local user IF file permissions hold (note:
  the DB file is currently mode 0644, see Residual risks).
- Values leaking into logs (verified: secret values, passwords, and key
  material do not appear in logs even at debug level).

**It does NOT protect against:**

- **A compromised or malicious server operator.** Whoever controls the running
  process controls `TRUSTISSUES_VAULT_KEY` and can decrypt every secret. This
  is not a zero-knowledge system. Your team is trusting the operator and the
  host, by design. Say so out loud to your team.
- **A compromised host / root user.** Same reason.
- **The client / browser.** Once a user unlocks the vault, plaintext values are
  sent to their browser and held in memory. A compromised browser or a
  malicious extension on the user's machine sees what the user sees.
- **A stolen key.** If the key leaks, every backup and every live copy of the
  database is decryptable. The key is the whole ballgame.

If you need the property that even the operator cannot read secrets
(zero-knowledge, client-side encryption), Trustissues is not that product.

## Authentication and session model

- Passwords are hashed with Argon2id; legacy bcrypt hashes upgrade on next
  login. Login has per-email lockout (5 failures / 15 min), per-IP throttling,
  and constant-time behavior for unknown accounts.
- Sessions are stateless JWTs signed with `TRUSTISSUES_JWT_SECRET`, delivered as
  an HttpOnly + Secure + SameSite=Strict cookie. Losing the JWT secret only
  forces everyone to log in again; it does NOT threaten stored data.
- Optional TOTP 2FA, with hashed single-use recovery codes. Admins can require
  2FA team-wide in the vault policy.
- Account roles: `admin` (full control), `user` (own entries + own profile),
  `vault_only` (browser-extension role, authenticates with an API key).
- Shared team vaults ("collections") with per-collection roles: `viewer`
  (read + reveal), `editor` (also create/update/delete entries), `manager`
  (also manage members and rename/delete the collection). A personal entry is
  owner-only (admins see all); a collection entry is governed by the caller's
  membership role. Access is enforced server-side on every read and write path
  (`entryAccess` in `internal/handlers/vault.go`), not just hidden in the UI.
  Sharing is an authorization layer only; the encryption model is unchanged.

## The vault "lock" is a client-side convenience, not a server control

When a user "unlocks" the vault they re-enter their password and the server
returns decrypted values. The auto-lock timer (vault policy `auto_lock_minutes`)
runs **in the browser**: it drops the decrypted values from memory after the
configured idle time. It does not revoke anything server-side. Treat auto-lock
as "clear my screen," not as a server-enforced session boundary. The real
server-side boundary is the JWT session duration and logout.

## Residual risks and mitigations

These are known, accepted-with-mitigation risks in this build. They are drawn
from the parallel hardening review; track them and apply the operator-side
mitigation until the code-side fix ships.

| # | Risk | Impact | Operator mitigation |
|---|------|--------|---------------------|
| R1 | **No master-key rotation path.** Changing `TRUSTISSUES_VAULT_KEY` silently orphans all data. | Total data loss on a naive rotation. | Deferred to Phase 2 (dual-key read + re-encrypt sweep; see `DEFERRED.md` (a)). Until then never rotate by editing env; use the export/re-import procedure in SECURITY.md. Guard the key like a root password. |
| R2 | **Backups are manual.** A hand-copied `.db` in WAL mode can be torn/stale. | Silent backup corruption; unrecoverable if paired with key loss. | Resolved for correctness: use `scripts/backup.sh` (SQLite online `.backup`, WAL-safe, mode 0600) per `docs/BACKUP.md`. Store the key separately. Scheduling is deferred (`DEFERRED.md` (d)); run it from cron/systemd. |
| R3 | ~~DB file world-readable.~~ **Resolved.** The server now sets umask 0o077 and chmods the db + `-wal`/`-shm` to 0600 (dir 0700) on boot. | Was: local users could read hashes + ciphertext. | Keep `TRUSTISSUES_DATA_DIR` on a non-shared path; the 0600 mode is enforced automatically. |
| R4 | **Bind host is configurable; default must be loopback.** Publishing 0.0.0.0 in plain HTTP exposes the API. | On a VPS this exposes the API to the internet in cleartext. | Set `TRUSTISSUES_BIND_HOST=127.0.0.1` (the safe default) and bind the compose port to `127.0.0.1:8080:8080` behind a TLS proxy. See README deploy section. Mandatory, not optional. |
| R5 | **X-Forwarded-For trust must be bounded.** Trusting XFF from any private/loopback peer lets a neighbor spoof the source IP. | A neighboring container can spoof source IP for rate-limit + audit. | Set `TRUSTISSUES_TRUSTED_PROXY_HOPS` to the exact number of proxies in front (1 for a single Caddy) so only that many hops are trusted; run behind that one proxy on an isolated network and do not co-locate untrusted containers on the same bridge. |
| R6 | ~~Extension API key never shown in the UI.~~ **Resolved.** Settings has an "API keys" tab where any user, including `vault_only`, mints a key, sees it once, and copies it to connect the extension. | Was: users could not self-serve an extension key. Note this table claimed "Resolved" while the router still redirected `vault_only` away from `/settings`, so it was false for the only role that needs it; fixed alongside this row. | None needed; issue keys from Settings. `vault_only` sees an Account and API keys tab only, enforced server-side by `AdminOnly` on every other surface. |
| R7 | ~~Secrets only length-checked.~~ **Resolved.** The server refuses to boot on a low-entropy or placeholder `TRUSTISSUES_VAULT_KEY`/`JWT_SECRET`, on top of the 32-char minimum. | Was: a lazy operator could run with a known key. | Generate both with `openssl rand -hex 32`. |

## Deployment assumptions (non-negotiable)

1. A TLS-terminating reverse proxy sits in front. Users only ever speak HTTPS.
2. The app listens on loopback (or an internal-only network), never directly on
   a public interface. Set `TRUSTISSUES_BIND_HOST=127.0.0.1`.
3. `TRUSTISSUES_VAULT_KEY` and `TRUSTISSUES_JWT_SECRET` are each 32+ random bytes
   from `openssl rand -hex 32`, stored in a secret manager, never committed.
4. The database directory is 0700 and backed up (WAL-safe, via `scripts/backup.sh`
   per `docs/BACKUP.md`), with the key stored separately from the backup.
5. The host is trusted and access-controlled. The operator is trusted with all
   secrets, because server-side crypto gives them that access by design.
6. **Single team, no organizations, no multi-tenancy.** One instance serves one
   team. Within it, personal vaults plus shared collections with per-collection
   roles (viewer/editor/manager) give intra-team access control, but there is no
   tenant isolation between mutually-distrusting groups: an instance admin can
   see everything by design. This is why several Phase 2 items (tamper-evident
   agent audit, post-deletion attribution) are safe to defer. See `DEFERRED.md`.
   Do not run one instance as a shared vault for mutually-distrusting teams.

## The AI boundary (gateway + MCP + Shield)

Trustissues can let an assistant or app use AI and stored credentials. The
protections differ by asset, and it is important to be precise:

- **Credentials: fully protected.** The AI gateway injects the provider key
  server-side; the MCP `use_secret` returns a single-use, destination-bound
  capability token, never a value. The AI and the human never see the secret,
  in use or at rest, and every use is attributed and logged.
- **PII in prompts/tool results: protected only with Shield on.** With
  `TRUSTISSUES_SHIELD_KEY` set, structured PII (email, phone, personnummer, IBAN)
  is tokenized before it crosses to the external model and resolved server-side
  for the trusted caller. Arbitrary names/companies in free-form prompts are NOT
  caught by the regex path (see DEFERRED (g)). With Shield off, prompt content
  passes through to the provider unchanged.
- **The prompt itself is never private from the provider.** Anthropic/OpenAI see
  whatever (tokenized) content the model needs to reason. Shield keeps the raw
  PII off that boundary; it does not make the conversation invisible to the
  provider. Full privacy requires a self-hosted model.
- **The server still decrypts to inject.** Server-side injection means the vault
  process transiently holds plaintext (the documented trust model). "Use without
  the AI or human seeing it" is achievable; "use without the server seeing it" is
  not, when the server does the injecting.

**Confused-deputy / prompt-injection controls.** Because an assistant can invoke
`use_secret`, a malicious prompt could try to make it act toward an
attacker-chosen destination. Mitigations, all enforced server-side: the secret's
`destination_patterns` allow-list is a hard ceiling a token request can only
narrow; tokens are single-use and destination-bound; per-(agent, secret) grants
gate issuance; the `/proxy` client refuses redirects (no key egress) and forwards
only to the bound host. High-risk automations should still keep a human in the
loop.

**Fail-safe posture.** A set-but-wrong-length `TRUSTISSUES_SHIELD_KEY` refuses to
boot rather than silently disabling tokenization; the gateway rejects (never
forwards) a request whose body cannot be tokenized while Shield is on.

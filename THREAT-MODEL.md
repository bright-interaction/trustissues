# Trustissues Threat Model

Read this before you deploy. It tells you, in plain terms, what Trustissues
protects, what it does not, and the handful of ways you can lose all your data.
It is written for the person running the server, not just the person who wrote
it.

Last reviewed: 2026-08-05 (authentication-path review).

The revision before this one was dated 2026-07-21 and was the document a
deploying operator is told to read first, while the system underneath it had
moved through audit rounds 15 to 19, migrations 00033 to 00038, the secret exit,
`internal/vaultfield` and the whole ownership surface. Two of its claims had gone
from true to false in that time (see "Authentication and session model"). If you
are reading a copy whose date is older than the newest `AUDIT-ROUND-*.md` in this
directory, assume the same has happened again and check the code before trusting
a sentence here.

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
2. **Change the key the wrong way and you still lose everything.** Rotation is
   supported now, but only through the documented sequence: set
   `TRUSTISSUES_VAULT_KEY_PREVIOUS` to the old key, restart, run the re-encrypt
   sweep, confirm it reports the store fully on the current key, and only then
   remove the previous key. Swapping `TRUSTISSUES_VAULT_KEY` for a new value on
   its own, with no previous key set, is still identical to losing the old one:
   the boot gate refuses to start (which keeps the data recoverable), and forcing
   past it with `TRUSTISSUES_ALLOW_KEY_MISMATCH=1` does not. See SECURITY.md,
   "Rotating the vault key".

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
- **The entry NAME is encrypted at rest (migration 00040), but three mirrors of
  it are not.** `vault_entries.name` is now stored as `enc:v1:` ciphertext like
  every sibling metadata column, with per-user uniqueness carried by a keyed
  blind index (`name_bidx`) that is unlinkable across users. A leaked `.db` no
  longer reveals the entry inventory from that table.

  The two audit mirrors of that name are encrypted too.
  `capability_log.secret_name` and `service_secret_audit.secret_names` are sealed
  under a separate data-encryption key (the audit DEK), which is itself stored
  wrapped under the master key in `settings.audit_name_dek`. That indirection is
  what lets them be encrypted at all: both tables are append-only (00003, 00039),
  so a master-key rotation could never rewrite them, and rotating rewraps the DEK
  instead. The name stays in the audit row, so the trail still names what was
  accessed after the entry itself is deleted, which is the case it exists for.

  What a leaked `.db` still reveals, stated plainly:

  1. `activity_log.detail` holds free text that names entries ("Vault entry
     moved: X", "Collection deleted: ..., 3 entries destroyed: [...]"). It is
     append-only and unencrypted, and it is the surface a future pass should
     take next.
  2. Audit rows written BEFORE this change are cleartext and will stay that way
     for ever. Append-only means exactly that: they cannot be converted, and a
     migration that rewrote them would be the tampering the triggers exist to
     prevent. A fresh install has none; an upgraded one keeps its history.

  Treat a backup as revealing your older audit history, never the secrets.
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
- Casual read of the DB by another local user, since the server sets umask 0o077
  and chmods the db plus its `-wal`/`-shm` to 0600 (dir 0700) on boot (R3). An
  earlier revision of this file still warned that the file was mode 0644 while
  the table below already recorded the fix; the 0600 statement is the correct one.
- Values leaking into logs (verified: secret values, passwords, and key
  material do not appear in logs even at debug level).

**What the column encryption specifically does NOT bind.** Every encrypted
column is sealed with AES-256-GCM under the same vault key, and
`internal/vaultfield` passes `nil` as the AEAD's additional authenticated data at
all five `Seal`/`Open` sites. The `vaultfield.Field` a caller supplies is a
DECLARATION, refused when zero, from which the encrypted-field ledger derives
coverage. It is not a cryptographic binding. So a ciphertext lifted out of one
column and written into another decrypts cleanly under the second column's
`Field`, and an attacker with DB WRITE access can move sealed values between
columns without ever holding the key. This does not weaken the keyless-backup
story, which is what R1/R3 are about, and an attacker with database write access
already has other paths. It matters when you reason about integrity rather than
confidentiality: the ledger tells you which columns are encrypted, not that a
given ciphertext belongs where it sits. A code comment claimed otherwise until
2026-08-05 (`352bdb327`).

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

This is the part of the system that had gone longest without being read. Rounds
1 to 19 audited what a session may REACH; round 14 recorded that nothing had
audited how a session is OBTAINED, and no later round picked it up. That review
ran on 2026-08-05 and is the reason for this revision. Three ordering defects
came out of it, all fixed in `027ed79d7`, and they are described here rather than
quietly dropped because the operator-visible behaviour changed.

- Passwords are hashed with Argon2id (m=64MiB, t=3, p=4); legacy bcrypt hashes
  upgrade on next login. Argon2 work is bounded by a 4-slot semaphore, so a login
  flood becomes latency and then 503, never a memory-exhaustion crash. Capacity
  exhaustion is answered as 503 and is never counted as a failed attempt, at every
  one of the six sites that verify a password, because counting it would make
  saturating the semaphore an account-lockout vector.
- Login has a per-email lockout (5 failures / 15 min, with a graduated delay from
  the third), per-IP throttling (20 failures / 15 min), a per-IP request limiter
  (30 / 15 min) and a dummy-hash verify so an unknown address cannot be told apart
  by latency. **The dummy hash was only half of that until 2026-08-05.** An address
  with no account returned before recording anything, so its failure counter stayed
  at zero forever: five wrong passwords at a real address answered 429 and the same
  five at an unknown address answered a fast 401, which made the status code a
  certain account-existence oracle. Both paths now accrue, delay and lock out
  identically.
- **Sessions are NOT stateless JWTs, and have not been since migration 00022.**
  The JWT signed with `TRUSTISSUES_JWT_SECRET` carries a session id as its `jti`,
  and every request revalidates the server-side `sessions` row: missing, revoked
  (logout), bound to a different user, idle past `session_idle_minutes` (default
  15), or past the row's absolute `expires_at` all reject with 401. A password
  change revokes every session row, moves the `sessions_valid_after` cutoff so
  older tokens die by `iat`, and revokes the user's API keys as well, because
  changing the password is the incident-response action after a compromise.
  A stolen token therefore stops working on logout, on password change, and on
  15 minutes of inactivity, rather than living to its natural expiry. Two knobs
  govern this and they are deliberately separate: `session_idle_minutes` is the
  HTTP session, `vault_auto_lock_max_minutes` is the browser-side vault lock.
  They shared one key once, so widening the vault auto-lock silently widened every
  HTTP session.
- Losing the JWT secret forces everyone to log in again and does NOT threaten
  stored data, which is still true. But note the asymmetry with the sentence above:
  because sessions are now server-side rows, an attacker who steals the JWT secret
  and forges a token must also name a live session id, so the secret alone is no
  longer sufficient to mint a working session.
- The session cookie is HttpOnly + Secure + SameSite=Strict, and every
  state-changing `/api` route additionally passes an Origin/Referer check that
  fails open only for callers that send none of `Origin`, `Referer` or
  `Sec-Fetch-Site` (a browser always sends at least one; the CLI and MCP
  connectors do not).
- Optional TOTP 2FA. A code is accepted only if its 30-second time step can also
  be CONSUMED, so an observed code is not replayable inside its own window, and
  recovery codes are spent under a compare-and-swap that refuses the login if the
  spend does not persist. Enabling 2FA requires the PASSWORD, not just a session,
  because enrolment is irreversible by the owner and a session thief could
  otherwise lock them out permanently. Disabling requires the password plus either
  a live code or a recovery code.
- Admins can require 2FA team-wide in the vault policy, which is enforced by
  refusing self-service disables. **That refusal used to spend the second factor
  before refusing**, so a user under the policy who tried to turn 2FA off burned a
  single-use recovery code and got a 409 anyway; eight attempts left an account
  with no recovery path at all and nothing reissues them. The policy is now
  consulted on the password alone, before anything is consumed.
- **`POST /api/auth/totp/verify` checked its lockout after the password verify's
  early return until 2026-08-05**, so the check could only ever fire once the
  password was already correct. The endpoint sits under the 500/min API limiter
  rather than the login limiter, so a stolen session had a password oracle two
  orders of magnitude faster than `/api/auth/login` with the lockout switched off,
  and the failures it recorded locked the real owner out of the login page
  meanwhile. If you are running a build older than `027ed79d7` and have any reason
  to think a session or extension API key leaked, treat the account password as
  guessable and rotate it.
- `login_attempts` holds a plaintext email and source IP per attempt, and is the
  one table where an unauthenticated caller can write a row of their choosing,
  bounded by the login limiter. It is swept hourly down to a 24 hour window
  (R8). Nothing reads a row older than 15 minutes; the login audit trail is
  `activity_log`, which is append-only and is not what gets swept.
- Account roles: `admin` (full control), `user` (own entries + own profile),
  `vault_only` (browser-extension role, authenticates with an API key).
- Shared team vaults ("collections") with per-collection roles: `viewer`
  (read + reveal), `editor` (also create/update/delete entries), `manager`
  (also manage members and rename/delete the collection). A personal entry is
  owner-only (admins see all); a collection entry is governed by the caller's
  membership role. Access is enforced server-side on every read and write path
  (`entryAccess` in `internal/handlers/vault.go`), not just hidden in the UI.
  Sharing is an authorization layer only; the encryption model is unchanged.
- One user cannot use the collection surface to learn who else has an account.
  Any authenticated role, including `vault_only`, can create a collection and is
  its first manager, so every answer that surface gives has to be independent of
  the rest of the directory. Inviting an address answers identically whether or
  not it matches an account, a pending seat is recorded by the invited EMAIL
  either way and carries no user id or display name until the invitee accepts,
  and withdrawing an invitation always answers 204. A seat created for an address
  with no account becomes a real pending membership when that account is created,
  so the invitation is still redeemable and the members list does not change
  shape when the address registers. The activity-log row is written on both
  branches with the same text, so the audit trail does not answer the question
  either.
  **What this does not hide: response timing.** Inviting or rescinding an address
  that matches an account runs three more SQLite reads than one that does not, so
  a caller who can measure the difference over enough samples still learns it.
  Nothing asserts constant time, and padding it would be a false promise on a
  single-file database whose page cache dominates the signal. Rate-limit
  `/api/collections/*` at the proxy if that matters for your instance.
- **Who may rename a shared entry.** `UNIQUE(user_id, name)` is scoped to the
  entry's creator, so a rename asks a question about the creator's private
  namespace and the answer (409 or 200) is readable by whoever asked. The rule:
  the creator and an instance admin rename freely; a **manager** of the
  collection may rename an entry whose creator has left that collection, and
  that rename **adopts** the entry (the new owner and the new name are written in
  one statement, so the uniqueness question lands in the manager's own namespace
  and the creator's vault is never consulted); everybody else, including a
  manager while the creator is still a member, is refused with a constant 403.
  Adoption's cost is deliberate: it ends the departed creator's residual recovery
  read on that one entry. The complete fix is scope-aware uniqueness (partial
  indexes on `(user_id, name) WHERE collection_id IS NULL` and
  `(collection_id, name)`), which SQLite cannot do without rebuilding
  `vault_entries`, and that rebuild would cascade-delete `capability_grants`.
- LLM provider keys are spendable only on inference. Trustissues holds the
  operator's provider key and injects it server-side, so the reachable methods
  and paths are an explicit allowlist (`providerInferenceRoutes` in
  `internal/handlers/provider_routes.go`) rather than whatever the caller names.
  It is enforced at BOTH doors onto that key, the AI gateway (`/api/ai/...`) and
  the capability bridge (`/proxy/{host}/...`), and the path is decoded and
  cleaned before it is matched so an encoded traversal cannot leave an allowed
  prefix. A provider host with no allowlist entry is refused entirely.

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
| R1 | ~~No master-key rotation path.~~ **Resolved.** Dual-key read (`TRUSTISSUES_VAULT_KEY_PREVIOUS`) plus an exhaustive re-encrypt sweep across every keyed column, in one verified transaction. | Was: total data loss on a naive rotation. | Follow SECURITY.md "Rotating the vault key". A naive in-place key change with no previous key set is still refused at boot rather than accepted, and `Settings -> Encryption` (or `GET /api/admin/vault-key`) reports which key the store is actually on. Remove the previous key once the sweep reports everything current. Guard the key like a root password. |
| R2 | **Backups are manual.** A hand-copied `.db` in WAL mode can be torn/stale. | Silent backup corruption; unrecoverable if paired with key loss. | Resolved for correctness: use `scripts/backup.sh` (SQLite online `.backup`, WAL-safe, mode 0600) per `docs/BACKUP.md`. Store the key separately. Scheduling is deferred (`DEFERRED.md` (d)); run it from cron/systemd. |
| R3 | ~~DB file world-readable.~~ **Resolved.** The server now sets umask 0o077 and chmods the db + `-wal`/`-shm` to 0600 (dir 0700) on boot. | Was: local users could read hashes + ciphertext. | Keep `TRUSTISSUES_DATA_DIR` on a non-shared path; the 0600 mode is enforced automatically. |
| R4 | **Bind host is configurable; default must be loopback.** Publishing 0.0.0.0 in plain HTTP exposes the API. | On a VPS this exposes the API to the internet in cleartext. | Set `TRUSTISSUES_BIND_HOST=127.0.0.1` (the safe default) and bind the compose port to `127.0.0.1:8080:8080` behind a TLS proxy. See README deploy section. Mandatory, not optional. |
| R5 | **X-Forwarded-For trust must be bounded.** Trusting XFF from any private/loopback peer lets a neighbor spoof the source IP. | A neighboring container can spoof source IP for rate-limit + audit. | Set `TRUSTISSUES_TRUSTED_PROXY_HOPS` to the exact number of proxies in front (1 for a single Caddy) so only that many hops are trusted; run behind that one proxy on an isolated network and do not co-locate untrusted containers on the same bridge. |
| R6 | ~~Extension API key never shown in the UI.~~ **Resolved.** Settings has an "API keys" tab where any user, including `vault_only`, mints a key, sees it once, and copies it to connect the extension. | Was: users could not self-serve an extension key. Note this table claimed "Resolved" while the router still redirected `vault_only` away from `/settings`, so it was false for the only role that needs it; fixed alongside this row. | None needed; issue keys from Settings. `vault_only` sees an Account and API keys tab only, enforced server-side by `AdminOnly` on every other surface. |
| R7 | ~~Secrets only length-checked.~~ **Resolved.** The server refuses to boot on a low-entropy or placeholder `TRUSTISSUES_VAULT_KEY`/`JWT_SECRET`, on top of the 32-char minimum. | Was: a lazy operator could run with a known key. | Generate both with `openssl rand -hex 32`. |
| R8 | ~~`login_attempts` is never purged.~~ **Resolved.** A janitor sweeps rows older than `handlers.LoginAttemptRetention` (24h) hourly and once at boot, so an instance that has been accumulating since before this existed is cleaned on its first boot with it. | Was: unbounded growth of a table of plaintext addresses and IPs, readable from a keyless backup, and the one table an unauthenticated caller can write a row of their choosing into. | None needed. The window is a constant rather than a setting, deliberately: nothing reads a row older than 15 minutes, and `TestLoginAttemptRetentionOutlivesEveryReader` derives every reader's window from the query files and fails if the constant stops exceeding the longest one. The login audit trail is `activity_log`, which is append-only and untouched by the sweep. |
| R9 | **Only `activity_log` is append-only.** Its `_no_update`/`_no_delete` triggers ABORT tampering (00003, amended by 00027 to allow anonymization). `capability_log` and `service_secret_audit` have no triggers at all. | Someone with direct SQLite access can erase the capability and service-secret trail without tripping anything, while the human-action trail resists it. The trails disagree about how well they are protected. | Direct filesystem access to the DB is already game over for confidentiality (see trust boundaries), so this is about post-incident reconstruction, not prevention. Ship the same triggers on both tables; tracked as DEFERRED (b). |
| R10 | **Nothing reads `capability_log`.** The table is written on every capability issue and use and there is no endpoint, no UI and no export over it. | The capability trail exists but cannot be reviewed without opening the database by hand, which means in practice it is not reviewed. | `sqlite3 $TRUSTISSUES_DATA_DIR/trustissues.db 'SELECT * FROM capability_log ORDER BY created_at DESC LIMIT 50'` until DEFERRED (c) ships. |
| R11 | **Audit actor attribution is lost on user deletion.** `activity_log.user_id` is `ON DELETE SET NULL`. | Deleting a user anonymizes their entire history in the one trail that IS tamper-evident, so "who did this" becomes unanswerable for exactly the person most likely to be under investigation. | Disable accounts instead of deleting them (`disabled = 1` is enforced at every auth path and keeps the rows intact). Tracked as DEFERRED (f). |
| R12 | **The rename oracle is mitigated, not closed.** `UNIQUE(user_id, name)` is table-level, so a rename still asks a question about the creator's private namespace; the shipped fix bounds who may ask. | A narrow existence oracle over another user's entry names, for the principals still permitted to rename. | None available at the operator level. The complete fix (partial indexes) needs a `vault_entries` rebuild that would cascade-delete `capability_grants`; tracked as DEFERRED (h). |

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
attacker-chosen destination. Mitigations, all enforced server-side: a token
request can only NARROW the secret's `destination_patterns`; tokens are
single-use and destination-bound; per-(agent, secret) grants gate issuance; the
`/proxy` client refuses redirects (no key egress) and forwards only to the bound
host. High-risk automations should still keep a human in the loop.

**Who may move the ceiling itself.** The sentence above used to say the
allow-list is "a hard ceiling", which was true of the token REQUEST and false of
the ceiling: `PUT /api/vault/{id}` is mounted for every role and authorized by
`grantFor` row 5, so any accepted collection editor (a role the PUBLIC invite
endpoint hands out as `vault_only`) could rewrite `destination_patterns` and have
`/proxy` deliver the operator's decrypted provider key, in cleartext, to a host
they named. That is an escalation even though a collection member can read a
shared secret through `/api/vault/unlock`, because unlock re-verifies the
caller's password and the proxy path does not: an API key alone turned "use
without seeing" into "see". Two rules now hold the boundary (`secret_egress.go`):

- **A provider key is pinned.** An entry an admin has wired into the AI gateway
  (`settings.ai_key_openai` / `ai_key_anthropic`, an `AdminOnly` write) is only
  ever delivered to that provider's own API host. The pin is derived from that
  admin-only row and the compile-time `aiProviders` table, never from the entry,
  so no one who can edit the entry can move it. It is enforced at mint, at
  delivery through `/proxy`, at the `destination_patterns` write, and on rotation
  delivery targets (a webhook target POSTs the value, so it is the same
  question). The delivery-side check is the load-bearing one: it also refuses
  rows written by an older binary, an import, or a restored backup.
- **Widening takes more than `manage`.** Anyone with manage may NARROW or clear a
  secret's destinations (clearing is the per-secret agent revocation). ADDING a
  destination takes the entry's creator, who deposited the plaintext, or an
  instance admin, and the creator must still be a current member. Enrolling a
  provider is gated the same way, because three presets expand a tenant value out
  of `provider_meta` into the host (`{tenant}.auth0.com`), which put the host in
  an editor's hands.

- **Delivery targets are destinations too.** Adding a rotation target whose type
  transmits the value (`webhook`, `forgejo_secret`) is the same act as widening
  the ceiling and takes the same right, at the write (`decideDeliveryEgress`) and
  at delivery (`secretexit.Exit`, round 7). Removing one, clearing the list,
  relabelling it, rotating its HMAC secret and configuring a `notify` target stay
  open to `manage`. This was DEFERRED (i) until 2026-08-02 and was the round-5
  blocker: an accepted `vault_only` editor pointed a shared secret's rotation
  webhook at a host they controlled and the scheduler delivered the freshly
  minted plaintext.

**Why this stopped being a per-handler check.** Rounds 2 through 5 each closed
one named field and the next round found the next one. Round 4 answered that with
a coverage table forcing every `vault_entries` column to be classified as
host-choosing or not. It did not stop round 5, because `rotation_targets` was
correctly classified and `UpdateTargets` wrote it without asking anybody: a
classification is a claim about the code, and a table that labels a field next to
an unenforced write path reads as coverage. So the enforcement point is now a
value a handler cannot fabricate. `internal/egressgate` issues a `Ticket` only
from `Decide`, which consults the authority oracle exactly when a write ADDS a
destination; every generated query that writes `destination_patterns`,
`provider`, `provider_meta` or `rotation_targets` is generated into
`internal/vaultegress/internal/egressq`, which Go's own `internal` rule puts out
of reach of every package except `internal/vaultegress`, whose six exported
functions each demand a Ticket for that entry and that field.

Round 5 stated that rule as "one file, checked by a test that reads the source",
and four planted write paths walked through the gaps in its regular expressions
while building clean. Round 6 removed the methods from every type a handler can
name, so a host-choosing write without a ticket does not fail a test, it fails
to compile. `TestPlantedEgressBypassesDoNotCompile` runs the real toolchain on
five planted bypasses and reads its refusals.

The residual the compiler cannot see (a NEW query in `internal/db`, or a
hand-written statement) is covered by
`TestNoStatementOutsideTheEgressPackageWritesAHostChoosingColumn`, which builds a
probe database in which those columns are `GENERATED` and hands every
compile-time constant in the module to SQLite. Which columns a statement writes
is the engine's answer, not a pattern's, so a table alias or doubled whitespace
changes nothing.

Adding a delivery destination takes the entry's creator or an instance admin,
and both halves of that rule (the write gate and the delivery gate) call one
function, `VaultHandler.mayConfigureDelivery`, which resolves admin status from
the users row. Since round 7 the delivery half reaches it through
`VaultHandler.AuthorizeSecretExit`, the single implementation of the owner rule,
and asks about the entry the SECRET CAME FROM rather than the entry being
rotated. Round 5 implemented the rule twice and the copies disagreed about
admins, so an admin's target was accepted and then silently never delivered.
`TestDeliveryGateAgreesWithWriteGate` runs both halves over nine principals and
fails if they ever differ.

**Who the owner IS, which turned out to be the next question.** The gate asks
"did the owner of the secret being sent authorise this destination", and until
round 8 it resolved owner from `vault_entries.user_id`. That is a column an
ordinary product route lets a collection manager write to their own id:
`AdoptAndRenameVaultEntry`, reached by `PUT /api/vault/{id}` with a new name once
the creator is no longer an accepted member, and a manager can bring that
precondition about themselves with `DELETE /api/collections/{id}/members/{creator}`,
which is manager-gated too. Two ordinary calls made the attacker the owner and the
exit then authorised them correctly. Ownership therefore moved to
`vault_entries.secret_owner` (migration 00034), a column no member route writes,
with 00035 and 00036 relaundering and reformatting the backfill and 00037 creating
the bookkeeping tables for instances already past those versions.

Transferring ownership is now an explicit, admin-only act:
`POST /api/admin/vault/{id}/ownership/claim`. An entry becomes claimable only when
its recorded owner has lost manage, and every way that happens (a manager removing
them from the collection or demoting them to viewer, an admin demoting their
instance role or disabling their account) is itself routine and reversible, while
the claim was not. Migration 00038 records the previous holder so a claim can be
undone. Prod holds zero ownership claims, so this surface is latent rather than
exercised; treat the claim route as an admin action with an audit trail, not as
part of normal member management.

**The ledger that says which columns are encrypted.** Round 8 replaced a prose
scope boundary with `theEncryptedFieldLedger` and a test that derives the real set
from the module's AST. Round 9 found it derived from four CALL SHAPES, so a
decryption spelled a fifth way was invisible to it. The current derivation is a
markup scan rather than a shape match, but keep the lesson: a guard that
recognises one spelling of the thing it guards is the recurring defect in this
codebase, and the ledger is a completeness claim, not an enforcement point. Pair
it with the compile-time refusals above, which are.

**What this does not cover.** `auto_rotate` still takes only `manage` and is
classified `egressTriggersDelivery`: it decides WHETHER the secret moves, never
WHERE. An API-key-only caller can still set it without a password and make the
scheduler act, but only toward destinations an authorised principal chose.

**Timing on membership writes.** `POST /collections/{id}/members` and
`DELETE /collections/{id}/invitations` answer identically whether or not an
address has an account, and write the same activity row either way, but a hit
does three more reads and one more insert. That difference cannot be removed
while one branch records a seat the other cannot, short of dummy writes. What is
removed is the sample count: both routes now sit behind a dedicated 30-per-15-
minutes limiter instead of the shared 500/min API budget, which is far above real
member management and far below averaging a sub-millisecond difference over a
network.

**Fail-safe posture.** A set-but-wrong-length `TRUSTISSUES_SHIELD_KEY` refuses to
boot rather than silently disabling tokenization; the gateway rejects (never
forwards) a request whose body cannot be tokenized while Shield is on.

## What has NOT been reviewed

Nineteen audit rounds is a lot of rounds, and the number is misleading unless you
also know where they pointed. Almost all of them went at one surface: what an
authenticated principal may reach, and specifically what can make a decrypted
secret leave the process. That surface is now guarded by things a handler cannot
route around, and it is the part of this system you should trust most.

The following have never been read by any round, and are listed here so nobody
mistakes nineteen rounds for coverage. This is round 14's own list, minus the
authentication path, which was read on 2026-08-05.

- `internal/handlers/vault_providers.go` (1852 lines), the largest unread file.
  Every rotation finding to date is about the wrapper. The code doing the actual
  upstream mint and revoke calls, response parsing and per-provider credential
  shapes has never been read.
- `internal/alerts/channels.go`, the off-box egress sink. A refuted "teammate
  email leaks in `last_rotation_error`" finding was argued at the caller; nobody
  read what is actually POSTed.
- `vault_ssrf.go`, `vault_target_purge.go` and `collection_target_purge.go`. At
  least one refutation depends on purge behaviour that was never read.
- The generated SQL in `internal/db`. The compare-and-swap contract is asserted in
  Go comments; the UPDATE that would make it true is unread.
- All 22 files under `frontend/src/`. Two confirmed findings are claims about what
  the operator SEES.

Two more honest caveats about this document. Scale first: production currently
holds 5 vault entries, 28 activity rows and 0 ownership claims, so several risks
described here are latent rather than live, and an item's position in this file is
not a statement about how urgent it is. Second, the per-round documents in this
directory each restate the previous round's residuals, so four of them describing
the same unresolved thing is one finding, not four. The round-14 write-up was
called `AUDIT-ROUND-14-PENDING.md` while saying COMPLETE on line 1, which is the
kind of contradiction that costs a reader an hour; it is `AUDIT-ROUND-14.md` now,
matching its five siblings and the glob the mirror strips them by.

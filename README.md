# Trustissues

Self-hosted, single-team password manager and API-key rotation service.
Extracted from the audited Dockyard vault engine: per-user entry ownership,
encrypted-at-rest secrets, TOTP 2FA, invitation-based onboarding for a
vault-only browser-extension role, and rotation delivery to webhooks,
Forgejo Actions secrets, and notification channels.

Stack: Go (chi + slog + sqlc), SQLite (WAL, embedded goose migrations),
React frontend served by the same binary. One container, one volume, no
external dependencies.

## Quickstart

```bash
export TRUSTISSUES_JWT_SECRET=$(openssl rand -hex 32)
export TRUSTISSUES_VAULT_KEY=$(openssl rand -hex 32)

go build -o bin/trustissues ./cmd/server
./bin/trustissues
```

Open http://localhost:8080 and complete first-run setup (the first account
becomes the admin; the register endpoint disables itself afterwards).

Or with Docker Compose:

```bash
cp .env.example .env   # or export the two secrets
docker compose up -d
```

Keep `TRUSTISSUES_VAULT_KEY` safe: rotating or losing it makes every
encrypted column (vault entries, TOTP seeds) unreadable.

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `TRUSTISSUES_JWT_SECRET` | yes | - | Signs session JWTs (>= 32 chars) |
| `TRUSTISSUES_VAULT_KEY` | yes | - | Encrypts secrets at rest (>= 32 chars) |
| `TRUSTISSUES_BIND_HOST` | no | `127.0.0.1` | Interface to listen on. Keep it loopback behind a TLS proxy; only widen it for an internal-only network |
| `TRUSTISSUES_PORT` | no | `8080` | HTTP listen port |
| `TRUSTISSUES_TRUSTED_PROXY_HOPS` | no | `1` | Number of trusted reverse proxies in front. Default `1` matches the intended single-Caddy deploy so `X-Forwarded-For` is honored for exactly one hop; set `0` to ignore forwarded headers and use the direct peer |
| `TRUSTISSUES_BASE_URL` | no | `http://localhost:8080` | External URL (invitation emails, extension setup) |
| `TRUSTISSUES_DATA_DIR` | no | `./data` | SQLite data directory |
| `TRUSTISSUES_FRONTEND_DIR` | no | `./frontend/dist` | Built frontend to serve |
| `TRUSTISSUES_LOG_LEVEL` | no | `info` | debug / info / warn / error |

The server refuses to start without the two required secrets: auth and
at-rest encryption are never optional.

## Roles

| Role | Access |
|---|---|
| `admin` | Everything, including all vault entries, users, invitations, settings, activity log |
| `user` | Own vault entries, own profile |
| `vault_only` | Locked to the vault UI / browser extension (API-key auth) |

## Development

```bash
sqlc generate      # after editing internal/db/queries/*.sql or schema.sql
go vet ./...
go build ./...
```

Migrations are embedded goose files in `internal/database/migrations/` and
run automatically at boot. See `CONTRACT.md` for the internal architecture
contract.

## Production deployment

Trustissues holds credentials, API keys, and 2FA seeds. Read
`THREAT-MODEL.md` and `SECURITY.md` before exposing it to anyone. The short
version of the rules:

1. Always run behind HTTPS. The session cookie is `Secure`, so over plain HTTP
   to a non-localhost host login will silently fail. That is the app refusing
   to send credentials in cleartext, not a bug.
2. Never let the app listen directly on a public interface. Bind it to loopback
   (or an internal network) and put a TLS proxy in front.
3. Generate real secrets. Never ship the `.env.example` placeholder.

### First run

1. Set the two required secrets and start the server (see Quickstart).
2. Open the site over HTTPS. You land on the first-run setup page.
3. Create the admin account. This is the one and only account the public
   register endpoint will ever create; it disables itself afterward. Everyone
   else joins by invitation.
4. Log in, then add your first vault entry. From here everything is done in the
   UI: create/reveal/rotate secrets, invite teammates (Users page), set the
   auto-lock and password policy (Settings, Vault policy tab), configure SMTP
   (Settings, Email tab).

### Generate the secrets

```bash
openssl rand -hex 32   # TRUSTISSUES_VAULT_KEY
openssl rand -hex 32   # TRUSTISSUES_JWT_SECRET
```

- `TRUSTISSUES_VAULT_KEY` encrypts everything at rest. **If you lose it, every
  secret is gone forever. There is no reset.** Back it up once, in a secret
  store separate from your database backups.
- `TRUSTISSUES_JWT_SECRET` signs sessions. Losing it just forces everyone to log
  in again.
- Do not rotate `TRUSTISSUES_VAULT_KEY` by editing the env var. There is no
  in-place re-key in this build, so a changed value orphans all data. See the
  rotation procedure in `SECURITY.md`.

### Run behind TLS (recommended: Caddy)

Bind the app to loopback and let the proxy own port 443. Example with the
Docker Compose file, publishing only to localhost:

```yaml
# docker-compose.override.yml
services:
  trustissues:
    ports: ["127.0.0.1:8080:8080"]   # not 0.0.0.0
```

A minimal Caddyfile (automatic HTTPS via Let's Encrypt):

```
vault.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Then set:

- `TRUSTISSUES_BASE_URL=https://vault.example.com` so invitation links and the
  extension setup point at the right host.
- `TRUSTISSUES_BIND_HOST=127.0.0.1` so the app only listens on loopback (the
  default), never a public interface.
- `TRUSTISSUES_TRUSTED_PROXY_HOPS=1` so the one Caddy in front is trusted for
  `X-Forwarded-For` and no other peer can spoof the client IP used for rate
  limits and the audit log. Use the exact number of proxies you actually run.

Caddy adds HSTS for you; if you use nginx/Traefik instead, enable HSTS there.

### Backups

A naive `cp` of the database while the server runs can produce a torn snapshot
(SQLite runs in WAL mode). Use the WAL-safe helper, which wraps SQLite's online
backup API and writes the snapshot mode 0600:

```bash
TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/backup.sh /secure/backups
```

For the Compose deploy, run the same `.backup` inside the container against
`/app/data/trustissues.db`, or stop the container and tar the named volume. See
`docs/BACKUP.md` for the full backup, restore, and key-custody procedure.

Backup rules (the short version):

- The backup is AES-GCM ciphertext + password hashes. It is safe at rest
  **without** the key, which is exactly why the key must live somewhere else. A
  backup and the `TRUSTISSUES_VAULT_KEY` stored together is the same as no
  encryption.
- To restore: drop the backup file into `TRUSTISSUES_DATA_DIR`, remove stale
  `-wal`/`-shm` sidecars, and start the server with the **same**
  `TRUSTISSUES_VAULT_KEY`. A different key yields `[decryption error]` on every
  secret, permanently.
- Automated/scheduled backups are deferred (`DEFERRED.md`); run the script from
  cron or a systemd timer for now.

### File permissions

`TRUSTISSUES_DATA_DIR` is created 0700. The database file itself is currently
0644, so do not bind-mount the data directory to a shared host path, and
`chmod 600 "$TRUSTISSUES_DATA_DIR"/trustissues.db*` after first boot on a
multi-user host.

## Browser extension setup

The `vault_only` role is the browser-extension role. To connect the extension a
user needs two things, both produced by Trustissues:

1. **Server URL**: the `TRUSTISSUES_BASE_URL` of your instance
   (for example `https://vault.example.com`).
2. **An API key**: a `ti_`-prefixed key that authenticates the extension via the
   `X-API-Key` header.

The key is minted when a `vault_only` invitation is redeemed:

1. An admin opens the Users page, clicks Invite, enters the teammate's email and
   picks the `vault_only` role, and creates the invitation.
2. The teammate opens the invite link (`/invite?code=...`), chooses a password,
   and their account is created. The redeem response contains their `api_key`
   and the `server_url`.
3. They paste the server URL and the API key into the extension.

> **Known gap (tracked):** the invite redemption UI does not currently display
> the returned `api_key` or `server_url`; it logs the user straight into the web
> vault and discards them. The key is stored only as a hash, so it cannot be
> recovered later, and there is no reissue endpoint yet. Until this is fixed, an
> admin must capture the `api_key` from the `POST /api/invitations/redeem`
> response (visible in the browser dev-tools Network tab at redemption time) and
> hand it to the user over a secure channel. This is a shipping blocker for a
> no-help extension setup and is called out in `THREAT-MODEL.md` (R6) and
> `SECURITY.md`.

## License

Trustissues Sustainable Use License (fair-code). Free to self-host and use
commercially for your own team; reselling it as a hosted service requires a
commercial license. See `LICENSE`.

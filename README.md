# Trustissues

Self-hosted, single-team password manager and API-key rotation service.
Extracted from the audited Dockyard vault engine: personal vaults plus shared
team collections with per-collection roles (viewer / editor / manager),
encrypted-at-rest secrets (values and metadata), TOTP 2FA, invitation-based
onboarding for a vault-only browser-extension role, and rotation delivery to
webhooks, Forgejo Actions secrets, and notification channels.

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

Keep `TRUSTISSUES_VAULT_KEY` safe: losing it makes every encrypted column
(vault entries, TOTP seeds) unreadable. Rotation is supported only through the
documented dual-key procedure; never replace the current key in isolation.

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
- Do not rotate `TRUSTISSUES_VAULT_KEY` by replacing the environment value
  alone. Put the old value in `TRUSTISSUES_VAULT_KEY_PREVIOUS`, set the new
  current key, restart, run and verify the transactional re-encryption sweep,
  then remove the previous key. See the exact procedure in `SECURITY.md`.

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
(SQLite runs in WAL mode). Use the WAL-safe helper, which creates a compacting
`VACUUM INTO` snapshot and writes it mode 0600:

```bash
# bare metal
TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/backup.sh /secure/backups

# docker compose (the data lives in a named volume at /app/data)
docker compose exec trustissues \
  sqlite3 /app/data/trustissues.db "VACUUM INTO '/app/data/backup.db'"
docker compose cp trustissues:/app/data/backup.db ./trustissues-snapshot.db
docker compose exec trustissues rm -f /app/data/backup.db
```

See `docs/BACKUP.md` for the full backup, restore, and key-custody procedure.

Backup rules (the short version):

- Secret payloads and entry metadata in the backup are AES-GCM ciphertext, but
  the file also contains password hashes plus account and audit metadata. Treat
  every snapshot as sensitive and encrypt the whole file before third-party or
  off-host storage. Keep that wrapping key and `TRUSTISSUES_VAULT_KEY` separate
  from the snapshots; a backup beside the vault key cancels column encryption.
- To restore, use `./scripts/restore.sh <snapshot>` (add `--compose` for the
  Compose deploy). It refuses while the service is running and clears the stale
  `-wal`/`-shm` sidecars, which matters: leaving them lets SQLite recover the OLD
  database's tail over your restored file and silently undo the restore. Start
  with the key (or current+previous keyring) that opens that snapshot. A wrong
  key makes normal startup refuse before serving data; restore the correct key
  rather than using the destructive key-mismatch override.
- **Schedule it.** `sudo ./deploy/systemd/install.sh` installs a daily backup
  timer, a weekly restore drill, retention (keep 7 daily / 4 weekly) and email
  alerting on failure, all driven by `/etc/trustissues/backup.env`. Hosts
  without systemd get the same two jobs from
  `deploy/cron/trustissues-backup.cron`. Run
  `sudo ./deploy/systemd/install.sh --test-alert` once: an unconfigured alerter
  is silent by design, so an untested one is indistinguishable from none.
- **Prove it restores.** `./scripts/restore-drill.sh /secure/backups` restores
  the newest snapshot into a throwaway directory and checks a known row survived.
  It also fails when the newest snapshot is too old, which is how a timer that
  stopped weeks ago gets noticed. A backup nobody has restored is a hypothesis.
- Keep the snapshots off the database's own disk. `backup.sh` refuses a
  destination inside the data directory and warns when the two share a
  filesystem. See `docs/BACKUP.md`.
- An in-process `trustissues backup` subcommand and off-host replication are
  still deferred (`DEFERRED.md` section (d)).

Database snapshots are for disaster recovery. The native vault export used to
move data between Trustissues instances is deliberately plaintext and needs a
different handling procedure; see `docs/PORTABILITY.md`.

### File permissions

The server enforces mode 0700 on `TRUSTISSUES_DATA_DIR` and mode 0600 on every
regular file inside it, including the database and WAL sidecars, at boot. Keep
the data directory on a non-shared host path anyway: filesystem permissions do
not protect against root, the container runtime, or a process running as the
service account.

## AI gateway and MCP (use AI while keeping secrets)

Trustissues can act as a safe boundary between your team and Claude/OpenAI so an
assistant or app gets the power of AI without ever holding a credential, and
without leaking PII to the model.

**AI gateway.** An admin points a provider at a stored key in Settings > AI &
MCP (each key is an `api_key` vault entry). Devs then aim their Anthropic or
OpenAI SDK at this instance instead of the provider:

- base URL `https://<your-host>/api/ai/anthropic` (or `/api/ai/openai`)
- authenticate with an API key from Settings > API keys (`X-API-Key` header)

Trustissues injects the team's provider key server-side (the dev never holds
it), tokenizes PII in the prompt through Shield before it egresses, resolves the
markers in the response, and logs attributed usage. Non-streaming only in v1
(`"stream": false`).

The gateway proxies **inference calls only**, and refuses anything else with
403 `route_not_allowed`. The call runs with the operator's provider account
rights, so an unscoped proxy let any caller delete objects, start fine-tunes or
create assistants on that account, and bill it for the privilege. Allowed:

| provider | allowed |
|----------|---------|
| anthropic | `POST /v1/messages`, `POST /v1/messages/count_tokens`, `POST /v1/complete`, `GET /v1/models`, `GET /v1/models/{id}` |
| openai | `POST /v1/chat/completions`, `POST /v1/responses`, `POST /v1/embeddings`, `POST /v1/moderations`, `POST /v1/completions`, `GET /v1/models`, `GET /v1/models/{id}` |

The same allowlist applies to the **capability bridge**: a token minted for a
vault entry that points at `api.openai.com` or `api.anthropic.com` can only spend
those routes through `/proxy/{host}/...` either. The team key is an ordinary
vault entry, usually kept in a collection, so both surfaces reach it and scoping
only one of them scopes nothing.

The path is fully decoded, then cleaned, then matched, and the matched string is
what gets forwarded, so `%2e%2e` and friends cannot walk out of an allowed
prefix. A model id may be one plain segment
(`[A-Za-z0-9._~:-]+`, e.g. `ft:gpt-4o-mini-2024-07-18:acme::9abc`).

Adding an endpoint is a deliberate edit to `providerInferenceRoutes` in
`internal/handlers/provider_routes.go`, never something a new provider API
inherits: a provider with no entry there is refused entirely.

**The provider key is pinned to its provider.** The allowlist above is keyed by
the provider's HOST, and the host a `/proxy` call reaches comes from the entry's
`destination_patterns`, which any accepted collection editor can edit. So
scoping the route alone left the destination open: rewrite the ceiling, mint,
and the operator's decrypted key is delivered in cleartext to a host of the
editor's choosing. An entry an admin has selected in **Settings > AI gateway** is
now pinned to that provider's API host, at mint, at `/proxy`, at the
`destination_patterns` write and on rotation delivery targets. The pin comes from
the admin-only setting plus the compile-time provider table, so nobody who can
edit the entry can move it. To repurpose such an entry, unwire it in Settings >
AI gateway first.

Separately, on **every** secret: anyone with write access may NARROW or clear the
agent destination list (clearing is how you revoke an agent), but ADDING a
destination takes the entry's creator or an instance admin. Editing an entry does
not carry the right to choose where its value is delivered.

Minting is not open to `vault_only` either. That role comes out of the public
invite endpoint and exists for the browser extension, so `/api/secrets/issue` and
`/api/mcp` refuse it, the same way `/api/ai/*` already did.

**MCP.** A remote MCP endpoint at `https://<your-host>/api/mcp` (JSON-RPC) that
Claude and ChatGPT connectors can add, authenticated with an API key
(`X-API-Key`). It exposes `list_secrets` (names only) and `use_secret` (mints a
single-use, destination-bound capability token so the assistant acts with a
secret it never sees, via `/proxy`). Tool results pass through Shield.

**Shield.** Set `TRUSTISSUES_SHIELD_KEY` (exactly 32 bytes) to turn on
LLM-boundary tokenization; leave it unset to pass data through unchanged. See
`THREAT-MODEL.md` for exactly what Shield does and does not protect.

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

If the redemption screen's one-time key is missed, the user mints another one
themselves: **Settings > API keys > Create**. The key is shown once and stored
only as a hash, so a lost key is replaced rather than recovered. This works for
every role, including `vault_only`, which is the role the extension is for.

> Previously the redemption UI discarded the returned `api_key`, and the router
> redirected `vault_only` users away from `/settings`, so the one role that needs
> an extension key could not reach the only UI that mints one. `POST /api/api-keys`
> always permitted their role; the block was entirely client-side. Fixed 2026-07-26.

## License

Trustissues Sustainable Use License (fair-code). Free to self-host and use
commercially for your own team; reselling it as a hosted service requires a
commercial license. See `LICENSE`.

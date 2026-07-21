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
| `TRUSTISSUES_PORT` | no | `8080` | HTTP listen port |
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

## License

Trustissues Sustainable Use License (fair-code). Free to self-host and use
commercially for your own team; reselling it as a hosted service requires a
commercial license. See `LICENSE`.

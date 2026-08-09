# Contributing to Trustissues

Thanks for helping improve Trustissues. Before anything else, please read
`SECURITY.md` and `THREAT-MODEL.md`. This project stores other people's API
keys, passwords and 2FA seeds, so "does it work" is only half of whether a
change is correct.

## Development setup

```bash
git clone https://github.com/bright-interaction/trustissues.git
cd trustissues
go build ./...
go test ./...
```

Go 1.22+ is required. SQLite is the default engine and there are no external
services to stand up. Migrations are embedded goose files in
`internal/database/migrations/` and run automatically at boot, so a fresh
checkout gets a working database on first start.

The frontend lives in `frontend/` (Vite + TypeScript). Use **bun**, not npm:
`Dockerfile` builds it with `oven/bun:1-alpine` and `bun install
--frozen-lockfile` against `bun.lock`, and installing with npm produces a
different tree from the one that ships.

```bash
cd frontend
bun install --frozen-lockfile
bun run dev      # vite dev server
bun run build    # tsc && vite build
bun run test     # vitest run
```

## Gates (run before every PR)

```bash
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

`staticcheck ./...` is encouraged; the repo ships `staticcheck.conf`. CI runs
the same gates.

## Database changes

Queries are generated, not hand-written. After editing
`internal/db/queries/*.sql` or the schema:

```bash
sqlc generate
```

Commit the regenerated files alongside the `.sql` change. Never hand-edit the
generated `*.sql.go` or `querier.go`: if they conflict during a merge, resolve
the `.sql` source and re-run `sqlc generate` rather than picking a side, or the
generated code silently freezes at one branch's view of the schema.

Schema changes need a new numbered migration in
`internal/database/migrations/`. Migrations are append-only; do not edit one
that has shipped.

## Code style

- Use `slog` for logging. Never log a secret, a token, a session cookie or a
  decrypted vault value, at any level.
- Return errors; do not panic in request paths.
- Parameterise SQL; never concatenate user input into a query.
- Prefer table-driven tests.
- No em dashes in code or prose.

## Security-sensitive changes

If your change touches the vault, encryption at rest (`internal/columncrypto`),
Shield (`internal/shield`, the PII and secret redactor), authentication, RBAC,
rotation providers, or any outbound request path, then:

1. Say so explicitly in the PR description.
2. Add a regression test that FAILS without your fix. A test that only passes
   after the change does not show the change was load-bearing.
3. For anything touching egress, state which hosts the code may now reach and
   why that set did not widen by accident. `DEFERRED.md` section (i) is a
   worked example of why this matters: adding a rotation delivery target is the
   same act as widening a destination pattern, and it was not gated as one.

Test fixtures that look like credentials are expected here, because a redactor
cannot be tested without them. Keep them obviously synthetic (spell the role
out in the value), and if a publish gate flags one, add it to
`scripts/mirror-secret-allowlist.txt` or `.gitleaks.toml` **by value with a
reason**. Never allowlist a credential prefix such as `sk_live_`: real keys
carry that prefix, and blinding the scanner to it in this repo of all repos
defeats the gate entirely.

## Reporting a vulnerability

Do not open a public issue. Email security@brightinteraction.com. See
`SECURITY.md`.

## License

Trustissues is fair-code under the Trustissues Sustainable Use License (see
`LICENSE`). By contributing you agree your contribution ships under it.

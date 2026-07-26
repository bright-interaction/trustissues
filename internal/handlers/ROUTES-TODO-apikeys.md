# Routes to wire: admin API-key incident response

Three handlers were added in `internal/handlers/apikeys.go` for FIX 1(d) and
they are not reachable until `cmd/server/main.go` wires them. `main.go` is owned
by another agent, so the exact lines are here instead of applied.

## Where

Inside the existing admin group in `cmd/server/main.go`:

```go
r.Route("/admin", func(r chi.Router) {
    r.Use(timw.AdminOnly())

    r.Route("/users", func(r chi.Router) {
        r.Get("/", userHandler.List)
        ...
```

Add these three lines to that `r.Route("/users", ...)` block, next to the
existing `/{id}/reset-password` route:

```go
			r.Get("/{id}/api-keys", apiKeyHandler.AdminList)
			r.Post("/{id}/api-keys/revoke-all", apiKeyHandler.AdminRevokeAll)
			r.Post("/{id}/api-keys/{keyId}/revoke", apiKeyHandler.AdminRevoke)
```

`apiKeyHandler` is already constructed at `main.go:169`, so no new wiring is
needed beyond these lines.

## Resulting surface

| Method | Path | Handler | Result |
|---|---|---|---|
| GET | `/api/admin/users/{id}/api-keys` | `AdminList` | 200 `[]apiKeyResponse` for that user, revoked keys included and marked via `revoked_at` |
| POST | `/api/admin/users/{id}/api-keys/revoke-all` | `AdminRevokeAll` | 204, every live key for that user revoked |
| POST | `/api/admin/users/{id}/api-keys/{keyId}/revoke` | `AdminRevoke` | 204, or 404 if the key does not belong to that user |

Notes:

- All three re-check `middleware.IsAdmin` internally, so they are safe even if
  the group middleware is ever changed. Wiring them under `timw.AdminOnly()` is
  still the intended placement.
- Revoke sets `revoked_at` instead of deleting, so the audit trail survives.
  `AdminRevoke` is idempotent: revoking an already-revoked key returns 204 and
  does not move the timestamp.
- The per-user routes at `/api/api-keys` are unchanged.

Delete this file once the routes are wired.

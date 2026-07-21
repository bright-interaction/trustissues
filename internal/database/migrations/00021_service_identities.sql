-- +goose Up
-- Service identities for sidecar fetch-on-boot (ported from dockyard's
-- 00070_service_identities.sql; single-team, no org concepts).
--
-- Each service running in production gets a dedicated, scope-limited
-- API key. The key authenticates the service to the trustissues vault,
-- and the service may fetch ONLY the secrets named in its
-- allowed_secrets whitelist. The service's entrypoint script writes the
-- fetched values to a tmpfs file (RAM-only, never disk), then execs the
-- actual service binary which reads the tmpfs as its .env.
--
-- Net: persistent .env files on the host contain only the service's
-- own trustissues service key. Real secrets exist on disk only inside
-- the encrypted vault. Process restarts re-fetch, transparently picking
-- up rotated values.

-- The identity row. One per service per host (e.g. "webapp-prod-host").
-- Distinguished from user api_keys (ti_) by the sk_ prefix on the key
-- value. Hashed with SHA-256 for storage to match the api_keys pattern.
CREATE TABLE IF NOT EXISTS service_identities (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,
    description        TEXT NOT NULL DEFAULT '',
    allowed_secrets    TEXT NOT NULL DEFAULT '[]',   -- JSON: ["VAULT_ENTRY_NAME", ...]
    key_hash           TEXT NOT NULL,
    key_prefix         TEXT NOT NULL,
    last_used_at       DATETIME,
    expires_at         DATETIME,
    revoked_at         DATETIME,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_user_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_service_identities_hash ON service_identities(key_hash);
CREATE INDEX IF NOT EXISTS idx_service_identities_name ON service_identities(name);

-- Per-fetch audit row. Records every fetch attempt (success, denied,
-- revoked) so the audit log can answer "which service pulled which
-- secrets and when" forever. Never stores the values; only references.
CREATE TABLE IF NOT EXISTS service_secret_audit (
    id                    TEXT PRIMARY KEY,
    service_identity_id   TEXT,                       -- NULL if unauthenticated request
    service_name          TEXT NOT NULL DEFAULT '',   -- denormalised for audit-after-delete
    event                 TEXT NOT NULL,              -- fetch | denied | revoked | invalid_key
    secret_names          TEXT NOT NULL DEFAULT '[]', -- JSON: secrets returned (success) or requested (denied)
    error                 TEXT NOT NULL DEFAULT '',
    remote_ip             TEXT NOT NULL DEFAULT '',
    occurred_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_service_secret_audit_identity ON service_secret_audit(service_identity_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_secret_audit_event ON service_secret_audit(event, occurred_at DESC);

-- +goose Down
DROP TABLE IF EXISTS service_secret_audit;
DROP TABLE IF EXISTS service_identities;

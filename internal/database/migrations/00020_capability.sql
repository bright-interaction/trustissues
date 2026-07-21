-- +goose Up
-- Capability bridge for the secrets vault (ported from dockyard's
-- 00069_capability_bridge.sql, orgs never applied here).
--
-- The AI agent never sees the raw secret. The bridge issues a short-
-- lived signed capability token bound to a specific destination, the
-- AI sends its outbound request through trustissues' substitution proxy
-- with the token, and the proxy resolves token -> secret -> injection
-- spec at the moment of forward. See internal/handlers/capability.go
-- for the threat model and architecture.
--
-- DEPENDS ON: vault_entries (created by the vault feature migration
-- 00010_vault.sql). That consolidated table ALREADY carries the two
-- bridge columns dockyard added in 00069 (destination_patterns TEXT
-- NOT NULL DEFAULT '[]' and injection_spec TEXT NOT NULL DEFAULT '{}'),
-- so this migration adds only the bridge's own tables.
--
-- Column semantics, for reference:
--   destination_patterns: JSON array of host+path globs the proxy may
--     auto-route to, e.g. '["api.cloudflare.com/*"]'. Empty array means
--     "no auto-route; require an explicit secret name". Per-entry so the
--     same vault can hold multiple Cloudflare tokens for different
--     zones (the patterns disambiguate).
--   injection_spec: JSON describing how to inject the decrypted secret
--     into the outbound request, e.g.
--     '{"type":"header","name":"Authorization","format":"Bearer {value}"}'.
--     Default '{}' means "no injection; reject auto-route requests".

-- Per-agent grants. An agent_id is whatever string the bridge
-- registered (e.g. "tom-laptop-claude-001"). Per (agent, secret) row;
-- presence = allowed. Empty table for a given agent_id = deny by
-- default. Composite PK keeps the lookup a single indexed read.
CREATE TABLE IF NOT EXISTS capability_grants (
    agent_id    TEXT NOT NULL,
    secret_id   TEXT NOT NULL REFERENCES vault_entries(id) ON DELETE CASCADE,
    granted_by  TEXT NOT NULL DEFAULT '',
    granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at  TEXT,
    notes       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (agent_id, secret_id)
);
CREATE INDEX IF NOT EXISTS idx_capability_grants_secret ON capability_grants(secret_id);

-- Per-issuance audit row. Every issued + every used + every denied
-- attempt. Never stores the secret value or the token bytes; just
-- references + outcomes so the audit log can answer "did this key
-- get used; from where; by what agent" forever.
CREATE TABLE IF NOT EXISTS capability_log (
    id           TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    secret_id    TEXT,
    secret_name  TEXT NOT NULL DEFAULT '',
    destination  TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT '',
    event        TEXT NOT NULL,  -- issued | used | denied | expired | replay
    status_code  INTEGER,         -- HTTP code from the upstream when event=used
    error        TEXT NOT NULL DEFAULT '',
    nonce        TEXT NOT NULL DEFAULT '',
    issued_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_capability_log_agent ON capability_log(agent_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_capability_log_secret ON capability_log(secret_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_capability_log_nonce ON capability_log(nonce);

-- Spent-nonce table for replay prevention. Each capability token
-- carries a fresh nonce; first use inserts the row, subsequent uses
-- collide on the PK and get rejected. Rows expire alongside the token
-- (5-min default), pruned by a periodic sweep.
CREATE TABLE IF NOT EXISTS capability_spent_nonces (
    nonce       TEXT PRIMARY KEY,
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capability_spent_nonces_expires ON capability_spent_nonces(expires_at);

-- +goose Down
DROP TABLE IF EXISTS capability_spent_nonces;
DROP TABLE IF EXISTS capability_log;
DROP TABLE IF EXISTS capability_grants;

-- +goose Up
-- Revocation flag for API keys. Revoking by flag rather than by DELETE keeps
-- the audit trail: after an incident you can still see which key existed, when
-- it was last used, and when it was cut off. The X-API-Key auth path rejects
-- any key whose revoked_at is set, so revocation takes effect on the next
-- request with no cache to invalidate.
--
-- Set on password change and on admin password reset (a stolen key must not
-- survive the incident-response action the account owner just took) and by the
-- admin revoke routes.
ALTER TABLE api_keys ADD COLUMN revoked_at DATETIME;

-- +goose Down
ALTER TABLE api_keys DROP COLUMN revoked_at;

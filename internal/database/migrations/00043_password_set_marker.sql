-- +goose Up
-- +goose StatementBegin
-- Whether a HUMAN ever set a password this account's owner could actually
-- supply, as opposed to a password minted by the server and immediately
-- discarded.
--
-- RedeemInvitation (internal/handlers/users.go) has a password-less path:
-- when the request carries no password (the shipped browser-extension
-- activation flow, bright-vault-extension/src/options/Options.tsx, POSTs
-- only {code}) it mints hex(rand 32) as the password, hashes it, and
-- discards the plaintext. Nobody, including the account's own owner, ever
-- learns it.
--
-- TOTPVerify -- the vault policy gate's SOLE exit from a 403 on every other
-- route once require_totp is on -- demanded that password from every
-- account. The reasoning (see the long comment at TOTPVerify) is sound for
-- an account a human actually chose a password for: the password is a
-- second factor a session/API-key thief does not have, so requiring it
-- stops that thief from enrolling 2FA and permanently locking the real
-- owner out. It is not sound here. For a password-less account the API key
-- IS the entire credential already; there is no second factor a thief could
-- lack, so demanding an unknowable password protects nobody and only made
-- enrolment permanently impossible the moment an admin turned require_totp
-- on. See ops/audits/trustissues-AUDIT-2026-08-24.md P0-2.
--
-- Defaults to 1 (set), so every EXISTING row keeps today's stricter
-- behaviour unconditionally across the deploy. Only the password-less
-- redemption branch writes a 0; every path that sets or changes a password
-- on behalf of a human (change-password, admin reset-password, and a
-- redemption that DID supply a password) writes it back to 1.
ALTER TABLE users
  ADD COLUMN password_set INTEGER NOT NULL DEFAULT 1
  CHECK (password_set IN (0, 1));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN password_set;
-- +goose StatementEnd

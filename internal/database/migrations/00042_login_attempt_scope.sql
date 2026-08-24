-- +goose Up
-- +goose StatementBegin
-- Which door recorded this failure, so that one door's failures cannot hold
-- another door shut.
--
-- login_attempts had one email-keyed counter and four readers: Login
-- (unauthenticated), TOTPVerify, TOTPDisable and the vault re-auth helper (all
-- three already authenticated). Anyone who knew an address could POST five wrong
-- passwords to the PUBLIC /api/auth/login and thereby refuse the real owner's
-- own TOTPVerify -- with a valid session, the correct password and a correct
-- live code -- because every reader counted every writer's rows.
--
-- On its own that was a nuisance. Once require_totp shipped it stopped being
-- one: the gate makes /api/auth/totp/verify the SOLE exit from a 403 on every
-- other route, so the same five-request spray holds an entire credential vault
-- shut, renewably, against a party with no credentials at all. Login enforces
-- the identical counter BEFORE the password check, so there is no log-in-again
-- self-heal, and no admin unlock endpoint exists.
--
-- Splitting the counter is what makes the authenticated doors un-sprayable: a
-- 'session_reauth' row can only be written by a request that already
-- authenticated AS that user, which is not something an outsider can supply.
-- 'password_login' rows stay attacker-writable by design -- that counter is the
-- password brute-force defence and is supposed to accrue from the public
-- endpoint -- but it now gates only the endpoint that produced it.
--
-- Existing rows become 'password_login': that keeps the login lockout's history
-- intact across the deploy (the strict direction) and starts the authenticated
-- doors clean (the direction that was the denial of service). Rows older than
-- 15 minutes are past every reader's window anyway, so the practical effect is
-- bounded by one lockout window.
--
-- The CHECK is defence in depth. Callers pass a db.LoginAttemptScope* constant,
-- so a typo is already a compile error; this makes it a write error too rather
-- than a row that silently counts toward nothing.
ALTER TABLE login_attempts
  ADD COLUMN scope TEXT NOT NULL DEFAULT 'password_login'
  CHECK (scope IN ('password_login', 'session_reauth'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE login_attempts DROP COLUMN scope;
-- +goose StatementEnd

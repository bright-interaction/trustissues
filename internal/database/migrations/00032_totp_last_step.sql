-- +goose Up
-- +goose StatementBegin
-- The last TOTP time step this user has successfully spent.
--
-- ValidateCode accepts the current step and the previous one (a 60s window) for clock
-- drift, and nothing recorded which step had been used. So a code observed once (a
-- real-time phishing relay, a code read aloud, a code pasted into a chat or typed on a
-- shared screen) was replayable for the rest of that window: the second factor degraded
-- from "proof of live possession of the device" to a 60-second bearer token, good for as
-- many sessions as the attacker wanted plus removing 2FA from the account.
--
-- Claiming the step monotonically makes each code single-use: a step less than or equal
-- to the last spent one is refused, which also correctly rejects a replay of the
-- drift-tolerance step.
ALTER TABLE users ADD COLUMN totp_last_step INTEGER;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN totp_last_step;
-- +goose StatementEnd

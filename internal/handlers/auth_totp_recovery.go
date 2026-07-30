package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"

	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/totp"
)

// recoveryCASAttempts bounds the retry. Contention is two logins for ONE account
// racing, so this converges immediately; the bound stops a pathological case spinning.
const recoveryCASAttempts = 4

// consumeRecoveryCode checks a recovery code and, if it matches, removes it under a
// compare-and-swap. It reports whether the code was valid AND durably spent.
//
// Consumption used to be a read-modify-write with a plain UPDATE, and the login
// continued even when the persist failed. Each recovery code is a standalone 64-bit
// 2FA bypass, so a code the user had already redeemed and crossed off their printed
// list stayed a working second factor. Two ways in: two concurrent logins each
// carrying a code, both reading before either writes; and a failed write that still
// completed the login.
//
// Returning false on a persist failure is the important half. A second factor that
// cannot be spent must not be accepted, because "accepted but not consumed" turns a
// single-use code into a permanent one.
func consumeRecoveryCode(ctx context.Context, q *db.Queries, userID, submitted string) bool {
	for attempt := 0; attempt < recoveryCASAttempts; attempt++ {
		state, err := q.GetUserTOTPState(ctx, userID)
		if err != nil {
			slog.Error("totp: read recovery codes failed", "user_id", userID, "error", err)
			return false
		}
		current := nullStringToString(state.TotpRecoveryCodes)

		var hashed []string
		if current != "" {
			if err := json.Unmarshal([]byte(current), &hashed); err != nil {
				slog.Error("totp: recovery codes are not valid JSON", "user_id", userID, "error", err)
				return false
			}
		}
		remaining, valid := totp.ValidateRecoveryCode(hashed, submitted)
		if !valid {
			return false
		}

		res, err := q.CASRecoveryCodes(ctx, db.CASRecoveryCodesParams{
			TotpRecoveryCodes:   sql.NullString{String: string(mustMarshalJSON(remaining)), Valid: true},
			ID:                  userID,
			TotpRecoveryCodes_2: sql.NullString{String: current, Valid: true},
		})
		if err != nil {
			slog.Error("totp: persisting the consumed recovery code failed", "user_id", userID, "error", err)
			return false
		}
		n, err := res.RowsAffected()
		if err != nil {
			slog.Error("totp: recovery code rows affected", "user_id", userID, "error", err)
			return false
		}
		if n > 0 {
			return true
		}
		// Someone else consumed a code between the read and the write. Re-read and
		// re-check: the submitted code may itself have been the one they spent.
		slog.Info("totp: recovery codes changed under us, retrying", "user_id", userID, "attempt", attempt+1)
	}
	slog.Error("totp: gave up consuming a recovery code after concurrent writes", "user_id", userID)
	return false
}

// spendTOTPStep validates a code AND consumes the time step it belongs to, so the
// same code cannot be used twice inside its own window.
//
// ValidateCode accepts the current step and the previous one for clock drift, and
// nothing recorded which step had been spent, so a code observed once (a real-time
// phishing relay, a code read aloud, a code pasted into a chat or typed on a shared
// screen) stayed valid for the rest of that window. The second factor degraded from
// proof of live possession to a 60-second bearer token: as many sessions as the
// attacker wanted, plus removing 2FA from the account.
//
// The claim is monotonic, so replaying the drift step is refused too. A failed claim
// means the step is already spent, which is a REPLAY and must be rejected: accepting a
// code we cannot mark as used is how the window stayed open.
func spendTOTPStep(ctx context.Context, q *db.Queries, userID, secret, code string) bool {
	step, ok := totp.ValidateCodeStep(secret, code)
	if !ok {
		return false
	}
	res, err := q.ClaimTOTPStep(ctx, db.ClaimTOTPStepParams{
		TotpLastStep:   sql.NullInt64{Int64: step, Valid: true},
		ID:             userID,
		TotpLastStep_2: sql.NullInt64{Int64: step, Valid: true},
	})
	if err != nil {
		slog.Error("totp: claiming the time step failed", "user_id", userID, "error", err)
		return false
	}
	n, err := res.RowsAffected()
	if err != nil {
		slog.Error("totp: step claim rows affected", "user_id", userID, "error", err)
		return false
	}
	if n == 0 {
		slog.Warn("totp: refused a replayed code (its time step was already spent)", "user_id", userID)
		return false
	}
	return true
}

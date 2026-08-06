package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
)

// The three tests in this file cover the authentication path itself: how a
// session is OBTAINED, as opposed to what one may reach once held. Nineteen
// audit rounds went at the authorization surface and every one of them skipped
// this, which round 14 recorded in its own "what is still unread" list and no
// later round picked up.

// TestTOTPVerifyLockoutGatesPasswordGuessing pins the ordering of the lockout
// check on POST /api/auth/totp/verify.
//
// The handler carries the comment "Rate limit TOTP verify attempts per user to
// prevent brute force", but the check sat AFTER the password verify's early
// return, so it could only ever be evaluated when the password was already
// correct. Against a password guesser it was unreachable code.
//
// That matters because of what this endpoint is for. Enrolling 2FA demands the
// password precisely so a stolen session cannot do it, and the endpoint is
// mounted under the ordinary /api limiter (500 requests per minute per IP), not
// the login limiter (30 per 15 minutes). So a session thief had a password
// oracle two orders of magnitude faster than /api/auth/login, with the account
// lockout switched off. Every wrong guess still wrote a login_attempts row, so
// the same spray locked the real owner out of the login page while the thief
// kept going.
//
// TOTPDisable checks the same counter in the correct order. One property, two
// doors, fixed at one of them.
func TestTOTPVerifyLockoutGatesPasswordGuessing(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	ctx := context.Background()

	// Guard the setup: if wrong passwords were not being counted at all, every
	// assertion below would be vacuous.
	before, err := queries.CountRecentFailedLoginAttemptsByEmail(ctx, "totp-user@example.com")
	if err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if before != 0 {
		t.Fatalf("ABORT: %d failed attempts already recorded", before)
	}

	guess := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		body := `{"code":"000000","password":"wrong-password-guess"}`
		ah.TOTPVerify(rec, withUser(
			httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))
		return rec
	}

	// Five wrong passwords is the documented lockout threshold.
	for i := 0; i < 5; i++ {
		if code := guess().Code; code != http.StatusUnauthorized {
			t.Fatalf("ABORT: guess %d answered %d, expected 401; the test is not exercising the guess path", i+1, code)
		}
	}

	n, err := queries.CountRecentFailedLoginAttemptsByEmail(ctx, "totp-user@example.com")
	if err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if n < 5 {
		t.Fatalf("ABORT: only %d attempts recorded after 5 wrong passwords, the lockout counter is not being fed", n)
	}

	// The sixth must be refused by the lockout, not answered as another
	// credential check. A 401 here means an attacker can keep guessing.
	if got := guess().Code; got != http.StatusTooManyRequests {
		t.Fatalf("the 6th wrong password answered %d, not 429.\n"+
			"The lockout check sits after the password verify's early return, so it never gates a "+
			"guesser: a stolen session can brute-force the password at the /api limit (500/min) with "+
			"no lockout, while the recorded failures lock the real owner out of /api/auth/login.", got)
	}
}

// TestRequireTOTPRefusalDoesNotBurnASecondFactor pins that a refused disable
// costs the user nothing.
//
// TOTPDisable consumed the TOTP time step or the recovery code FIRST and
// consulted the require_totp policy afterwards, so a user under the policy who
// tried to turn 2FA off got a 409 and permanently lost the factor they spent
// getting it. Recovery codes are the case that bites: there are eight, they are
// single-use, and no admin route exists to reissue them. Eight refused attempts
// and the account has no recovery path left, having never once succeeded at
// anything.
//
// TestRequireTOTPPolicyIsActuallyEnforced covers the policy, but only through
// settingBool; it never calls the handler, so this ordering was never exercised.
func TestRequireTOTPRefusalDoesNotBurnASecondFactor(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	ctx := context.Background()
	codes := mustEnable2FA(t, ah, queries, user)

	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "require_totp", Value: "true"}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	if !settingBool(ctx, queries, "require_totp", false) {
		t.Fatal("ABORT: policy did not persist, the refusal below would not happen")
	}

	disable := func(code string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		body := `{"password":"` + totpTestPassword + `","code":"` + code + `"}`
		ah.TOTPDisable(rec, withUser(
			httptest.NewRequest(http.MethodPost, "/api/auth/totp/disable", strings.NewReader(body)), user))
		return rec
	}

	if got := disable(codes[0]).Code; got != http.StatusConflict {
		t.Fatalf("ABORT: the policy did not refuse the disable (%d), so nothing below is being tested", got)
	}

	// The refusal must not have spent the code. Lift the policy and try the
	// SAME code again: it is the user's only remaining way off 2FA if their
	// authenticator is gone.
	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "require_totp", Value: "false"}); err != nil {
		t.Fatalf("clear policy: %v", err)
	}
	rec := disable(codes[0])
	if rec.Code != http.StatusOK {
		t.Fatalf("the recovery code was rejected (%d %s) after a refused disable consumed it.\n"+
			"A policy refusal must cost the user nothing: eight refusals under require_totp would "+
			"otherwise destroy every recovery code the account has, with no route to reissue them.",
			rec.Code, rec.Body.String())
	}
}

// TestLoginDoesNotRevealWhichEmailsHaveAccounts pins that the lockout treats a
// real address and an unknown one identically.
//
// Login deliberately verifies a dummy hash when the account does not exist, so
// response LATENCY cannot separate the two. That control was undone by the
// lockout sitting in front of it: the unknown-email path returned before
// recording anything, so its failure counter stayed at zero forever. Five wrong
// passwords at a real address produced 429 plus a two-then-four second delay;
// the same five at an unknown address produced a fast 401 every time. Status
// code alone gave a certain answer to "does this person have a vault account".
//
// It is deliberately structured to do no sleeping. Login's graduated delay fires
// at three recorded failures, so the accrual half stops at three probes, and the
// lockout half seeds both addresses to five and probes once: the `failCount >= 5`
// check returns before the sleep, so the boundary is reachable for free. Seeding
// is honest here only because the first half already proved the handler records
// for both; seeding alone would assume what is being tested. The earlier version
// of this test spent twelve seconds in time.Sleep, in a package that was already
// over ci-go's 600s -race ceiling.
func TestLoginDoesNotRevealWhichEmailsHaveAccounts(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ah := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
	})
	ctx := context.Background()

	const real = "enumeration-target@example.com"
	const ghost = "no-such-account@example.com"
	mustUser(t, queries, real, "user", totpTestPassword)

	// Distinct source addresses so the per-IP limit (20) cannot be what stops
	// either probe first; the property under test is the per-EMAIL counter.
	probe := func(email, ip string) int {
		rec := httptest.NewRecorder()
		body := `{"email":"` + email + `","password":"definitely-not-the-password"}`
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.RemoteAddr = ip + ":40000"
		ah.Login(rec, req)
		return rec.Code
	}

	// Half one: the handler must RECORD identically. Three probes each, which is
	// one below the graduated delay's threshold.
	var realCodes, ghostCodes []int
	for i := 0; i < 3; i++ {
		realCodes = append(realCodes, probe(real, "198.51.100.10"))
		ghostCodes = append(ghostCodes, probe(ghost, "198.51.100.20"))
	}
	for i := range realCodes {
		if realCodes[i] != ghostCodes[i] {
			t.Fatalf("probe %d: real account answered %d, unknown address answered %d (real=%v ghost=%v)",
				i+1, realCodes[i], ghostCodes[i], realCodes, ghostCodes)
		}
	}

	realN, err := queries.CountRecentFailedLoginAttemptsByEmail(ctx, real)
	if err != nil {
		t.Fatalf("count real: %v", err)
	}
	ghostN, err := queries.CountRecentFailedLoginAttemptsByEmail(ctx, ghost)
	if err != nil {
		t.Fatalf("count ghost: %v", err)
	}
	if realN != 3 {
		t.Fatalf("ABORT: the real address recorded %d of 3 attempts; the comparison below is vacuous", realN)
	}
	if ghostN != realN {
		t.Fatalf("after 3 identical probes the real address recorded %d failures and the unknown "+
			"address recorded %d.\n"+
			"An address that never accrues never locks out, so five wrong passwords answer 429 at a "+
			"real address and a fast 401 at an unknown one. That makes the status code a certain "+
			"account-existence oracle and defeats the dummy-hash timing equalization the same handler "+
			"goes to the trouble of doing.", realN, ghostN)
	}

	// Half two: at the lockout boundary the two must still answer alike. Seed
	// both to five (the >=5 branch returns before the graduated sleep, so this
	// costs nothing) and probe once each.
	for _, email := range []string{real, ghost} {
		if _, err := vh.db.ExecContext(ctx,
			`INSERT INTO login_attempts (email, ip_address, success)
			 VALUES (?, '203.0.113.9', 0), (?, '203.0.113.9', 0)`, email, email); err != nil {
			t.Fatalf("seed %s: %v", email, err)
		}
	}
	realLocked := probe(real, "198.51.100.11")
	ghostLocked := probe(ghost, "198.51.100.21")
	if realLocked != http.StatusTooManyRequests {
		t.Fatalf("ABORT: the real account answered %d at five failures instead of 429; the oracle "+
			"under test is absent and the comparison proves nothing", realLocked)
	}
	if ghostLocked != realLocked {
		t.Fatalf("at the lockout boundary the real address answered %d and the unknown address "+
			"answered %d; the status code still separates them", realLocked, ghostLocked)
	}
}

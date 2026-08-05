package handlers

import (
	"context"
	"encoding/json"
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
// This runs for roughly ten seconds: the graduated delay on attempts four and
// five is the behaviour under test, so it cannot be skipped.
func TestLoginDoesNotRevealWhichEmailsHaveAccounts(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ah := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
	})

	const real = "enumeration-target@example.com"
	const ghost = "no-such-account@example.com"
	mustUser(t, queries, real, "user", totpTestPassword)

	// Distinct source addresses so the per-IP limit (20) cannot be what stops
	// either probe first; the property under test is the per-EMAIL counter.
	probe := func(email, ip string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		body := `{"email":"` + email + `","password":"definitely-not-the-password"}`
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.RemoteAddr = ip + ":40000"
		ah.Login(rec, req)
		return rec
	}

	var realCodes, ghostCodes []int
	for i := 0; i < 6; i++ {
		realCodes = append(realCodes, probe(real, "198.51.100.10").Code)
		ghostCodes = append(ghostCodes, probe(ghost, "198.51.100.20").Code)
	}

	// Guard the setup: the real account must actually reach the lockout, or the
	// comparison proves nothing.
	if realCodes[5] != http.StatusTooManyRequests {
		t.Fatalf("ABORT: the real account answered %v and never locked out; the oracle under test is absent",
			realCodes)
	}

	for i := range realCodes {
		if realCodes[i] != ghostCodes[i] {
			t.Fatalf("probe %d: real account answered %d, unknown address answered %d.\n"+
				"real=%v ghost=%v\n"+
				"An unknown address never accrues a failed attempt, so it never locks out. That makes "+
				"the status code a certain account-existence oracle and defeats the dummy-hash timing "+
				"equalization the same handler goes to the trouble of doing.",
				i+1, realCodes[i], ghostCodes[i], realCodes, ghostCodes)
		}
	}

	// And the equalization must come from recording the attempt, not from
	// having quietly stopped locking real accounts out.
	n, err := queries.CountRecentFailedLoginAttemptsByEmail(context.Background(), ghost)
	if err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if n == 0 {
		t.Fatal("the unknown address recorded no failed attempts; the two paths agree only by accident")
	}

	// A real login must still work after all this, from a fresh address.
	var out authResponse
	rec := httptest.NewRecorder()
	body := `{"email":"` + real + `","password":"` + totpTestPassword + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.30:40000"
	ah.Login(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the target account to still be locked out (429), got %d", rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
}

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/totp"
)

// seedFailure writes a failed attempt directly, at a chosen scope. Driving five
// real Login requests instead would cost six seconds in the handler's graduated
// delay (2s at the fourth, 4s at the fifth), in a package the audit already
// flagged as close to ci-go's 600s -race ceiling. The handler's own writes are
// proven separately and cheaply by TestLoginFailuresAreRecordedAsPasswordLogin
// and TestEnrolmentFailuresAreRecordedAsSessionReauth below, so nothing here
// assumes what it is testing.
func seedFailure(t *testing.T, queries *db.Queries, email, scope string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := queries.CreateLoginAttempt(context.Background(), db.CreateLoginAttemptParams{
			Email: email, IpAddress: "203.0.113.7", Success: 0, Scope: scope,
		}); err != nil {
			t.Fatalf("seed %s attempt %d: %v", scope, i+1, err)
		}
	}
}

func liveCode(t *testing.T, queries *db.Queries, user string) string {
	t.Helper()
	secRow, err := queries.GetTOTPSecret(context.Background(), user)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	code, err := totp.GenerateCode(decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32)), time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	return code
}

// THE P0: a stranger must not be able to hold the require_totp gate's only exit shut.
//
// login_attempts had one email-keyed counter and four readers, three of them on
// already-authenticated endpoints. So five wrong passwords POSTed to the PUBLIC
// /api/auth/login, by a party with no credentials who merely knows the address,
// refused the owner's own TOTPVerify -- with a valid session, the correct
// password and a correct live code.
//
// Before require_totp that was a nuisance. After it, TOTPVerify is the SOLE exit
// from a 403 on every other route, so the same five requests hold an entire
// credential vault shut. There is no self-heal: Login enforces the identical
// counter BEFORE the password check, so logging in again cannot clear it, and no
// admin unlock endpoint exists. Against the single-admin production deployment
// that is a total, renewable, unauthenticated product outage.
func TestPublicLoginSprayCannotCloseTheEnrolmentExit(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	const victim = "totp-user@example.com"

	// The attacker's spray: failures at the public login door, and only there.
	seedFailure(t, queries, victim, db.LoginAttemptScopePasswordLogin, 5)

	// Guard the setup. If these rows did not actually trip the login lockout,
	// the assertion below would pass against a counter that reads nothing at all
	// and would prove precisely nothing.
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"email":"`+victim+`","password":"`+totpTestPassword+`"}`))
	loginReq.RemoteAddr = "198.51.100.99:40000"
	ah.Login(loginRec, loginReq)
	if loginRec.Code != http.StatusTooManyRequests {
		t.Fatalf("ABORT: after 5 seeded password_login failures the login endpoint answered %d, "+
			"expected 429. The seeded rows are not reaching the login lockout, so this test "+
			"cannot demonstrate anything about the enrolment exit.", loginRec.Code)
	}

	// Now the property. The victim holds a live session, knows their password and
	// has a correct live code. Enrolment is the only way out of the gate.
	setupRec := httptest.NewRecorder()
	ah.TOTPSetup(setupRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), user))
	if setupRec.Code != http.StatusOK {
		t.Fatalf("ABORT: setup answered %d %s", setupRec.Code, setupRec.Body.String())
	}

	rec := httptest.NewRecorder()
	body := `{"code":"` + liveCode(t, queries, user) + `","password":"` + totpTestPassword + `"}`
	ah.TOTPVerify(rec, withUser(
		httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))

	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("a stranger who knows the address closed the gate's only exit: 5 wrong passwords "+
			"at the PUBLIC login endpoint refused the owner's own enrolment (429 %s).\n"+
			"Under require_totp every other route answers 403 and this is the one way out, so the "+
			"vault is held shut, renewably, by a party with no credentials -- and Login enforces "+
			"the same counter before the password check, so there is no way to clear it.",
			rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("enrolment answered %d %s, expected 200", rec.Code, rec.Body.String())
	}
}

// The complement of the P0 fix: splitting the counter must not disarm the
// brute-force defence it was protecting. A caller who is already authenticated
// as this user still gets exactly five wrong passwords at the enrolment door.
func TestSessionReauthSprayStillLocksTheEnrolmentDoor(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)

	seedFailure(t, queries, "totp-user@example.com", db.LoginAttemptScopeSessionReauth, 5)

	rec := httptest.NewRecorder()
	body := `{"code":"000000","password":"` + totpTestPassword + `"}`
	ah.TOTPVerify(rec, withUser(
		httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after 5 session_reauth failures the enrolment door answered %d, expected 429.\n"+
			"Scoping the counter must not switch the lockout off: a stolen session would then have "+
			"an unthrottled password oracle.", rec.Code)
	}
}

// The other direction, which the old shared counter also got wrong: password
// guesses made THROUGH a stolen session must not lock the real owner out of the
// login page. The thief kept guessing while the owner was refused at the door.
func TestSessionReauthFailuresDoNotLockTheLoginPage(t *testing.T) {
	ah, _, queries, _ := newTOTPEnv(t)
	const victim = "totp-user@example.com"

	seedFailure(t, queries, victim, db.LoginAttemptScopeSessionReauth, 5)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"email":"`+victim+`","password":"`+totpTestPassword+`"}`))
	req.RemoteAddr = "198.51.100.98:40000"
	ah.Login(rec, req)

	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("5 failures made through an authenticated session locked the owner out of the " +
			"login page; the two doors still hold each other shut")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("login with the correct password answered %d %s, expected 200", rec.Code, rec.Body.String())
	}
}

// The seeding above is only honest if the handlers really do write these scopes.
// Two cheap real requests, one per door, pin that. Both stay under the graduated
// delay's threshold, so neither sleeps.
func TestLoginFailuresAreRecordedAsPasswordLogin(t *testing.T) {
	ah, _, queries, _ := newTOTPEnv(t)
	const victim = "totp-user@example.com"
	ctx := context.Background()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"email":"`+victim+`","password":"wrong-password-entirely"}`))
	req.RemoteAddr = "198.51.100.97:40000"
	ah.Login(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ABORT: wrong password answered %d, expected 401", rec.Code)
	}

	pw, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: victim, Scope: db.LoginAttemptScopePasswordLogin,
		})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if pw != 1 {
		t.Fatalf("a failed login recorded %d password_login rows, expected 1", pw)
	}

	sr, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: victim, Scope: db.LoginAttemptScopeSessionReauth,
		})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if sr != 0 {
		t.Fatalf("a failed PUBLIC login wrote %d session_reauth rows; that is the P0 -- an "+
			"outsider must not be able to feed the counter that gates the gate's only exit", sr)
	}
}

func TestEnrolmentFailuresAreRecordedAsSessionReauth(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	const victim = "totp-user@example.com"
	ctx := context.Background()

	rec := httptest.NewRecorder()
	body := `{"code":"000000","password":"wrong-password-entirely"}`
	ah.TOTPVerify(rec, withUser(
		httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ABORT: wrong password at enrolment answered %d, expected 401", rec.Code)
	}

	sr, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: victim, Scope: db.LoginAttemptScopeSessionReauth,
		})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if sr != 1 {
		t.Fatalf("a failed enrolment recorded %d session_reauth rows, expected 1; the door's own "+
			"lockout is not being fed", sr)
	}

	pw, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: victim, Scope: db.LoginAttemptScopePasswordLogin,
		})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if pw != 0 {
		t.Fatalf("a failed enrolment wrote %d password_login rows; guesses through a session must "+
			"not lock the owner out of the login page", pw)
	}
}

// A missing Scope is the fail-open this split introduced, and the compiler does
// NOT catch it: CreateLoginAttemptParams is a struct literal, so an omitted
// field is the empty string, which the CHECK in migration 00042 refuses. The
// insert then errors, the caller logs and continues, and the failure is never
// counted -- a silently disarmed lockout, which is strictly worse than the bug
// this whole change is fixing.
//
// So this asserts the COMPLEMENT: not "some call site passes a scope" (a decoy
// satisfies that), but "no literal anywhere omits one".
func TestEveryLoginAttemptWriteNamesAScope(t *testing.T) {
	const root = "../.."
	const marker = "CreateLoginAttemptParams{"

	var checked int
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "node_modules" || name == "frontend" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(body)
		for idx := 0; ; {
			i := strings.Index(src[idx:], marker)
			if i < 0 {
				break
			}
			start := idx + i + len(marker)
			// Walk to the matching close brace so the check reads exactly this
			// literal and cannot be satisfied by a neighbouring one.
			depth, end := 1, -1
			for j := start; j < len(src); j++ {
				switch src[j] {
				case '{':
					depth++
				case '}':
					depth--
					if depth == 0 {
						end = j
					}
				}
				if end >= 0 {
					break
				}
			}
			if end < 0 {
				t.Fatalf("%s: unbalanced %s literal at offset %d", path, marker, start)
			}
			checked++
			if !strings.Contains(src[start:end], "Scope:") {
				line := 1 + strings.Count(src[:start], "\n")
				t.Errorf("%s:%d: a CreateLoginAttemptParams literal does not set Scope.\n"+
					"It would insert the empty string, the CHECK in migration 00042 would refuse "+
					"the row, and the failure would go uncounted -- the lockout at that door is "+
					"then silently off.", path, line)
			}
			idx = end
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// Vacuity guard. If the walk found no literals the test would pass against a
	// tree that had stopped recording login attempts entirely.
	if checked == 0 {
		t.Fatal("ABORT: found zero CreateLoginAttemptParams literals; this guard is looking in " +
			"the wrong place and would pass against anything")
	}
	t.Logf("checked %d CreateLoginAttemptParams literals", checked)
}

// And the CHECK the guard above relies on must actually be live in the schema
// the tests run against, or that guard is protecting against nothing.
func TestUnknownLoginAttemptScopeIsRefused(t *testing.T) {
	vh, _ := newCollectionAuthzEnv(t)
	_, err := vh.db.ExecContext(context.Background(),
		`INSERT INTO login_attempts (email, ip_address, success, scope) VALUES (?, ?, 0, ?)`,
		"check@example.com", "203.0.113.9", "not_a_real_scope")
	if err == nil {
		t.Fatal("the database accepted an unknown login_attempts.scope; the CHECK from migration " +
			"00042 is not present, so a typo'd scope would silently count toward nothing")
	}
	if !strings.Contains(err.Error(), "CHECK") {
		t.Fatalf("insert failed, but not on the CHECK constraint: %v", err)
	}
}

// The FOURTH door, and the one the original report was named after: an
// unauthenticated stranger who knows your address must not be able to freeze an
// already-logged-in session's reveals.
//
// vault re-auth (unlock, rotate, validate, retry-pending-revoke) read the same
// shared counter, so five wrong passwords at the public login endpoint refused
// the owner's own unlock while they were sitting in the product with a valid
// session and the correct password.
func TestPublicLoginSprayCannotFreezeVaultReauth(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	const password = "reauth-scope-password"
	const victim = "reauth-scope-victim@example.com"
	owner := mustUser(t, queries, victim, "user", password)

	// The attacker's spray, at the public login door and only there.
	seedFailure(t, queries, victim, db.LoginAttemptScopePasswordLogin, 5)

	rec := httptest.NewRecorder()
	h.Unlock(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/unlock", owner, "user", "",
		`{"password":`+quote(password)+`}`))

	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("5 wrong passwords at the PUBLIC login endpoint froze the owner's vault re-auth "+
			"(429 %s).\nAn unauthenticated stranger who knows the address can hold an "+
			"already-logged-in session's reveals shut, renewably.", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("unlock with the correct password answered %d %s, expected 200", rec.Code, rec.Body.String())
	}
}

// The complement: re-auth keeps its own brute-force lockout, so a stolen session
// still cannot grind the account password through unlock.
func TestSessionReauthSprayStillLocksVaultReauth(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	const password = "reauth-scope-password-2"
	const victim = "reauth-scope-victim2@example.com"
	owner := mustUser(t, queries, victim, "user", password)

	seedFailure(t, queries, victim, db.LoginAttemptScopeSessionReauth, 5)

	rec := httptest.NewRecorder()
	h.Unlock(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/unlock", owner, "user", "",
		`{"password":`+quote(password)+`}`))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after 5 session_reauth failures unlock answered %d, expected 429; scoping the "+
			"counter must not disarm the re-auth lockout", rec.Code)
	}
}

// And re-auth failures must land in session_reauth, or the door above is gated by
// a counter nothing feeds.
func TestVaultReauthFailuresAreRecordedAsSessionReauth(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const password = "reauth-scope-password-3"
	const victim = "reauth-scope-victim3@example.com"
	owner := mustUser(t, queries, victim, "user", password)

	rec := httptest.NewRecorder()
	h.Unlock(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/unlock", owner, "user", "",
		`{"password":`+quote("entirely-the-wrong-password")+`}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ABORT: wrong re-auth password answered %d, expected 403", rec.Code)
	}

	sr, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: victim, Scope: db.LoginAttemptScopeSessionReauth,
		})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if sr != 1 {
		t.Fatalf("a failed re-auth recorded %d session_reauth rows, expected 1", sr)
	}

	pw, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: victim, Scope: db.LoginAttemptScopePasswordLogin,
		})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if pw != 0 {
		t.Fatalf("a failed re-auth wrote %d password_login rows; a stolen session must not lock "+
			"the owner out of the login page", pw)
	}
}

// ---------------------------------------------------------------------------
// Findings P1-2 .. P1-7 from the 2026-08-24 crew audit.
//
// Every test above asserted that the SPLIT works: rows land in the right scope
// and each door reads its own. None of them pinned the NUMBERS. The audit
// mutated the shared 15-minute window to `-1 seconds` and `-60 minutes`, and the
// `>= 5` threshold to `>= 1`, and the whole suite stayed green -- so the lockout
// could be switched off at a realistic request cadence, or tightened until one
// mistyped password freezes a vault, with nothing failing.
//
// A guard that proves rows are counted, without proving WHICH rows or HOW MANY,
// is only half a guard.
// ---------------------------------------------------------------------------

// seedFailureAt writes a failure with an explicit age, which the sqlc query
// cannot express (created_at is DEFAULT CURRENT_TIMESTAMP).
func seedFailureAt(t *testing.T, h *VaultHandler, email, scope string, minutesAgo int) {
	t.Helper()
	_, err := h.db.ExecContext(context.Background(),
		`INSERT INTO login_attempts (email, ip_address, success, scope, created_at)
		 VALUES (?, ?, 0, ?, datetime('now', ?))`,
		email, "203.0.113.8", scope, fmt.Sprintf("-%d minutes", minutesAgo))
	if err != nil {
		t.Fatalf("seed aged attempt: %v", err)
	}
}

// The window is 15 minutes, pinned from BOTH sides.
//
// Only one direction was pinned before, and only implicitly: fresh rows count.
// That is satisfied by a window of an hour, or of a second -- `-1 seconds`
// survived every test, and at a realistic cadence (attempts seconds apart) the
// counter then reads 1 forever and the lockout is off while CI stays green.
func TestTheLockoutWindowIsFifteenMinutesInBothDirections(t *testing.T) {
	_, vh, queries, _ := newTOTPEnv(t)
	ctx := context.Background()
	const victim = "window-pin@example.com"

	count := func() int64 {
		n, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
			db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
				Email: victim, Scope: db.LoginAttemptScopePasswordLogin,
			})
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	// Inside the window, and old enough that a too-SHORT window (seconds, or a
	// minute) would already have dropped it.
	seedFailureAt(t, vh, victim, db.LoginAttemptScopePasswordLogin, 14)
	if n := count(); n != 1 {
		t.Fatalf("a failure 14 minutes old counted %d, expected 1.\n"+
			"The window is shorter than the documented 15 minutes, so attempts spaced out "+
			"even slightly never accumulate and the lockout never trips.", n)
	}

	// Outside it, and only just: a too-LONG window would still be counting this.
	seedFailureAt(t, vh, victim, db.LoginAttemptScopePasswordLogin, 16)
	if n := count(); n != 1 {
		t.Fatalf("a failure 16 minutes old still counted (total %d, expected 1).\n"+
			"The window is longer than 15 minutes, so a lockout outlives its documented "+
			"duration and the retention sweep's contract no longer covers every reader.", n)
	}

	// And far outside, to catch a window measured in hours or days.
	seedFailureAt(t, vh, victim, db.LoginAttemptScopePasswordLogin, 24*60)
	if n := count(); n != 1 {
		t.Fatalf("a day-old failure is still being counted (total %d, expected 1)", n)
	}
}

// Five, not one, and not six. Pinned at EVERY door.
//
// `>= 5` -> `>= 1` survived at vault re-auth and at TOTPDisable: one mistyped
// password would freeze a vault for fifteen minutes with no test failing. The
// four-failure case is the half that catches an over-tightened threshold; the
// five-failure case is the half that catches a disabled one.
func TestTheLockoutThresholdIsFiveAtEveryDoor(t *testing.T) {
	// Each door is exercised on a FRESH environment, so a seeded count cannot
	// leak from one door's probe into the next and make a dead lockout look live.

	// --- door 1: TOTPVerify ---
	verifyAt := func(t *testing.T, failures int) int {
		t.Helper()
		ah, _, queries, user := newTOTPEnv(t)
		seedFailure(t, queries, "totp-user@example.com", db.LoginAttemptScopeSessionReauth, failures)
		rec := httptest.NewRecorder()
		ah.TOTPSetup(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), user))
		if rec.Code != http.StatusOK {
			t.Fatalf("ABORT: setup %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		body := `{"code":"` + liveCode(t, queries, user) + `","password":"` + totpTestPassword + `"}`
		ah.TOTPVerify(rec, withUser(
			httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))
		return rec.Code
	}
	if got := verifyAt(t, 4); got == http.StatusTooManyRequests {
		t.Error("totp/verify: FOUR failures already locked the door. The threshold is below the " +
			"documented five, so a user who fumbles their password a few times loses the only " +
			"exit from the gate.")
	}
	if got := verifyAt(t, 5); got != http.StatusTooManyRequests {
		t.Errorf("totp/verify: five failures answered %d, expected 429. The lockout is not "+
			"tripping, so a stolen session has an unthrottled password oracle.", got)
	}

	// --- door 2: TOTPDisable (P1-2: previously zero lockout coverage) ---
	disableAt := func(t *testing.T, failures int) int {
		t.Helper()
		ah, _, queries, user := newTOTPEnv(t)
		codes := mustEnable2FA(t, ah, queries, user)
		seedFailure(t, queries, "totp-user@example.com", db.LoginAttemptScopeSessionReauth, failures)
		rec := httptest.NewRecorder()
		body := `{"password":"` + totpTestPassword + `","code":"` + codes[0] + `"}`
		ah.TOTPDisable(rec, withUser(
			httptest.NewRequest(http.MethodPost, "/api/auth/totp/disable", strings.NewReader(body)), user))
		return rec.Code
	}
	if got := disableAt(t, 4); got == http.StatusTooManyRequests {
		t.Error("totp/disable: FOUR failures already locked the door")
	}
	if got := disableAt(t, 5); got != http.StatusTooManyRequests {
		t.Errorf("totp/disable: five failures answered %d, expected 429. This door had NO lockout "+
			"coverage at all: six separate mutations, including deleting the whole block, "+
			"survived the suite.", got)
	}

	// --- door 3: vault re-auth ---
	unlockAt := func(t *testing.T, failures int) int {
		t.Helper()
		h, queries := newCollectionAuthzEnv(t)
		const pw = "threshold-probe-password"
		email := fmt.Sprintf("threshold-%d@example.com", failures)
		owner := mustUser(t, queries, email, "user", pw)
		seedFailure(t, queries, email, db.LoginAttemptScopeSessionReauth, failures)
		rec := httptest.NewRecorder()
		h.Unlock(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/unlock", owner, "user", "",
			`{"password":`+quote(pw)+`}`))
		return rec.Code
	}
	if got := unlockAt(t, 4); got == http.StatusTooManyRequests {
		t.Error("vault re-auth: FOUR failures already locked the vault. One mistyped password " +
			"away from freezing a credential vault for fifteen minutes.")
	}
	if got := unlockAt(t, 5); got != http.StatusTooManyRequests {
		t.Errorf("vault re-auth: five failures answered %d, expected 429", got)
	}

	// --- door 4: login ---
	loginAt := func(t *testing.T, failures int) int {
		t.Helper()
		ah, _, queries, _ := newTOTPEnv(t)
		seedFailure(t, queries, "totp-user@example.com", db.LoginAttemptScopePasswordLogin, failures)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
			strings.NewReader(`{"email":"totp-user@example.com","password":"`+totpTestPassword+`"}`))
		req.RemoteAddr = "198.51.100.55:40000"
		ah.Login(rec, req)
		return rec.Code
	}
	if got := loginAt(t, 4); got == http.StatusTooManyRequests {
		t.Error("login: FOUR failures already locked the account")
	}
	if got := loginAt(t, 5); got != http.StatusTooManyRequests {
		t.Errorf("login: five failures answered %d, expected 429", got)
	}
}

// P1-5: TOTPVerify's WRONG-CODE branch was never executed.
//
// The existing test sends a wrong password, which returns at the password check
// above -- so the code-failure write at auth.go:899 was unreached, and deleting
// it changed nothing observable. A wrong code with the CORRECT password is the
// only way into that branch.
func TestAWrongTOTPCodeIsRecordedAsSessionReauth(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	ctx := context.Background()
	const victim = "totp-user@example.com"

	rec := httptest.NewRecorder()
	ah.TOTPSetup(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), user))
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: setup %d", rec.Code)
	}

	// Correct password, wrong code: past the password check, into the code check.
	rec = httptest.NewRecorder()
	body := `{"code":"000000","password":"` + totpTestPassword + `"}`
	ah.TOTPVerify(rec, withUser(
		httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ABORT: correct password + wrong code answered %d, expected 401. If this is 200 "+
			"the code check is not running at all.", rec.Code)
	}

	n, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
		db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{
			Email: victim, Scope: db.LoginAttemptScopeSessionReauth,
		})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("a wrong TOTP code recorded %d session_reauth rows, expected 1.\n"+
			"Then code guessing is unthrottled: only wrong PASSWORDS feed the lockout, and "+
			"a six-digit code is the cheaper thing to guess.", n)
	}
}

// P1-6: the source guard accepts `Scope: ""`, which the CHECK then refuses.
//
// TestEveryLoginAttemptWriteNamesAScope asks whether the literal mentions the
// field. An explicit empty string satisfies that and still produces the exact
// fail-open the guard exists to prevent: the insert errors, the caller logs and
// continues, and that door's lockout silently stops accruing. So the write side
// is pinned behaviourally too -- every scope constant must actually round-trip
// into a row the matching reader sees.
func TestEveryScopeConstantRoundTripsIntoItsOwnCounter(t *testing.T) {
	_, _, queries, _ := newTOTPEnv(t)
	ctx := context.Background()

	scopes := []string{db.LoginAttemptScopePasswordLogin, db.LoginAttemptScopeSessionReauth}
	for _, scope := range scopes {
		email := "roundtrip-" + scope + "@example.com"
		if err := queries.CreateLoginAttempt(ctx, db.CreateLoginAttemptParams{
			Email: email, IpAddress: "203.0.113.10", Success: 0, Scope: scope,
		}); err != nil {
			t.Fatalf("scope %q is not accepted by the database: %v.\n"+
				"A constant the CHECK refuses means every write at that door is dropped and "+
				"its lockout is off.", scope, err)
		}
		n, err := queries.CountRecentFailedLoginAttemptsByEmailAndScope(ctx,
			db.CountRecentFailedLoginAttemptsByEmailAndScopeParams{Email: email, Scope: scope})
		if err != nil {
			t.Fatalf("count %q: %v", scope, err)
		}
		if n != 1 {
			t.Fatalf("a row written at scope %q was not visible to the reader for that scope "+
				"(count %d)", scope, n)
		}
	}

	// And the empty string -- what an omitted or blanked field produces -- must
	// be refused by the database rather than silently stored.
	err := queries.CreateLoginAttempt(ctx, db.CreateLoginAttemptParams{
		Email: "empty-scope@example.com", IpAddress: "203.0.113.11", Success: 0, Scope: "",
	})
	if err == nil {
		t.Fatal("the database accepted an EMPTY scope. Then a writer that omits or blanks the " +
			"field stores a row no reader counts, and that door's lockout is silently off.")
	}
}

// P1-7: only the un-enrolled arm of the login flag was tested.
//
// Dropping `!totpEnabled &&` from the expression survived the whole suite: every
// user, enrolled or not, would be told to enrol, and the banner would never go
// away for anyone.
func TestLoginDoesNotFlagAnAlreadyEnrolledUser(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	mustEnable2FA(t, ah, queries, user)

	if err := queries.UpsertSetting(t.Context(), db.UpsertSettingParams{
		Key: "require_totp", Value: "true",
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// An enrolled user's login needs the second factor, so drive it the same way
	// a browser would: the code comes from the live secret.
	rec := httptest.NewRecorder()
	body := `{"email":"totp-user@example.com","password":"` + totpTestPassword +
		`","totp_code":"` + liveCode(t, queries, user) + `"}`
	ah.Login(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: enrolled login answered %d %s", rec.Code, rec.Body.String())
	}

	var out struct {
		User struct {
			TOTPEnrollmentRequired bool `json:"totp_enrollment_required"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.User.TOTPEnrollmentRequired {
		t.Fatal("an ENROLLED user's login response says enrolment is still required.\n" +
			"The banner then never goes away for anyone, and it stops meaning anything.")
	}
}

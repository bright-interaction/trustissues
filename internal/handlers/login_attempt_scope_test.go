package handlers

import (
	"context"
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

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/passwordhash"
	"github.com/bright-interaction/trustissues/internal/totp"
)

const totpTestPassword = "CorrectHorseBatteryStaple1!"

func newTOTPEnv(t *testing.T) (*AuthHandler, *VaultHandler, *db.Queries, string) {
	t.Helper()
	vh, queries := newCollectionAuthzEnv(t)
	ah := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
	})
	user := mustUser(t, queries, "totp-user@example.com", "user", totpTestPassword)
	return ah, vh, queries, user
}

func withUser(r *http.Request, userID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), middleware.UserIDKey, userID))
}

// Enabling 2FA must require the PASSWORD, not merely a session.
//
// Enrolment used to need only a live session or API key, and turning 2FA on is
// irreversible by the owner: afterwards login demands a code they do not have,
// TOTPDisable demands a live code they cannot produce, the recovery codes were returned
// to whoever enrolled, and NO admin route exists to reset another user's 2FA.
//
// So anyone holding a stolen session, or the vault_only extension API key handed out by
// the PUBLIC invite-redemption endpoint, could permanently lock the owner out of their
// own vault without ever learning the password. Disabling already required the password;
// enabling did not, and that asymmetry was the whole vector.
func TestEnabling2FARequiresThePassword(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)

	// Setup is fine with a session: it only mints a secret, it does not enable.
	setupRec := httptest.NewRecorder()
	ah.TOTPSetup(setupRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), user))
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", setupRec.Code, setupRec.Body.String())
	}

	secRow, err := queries.GetTOTPSecret(context.Background(), user)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	secret := decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	// THE VECTOR: a valid code and a live session, but no password.
	rec := httptest.NewRecorder()
	body := `{"code":"` + code + `"}`
	ah.TOTPVerify(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))
	if rec.Code == http.StatusOK {
		t.Fatalf("2FA was enabled with a session alone and no password (%d %s).\n"+
			"That permanently locks the owner out: they cannot log in without a code, cannot "+
			"disable without a live code, never saw the recovery codes, and no admin can reset it.",
			rec.Code, rec.Body.String())
	}

	state, _ := queries.GetUserTOTPState(context.Background(), user)
	if nullInt64Is1(state.TotpEnabled) {
		t.Fatal("2FA is enabled on the account despite the request being refused")
	}

	// And with the password it must still work, or the fix has broken enrolment.
	rec2 := httptest.NewRecorder()
	body2 := `{"code":"` + code + `","password":"` + totpTestPassword + `"}`
	ah.TOTPVerify(rec2, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body2)), user))
	if rec2.Code != http.StatusOK {
		t.Fatalf("enrolment with the correct password was refused (%d %s); the fix must not make "+
			"2FA impossible to turn on", rec2.Code, rec2.Body.String())
	}
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &out)
	if len(out.RecoveryCodes) == 0 {
		t.Error("enrolment returned no recovery codes")
	}
}

// A recovery code must be able to REMOVE 2FA, not just buy another login.
//
// TOTPDisable accepted only a live authenticator code, so a user who lost their device
// could log in 8 times with recovery codes and never turn 2FA off. After the eighth the
// account was permanently unauthenticatable, and no admin route exists to reset it. The
// advertised recovery mechanism recovered nothing.
func TestARecoveryCodeCanRemove2FA(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	codes := mustEnable2FA(t, ah, queries, user)

	// The authenticator is gone: the user has only a recovery code and the password.
	rec := httptest.NewRecorder()
	body := `{"password":"` + totpTestPassword + `","code":"` + codes[0] + `"}`
	ah.TOTPDisable(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/disable", strings.NewReader(body)), user))
	if rec.Code != http.StatusOK {
		t.Fatalf("a recovery code could not remove 2FA (%d %s).\n"+
			"Then recovery codes buy 8 logins and nothing else, and the account is permanently "+
			"unauthenticatable once they run out.", rec.Code, rec.Body.String())
	}
	state, _ := queries.GetUserTOTPState(context.Background(), user)
	if nullInt64Is1(state.TotpEnabled) {
		t.Error("the request succeeded but 2FA is still enabled")
	}
}

// A recovery code is single use, even under concurrency.
//
// Consumption was a read-modify-write with a plain UPDATE, and the login continued even
// when the persist failed. Each code is a standalone 64-bit 2FA bypass, so a code the
// user had already redeemed and crossed off their printed list stayed a working second
// factor.
func TestARecoveryCodeIsSpentExactlyOnce(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	codes := mustEnable2FA(t, ah, queries, user)
	target := codes[0]

	const n = 6
	var wg sync.WaitGroup
	accepted := make([]bool, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			accepted[i] = consumeRecoveryCode(context.Background(), queries, user, target)
		}(i)
	}
	close(start)
	wg.Wait()

	got := 0
	for _, a := range accepted {
		if a {
			got++
		}
	}
	if got != 1 {
		t.Errorf("one recovery code was accepted %d times across %d concurrent attempts, want exactly 1.\n"+
			"Each accepted use is a full 2FA bypass, so a code the user believes is spent stays live.", got, n)
	}

	// And it must be gone afterwards.
	if consumeRecoveryCode(context.Background(), queries, user, target) {
		t.Error("the same recovery code was accepted again after being spent")
	}
}

// A TOTP code cannot be replayed inside its own window.
//
// ValidateCode accepts the current step and the previous one for clock drift, and
// nothing recorded which step had been spent, so an observed code stayed valid for the
// rest of that window: the second factor became a 60-second bearer token, good for as
// many sessions as an attacker wanted plus removing 2FA.
func TestATOTPCodeCannotBeReplayed(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	_ = mustEnable2FA(t, ah, queries, user)

	secRow, _ := queries.GetTOTPSecret(context.Background(), user)
	secret := decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	// Enrolment already spent a step, so a fresh code for the CURRENT step is what an
	// attacker would capture. First use may or may not be the same step as enrolment;
	// what matters is that a code cannot be used twice.
	first := spendTOTPStep(context.Background(), queries, user, secret, code)
	second := spendTOTPStep(context.Background(), queries, user, secret, code)

	if second {
		t.Errorf("the same TOTP code was accepted twice (first=%v second=%v).\n"+
			"Inside its 60-second window a captured code then yields unlimited sessions and can "+
			"remove 2FA from the account.", first, second)
	}
}

// mustEnable2FA enrols the user and returns the plaintext recovery codes.
func mustEnable2FA(t *testing.T, ah *AuthHandler, queries *db.Queries, user string) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	ah.TOTPSetup(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), user))
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	secRow, err := queries.GetTOTPSecret(context.Background(), user)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	secret := decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	vrec := httptest.NewRecorder()
	body := `{"code":"` + code + `","password":"` + totpTestPassword + `"}`
	ah.TOTPVerify(vrec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))
	if vrec.Code != http.StatusOK {
		t.Fatalf("ABORT: could not enable 2FA (%d %s), so nothing below is being tested",
			vrec.Code, vrec.Body.String())
	}
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(vrec.Body.Bytes(), &out); err != nil || len(out.RecoveryCodes) == 0 {
		t.Fatalf("ABORT: no recovery codes returned: %v %s", err, vrec.Body.String())
	}
	return out.RecoveryCodes
}

var _ = passwordhash.ProdCost

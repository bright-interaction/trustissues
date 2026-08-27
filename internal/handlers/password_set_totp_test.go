package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/passwordhash"
	"github.com/bright-interaction/trustissues/internal/totp"
)

func seedLegacyPasswordlessUser(t *testing.T, queries *db.Queries, email string) string {
	t.Helper()
	hash, err := passwordhash.Hash("LegacyServerGeneratedPasswordThatNobodyReceived!1")
	if err != nil {
		t.Fatalf("hash legacy unknown password: %v", err)
	}
	userID, err := queries.CreateInvitedUser(context.Background(), db.CreateInvitedUserParams{
		Email: email, PasswordHash: hash, Name: toNullString("Legacy client"),
		Role: "vault_only", PasswordSet: 0,
	})
	if err != nil {
		t.Fatalf("seed legacy password_set=0 user: %v", err)
	}
	return userID
}

// P0-2 legacy-recovery regression: releases before web-first onboarding could
// create vault_only accounts whose random password was never disclosed. Such a
// migrated password_set=0 account must still be able to enrol TOTP once an
// admin turns require_totp on. New invitations always require a human password;
// this fixture is deliberately seeded directly so the compatibility path does
// not become a second account-creation path.
//
// See ops/audits/trustissues-AUDIT-2026-08-24.md P0-2 and migration 00043.
func TestLegacyPasswordlessVaultOnlyUserCanEnrolAfterRequireTOTPIsTurnedOn(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ah := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
	})
	ctx := context.Background()

	clientID := seedLegacyPasswordlessUser(t, queries, "legacy-client@example.com")

	// Pin the mechanism: the marker this whole fix hinges on must read
	// password-less for the directly seeded legacy row.
	passwordSet, err := queries.GetUserPasswordSet(ctx, clientID)
	if err != nil {
		t.Fatalf("read password_set: %v", err)
	}
	if passwordSet != 0 {
		t.Fatalf("ABORT: legacy fixture has password_set=%d, want 0", passwordSet)
	}

	// An admin turns on the vault policy.
	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "require_totp", Value: "true"}); err != nil {
		t.Fatalf("enable require_totp: %v", err)
	}

	// THE FIRST HALF OF THE DEADLOCK: every route now 403s this user, run
	// through the REAL gate middleware, not a stand-in.
	gateStatus, gateReached := runThroughGate(t, vh, clientID)
	if gateStatus != http.StatusForbidden {
		t.Fatalf("ABORT: un-enrolled user got %d through the gate, want 403; the policy did not take", gateStatus)
	}
	if gateReached {
		t.Fatal("ABORT: the gate let the request through to the handler despite returning 403")
	}

	// TOTPSetup is outside the gated group (see RequireTOTPEnrollment's doc
	// comment on why /api/auth stays reachable) and needs no password, so it
	// still works.
	setupRec := httptest.NewRecorder()
	ah.TOTPSetup(setupRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), clientID))
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", setupRec.Code, setupRec.Body.String())
	}
	secRow, err := queries.GetTOTPSecret(ctx, clientID)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	secret := decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	// The legacy recovery exception: no human ever received this row's password.
	verifyRec := httptest.NewRecorder()
	verifyBody := `{"code":"` + code + `"}`
	ah.TOTPVerify(verifyRec,
		withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(verifyBody)), clientID))
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("LEGACY PASSWORDLESS USER COULD NOT ENROL (%d %s).\n"+
			"A migrated password_set=0 account has no known password, and TOTPVerify is the gate's "+
			"only exit from the 403 every gated route returns.",
			verifyRec.Code, verifyRec.Body.String())
	}
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &out); err != nil || len(out.RecoveryCodes) == 0 {
		t.Fatalf("enrolment returned no recovery codes: %s", verifyRec.Body.String())
	}

	state, err := queries.GetUserTOTPState(ctx, clientID)
	if err != nil {
		t.Fatalf("read totp state: %v", err)
	}
	if !nullInt64Is1(state.TotpEnabled) {
		t.Fatal("TOTPVerify returned 200 but did not actually enable 2FA")
	}

	// THE SECOND HALF: the gate must now let the enrolled user through.
	gateStatus2, gateReached2 := runThroughGate(t, vh, clientID)
	if gateStatus2 != http.StatusOK || !gateReached2 {
		t.Errorf("after enrolling, the gate still refuses this user: status=%d reached=%v",
			gateStatus2, gateReached2)
	}
}

// A password-HAVING account must still be refused: the original vector this
// codebase was protecting against (a session/API-key thief enrolling 2FA on
// someone else's real account) must stay closed. This mirrors
// TestEnabling2FARequiresThePassword in auth_totp_test.go and pins the
// password_set side of the same property directly.
func TestPasswordHavingAccountMarkerIsSetAndStillRequiresThePassword(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	ctx := context.Background()

	passwordSet, err := queries.GetUserPasswordSet(ctx, user)
	if err != nil {
		t.Fatalf("read password_set: %v", err)
	}
	if passwordSet != 1 {
		t.Fatalf("a normally created user has password_set=%d, want 1", passwordSet)
	}

	setupRec := httptest.NewRecorder()
	ah.TOTPSetup(setupRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), user))
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", setupRec.Code, setupRec.Body.String())
	}
	secRow, _ := queries.GetTOTPSecret(ctx, user)
	secret := decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	rec := httptest.NewRecorder()
	body := `{"code":"` + code + `"}`
	ah.TOTPVerify(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", strings.NewReader(body)), user))
	if rec.Code == http.StatusOK {
		t.Fatalf("a password-having account enrolled 2FA with no password (%d %s); the original "+
			"session/API-key-thief vector is open again", rec.Code, rec.Body.String())
	}
}

// Every current redemption supplies a password and must record password_set=1.
// Missing the marker would misclassify a normal web-first invitee as a legacy
// recovery account and weaken later password checks.
func TestRedemptionWithASuppliedPasswordSetsTheMarker(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	uh := NewUserHandler(queries, &config.Config{VaultKey: strings.Repeat("k", 32)})
	uh.SetVault(vh)
	ctx := context.Background()

	admin := mustUser(t, queries, "p02-admin2@example.com", "admin", "AdminPassw0rd!")
	createRec := httptest.NewRecorder()
	createReq := withUser(httptest.NewRequest(http.MethodPost, "/api/admin/invitations",
		strings.NewReader(`{"email":"colleague2@example.com","name":"Colleague","role":"user"}`)), admin)
	uh.CreateInvitation(createRec, createReq)
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create invitation: %d %s", createRec.Code, createRec.Body.String())
	}
	var invited struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &invited); err != nil || invited.Code == "" {
		t.Fatalf("no code: %s", createRec.Body.String())
	}

	redeemRec := httptest.NewRecorder()
	redeemReq := httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
		strings.NewReader(`{"code":"`+invited.Code+`","password":"ChosenByHuman1!"}`))
	uh.RedeemInvitation(redeemRec, redeemReq)
	if redeemRec.Code != http.StatusOK {
		t.Fatalf("redeem: %d %s", redeemRec.Code, redeemRec.Body.String())
	}
	var redeemed struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(redeemRec.Body.Bytes(), &redeemed); err != nil || redeemed.User.ID == "" {
		t.Fatalf("no user in response: %s", redeemRec.Body.String())
	}

	passwordSet, err := queries.GetUserPasswordSet(ctx, redeemed.User.ID)
	if err != nil {
		t.Fatalf("read password_set: %v", err)
	}
	if passwordSet != 1 {
		t.Errorf("web-first redemption produced password_set=%d, want 1", passwordSet)
	}
}

// TOTPDisable must NOT be weakened by the legacy recovery exception. A migrated
// password_set=0 account that has enrolled 2FA still
// cannot disable it through this endpoint, because TOTPDisable unconditionally
// requires the password and this account's password is unknowable by
// construction. This is deliberate, not an oversight: disabling 2FA is a
// weaker-security action than enabling it, and the asymmetry this fix creates
// (enable: session+code is enough; disable: still needs the password) is the
// one documented at TOTPVerify. The only route out for this account is an
// admin reset-password, which is the same costly-but-available remedy the
// audit already priced in for P0-2.
func TestLegacyPasswordlessAccountStillCannotSelfDisable2FA(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ah := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
	})
	ctx := context.Background()

	clientID := seedLegacyPasswordlessUser(t, queries, "legacy-disable@example.com")

	setupRec := httptest.NewRecorder()
	ah.TOTPSetup(setupRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), clientID))
	secRow, _ := queries.GetTOTPSecret(ctx, clientID)
	secret := decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32))
	code, _ := totp.GenerateCode(secret, time.Now())
	verifyRec := httptest.NewRecorder()
	ah.TOTPVerify(verifyRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify",
		strings.NewReader(`{"code":"`+code+`"}`)), clientID))
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("ABORT: could not enrol this legacy password-less account, so disable cannot be tested: %d %s",
			verifyRec.Code, verifyRec.Body.String())
	}

	// A fresh code, since the enrolment call above already spent one step.
	code2, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("code2: %v", err)
	}
	disableRec := httptest.NewRecorder()
	// No password known to supply: try the empty string, exactly what a
	// legacy password-less owner has.
	disableBody := `{"password":"","code":"` + code2 + `"}`
	ah.TOTPDisable(disableRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/disable",
		strings.NewReader(disableBody)), clientID))
	if disableRec.Code == http.StatusOK {
		t.Fatal("TOTPDisable succeeded with no password on a legacy password-less account; " +
			"this test exists to DOCUMENT that it should still fail, not to celebrate it failing")
	}

	state, _ := queries.GetUserTOTPState(ctx, clientID)
	if !nullInt64Is1(state.TotpEnabled) {
		t.Error("2FA is disabled despite the disable request being refused")
	}
}

// The admin remedy: after ResetPassword gives a legacy password-less account a real,
// human-chosen password, password_set must flip to 1 and TOTPVerify must
// start requiring that password again. A ResetPassword that forgot to use
// SetPasswordHash (falling back to the marker-blind UpdatePasswordHash) would
// leave the account looking password-less forever, silently reopening the
// exact hole this fix closes: TOTPVerify would keep accepting session+code
// alone even though the account now has a real password a thief could be
// missing.
func TestAdminResetPasswordSetsTheMarkerAndReclosesTheDoor(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	uh := NewUserHandler(queries, &config.Config{VaultKey: strings.Repeat("k", 32)})
	uh.SetVault(vh)
	ah := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
	})
	ctx := context.Background()

	admin := mustUser(t, queries, "p02-admin4@example.com", "admin", "AdminPassw0rd!")
	clientID := seedLegacyPasswordlessUser(t, queries, "legacy-reset@example.com")

	if got, err := queries.GetUserPasswordSet(ctx, clientID); err != nil || got != 0 {
		t.Fatalf("ABORT: legacy fixture is not password-less before the reset (got=%d err=%v)", got, err)
	}

	const newPassword = "AdminChosenForClient1!"
	resetRec := httptest.NewRecorder()
	resetReq := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+clientID+"/reset-password",
		strings.NewReader(`{"password":"`+newPassword+`"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", clientID)
	rc := context.WithValue(resetReq.Context(), chi.RouteCtxKey, rctx)
	rc = context.WithValue(rc, timw.UserIDKey, admin)
	resetReq = resetReq.WithContext(rc)
	uh.ResetPassword(resetRec, resetReq)
	if resetRec.Code != http.StatusNoContent {
		t.Fatalf("reset-password: %d %s", resetRec.Code, resetRec.Body.String())
	}

	passwordSet, err := queries.GetUserPasswordSet(ctx, clientID)
	if err != nil {
		t.Fatalf("read password_set: %v", err)
	}
	if passwordSet != 1 {
		t.Fatalf("after an admin reset-password, password_set=%d, want 1: the account now has a real "+
			"password a thief could be missing, so TOTPVerify must go back to demanding it", passwordSet)
	}

	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "require_totp", Value: "true"}); err != nil {
		t.Fatalf("enable require_totp: %v", err)
	}
	setupRec := httptest.NewRecorder()
	ah.TOTPSetup(setupRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil), clientID))
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", setupRec.Code, setupRec.Body.String())
	}
	secRow, _ := queries.GetTOTPSecret(ctx, clientID)
	secret := decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	// No password: must now be REFUSED, because this account has a real one.
	// This attempt is refused on the password check, BEFORE the code is ever
	// validated, so it does not spend the TOTP step; the same code is still
	// good for the next call below.
	noPwRec := httptest.NewRecorder()
	ah.TOTPVerify(noPwRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify",
		strings.NewReader(`{"code":"`+code+`"}`)), clientID))
	if noPwRec.Code == http.StatusOK {
		t.Fatal("TOTPVerify enrolled 2FA with no password on an account that HAS a real, " +
			"human-chosen password; the reset must have left password_set unset")
	}

	// The correct password must work.
	withPwRec := httptest.NewRecorder()
	body := `{"code":"` + code + `","password":"` + newPassword + `"}`
	ah.TOTPVerify(withPwRec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify",
		strings.NewReader(body)), clientID))
	if withPwRec.Code != http.StatusOK {
		t.Fatalf("enrolment with the correct post-reset password was refused (%d %s)",
			withPwRec.Code, withPwRec.Body.String())
	}
}

// runThroughGate drives one request for userID through the REAL
// RequireTOTPEnrollment middleware (not a mock), the same way main.go mounts
// it, and reports the status plus whether the wrapped handler ran.
func runThroughGate(t *testing.T, vh *VaultHandler, userID string) (status int, reached bool) {
	t.Helper()
	h := timw.RequireTOTPEnrollment(vh.db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/vault", nil), userID)
	h.ServeHTTP(rec, req)
	return rec.Code, reached
}

package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/totp"
)

// The second half of P0-2. The first half (migration 00043 + TOTPVerify's
// password_set gate) let a password-less vault_only account past the
// enrolment gate. It still could not read a secret: reauthOrRefuse
// (vault.go, backing Unlock/Rotate/ValidateKey) unconditionally demands a
// password this account never had. POST /api/auth/set-initial-password is
// the only way such an account ever acquires one.
//
// setInitialPasswordEnv wires a real chi router with the SAME topology as
// cmd/server/main.go's /api group: set-initial-password sits in the
// password-less-reachable /api/auth route group, and vault/unlock sits in the
// group behind RequireTOTPEnrollment. Using the real middleware and real
// routing (not a direct handler call) is what makes the "reachable outside
// the gate" claim below load-bearing: a future change that accidentally moves
// the route inside the gated group fails this test, not just a code reading.
type setInitialPasswordEnv struct {
	srv     *httptest.Server
	queries *db.Queries
	vh      *VaultHandler
	uh      *UserHandler
	ah      *AuthHandler
}

func newSetInitialPasswordEnv(t *testing.T) *setInitialPasswordEnv {
	t.Helper()
	vh, queries := newCollectionAuthzEnv(t)
	cfg := &config.Config{VaultKey: strings.Repeat("k", 32), JWTSecret: strings.Repeat("j", 32)}
	uh := NewUserHandler(queries, cfg)
	uh.SetVault(vh)
	ah := NewAuthHandler(queries, cfg)
	ah.SetVault(vh)

	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) {
		// Public, matches main.go: no auth required to redeem an invitation.
		r.Post("/invitations/redeem", uh.RedeemInvitation)

		r.Group(func(r chi.Router) {
			r.Use(timw.JWTOrAPIKeyAuth(cfg.JWTSecret, vh.db))

			// /api/auth: deliberately OUTSIDE RequireTOTPEnrollment. See
			// main.go around the "Everything past this point is behind the
			// TOTP-enrolment gate" comment.
			r.Route("/auth", func(r chi.Router) {
				r.Post("/set-initial-password", ah.SetInitialPassword)
				r.Post("/totp/setup", ah.TOTPSetup)
				r.Post("/totp/verify", ah.TOTPVerify)
				r.Post("/change-password", ah.ChangePassword)
			})

			// Gated group: everything an un-enrolled account may not reach.
			r.Group(func(r chi.Router) {
				r.Use(timw.RequireTOTPEnrollment(vh.db))
				r.Post("/vault/unlock", vh.Unlock)
			})
		})
	})

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &setInitialPasswordEnv{srv: srv, queries: queries, vh: vh, uh: uh, ah: ah}
}

func (e *setInitialPasswordEnv) do(t *testing.T, method, path, apiKey, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read response body: %v", readErr)
	}
	return resp, string(data)
}

// createVaultOnlyInvite mints a vault_only invitation the way an admin would,
// and returns its redemption code.
func (e *setInitialPasswordEnv) createVaultOnlyInvite(t *testing.T, email string) string {
	t.Helper()
	admin := mustUser(t, e.queries, "admin-"+email, "admin", "AdminPassw0rd!")
	rec := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/admin/invitations",
		strings.NewReader(`{"email":"`+email+`","name":"Client","role":"vault_only"}`)), admin)
	e.uh.CreateInvitation(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create invitation: %d %s", rec.Code, rec.Body.String())
	}
	var invited struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &invited); err != nil || invited.Code == "" {
		t.Fatalf("no invitation code returned: %s", rec.Body.String())
	}
	return invited.Code
}

// TestSetInitialPasswordFullJourney is the mandatory end-to-end proof: a
// vault_only extension user who redeemed a password-less invitation can walk
// all the way from "holds only an API key" to "read back a real secret"
// through /api/vault/unlock, with require_totp switched on throughout.
func TestSetInitialPasswordFullJourney(t *testing.T) {
	e := newSetInitialPasswordEnv(t)
	ctx := context.Background()

	// 1. Password-less redemption: THE EXTENSION'S ACTUAL FLOW, POST {code},
	// no password. See bright-vault-extension/src/options/Options.tsx:104-111.
	code := e.createVaultOnlyInvite(t, "journey-client@example.com")
	resp, body := e.do(t, http.MethodPost, "/api/invitations/redeem", "", `{"code":"`+code+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeem: %d %s", resp.StatusCode, body)
	}
	var redeemed struct {
		APIKey string `json:"api_key"`
		User   struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(body), &redeemed); err != nil || redeemed.User.ID == "" || redeemed.APIKey == "" {
		t.Fatalf("ABORT: redemption did not return an API key and user id: %s", body)
	}
	clientID := redeemed.User.ID
	apiKey := redeemed.APIKey

	if got, err := e.queries.GetUserPasswordSet(ctx, clientID); err != nil || got != 0 {
		t.Fatalf("ABORT: fixture is not password-less (password_set=%d err=%v)", got, err)
	}

	// 2. An admin turns on the enrolment-gate policy.
	if err := e.queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "require_totp", Value: "true"}); err != nil {
		t.Fatalf("enable require_totp: %v", err)
	}

	// 3. BEFORE enrolling: the gate refuses vault access outright, using only
	// the API key. This is the P0-2 deadlock's first half, already fixed on
	// this branch's base commit, re-pinned here as the journey's starting
	// condition.
	resp, body = e.do(t, http.MethodPost, "/api/vault/unlock", apiKey, `{"password":"whatever"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ABORT: un-enrolled account got %d through the gate before TOTP setup, want 403: %s",
			resp.StatusCode, body)
	}

	// 4. Enrol TOTP using only the API key (no password field: this account
	// never had one to send).
	resp, body = e.do(t, http.MethodPost, "/api/auth/totp/setup", apiKey, ``)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("totp setup: %d %s", resp.StatusCode, body)
	}
	secRow, err := e.queries.GetTOTPSecret(ctx, clientID)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	secret := decryptTOTPSecret(nullStringToString(secRow), strings.Repeat("k", 32))
	genCode := func(offset time.Duration) string {
		c, err := totp.GenerateCode(secret, time.Now().Add(offset))
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		return c
	}
	resp, body = e.do(t, http.MethodPost, "/api/auth/totp/verify", apiKey, `{"code":"`+genCode(0)+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PASSWORDLESS USER COULD NOT ENROL (%d %s)", resp.StatusCode, body)
	}

	// 5. STILL BROKEN AT THIS POINT, which is exactly the finding this test
	// closes: enrolled in TOTP, past the gate, and still cannot read a
	// secret, because this account has never had a password to give
	// reauthOrRefuse.
	resp, body = e.do(t, http.MethodPost, "/api/vault/unlock", apiKey, `{"password":"a-guess"}`)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("ABORT: unlock succeeded with a guessed password before set-initial-password ran: %s", body)
	}

	// 6. THE FIX: set the account's first real, human-chosen password, using
	// only the API key, with require_totp still on and no session cookie
	// anywhere in this test.
	const chosenPassword = "ClientChosenPassw0rd!"
	resp, body = e.do(t, http.MethodPost, "/api/auth/set-initial-password", apiKey,
		`{"password":"`+chosenPassword+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set-initial-password: %d %s", resp.StatusCode, body)
	}
	if got, err := e.queries.GetUserPasswordSet(ctx, clientID); err != nil || got != 1 {
		t.Fatalf("password_set=%d (err=%v) after set-initial-password, want 1", got, err)
	}

	// 7. Give the account a secret to read.
	const plaintext = "sk_live_JOURNEY_SECRET"
	mustEntry(t, e.vh, e.queries, "journey-entry", clientID, "journey-entry", plaintext)

	// 8. THE PAYOFF: POST /api/vault/unlock, with the password the user just
	// chose, returns the secret.
	resp, body = e.do(t, http.MethodPost, "/api/vault/unlock", apiKey, `{"password":"`+chosenPassword+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("THE JOURNEY IS STILL BROKEN: unlock with the just-chosen password failed (%d %s)",
			resp.StatusCode, body)
	}
	if !strings.Contains(body, plaintext) {
		t.Fatalf("unlock succeeded but did not carry the secret: %s", body)
	}
}

// TestSetInitialPasswordRefusesAccountThatAlreadyHasAPassword is the
// anti-bypass assertion. This endpoint must be structurally incapable of
// overwriting a password a human already chose, or it is a password-reset
// bypass for anyone holding a stolen session or API key.
func TestSetInitialPasswordRefusesAccountThatAlreadyHasAPassword(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	ctx := context.Background()

	if got, err := queries.GetUserPasswordSet(ctx, user); err != nil || got != 1 {
		t.Fatalf("ABORT: fixture user has password_set=%d (err=%v), want 1", got, err)
	}
	originalHash, err := queries.GetPasswordHashByUserID(ctx, user)
	if err != nil {
		t.Fatalf("read original hash: %v", err)
	}

	rec := httptest.NewRecorder()
	ah.SetInitialPassword(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/auth/set-initial-password",
		strings.NewReader(`{"password":"AttackerChosenPassw0rd!"}`)), user))
	if rec.Code != http.StatusConflict {
		t.Fatalf("a password-having account got %d, want 409: %s", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody.Code != "password_already_set" {
		t.Fatalf("refusal did not carry the machine-readable code password_already_set: %s", rec.Body.String())
	}

	newHash, err := queries.GetPasswordHashByUserID(ctx, user)
	if err != nil {
		t.Fatalf("read hash after refusal: %v", err)
	}
	if newHash != originalHash {
		t.Fatal("the password hash changed despite the refusal")
	}
	if got, err := queries.GetUserPasswordSet(ctx, user); err != nil || got != 1 {
		t.Fatalf("password_set changed to %d (err=%v) despite the refusal", got, err)
	}
}

// TestStolenAPIKeyCannotUseSetInitialPasswordToTakeOverANormalAccount proves
// the attack this endpoint must never enable: an attacker holding a session's
// or an API key's worth of access to a NORMAL, password-having account cannot
// use this endpoint to plant a password of their own choosing. Goes through
// the real HTTP path with a real, minted API key and the real
// JWTOrAPIKeyAuth middleware, not a context shortcut, because the whole
// point being tested is what an attacker holding only that key can do.
func TestStolenAPIKeyCannotUseSetInitialPasswordToTakeOverANormalAccount(t *testing.T) {
	e := newSetInitialPasswordEnv(t)
	ctx := context.Background()

	const victimPassword = "VictimsRealPassw0rd!"
	victim := mustUser(t, e.queries, "victim@example.com", "user", victimPassword)
	if got, err := e.queries.GetUserPasswordSet(ctx, victim); err != nil || got != 1 {
		t.Fatalf("ABORT: victim fixture has password_set=%d (err=%v), want 1", got, err)
	}

	// Mint a real API key for the victim, the way the extension-connect flow
	// does, then treat its plaintext as "stolen" -- from here on this test
	// only ever uses the key, never the victim's actual password.
	apiKeyHandler := NewAPIKeyHandler(e.queries)
	createRec := httptest.NewRecorder()
	apiKeyHandler.Create(createRec, withUser(httptest.NewRequest(http.MethodPost, "/api/api-keys",
		strings.NewReader(`{"name":"stolen-key"}`)), victim))
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("mint victim api key: %d %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil || created.Key == "" {
		t.Fatalf("no key in response: %s", createRec.Body.String())
	}
	stolenKey := created.Key

	// The attacker, holding only the stolen key, tries to plant their own
	// password on the victim's account.
	resp, body := e.do(t, http.MethodPost, "/api/auth/set-initial-password", stolenKey,
		`{"password":"AttackerPlantedPassw0rd!"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("attacker with a stolen API key got %d, want 409: %s", resp.StatusCode, body)
	}

	// The real check: the victim's ACTUAL password must still be the only one
	// that works. Prove it through the real Unlock route, with require_totp
	// off so the gate is not what is being tested here.
	resp, body = e.do(t, http.MethodPost, "/api/vault/unlock", stolenKey, `{"password":"AttackerPlantedPassw0rd!"}`)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("THE ATTACK WORKED: unlock succeeded with the attacker-planted password: %s", body)
	}
	resp, body = e.do(t, http.MethodPost, "/api/vault/unlock", stolenKey, `{"password":"`+victimPassword+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the victim's real password no longer works after the attack attempt (%d %s)",
			resp.StatusCode, body)
	}
}

// TestSetInitialPasswordReachableWithoutTOTPEnrolment is the routing-topology
// proof: with require_totp on and this account NOT enrolled in TOTP,
// set-initial-password must still be reachable, and a route that IS behind
// the gate (vault/unlock, in this same router) must still be refused. Both
// assertions run against the SAME real router built from the SAME topology as
// main.go's /api group, so this is not just "the handler has no enrolment
// check" -- it is "the route is not wrapped by RequireTOTPEnrollment". If a
// future edit moved set-initial-password inside the gated group, this test
// fails.
func TestSetInitialPasswordReachableWithoutTOTPEnrolment(t *testing.T) {
	e := newSetInitialPasswordEnv(t)
	ctx := context.Background()

	code := e.createVaultOnlyInvite(t, "gate-probe@example.com")
	resp, body := e.do(t, http.MethodPost, "/api/invitations/redeem", "", `{"code":"`+code+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeem: %d %s", resp.StatusCode, body)
	}
	var redeemed struct {
		APIKey string `json:"api_key"`
		User   struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(body), &redeemed); err != nil || redeemed.APIKey == "" {
		t.Fatalf("no api key: %s", body)
	}
	apiKey := redeemed.APIKey

	if err := e.queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "require_totp", Value: "true"}); err != nil {
		t.Fatalf("enable require_totp: %v", err)
	}
	if enabled, err := e.queries.GetUserTOTPState(ctx, redeemed.User.ID); err != nil || nullInt64Is1(enabled.TotpEnabled) {
		t.Fatalf("ABORT: fixture user already has TOTP enabled (err=%v)", err)
	}

	// Control: a route actually behind the gate must be refused for this
	// account right now, proving the gate is live in this exact router.
	resp, body = e.do(t, http.MethodPost, "/api/vault/unlock", apiKey, `{"password":"x"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ABORT: the gate did not refuse an un-enrolled account on a gated route (%d %s); "+
			"the control is not exercising the gate", resp.StatusCode, body)
	}

	// The route under test must NOT be refused by the gate for the same
	// account in the same state.
	resp, body = e.do(t, http.MethodPost, "/api/auth/set-initial-password", apiKey, `{"password":"FreshChosenPassw0rd!"}`)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("set-initial-password was blocked by the TOTP-enrolment gate (%d %s); "+
			"this makes the whole fix void, see main.go's /api/auth route group placement", resp.StatusCode, body)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set-initial-password: %d %s", resp.StatusCode, body)
	}
}

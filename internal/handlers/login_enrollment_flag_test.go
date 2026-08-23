package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// The login response must carry totp_enrollment_required, not only /auth/me.
//
// This is the escape hatch for the enrolment gate, and it was broken on the one
// path every gated user takes. Login built its userInfo literal without the
// field; the field is a bool with omitempty, so the key vanished from the
// payload entirely. The SPA's useAuth.login does setUser(res.user) and
// navigates, and never calls /auth/me -- so Layout's
// {user?.totp_enrollment_required && ...} was always falsy right after login.
//
// The user the gate had just locked out of every route therefore landed on
// /vault, watched every query return 403, and was shown nothing at all telling
// them to enrol. Pressing F5 fixed it, because the reload path DOES call
// /auth/me. Nobody would guess that.
//
// Both halves are asserted below. The /auth/me half passing while the login
// half failed is exactly what made this a real defect rather than a broken
// fixture, so the pair stays together.
func TestLoginResponseCarriesTOTPEnrollmentRequired(t *testing.T) {
	ah, _, queries, _ := newTOTPEnv(t)
	user := mustUser(t, queries, "gated@example.com", "user", totpTestPassword)

	// The policy is on and this user has never enrolled.
	if err := queries.UpsertSetting(t.Context(), db.UpsertSettingParams{Key: "require_totp", Value: "true"}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	body := `{"email":"gated@example.com","password":"` + totpTestPassword + `"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	ah.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		User struct {
			TOTPEnrollmentRequired bool `json:"totp_enrollment_required"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if !resp.User.TOTPEnrollmentRequired {
		t.Fatalf("login response omits totp_enrollment_required.\n"+
			"body: %s\n"+
			"The SPA does not call /auth/me after login, so the enrolment banner never renders "+
			"and the gated user has no way to discover they must enrol.", rec.Body.String())
	}

	// The sibling half: /auth/me must agree.
	meRec := httptest.NewRecorder()
	ah.Me(meRec, withUser(httptest.NewRequest(http.MethodGet, "/api/auth/me", nil), user))
	if meRec.Code != http.StatusOK {
		t.Fatalf("me status = %d", meRec.Code)
	}
	var me struct {
		TOTPEnrollmentRequired bool `json:"totp_enrollment_required"`
	}
	if err := json.Unmarshal(meRec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	if !me.TOTPEnrollmentRequired {
		t.Fatalf("/auth/me omits totp_enrollment_required: %s", meRec.Body.String())
	}
}

// An ENROLLED user must not be told to enrol on either path.
func TestEnrolledUserIsNotFlaggedForEnrollment(t *testing.T) {
	ah, _, queries, user := newTOTPEnv(t)
	if err := queries.UpsertSetting(t.Context(), db.UpsertSettingParams{Key: "require_totp", Value: "true"}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if err := queries.EnableTOTP(t.Context(), db.EnableTOTPParams{ID: user}); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	rec := httptest.NewRecorder()
	ah.Me(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/auth/me", nil), user))
	var me struct {
		TOTPEnrollmentRequired bool `json:"totp_enrollment_required"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me.TOTPEnrollmentRequired {
		t.Fatal("an enrolled user is being told to enrol")
	}
}

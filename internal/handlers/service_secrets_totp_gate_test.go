package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// P0-1 (crew audit trustissues-AUDIT-2026-08-24.md): X-Service-Key walked past
// the TOTP enrolment gate entirely. cmd/server/main.go registers
// POST /api/service-identities/me/secrets OUTSIDE the session-auth group (it
// has to: service containers call it with no cookie and no session), so
// RequireTOTPEnrollment never ran on it, and FetchOwnSecrets itself checked
// revoked_at, expires_at and the owner's disabled flag but never enrolment.
// While a session or X-API-Key for the same un-enrolled user got 403
// totp_enrollment_required, a pre-existing service key for that owner kept
// returning plaintext secrets, permanently: service_identities.expires_at is
// nullable with no default.
//
// The fix binds the identity's fetch to its owner's enrolment status: a
// machine principal has no human to enrol, so the human who CAN enrol -- the
// owner who created it -- is who the policy is asked about. This is the
// gate, not a banner: it refuses the fetch, the same way the session/API-key
// gate refuses the request, rather than just flagging the response.

// fetchOwnSecretsCS is fetchOwnSecrets (entry_name_at_rest_lookup_test.go)
// with (code, body string) instead of a recorder, which every assertion
// below wants directly.
func fetchOwnSecretsCS(t *testing.T, h *ServiceSecretsHandler, rawKey string) (int, string) {
	t.Helper()
	rec := fetchOwnSecrets(t, h, rawKey)
	return rec.Code, rec.Body.String()
}

func setRequireTOTP(t *testing.T, q *db.Queries, on bool) {
	t.Helper()
	v := "false"
	if on {
		v = "true"
	}
	if err := q.UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: "require_totp", Value: v,
	}); err != nil {
		t.Fatalf("set require_totp=%v: %v", on, err)
	}
}

// TestFetchOwnSecrets_RefusesUnenrolledOwnerUnderRequireTOTP is the P0-1
// repro, kept as the permanent regression test. Before the fix this returned
// 200 with the seeded plaintext secret in every one of these cases; the crew's
// executed repro found session 403 / service-key 200 on identical DB state.
func TestFetchOwnSecrets_RefusesUnenrolledOwnerUnderRequireTOTP(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	q := db.New(dbConn)

	seedSecret(t, dbConn, "PROD_DB", "super-secret-value")
	rawKey := seedServiceIdentity(t, dbConn, "api-prod", []string{"PROD_DB"})

	// Guard the setup: policy off, owner not enrolled (the fixture default),
	// the key must work. If this fails every assertion below is vacuous.
	code, body := fetchOwnSecretsCS(t, h, rawKey)
	if code != http.StatusOK {
		t.Fatalf("ABORT: key does not work with the policy off (%d): %s", code, body)
	}

	// Turn the policy on the way UpdateVaultPolicy does. The owner (seeded by
	// newServiceTestDB) has totp_enabled = 0.
	setRequireTOTP(t, q, true)

	code, body = fetchOwnSecretsCS(t, h, rawKey)
	if code == http.StatusOK {
		t.Fatalf("P0-1 REGRESSION: require_totp is on, the owner has not enrolled, and the service "+
			"key still returned 200 with plaintext secrets: %s", body)
	}
	if code != http.StatusForbidden {
		t.Errorf("expected 403 (refusal, not a lookup failure), got %d: %s", code, body)
	}
	var apiErr APIError
	if err := json.Unmarshal([]byte(body), &apiErr); err != nil {
		t.Fatalf("response did not parse as APIError: %v (%s)", err, body)
	}
	if apiErr.Code != middleware.TOTPEnrollmentRequiredCode {
		t.Errorf("expected machine-readable code %q (the same one session/API-key callers get), got %q",
			middleware.TOTPEnrollmentRequiredCode, apiErr.Code)
	}
	// Must not leak the secret value anywhere in the refusal body.
	if strings.Contains(body, "super-secret-value") {
		t.Fatalf("refusal body leaked the secret value: %s", body)
	}

	// The owner enrols. Every identity they created must start working again
	// with no separate admin action -- that is the whole point of binding the
	// identity to the owner instead of gating the identity itself.
	if _, err := dbConn.Exec(`UPDATE users SET totp_enabled = 1 WHERE id = ?`, svcTestOwnerID); err != nil {
		t.Fatalf("enrol owner: %v", err)
	}
	code, body = fetchOwnSecretsCS(t, h, rawKey)
	if code != http.StatusOK {
		t.Fatalf("owner enrolled but the service key still refuses (%d): %s", code, body)
	}
	var got struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil || got.Secrets["PROD_DB"] != "super-secret-value" {
		t.Fatalf("enrolled owner's service key did not resolve the seeded secret: %s", body)
	}

	// Un-enrol again, then turn the policy back off: the exemption for a
	// disabled policy must still hold (this is not "always require TOTP for
	// service keys", it is "honour the same policy sessions honour").
	if _, err := dbConn.Exec(`UPDATE users SET totp_enabled = 0 WHERE id = ?`, svcTestOwnerID); err != nil {
		t.Fatalf("un-enrol owner: %v", err)
	}
	setRequireTOTP(t, q, false)
	code, body = fetchOwnSecretsCS(t, h, rawKey)
	if code != http.StatusOK {
		t.Fatalf("policy is off, an un-enrolled owner's key must work exactly as before this change (%d): %s",
			code, body)
	}
}

// TestFetchOwnSecrets_EnrolledOwnerUnaffectedByRequireTOTP is the "keeps
// working" side: an owner who HAS enrolled must never see this gate, at any
// point before or after the policy flips.
func TestFetchOwnSecrets_EnrolledOwnerUnaffectedByRequireTOTP(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	q := db.New(dbConn)

	seedSecret(t, dbConn, "API_TOKEN", "token-value")
	rawKey := seedServiceIdentity(t, dbConn, "api-enrolled", []string{"API_TOKEN"})

	if _, err := dbConn.Exec(`UPDATE users SET totp_enabled = 1 WHERE id = ?`, svcTestOwnerID); err != nil {
		t.Fatalf("enrol owner: %v", err)
	}

	// Policy off, then on: an enrolled owner's identity must fetch
	// successfully in both states.
	for _, on := range []bool{false, true} {
		setRequireTOTP(t, q, on)
		code, body := fetchOwnSecretsCS(t, h, rawKey)
		if code != http.StatusOK {
			t.Fatalf("enrolled owner refused with require_totp=%v (%d): %s", on, code, body)
		}
		var got struct {
			Secrets map[string]string `json:"secrets"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil || got.Secrets["API_TOKEN"] != "token-value" {
			t.Fatalf("require_totp=%v: enrolled owner's key did not resolve the secret: %s", on, body)
		}
	}
}

// TestFetchOwnSecrets_RequireTOTPOffBehavesExactlyAsBefore pins the
// off-by-default / off-explicitly case so this change cannot regress the
// unconditional path every existing service_secrets_test.go case exercises.
func TestFetchOwnSecrets_RequireTOTPOffBehavesExactlyAsBefore(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	q := db.New(dbConn)

	seedSecret(t, dbConn, "PLAIN", "plain-value")
	rawKey := seedServiceIdentity(t, dbConn, "api-plain", []string{"PLAIN"})

	// No settings row at all (the production default: settingBool falls back
	// to false on sql.ErrNoRows).
	code, body := fetchOwnSecretsCS(t, h, rawKey)
	if code != http.StatusOK {
		t.Fatalf("no require_totp row: expected the pre-existing unconditional behaviour, got %d: %s", code, body)
	}

	// Explicit false behaves the same as an absent row.
	setRequireTOTP(t, q, false)
	code, body = fetchOwnSecretsCS(t, h, rawKey)
	if code != http.StatusOK {
		t.Fatalf("require_totp explicitly false: got %d: %s", code, body)
	}
	var got struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil || got.Secrets["PLAIN"] != "plain-value" {
		t.Fatalf("did not resolve the seeded secret: %s", body)
	}
}

// TestListServiceIdentities_SurfacesOwnerEnrollmentStatus is the operator-
// visibility half of the fix: an admin must be able to see, from the SAME
// list they already use to manage service identities, which ones will start
// being refused the moment they turn require_totp on -- before a boot
// failure is how anyone finds out.
func TestListServiceIdentities_SurfacesOwnerEnrollmentStatus(t *testing.T) {
	h, dbConn := setupServiceHandler(t)

	seedSecret(t, dbConn, "X", "y")
	seedServiceIdentity(t, dbConn, "api-one", []string{"X"})

	rows := listServiceIdentitiesAsAdmin(t, h)
	if len(rows) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(rows))
	}
	if rows[0].OwnerTOTPEnabled {
		t.Fatalf("owner has not enrolled; OwnerTOTPEnabled must be false")
	}
	if rows[0].OwnerEmail == nil || *rows[0].OwnerEmail != "svc-owner@example.com" {
		t.Fatalf("expected the seeded owner's email, got %v", rows[0].OwnerEmail)
	}

	if _, err := dbConn.Exec(`UPDATE users SET totp_enabled = 1 WHERE id = ?`, svcTestOwnerID); err != nil {
		t.Fatalf("enrol owner: %v", err)
	}
	rows = listServiceIdentitiesAsAdmin(t, h)
	if !rows[0].OwnerTOTPEnabled {
		t.Fatalf("owner enrolled; OwnerTOTPEnabled must now be true")
	}

	// A deleted owner must list as UNENROLLED, not enrolled. The query uses
	// COALESCE(u.totp_enabled, 0) precisely so a NULL from the LEFT JOIN
	// (no matching user row) reads as false rather than true. Getting this
	// backwards would tell an admin "this identity is fine" for exactly the
	// identity FetchOwnSecrets already refuses outright (the owner-liveness
	// check), which is the one case this visibility feature must not lie
	// about.
	if _, err := dbConn.Exec(`DELETE FROM users WHERE id = ?`, svcTestOwnerID); err != nil {
		t.Fatalf("delete owner: %v", err)
	}
	rows = listServiceIdentitiesAsAdmin(t, h)
	if len(rows) != 1 {
		t.Fatalf("expected the identity to still be listed after its owner was deleted, got %d rows", len(rows))
	}
	if rows[0].OwnerTOTPEnabled {
		t.Fatalf("deleted owner must list as OwnerTOTPEnabled=false, not true")
	}
	if rows[0].OwnerEmail != nil {
		t.Fatalf("deleted owner must list with a nil OwnerEmail, got %v", *rows[0].OwnerEmail)
	}
}

func listServiceIdentitiesAsAdmin(t *testing.T, h *ServiceSecretsHandler) []serviceIdentityListResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/service-identities", nil)
	req = req.WithContext(contextAsAdmin(t))
	rec := httptest.NewRecorder()
	h.ListServiceIdentities(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListServiceIdentities: %d: %s", rec.Code, rec.Body.String())
	}
	var out []serviceIdentityListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

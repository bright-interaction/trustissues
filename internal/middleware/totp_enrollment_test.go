package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// enrollmentDB builds the two tables the gate reads. policy is written only
// when set, so the "no row at all" case (a fresh instance that has never
// touched the setting) is exercised by passing "".
func enrollmentDB(t *testing.T, policy string, users map[string]bool) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
		CREATE TABLE users (id TEXT PRIMARY KEY, totp_enabled INTEGER DEFAULT 0);`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if policy != "" {
		if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('require_totp', ?)`, policy); err != nil {
			t.Fatalf("seed policy: %v", err)
		}
	}
	for id, enrolled := range users {
		n := 0
		if enrolled {
			n = 1
		}
		if _, err := db.Exec(`INSERT INTO users (id, totp_enabled) VALUES (?, ?)`, id, n); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	return db
}

// serveThroughGate runs one request through RequireTOTPEnrollment with the
// given context values already applied, and reports the status plus whether
// the wrapped handler ran at all. "Did the handler run" is the property that
// matters: a gate that returns 403 but still calls through has not gated
// anything.
func serveThroughGate(t *testing.T, db *sql.DB, ctx context.Context) (int, bool) {
	t.Helper()
	reached := false
	h := RequireTOTPEnrollment(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/vault", nil).WithContext(ctx))
	return rec.Code, reached
}

func sessionCtx(userID string) context.Context {
	ctx := context.WithValue(context.Background(), UserIDKey, userID)
	return context.WithValue(ctx, PrincipalKindKey, PrincipalSession)
}

// The defect this middleware exists to close: the policy was on, the user had
// never enrolled, and every request went through anyway.
func TestUnenrolledSessionIsRefusedWhilePolicyRequiresTOTP(t *testing.T) {
	db := enrollmentDB(t, "true", map[string]bool{"u1": false})
	code, reached := serveThroughGate(t, db, sessionCtx("u1"))
	if reached {
		t.Fatal("the wrapped handler ran: an un-enrolled session reached a gated route while require_totp was on")
	}
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", code, http.StatusForbidden)
	}
}

// The refusal has to be machine-readable, because the SPA routes to the
// enrolment screen on the code rather than on the prose.
func TestRefusalCarriesTheEnrollmentCode(t *testing.T) {
	db := enrollmentDB(t, "true", map[string]bool{"u1": false})
	h := RequireTOTPEnrollment(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/vault", nil).WithContext(sessionCtx("u1")))
	if !strings.Contains(rec.Body.String(), TOTPEnrollmentRequiredCode) {
		t.Fatalf("body %q does not carry %q; the client cannot tell this apart from any other 403",
			rec.Body.String(), TOTPEnrollmentRequiredCode)
	}
}

// The three cases that must NOT be refused, or the gate is an outage.
func TestGatePassesEveryCaseItMustNotBlock(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		users  map[string]bool
		ctx    context.Context
		why    string
	}{
		{
			"policy off, not enrolled", "false", map[string]bool{"u1": false}, sessionCtx("u1"),
			"the gate must do nothing at all until an administrator turns the policy on",
		},
		{
			"policy never set, not enrolled", "", map[string]bool{"u1": false}, sessionCtx("u1"),
			"a fresh instance has no require_totp row; a missing row is not an enabled policy",
		},
		{
			"policy on, enrolled", "true", map[string]bool{"u1": true}, sessionCtx("u1"),
			"an enrolled user satisfies the policy and must be unaffected",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db := enrollmentDB(t, c.policy, c.users)
			code, reached := serveThroughGate(t, db, c.ctx)
			if !reached || code != http.StatusOK {
				t.Fatalf("status = %d reached = %v, want 200/true: %s", code, reached, c.why)
			}
		})
	}
}

// The browser extension authenticates with an API key and holds it
// permanently. Gating that path would break the extension for every
// un-enrolled user while denying an attacker nothing, because an attacker
// holding a stolen API key never touches the interactive login this control
// guards.
func TestAPIKeyPrincipalIsNotSubjectToTheEnrollmentGate(t *testing.T) {
	db := enrollmentDB(t, "true", map[string]bool{"u1": false})
	ctx := context.WithValue(context.Background(), UserIDKey, "u1")
	ctx = context.WithValue(ctx, PrincipalKindKey, PrincipalAPIKey)
	code, reached := serveThroughGate(t, db, ctx)
	if !reached || code != http.StatusOK {
		t.Fatalf("status = %d reached = %v, want 200/true: the extension's API key must keep working", code, reached)
	}
}

// The exemption is for API keys SPECIFICALLY, not for "anything that is not a
// session". A principal kind nobody has considered yet must be gated, so a
// future auth path cannot inherit an exemption it was never granted.
func TestUnknownPrincipalKindIsGatedNotExempted(t *testing.T) {
	db := enrollmentDB(t, "true", map[string]bool{"u1": false})
	for _, kind := range []string{"", "future_sso", "service_identity"} {
		t.Run("kind="+kind, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), UserIDKey, "u1")
			if kind != "" {
				ctx = context.WithValue(ctx, PrincipalKindKey, kind)
			}
			_, reached := serveThroughGate(t, db, ctx)
			if reached {
				t.Fatalf("principal kind %q was let through; only PrincipalAPIKey may bypass this gate", kind)
			}
		})
	}
}

// A gate that stops enforcing when the database is unhealthy is not a gate.
// Same rule the login path already applies to its own 2FA lookup.
func TestDatabaseErrorFailsClosed(t *testing.T) {
	db := enrollmentDB(t, "true", map[string]bool{"u1": false})
	// Drop the table the gate reads, so the query cannot succeed.
	if _, err := db.Exec(`DROP TABLE settings`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	code, reached := serveThroughGate(t, db, sessionCtx("u1"))
	if reached {
		t.Fatal("the handler ran despite the gate's query failing: this is a 2FA bypass on any DB fault")
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", code, http.StatusInternalServerError)
	}
}

// A session whose user row is gone is refused rather than passed through.
// enrichUserContext rejects this upstream, so the case is defence in depth --
// but the fail-closed default is the point, and it is worth pinning.
func TestMissingUserRowIsRefused(t *testing.T) {
	db := enrollmentDB(t, "true", map[string]bool{})
	_, reached := serveThroughGate(t, db, sessionCtx("ghost"))
	if reached {
		t.Fatal("a session for a nonexistent user reached a gated route")
	}
}

// An unauthenticated request must not sail through on the strength of having
// no user id. The mounted configuration puts JWTOrAPIKeyAuth in front, so this
// is unreachable today; it is asserted so that stays a property of the code
// rather than of the current wiring.
func TestNoUserIDIsRefused(t *testing.T) {
	db := enrollmentDB(t, "true", map[string]bool{"u1": false})
	code, reached := serveThroughGate(t, db, context.WithValue(context.Background(), PrincipalKindKey, PrincipalSession))
	if reached {
		t.Fatal("a request with no authenticated user reached a gated route")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", code, http.StatusUnauthorized)
	}
}

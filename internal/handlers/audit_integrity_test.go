package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Authentication events must record WHERE they came from.
//
// The four auth events (setup_completed, login, login_failed, logout) all went through
// LogActivity, which passes "" for ip_address and user_agent, so the audit trail was
// blind on exactly the surface it exists for. Every vault operation carried an IP; the
// login did not.
//
// Found by reading PRODUCTION rows rather than source: every auth.login row had an empty
// ip_address column, with the address visible only inside the free-text detail ("Login
// from 84.55.97.134"), where it cannot be filtered, grouped, or read from the column the
// activity UI and both exports display. No lens caught it because the code reads
// perfectly well until you ask what the table actually contains.
//
// auth.login_failed is the sharpest: a credential-stuffing run is the single thing an
// operator greps this table for, and its source was the one field never recorded.
func TestAuthEventsRecordTheirSource(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "203.0.113.45:51000"
	req.Header.Set("User-Agent", "Mozilla/5.0 (audit-probe)")

	user := mustUser(t, queries, "audit-src@example.com", "user", "")
	for _, action := range []string{"auth.login", "auth.login_failed", "auth.logout", "auth.setup_completed"} {
		logAuthEvent(queries, req, &user, action, "probe")
	}

	rows, err := vh.db.QueryContext(ctx,
		`SELECT action, COALESCE(ip_address,''), COALESCE(user_agent,'')
		   FROM activity_log WHERE action LIKE 'auth.%'`)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer rows.Close()

	seen := 0
	for rows.Next() {
		var action, ip, ua string
		if err := rows.Scan(&action, &ip, &ua); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen++
		if ip == "" {
			t.Errorf("%s recorded NO source ip.\n"+
				"A credential-stuffing run is what this table is grepped for, and the source "+
				"would be the one field missing.", action)
		}
		if ua == "" {
			t.Errorf("%s recorded no user agent", action)
		}
	}
	if seen != 4 {
		t.Fatalf("ABORT: %d auth rows found, want 4; the fixture is not exercising the path", seen)
	}
}

// An attacker-influenced audit field cannot be used to fill the disk.
//
// user_agent was stored verbatim with nothing truncating it anywhere in the tree, the
// column has no length bound, and the server set no MaxHeaderBytes, so Go's 1 MB default
// applied to one header value. Any authenticated user, including the lowest vault_only
// role, could commit ~1 MB of chosen bytes per request into the SAME SQLite file that
// holds the encrypted vault, at 500 requests/minute.
//
// Migration 00003 installs an append-only trigger, so DELETE FROM activity_log is
// impossible: there is no cleanup path once it lands. Both the activity list and the
// exports then become too large to read, which is the surface the operator needs DURING
// that incident, and the disk backing the vault fills.
//
// Asserted at logActivityInternal, the single chokepoint every audit row passes through,
// because there are 30+ call sites and the one that forgets is the one that gets used.
func TestAuditFieldsAreBounded(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	user := mustUser(t, queries, "audit-bound@example.com", "user", "")

	huge := strings.Repeat("A", 1<<20) // the 1 MB a single header can carry
	logActivityInternal(queries, &user, "test.bounded", huge, huge, huge)

	var ipLen, uaLen, detailLen int
	if err := vh.db.QueryRowContext(ctx,
		`SELECT LENGTH(COALESCE(ip_address,'')), LENGTH(COALESCE(user_agent,'')),
		        LENGTH(COALESCE(detail,''))
		   FROM activity_log WHERE action = 'test.bounded'`).
		Scan(&ipLen, &uaLen, &detailLen); err != nil {
		t.Fatalf("read: %v", err)
	}

	for _, c := range []struct {
		name string
		got  int
		max  int
	}{
		{"user_agent", uaLen, maxAuditUserAgentLen + 32},
		{"ip_address", ipLen, maxAuditIPLen + 32},
		{"detail", detailLen, maxAuditDetailLen + 32},
	} {
		if c.got > c.max {
			t.Errorf("%s stored %d bytes from a 1 MB input, want <= %d.\n"+
				"activity_log is append-only (migration 00003 forbids DELETE) and shares the "+
				"SQLite file with the encrypted vault, so unbounded writes here fill the disk "+
				"with no way to reclaim it.", c.name, c.got, c.max)
		}
		if c.got == 0 {
			t.Errorf("%s stored nothing at all; truncation must clip, not drop", c.name)
		}
	}
}

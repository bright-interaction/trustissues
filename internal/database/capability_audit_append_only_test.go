package database

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

const capabilityAuditAppendOnlyVersion = 39

// TestTheCredentialAuditTablesRejectRewritesAndErasure drives the two tables an
// operator would actually consult after a suspected compromise.
//
// capability_log records every capability token issued, used and denied;
// service_secret_audit records every secret fetch by a service identity. Both
// carried the same guarantee activity_log has had since 00003 only by
// convention: no code path wrote anything but INSERT. Convention is not a
// guarantee against the threat these tables exist to document, because an
// attacker with a write handle does not restrict themselves to the queries the
// application happens to define.
//
// Each case here is the attack, not a schema assertion: rewrite the row to hide
// what happened, then erase it. Both must abort, and the original row must
// survive byte-identical, since a trigger that aborted the statement after
// SQLite had already applied part of it would pass a check that only looked at
// the returned error.
func TestTheCredentialAuditTablesRejectRewritesAndErasure(t *testing.T) {
	conn := migratedDB(t)

	// A capability token issued to an agent, and a secret fetch by a service.
	// These are the rows that say "this credential was accessed".
	if _, err := conn.Exec(
		`INSERT INTO capability_log (id, agent_id, secret_id, secret_name, destination, method, event, error, nonce)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"cap-1", "agent-attacker", "secret-1", "STRIPE_KEY", "api.stripe.com", "POST", "used", "", "nonce-1"); err != nil {
		t.Fatalf("seed capability_log: %v", err)
	}
	if _, err := conn.Exec(
		`INSERT INTO service_secret_audit (id, service_identity_id, service_name, event, secret_names, error, remote_ip)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"ssa-1", "svc-1", "billing-worker", "fetch", `["STRIPE_KEY"]`, "", "10.0.0.9"); err != nil {
		t.Fatalf("seed service_secret_audit: %v", err)
	}

	cases := []struct {
		name  string
		table string
		id    string
		// cover is the rewrite that would launder the row: make a real use look
		// like a denial, and move the actor off the attacker.
		cover string
	}{
		{
			name:  "capability_log",
			table: "capability_log",
			id:    "cap-1",
			cover: `UPDATE capability_log SET event = 'denied', agent_id = 'someone-else' WHERE id = 'cap-1'`,
		},
		{
			name:  "service_secret_audit",
			table: "service_secret_audit",
			id:    "ssa-1",
			cover: `UPDATE service_secret_audit SET event = 'denied', service_name = 'someone-else' WHERE id = 'ssa-1'`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// THE COVER-UP.
			if _, err := conn.Exec(tc.cover); err == nil {
				t.Fatalf("THE AUDIT ROW WAS REWRITTEN: %s accepted an UPDATE, so anyone with a write "+
					"handle can make a credential access look like a denial", tc.table)
			} else if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("the UPDATE was rejected, but not by the append-only trigger: %v", err)
			}

			// THE ERASURE.
			if _, err := conn.Exec(`DELETE FROM `+tc.table+` WHERE id = ?`, tc.id); err == nil {
				t.Fatalf("THE AUDIT ROW WAS DELETED: %s accepted a DELETE, so the record of a "+
					"credential access can be removed entirely", tc.table)
			} else if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("the DELETE was rejected, but not by the append-only trigger: %v", err)
			}

			// AND THE ROW IS STILL THERE, UNTOUCHED. An abort that had already
			// applied half the statement would satisfy both checks above.
			var count int
			if err := conn.QueryRow(`SELECT COUNT(*) FROM `+tc.table+` WHERE id = ?`, tc.id).Scan(&count); err != nil {
				t.Fatalf("count %s: %v", tc.table, err)
			}
			if count != 1 {
				t.Fatalf("%s row %q is gone after two aborted statements", tc.table, tc.id)
			}
			var event string
			if err := conn.QueryRow(`SELECT event FROM `+tc.table+` WHERE id = ?`, tc.id).Scan(&event); err != nil {
				t.Fatalf("read back %s: %v", tc.table, err)
			}
			if event != "used" && event != "fetch" {
				t.Errorf("%s row %q was partially rewritten before the abort: event=%q", tc.table, tc.id, event)
			}
		})
	}

	// The INSERT path stays open, or the triggers have broken the logging they
	// exist to protect.
	if _, err := conn.Exec(
		`INSERT INTO capability_log (id, agent_id, event, nonce) VALUES (?, ?, ?, ?)`,
		"cap-2", "agent-2", "issued", "nonce-2"); err != nil {
		t.Errorf("the triggers blocked a legitimate capability_log INSERT: %v", err)
	}
	if _, err := conn.Exec(
		`INSERT INTO service_secret_audit (id, service_name, event) VALUES (?, ?, ?)`,
		"ssa-2", "billing-worker", "denied"); err != nil {
		t.Errorf("the triggers blocked a legitimate service_secret_audit INSERT: %v", err)
	}
}

// TestTheAppendOnlyAuditTriggersSurviveADownUpCycle. CREATE TRIGGER has no
// IF NOT EXISTS in the form used here, so a Down that failed to drop the four
// triggers would leave the next Up dying on "trigger already exists" against a
// database that reverted cleanly, which is the shape 00038 was caught on.
func TestTheAppendOnlyAuditTriggersSurviveADownUpCycle(t *testing.T) {
	conn := migratedDB(t)

	for _, name := range appendOnlyAuditTriggers {
		if !triggerExists(t, conn, name) {
			t.Fatalf("ABORT: trigger %s does not exist after the first up, so this test is not "+
				"about the migration it names", name)
		}
	}

	if err := goose.DownTo(conn, "migrations", capabilityAuditAppendOnlyVersion-1); err != nil {
		t.Fatalf("down to %d: %v", capabilityAuditAppendOnlyVersion-1, err)
	}
	for _, name := range appendOnlyAuditTriggers {
		if triggerExists(t, conn, name) {
			t.Errorf("THE DOWN LEFT %s BEHIND: the next up will fail with a duplicate trigger", name)
		}
	}

	if err := goose.Up(conn, "migrations"); err != nil {
		t.Fatalf("SECOND UP FAILED, so this migration is forward-only and reverting it strands the "+
			"database: %v", err)
	}
	for _, name := range appendOnlyAuditTriggers {
		if !triggerExists(t, conn, name) {
			t.Errorf("trigger %s did not come back after the cycle, so the audit tables are "+
				"writable on a database that reverted and re-migrated", name)
		}
	}
}

var appendOnlyAuditTriggers = []string{
	"capability_log_no_update",
	"capability_log_no_delete",
	"service_secret_audit_no_update",
	"service_secret_audit_no_delete",
}

func migratedDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ti.db")
	conn, err := sql.Open("sqlite3", "file:"+path+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.Up(conn, "migrations"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	return conn
}

func triggerExists(t *testing.T, conn *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := conn.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatalf("read sqlite_master for trigger %s: %v", name, err)
	}
	return n > 0
}

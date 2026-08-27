package database

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

const passwordSetMarkerVersion = 43

// TestPasswordSetMarkerDefaultsToSetForExistingRowsAndSurvivesADownUpCycle
// pins the two properties the P0-2 fix depends on:
//
//  1. A row created BEFORE 00043 (every account that existed at deploy time)
//     reads password_set = 1 (the strict, pre-existing behaviour) once 00043
//     runs, with no backfill statement required. That is what the DEFAULT 1
//     clause buys, and it is easy to get backwards: a migration that
//     defaulted to 0 would silently make every current user's account look
//     password-less to TOTPVerify.
//  2. ALTER TABLE ADD COLUMN is not naturally reversible in SQLite, so this
//     drives the real chain up to 43, down to 42, and up to 43 again, the way
//     TestTheClaimPreviousHolderMigrationSurvivesADownUpCycle does for
//     00038: a Down that did not actually drop the column would make the
//     second Up die on "duplicate column name" against an otherwise healthy
//     database, on nobody's first deploy.
func TestPasswordSetMarkerDefaultsToSetForExistingRowsAndSurvivesADownUpCycle(t *testing.T) {
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

	// Stop ONE SHORT of 00043 and insert a row the way every pre-existing
	// account in the world looked: no password_set column exists yet.
	if err := goose.UpTo(conn, "migrations", passwordSetMarkerVersion-1); err != nil {
		t.Fatalf("up to %d: %v", passwordSetMarkerVersion-1, err)
	}
	if columnExists(t, conn, "users", "password_set") {
		t.Fatal("ABORT: password_set already exists before 00043 ran; this test is not isolating the migration")
	}
	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, name, role) VALUES (?, ?, ?, ?, ?)`,
		"pre-existing-user", "pre-existing@example.com", "some-hash", "Pre Existing", "user")

	// THE MIGRATION UNDER TEST.
	if err := goose.UpTo(conn, "migrations", passwordSetMarkerVersion); err != nil {
		t.Fatalf("up to %d: %v", passwordSetMarkerVersion, err)
	}
	if !columnExists(t, conn, "users", "password_set") {
		t.Fatalf("ABORT: users.password_set does not exist after 00043 ran")
	}

	// PROPERTY 1: the pre-existing row is unaffected -- it reads as password_set,
	// exactly like every account had to be treated before this column existed.
	var got int
	if err := conn.QueryRow(`SELECT password_set FROM users WHERE id = ?`, "pre-existing-user").
		Scan(&got); err != nil {
		t.Fatalf("read back password_set: %v", err)
	}
	if got != 1 {
		t.Errorf("pre-existing row has password_set=%d after the migration, want 1 (the strict "+
			"default): a row that predates this column must not silently become password-less to "+
			"TOTPVerify, or every current user's enrolment gate weakens on deploy", got)
	}

	// A freshly-inserted row that does not mention the column must ALSO default
	// to 1: CreateUser, CreateFirstAdmin and ordinary INSERTs never set it.
	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, name, role) VALUES (?, ?, ?, ?, ?)`,
		"fresh-user", "fresh@example.com", "some-hash", "Fresh", "user")
	var freshGot int
	if err := conn.QueryRow(`SELECT password_set FROM users WHERE id = ?`, "fresh-user").
		Scan(&freshGot); err != nil {
		t.Fatalf("read back fresh password_set: %v", err)
	}
	if freshGot != 1 {
		t.Errorf("a freshly inserted row that did not mention password_set reads %d, want 1", freshGot)
	}

	// PROPERTY 2: the down/up cycle.
	if err := goose.DownTo(conn, "migrations", passwordSetMarkerVersion-1); err != nil {
		t.Fatalf("down to %d: %v", passwordSetMarkerVersion-1, err)
	}
	if columnExists(t, conn, "users", "password_set") {
		t.Error("THE DOWN LEFT password_set BEHIND: the next up will fail with a duplicate column " +
			"on a database that reverted cleanly")
	}

	if err := goose.Up(conn, "migrations"); err != nil {
		t.Fatalf("SECOND UP FAILED, so this migration is forward-only and reverting it strands the "+
			"database: %v", err)
	}
	v, err := goose.GetDBVersion(conn)
	if err != nil {
		t.Fatalf("read version: %v", err)
	}
	if v < passwordSetMarkerVersion {
		t.Fatalf("after the cycle the database is at version %d, expected at least %d",
			v, passwordSetMarkerVersion)
	}
	if !columnExists(t, conn, "users", "password_set") {
		t.Fatal("password_set is missing after the up/down/up cycle")
	}

	// And the column still represents an explicit legacy password-less account.
	// Current invitation redemption always writes 1; retaining 0 is what lets an
	// administrator repair an account created by an older binary.
	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, name, role, password_set) VALUES (?, ?, ?, ?, ?, 0)`,
		"cycle-passwordless-user", "cycle-passwordless@example.com", "discarded-hash", "Cycle Passwordless", "vault_only")
	var cycleGot int
	if err := conn.QueryRow(`SELECT password_set FROM users WHERE id = ?`, "cycle-passwordless-user").
		Scan(&cycleGot); err != nil {
		t.Fatalf("read back cycle password_set: %v", err)
	}
	if cycleGot != 0 {
		t.Errorf("explicit password_set=0 round-tripped as %d after the up/down/up cycle, want 0", cycleGot)
	}

	// The CHECK constraint must still refuse anything outside {0,1}.
	if _, err := conn.Exec(
		`INSERT INTO users (id, email, password_hash, name, role, password_set) VALUES (?, ?, ?, ?, ?, 2)`,
		"bad-marker-user", "bad-marker@example.com", "hash", "Bad Marker", "user"); err == nil {
		t.Error("password_set accepted the value 2, so the CHECK constraint did not survive the migration")
	}
}

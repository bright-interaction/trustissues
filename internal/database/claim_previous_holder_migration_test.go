package database

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

const claimPreviousHolderVersion = 38

// TestTheClaimPreviousHolderMigrationSurvivesADownUpCycle is the property
// ALTER TABLE ADD COLUMN does not give you for free.
//
// SQLite has no ADD COLUMN IF NOT EXISTS. 00038 adds two columns to
// secret_ownership_claims, so a Down that did nothing (the shape 00035, 00036
// and 00037 all use, because what they add are tables guarded by CREATE TABLE IF
// NOT EXISTS) would leave the columns in place and the next Up would die on
// "duplicate column name" against a database that is otherwise healthy. The
// failure would not appear on any fresh install or any forward-only upgrade,
// which is the worst possible time to find it.
//
// This drives the real chain on a real database: up to 38, down to 37, up to 38
// again, and then writes the row the handler writes, so a Down that dropped the
// columns without an Up that puts them back would not pass either.
func TestTheClaimPreviousHolderMigrationSurvivesADownUpCycle(t *testing.T) {
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
		t.Fatalf("first up: %v", err)
	}
	for _, col := range []string{"previous_owner_user_id", "previous_custodian_user_id"} {
		if !columnExists(t, conn, "secret_ownership_claims", col) {
			t.Fatalf("ABORT: secret_ownership_claims.%s does not exist after the first up, so this "+
				"test is not about the migration it names", col)
		}
	}

	if err := goose.DownTo(conn, "migrations", claimPreviousHolderVersion-1); err != nil {
		t.Fatalf("down to %d: %v", claimPreviousHolderVersion-1, err)
	}
	for _, col := range []string{"previous_owner_user_id", "previous_custodian_user_id"} {
		if columnExists(t, conn, "secret_ownership_claims", col) {
			t.Errorf("THE DOWN LEFT %s BEHIND: the next up will fail with a duplicate column on a "+
				"database that reverted cleanly", col)
		}
	}

	// THE CYCLE. This is the statement that used to be impossible.
	if err := goose.Up(conn, "migrations"); err != nil {
		t.Fatalf("SECOND UP FAILED, so this migration is forward-only and reverting it strands the "+
			"database: %v", err)
	}

	v, err := goose.GetDBVersion(conn)
	if err != nil {
		t.Fatalf("read version: %v", err)
	}
	if v < claimPreviousHolderVersion {
		t.Fatalf("after the cycle the database is at version %d, expected at least %d",
			v, claimPreviousHolderVersion)
	}

	// AND THE COLUMNS TAKE THE WRITE THE HANDLER MAKES. A cycle that ended with
	// the columns present but the wrong shape would pass everything above.
	if _, err := conn.Exec(
		`INSERT INTO secret_ownership_claims
		   (entry_id, claimed_by, withdrawn_json, previous_owner_user_id, previous_custodian_user_id)
		 VALUES (?, ?, ?, ?, ?)`,
		"entry-cycle", "admin-cycle", "{}", "owner-cycle", "custodian-cycle"); err != nil {
		t.Fatalf("the claim record the handler writes does not fit the post-cycle schema: %v", err)
	}
	var prevOwner, prevCustodian string
	if err := conn.QueryRow(
		`SELECT previous_owner_user_id, previous_custodian_user_id
		 FROM secret_ownership_claims WHERE entry_id = ?`, "entry-cycle").
		Scan(&prevOwner, &prevCustodian); err != nil {
		t.Fatalf("read back the claim record: %v", err)
	}
	if prevOwner != "owner-cycle" || prevCustodian != "custodian-cycle" {
		t.Errorf("the displaced holder did not round-trip: owner=%q custodian=%q",
			prevOwner, prevCustodian)
	}
}

package database

import (
	"strings"
	"testing"
)

// THE REBUILD IS DESTRUCTIVE ON PURPOSE, AND THAT IS EXACTLY WHY IT IS PINNED.
//
// 00041 clears activity_log because the rows written before the entry name was
// sealed at rest named vault secrets in cleartext, and append-only means the
// application could never rewrite them. A migration that deletes audit history
// is the sort of thing that gets copied later by someone who wants a tidier log,
// so the three properties that make this one defensible are asserted here rather
// than left in the file's prose.

// TestTheRebuildLeavesTheLogAppendOnly is the property that stops this migration
// being a hole. It drops both triggers to do its work; if it ever forgot to put
// them back, the server would be free to rewrite and delete audit rows from then
// on, and nothing else in the suite would notice.
func TestTheRebuildLeavesTheLogAppendOnly(t *testing.T) {
	conn := openBefore(t)
	seedPeople(t, conn)
	insertEntry(t, conn, "e-personal", "u-victim", "personal", "")
	applyTheMigration(t, conn)

	if _, err := conn.Exec(
		`INSERT INTO activity_log (user_id, action, detail) VALUES (NULL, 'test.row', 'a line')`); err != nil {
		t.Fatalf("the rebuilt log refuses an ordinary INSERT: %v", err)
	}

	if _, err := conn.Exec(`UPDATE activity_log SET detail = 'rewritten' WHERE action = 'test.row'`); err == nil {
		t.Error("UPDATE succeeded against the rebuilt activity_log. 00041 drops the append-only " +
			"triggers to clear the table and has not put them back, so the application can now " +
			"rewrite audit history, which is the one thing the log exists to prevent")
	}
	if _, err := conn.Exec(`DELETE FROM activity_log WHERE action = 'test.row'`); err == nil {
		t.Error("DELETE succeeded against the rebuilt activity_log; the no_delete trigger was not " +
			"restored")
	}
}

// TestTheRebuildKeepsTheActorAnonymizationExemption pins that the restored
// trigger is 00027's and not 00003's.
//
// 00003's blanket UPDATE trigger aborted the ON DELETE SET NULL that SQLite
// performs for activity_log.user_id, so deleting a user always rolled back and
// offboarding was impossible. 00027 narrowed it. A rebuild that recreated the
// trigger from the ORIGINAL migration would reintroduce that bug silently, and
// it would only surface the next time somebody tried to delete an account.
func TestTheRebuildKeepsTheActorAnonymizationExemption(t *testing.T) {
	conn := openBefore(t)
	seedPeople(t, conn)
	applyTheMigration(t, conn)

	if _, err := conn.Exec(
		`INSERT INTO activity_log (user_id, action, detail) VALUES ('u-victim', 'test.row', 'a line')`); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	// Exactly what the foreign key does when the user is deleted.
	if _, err := conn.Exec(
		`UPDATE activity_log SET user_id = NULL WHERE action = 'test.row'`); err != nil {
		t.Fatalf("the rebuilt trigger refuses actor anonymization, so deleting a user will roll "+
			"back and offboarding is impossible again (this is the 00027 bug): %v", err)
	}
}

// TestTheRebuildIsSilentOnAFreshInstall is the first-run case. goose applies
// every migration to an empty file before the server takes a request, and a
// brand new instance must not open its life with a notice about a history it
// never had.
func TestTheRebuildIsSilentOnAFreshInstall(t *testing.T) {
	conn := openBefore(t)
	applyTheMigration(t, conn)

	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM activity_log`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("a fresh install came up with %d activity row(s); 00041 is announcing the clearing "+
			"of a log that never existed", n)
	}
}

// TestTheRebuildSaysWhatItDiscarded covers the other direction: on an instance
// that HAD a log, the new one must open with the reason it is empty, or an
// auditor is left to conclude the product simply lost it.
func TestTheRebuildSaysWhatItDiscarded(t *testing.T) {
	conn := openBefore(t)
	seedPeople(t, conn)
	// A row that exists before 00041 runs. insertEntry drives the ownership
	// backfill; this is an ordinary line of the kind the old log was full of.
	if _, err := conn.Exec(
		`INSERT INTO activity_log (user_id, action, detail)
		 VALUES ('u-victim', 'vault.entry_created', 'Vault secret created: Stripe live key')`); err != nil {
		t.Fatalf("seed pre-existing row: %v", err)
	}
	applyTheMigration(t, conn)

	var detail string
	if err := conn.QueryRow(
		`SELECT detail FROM activity_log WHERE action = 'admin.activity_log_rebuilt'`).Scan(&detail); err != nil {
		t.Fatalf("no admin.activity_log_rebuilt row after clearing a non-empty log: %v", err)
	}
	for _, want := range []string{"migration 00041", "/app/data/backups"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the notice does not mention %q, so a reader cannot find the discarded log.\n  got: %s",
				want, detail)
		}
	}

	// And the cleartext it existed to remove is actually gone.
	var leaked int
	if err := conn.QueryRow(
		`SELECT COUNT(*) FROM activity_log WHERE detail LIKE '%Stripe live key%'`).Scan(&leaked); err != nil {
		t.Fatalf("count leaked: %v", err)
	}
	if leaked != 0 {
		t.Errorf("%d row(s) still name a secret in the clear after the rebuild", leaked)
	}
}

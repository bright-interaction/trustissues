package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

// THE MIGRATION THAT MUST NOT LAUNDER THE ATTACK.
//
// Migration 00034 exists because vault_entries.user_id is a column a collection
// MANAGER moves to their own id with two ordinary product calls: remove the
// creator from the collection, then rename the entry (AdoptAndRenameVaultEntry).
// The exit resolved "whose secret is this" from that column, so the attacker
// wrote their own authority.
//
// Its first version ended with
//
//	UPDATE vault_entries SET secret_owner_user_id = user_id;
//
// which on a live instance where the attack had ALREADY run would have promoted
// the attacker from custodian to OWNER, permanently, in the one column nothing
// below an instance admin can move. THE FIX WOULD HAVE BOOTSTRAPPED ITS
// AUTHORITY FROM THE COLUMN IT EXISTS TO DISTRUST.
//
// These tests apply the real migration, through goose, to a database that has
// been left in each of the states a live instance can actually be in, and check
// which rows come out with an owner.
//
// The wire half (the attacker performing the attack through the product's own
// HTTP routes on an OLD binary, then failing to direct the secret on the NEW
// one) is scripts/live-crossversion-skeptic.sh. This is the data half, and it
// is the one that can enumerate the cases.

// the version of the migration under test, and the one immediately before it.
const (
	secretOwnerVersion = 34
	beforeSecretOwner  = 33
	relaunderVersion   = 35
)

// openBefore returns a database migrated to the version BEFORE the secret-owner
// split, i.e. the shape a live instance is in on the day of the upgrade.
func openBefore(t *testing.T) *sql.DB {
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
	if err := goose.UpTo(conn, "migrations", beforeSecretOwner); err != nil {
		t.Fatalf("migrate to %d: %v", beforeSecretOwner, err)
	}
	// The premise of the whole exercise: the column does not exist yet, so
	// anything below is genuinely crossing the boundary.
	if columnExists(t, conn, "vault_entries", "secret_owner_user_id") {
		t.Fatalf("ABORT: vault_entries.secret_owner_user_id already exists at version %d, so this test "+
			"never crosses the migration it is about", beforeSecretOwner)
	}
	return conn
}

// applyTheMigration runs the rest of the migrations, which is 00034 and
// anything after it.
func applyTheMigration(t *testing.T, conn *sql.DB) {
	t.Helper()
	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.Up(conn, "migrations"); err != nil {
		t.Fatalf("goose up: %v", err)
	}
	if !columnExists(t, conn, "vault_entries", "secret_owner_user_id") {
		t.Fatal("ABORT: the migration ran and vault_entries.secret_owner_user_id does not exist")
	}
	v, err := goose.GetDBVersion(conn)
	if err != nil {
		t.Fatalf("goose version: %v", err)
	}
	if v < secretOwnerVersion {
		t.Fatalf("ABORT: database is at goose version %d, want at least %d", v, secretOwnerVersion)
	}
}

func columnExists(t *testing.T, conn *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := conn.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}

func mustExec(t *testing.T, conn *sql.DB, stmt string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(stmt, args...); err != nil {
		t.Fatalf("exec %q: %v", collapse(stmt), err)
	}
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

func ownerOf(t *testing.T, conn *sql.DB, entryID string) string {
	t.Helper()
	var owner string
	if err := conn.QueryRow(
		"SELECT secret_owner_user_id FROM vault_entries WHERE id = ?", entryID).Scan(&owner); err != nil {
		t.Fatalf("read owner of %s: %v", entryID, err)
	}
	return owner
}

// seedPeople creates the cast every case shares: the victim who deposits
// secrets, the manager who takes them over, and a collection.
func seedPeople(t *testing.T, conn *sql.DB) {
	t.Helper()
	for _, u := range []struct{ id, email, role string }{
		{"u-victim", "victim@example.com", "user"},
		{"u-manager", "manager@example.com", "user"},
		{"u-admin", "admin@example.com", "admin"},
	} {
		mustExec(t, conn,
			`INSERT INTO users (id, email, password_hash, name, role) VALUES (?, ?, 'x', ?, ?)`,
			u.id, u.email, u.email, u.role)
	}
	mustExec(t, conn, `INSERT INTO collections (id, name, created_by) VALUES ('c-team', 'Team', 'u-victim')`)
	mustExec(t, conn,
		`INSERT INTO collection_members (collection_id, user_id, role, accepted_at)
		 VALUES ('c-team', 'u-manager', 'manager', CURRENT_TIMESTAMP)`)
}

// insertEntry writes one vault_entries row in the pre-00034 shape: no owner
// column exists yet, so a row is exactly a custodian, a name and a collection.
func insertEntry(t *testing.T, conn *sql.DB, id, custodian, name, collection string) {
	t.Helper()
	var coll any
	if collection != "" {
		coll = collection
	}
	mustExec(t, conn,
		`INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, collection_id)
		 VALUES (?, ?, ?, X'00', X'00', ?)`, id, custodian, name, coll)
}

func logRow(t *testing.T, conn *sql.DB, actor, action, detail string) {
	t.Helper()
	mustExec(t, conn,
		`INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)`, actor, action, detail)
}

// TestTheBackfillNeverStampsAnAttackerAsOwner is the table.
//
// Each case is one entry, in one of the states a live database can be in on the
// morning of the upgrade, with the evidence the product would actually have
// written. The expectation is the OWNER the migration leaves behind: either the
// custodian (proved safe) or empty (which denies).
func TestTheBackfillNeverStampsAnAttackerAsOwner(t *testing.T) {
	type entryCase struct {
		name string
		// how the row and its history are laid down, before the migration.
		seed func(t *testing.T, conn *sql.DB, id string)
		// the owner the migration must leave behind. "" means denied.
		wantOwner string
		why       string
	}

	cases := []entryCase{
		{
			name: "a personal entry nobody has ever touched keeps its owner",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-victim", "personal-"+id, "")
			},
			wantOwner: "u-victim",
			why: "adoption cannot reach a personal entry and the log records no move, so the custodian " +
				"is provably still the creator. This is the POSITIVE CONTROL: without it the migration " +
				"would be trivially safe and useless",
		},
		{
			name: "THE ATTACK: an adopted collection entry does NOT make the manager the owner",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				// The victim created it in the collection.
				insertEntry(t, conn, id, "u-victim", "adopted-"+id, "c-team")
				// Step 1 of the attack, manager-gated, and logged.
				logRow(t, conn, "u-manager", "collection.member_removed",
					"Member u-victim removed from collection c-team")
				// Step 2: adopt and rename. THIS is the statement that moved
				// user_id, verbatim from internal/db/queries/vault.sql.
				mustExec(t, conn,
					`UPDATE vault_entries SET user_id = ?, name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
					"u-manager", "taken-"+id, id)
				logRow(t, conn, "u-manager", "vault.entry_adopted",
					"Entry "+id+" renamed and adopted by a collection manager (its creator has left the collection)")
			},
			wantOwner: "",
			why: "the attacker holds user_id. Copying it into secret_owner_user_id is the laundering " +
				"step this whole round exists to remove",
		},
		{
			name: "an adoption by an OLDER binary, which left no vault.entry_adopted row, is still denied",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-victim", "silent-"+id, "c-team")
				logRow(t, conn, "u-manager", "collection.member_removed",
					"Member u-victim removed from collection c-team")
				mustExec(t, conn,
					`UPDATE vault_entries SET user_id = ?, name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
					"u-manager", "taken-"+id, id)
				// No adoption row: that audit action was only added on
				// 2026-08-02, so pre-upgrade adoptions have none. The ONLY
				// thing standing between this row and the attacker owning it
				// is that the migration refuses every collection entry.
				logRow(t, conn, "u-manager", "vault.entry_updated",
					"Vault secret updated: taken-"+id+" (user: u-manager)")
			},
			wantOwner: "",
			why: "this is the case that decides whether the backfill is honest. There is no evidence " +
				"here at all, and guessing in the attacker's favour is what the round-6 root cause was",
		},
		{
			name: "an untouched COLLECTION entry is denied too, because nothing tells it apart",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-victim", "shared-"+id, "c-team")
			},
			wantOwner: "",
			why: "the honest cost. A row whose creator still holds it is byte-identical to an adopted " +
				"one, so it is refused with the rest and repaired at Settings -> Ownership",
		},
		{
			name: "a personal entry that WAS once in a collection is denied",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-manager", "moved-"+id, "")
				logRow(t, conn, "u-manager", "vault.entry_moved",
					"Vault entry moved: moved-"+id+" (id: "+id+", from: collection c-team, to: personal vault)")
			},
			wantOwner: "",
			why: "adopt, then move out to personal, is the way a manager launders an adopted entry into " +
				"the class the migration trusts. The move is logged with the entry id, so it does not work",
		},
		{
			name: "a move row naming a DIFFERENT entry does not deny this one",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-victim", "unrelated-"+id, "")
				logRow(t, conn, "u-manager", "vault.entry_moved",
					"Vault entry moved: somebody-else (id: some-other-entry-id, from: personal vault, to: collection c-team)")
			},
			wantOwner: "u-victim",
			why: "the id match has to be exact, or the first move on the instance would deny every " +
				"personal entry and the migration would be a blanket outage wearing a proof",
		},
		{
			name: "THE LOG FORMAT THE CITED COMMIT ACTUALLY WROTE denies the row it names",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				// The laundering path, run entirely on a binary from
				// 2026-07-24 to 2026-07-26: created personal, moved INTO a
				// collection, adopted by a manager while vault.entry_adopted
				// did not exist yet, moved back OUT to personal.
				insertEntry(t, conn, id, "u-manager", "laundered-"+id, "")
				// VERBATIM from 4e9bd5ec, the commit both migrations cite as
				// their authority. Closing paren, no comma, no name, no
				// from/to. The first predicate asked for "(id: X," and could
				// not see either of these rows.
				logRow(t, conn, "u-manager", "vault.entry_moved",
					"Vault entry moved to collection (id: "+id+")")
				logRow(t, conn, "u-manager", "vault.entry_moved",
					"Vault entry moved to collection (id: "+id+")")
			},
			wantOwner: "",
			why: "this is the fixture that caught it. The entry is personal now, both of its move rows " +
				"are in the paren wording, and vault.entry_adopted did not exist when it was taken, so " +
				"a predicate reading the CURRENT wording sees an entry that has never been in a " +
				"collection and stamps u-manager: a non-creator, promoted to owner, in the column " +
				"nothing below an instance admin can move",
		},
		{
			name: "an entry NAMED with another entry's id is withheld, and that is the trade",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-victim", id, "")
				// The move detail carries the moved entry's NAME, and this
				// row's name is its own id, so a wording-independent match on
				// the bare id sees itself here.
				logRow(t, conn, "u-manager", "vault.entry_moved",
					"Vault entry moved: "+id+" (id: a-completely-different-id, from: personal vault, to: collection c-team)")
			},
			wantOwner: "",
			why: "the deliberate cost of not parsing the wording. In production an id is 32 fixed-width " +
				"hex characters, so hitting this takes NAMING an entry with another entry's id, which " +
				"is a self-inflicted denial of one row repaired by one admin claim. The alternative is " +
				"a predicate coupled to a prose string that has already been reworded once with nobody " +
				"noticing",
		},
		{
			name: "an adoption row naming this entry denies it even when it is personal now",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-manager", "adopted-then-personal-"+id, "")
				// The move row is missing: LogActivityFromRequest is best
				// effort and this is the residual the migration documents. The
				// adoption row is the SECOND, independent signal, and it is why
				// two rows have to be lost rather than one.
				logRow(t, conn, "u-manager", "vault.entry_adopted",
					"Entry "+id+" renamed and adopted by a collection manager (its creator has left the collection)")
			},
			wantOwner: "",
			why: "the two clauses are independent on purpose: the collection_id clause already implies " +
				"this one, and keeping it means a single lost audit insert is not enough to launder a row",
		},
		{
			name: "an entry with no custodian at all is denied rather than owned by nobody",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "", "orphan-"+id, "")
			},
			wantOwner: "",
			why: "user_id defaults to the empty string, and an empty owner is the value that DENIES, so " +
				"copying it is harmless but stating it is clearer",
		},
	}

	conn := openBefore(t)
	seedPeople(t, conn)

	ids := make([]string, len(cases))
	for i, c := range cases {
		id := fmt.Sprintf("e%02d", i)
		ids[i] = id
		c.seed(t, conn, id)
	}

	applyTheMigration(t, conn)

	stamped := 0
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ownerOf(t, conn, ids[i])
			if got != c.wantOwner {
				t.Errorf("entry %s (%s):\n  secret_owner_user_id = %q\n  want                 %q\n  %s",
					ids[i], c.name, got, c.wantOwner, c.why)
			}
		})
		if c.wantOwner != "" {
			stamped++
		}
	}

	// Both directions have to be exercised or the table proves nothing: a
	// migration that stamps NOTHING passes every deny case, and one that stamps
	// everything passes every keep case.
	if stamped < 2 {
		t.Fatalf("ABORT: only %d cases expect an owner to be stamped. A table with no positive control "+
			"is satisfied by a migration that does nothing", stamped)
	}
	if stamped >= len(cases) {
		t.Fatalf("ABORT: every case expects an owner, so this table cannot notice a migration that " +
			"stamps user_id unconditionally")
	}
}

// TestTheBackfillTellsTheOperatorItWithheldSomething is the other half of
// failing closed.
//
// A migration that strands secrets silently is its own outage. The operator has
// to be told, in the surface they already read, and the row has to name the page
// that repairs it.
func TestTheBackfillTellsTheOperatorItWithheldSomething(t *testing.T) {
	t.Run("it says so when something was withheld", func(t *testing.T) {
		conn := openBefore(t)
		seedPeople(t, conn)
		insertEntry(t, conn, "e-shared", "u-victim", "shared", "c-team")
		insertEntry(t, conn, "e-personal", "u-victim", "personal", "")
		applyTheMigration(t, conn)

		var detail string
		err := conn.QueryRow(
			`SELECT detail FROM activity_log WHERE action = 'vault.owner_backfill_withheld'`).Scan(&detail)
		if err != nil {
			t.Fatalf("no vault.owner_backfill_withheld row after a migration that withheld one entry: %v", err)
		}
		for _, want := range []string{"1", "no recorded secret owner", "Settings -> Ownership"} {
			if !strings.Contains(detail, want) {
				t.Errorf("the operator notice does not mention %q.\n  got: %s", want, detail)
			}
		}
	})

	t.Run("it stays quiet when nothing was withheld", func(t *testing.T) {
		conn := openBefore(t)
		seedPeople(t, conn)
		insertEntry(t, conn, "e-personal", "u-victim", "personal", "")
		applyTheMigration(t, conn)

		var n int
		if err := conn.QueryRow(
			`SELECT COUNT(*) FROM activity_log WHERE action = 'vault.owner_backfill_withheld'`).Scan(&n); err != nil {
			t.Fatalf("count notices: %v", err)
		}
		if n != 0 {
			t.Errorf("the migration wrote %d withheld-notice rows on a database where every entry was "+
				"stamped. An alarm that fires when nothing is wrong is an alarm nobody reads", n)
		}
	})

	t.Run("it stays quiet on a database that has never held an entry", func(t *testing.T) {
		// The FIRST-RUN case: goose applies every migration to an empty file
		// before the server has taken a single request.
		conn := openBefore(t)
		applyTheMigration(t, conn)
		var n int
		if err := conn.QueryRow(`SELECT COUNT(*) FROM activity_log`).Scan(&n); err != nil {
			t.Fatalf("count activity: %v", err)
		}
		if n != 0 {
			t.Errorf("a fresh install came up with %d activity rows; the migration is writing a notice "+
				"about nothing", n)
		}
	})
}

// TestTheMigrationAppliesToAFreshDatabase is the case the cross-version script
// covers on the wire and this one covers in isolation: 00034 running for the
// FIRST time, against a database that has never seen it.
func TestTheMigrationAppliesToAFreshDatabase(t *testing.T) {
	conn := openBefore(t)
	v, err := goose.GetDBVersion(conn)
	if err != nil {
		t.Fatalf("goose version: %v", err)
	}
	if v != beforeSecretOwner {
		t.Fatalf("ABORT: expected to be at version %d before applying, got %d", beforeSecretOwner, v)
	}
	applyTheMigration(t, conn)
}

// TestTheRepairMigrationUndoesTheLaunderedOwnership is 00035.
//
// 00034 is corrected in place, which is what a fresh database gets. That is
// worth nothing to a database that already applied the FIRST cut of it: goose
// records version 34 and never reads the file again, so the attacker stays the
// owner forever. 00035 re-derives the same rule so the correction reaches those
// databases too.
//
// The fixture is the honest one: apply 00034, then run the LAUNDERING statement
// by hand, which is byte-for-byte what the first cut did. That is the state a
// live instance would actually be in.
func TestTheRepairMigrationUndoesTheLaunderedOwnership(t *testing.T) {
	cases := []struct {
		name string
		// seed runs BEFORE any migration, against the pre-00034 schema.
		seed func(t *testing.T, conn *sql.DB, id string)
		// afterLaundering runs once the broken 00034 has been simulated, for the
		// cases that model a legitimate transfer happening in between.
		afterLaundering func(t *testing.T, conn *sql.DB, id string)
		wantOwner       string
		why             string
	}{
		{
			name: "THE LAUNDERED ATTACK is withdrawn",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-victim", "adopted-"+id, "c-team")
				mustExec(t, conn,
					`UPDATE vault_entries SET user_id = ? WHERE id = ?`, "u-manager", id)
				logRow(t, conn, "u-manager", "vault.entry_adopted",
					"Entry "+id+" renamed and adopted by a collection manager (its creator has left the collection)")
			},
			wantOwner: "",
			why: "the broken migration made the attacker the owner. 00035 is the only thing that can " +
				"reach a database where that already happened",
		},
		{
			name: "an entry the migration could prove KEEPS its owner",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-victim", "personal-"+id, "")
			},
			wantOwner: "u-victim",
			why: "00035 is the same rule as the corrected 00034, so on a database that ran the correct " +
				"one it must be a no-op. A repair that clears everything is safe and useless",
		},
		{
			name: "an ownership an ADMIN claimed through the product is left alone",
			seed: func(t *testing.T, conn *sql.DB, id string) {
				insertEntry(t, conn, id, "u-victim", "shared-"+id, "c-team")
			},
			afterLaundering: func(t *testing.T, conn *sql.DB, id string) {
				mustExec(t, conn,
					`UPDATE vault_entries SET user_id = ?, secret_owner_user_id = ? WHERE id = ?`,
					"u-admin", "u-admin", id)
				logRow(t, conn, "u-admin", "vault.ownership_claimed",
					"Entry "+id+": secret ownership claimed by admin u-admin (it had none)")
			},
			wantOwner: "u-admin",
			why: "clearing an owner an admin deliberately took would undo a decision rather than an " +
				"accident, and the claim writes an audit row naming the entry",
		},
	}

	conn := openBefore(t)
	seedPeople(t, conn)
	ids := make([]string, len(cases))
	for i, c := range cases {
		ids[i] = fmt.Sprintf("r%02d", i)
		c.seed(t, conn, ids[i])
	}

	// 00034 only, so the laundering below lands on exactly the schema the first
	// cut left behind.
	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.UpTo(conn, "migrations", secretOwnerVersion); err != nil {
		t.Fatalf("migrate to %d: %v", secretOwnerVersion, err)
	}

	// THE LAUNDERING, verbatim from the first cut of 00034.
	mustExec(t, conn, `UPDATE vault_entries SET secret_owner_user_id = user_id WHERE secret_owner_user_id = ''`)
	for i, c := range cases {
		if c.afterLaundering != nil {
			c.afterLaundering(t, conn, ids[i])
		}
	}
	// The control on the fixture: if the laundering did not actually take, the
	// repair below would have nothing to undo and would pass over anything.
	if got := ownerOf(t, conn, ids[0]); got != "u-manager" {
		t.Fatalf("ABORT: the laundering fixture did not put the attacker in the owner column (got %q). "+
			"Nothing below is testing a repair", got)
	}

	if err := goose.Up(conn, "migrations"); err != nil {
		t.Fatalf("goose up to the repair: %v", err)
	}
	v, err := goose.GetDBVersion(conn)
	if err != nil {
		t.Fatalf("goose version: %v", err)
	}
	if v < relaunderVersion {
		t.Fatalf("ABORT: the repair migration did not apply; database is at version %d", v)
	}

	kept := 0
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ownerOf(t, conn, ids[i]); got != c.wantOwner {
				t.Errorf("entry %s (%s):\n  secret_owner_user_id = %q\n  want                 %q\n  %s",
					ids[i], c.name, got, c.wantOwner, c.why)
			}
		})
		if c.wantOwner != "" {
			kept++
		}
	}
	if kept < 2 {
		t.Fatalf("ABORT: only %d cases expect an owner to survive the repair. A migration that clears "+
			"the column outright passes every attack case", kept)
	}
}

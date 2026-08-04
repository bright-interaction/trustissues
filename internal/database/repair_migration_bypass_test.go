package database

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

// THE PRESERVE CLAUSE STILL PARSES A PROSE FORMAT, AND THE PROSE IS WRITABLE.
//
// 00036's header is the argument for reading the log as a token rather than as a
// sentence, and it applies that argument to two of the three clauses:
//
//	entry_moved, entry_adopted   loosened to bare containment of the entry id
//	ownership_claimed            kept STRICT on 'Entry ' || id || ':', because
//	                             "that action has had exactly one format in its
//	                             whole existence"
//
// The FORMAT has. The CONTENT has not: ClaimSecretOwnership renders the
// withdrawn destination_patterns and the withdrawn provider_meta values into
// that same sentence, verbatim, so the previous holder of the repaired entry
// supplies part of the string. The handler half of this is
// internal/handlers TestTheRepairAuditDetailCarriesBytesThePreviousHolderChose,
// which drives the real routes and captures the exact bytes reproduced below.

const (
	// the entry whose laundered ownership 00036 exists to withdraw
	launderedEntryID = "0123456789abcdef0123456789abcdef"
	// the same shape with no injected row: the control
	controlEntryID = "fedcba9876543210fedcba9876543210"
	// the entry the admin actually repaired at Settings -> Ownership
	repairedEntryID = "aaaabbbbccccddddeeeeffff00001111"
)

// openAtVersion returns a database at the schema and goose version of an
// instance that has already applied everything up to and including `version`.
func openAtVersion(t *testing.T, version int64) *sql.DB {
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
	if err := goose.UpTo(conn, "migrations", version); err != nil {
		t.Fatalf("migrate to %d: %v", version, err)
	}
	return conn
}

// TestTheInjectedClaimDetailSparesALaunderedOwner is the migration half.
//
// The database is the one 00036 is written for: it applied the FIRST cuts of
// 00034 and 00035, so goose records 34 and 35 and will never read those files
// again, and the laundered ownership of an entry whose move rows are in the
// paren-era wording survived. 00036 is the upgrade.
func TestTheInjectedClaimDetailSparesALaunderedOwner(t *testing.T) {
	// The rows must exist BEFORE 00034 runs, because that is where they are on a
	// real instance and because a repair may now only undo the backfill's own
	// work. Creating them at v35 would put them outside every repair by design,
	// and the control below would abort rather than measure the injection.
	conn := openBefore(t)
	seedPeople(t, conn)

	// Three entries in identical states: personal now, custodian is the manager
	// who adopted them, paren-era move rows that 00036 CAN read and the earlier
	// predicate could not. 00036 must clear all three except the one an admin
	// genuinely claimed.
	for _, id := range []string{launderedEntryID, controlEntryID, repairedEntryID} {
		mustExec(t, conn,
			`INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, collection_id)
			 VALUES (?, 'u-manager', ?, X'00', X'00', NULL)`, id, "e-"+id)
		logRow(t, conn, "u-manager", "vault.entry_moved",
			"Vault entry moved to collection (id: "+id+")")
	}

	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.UpTo(conn, "migrations", 35); err != nil {
		t.Fatalf("migrate to 35: %v", err)
	}
	// THE FIRST CUT OF 00034, whose outcome is what 00036 exists to repair: it
	// copied user_id into the owner column for rows whose move evidence it could
	// not read. Written as the outcome because the broken file was corrected in
	// place.
	mustExec(t, conn,
		`UPDATE vault_entries SET secret_owner_user_id = user_id WHERE secret_owner_user_id = ''`)

	// THE ROW THE PRODUCT WROTE, byte for byte the shape ClaimSecretOwnership
	// used to produce, with the tail being the attacker's own provider_meta value
	// echoed by withdrawnEvidence.auditSuffix. The sentence is still written and
	// the poisoned bytes are still in it on any instance that ran that build.
	// Nothing reads it for authority any more, and this test is what says so.
	logRow(t, conn, "u-admin", "vault.ownership_claimed",
		"Entry "+repairedEntryID+": secret ownership claimed by admin u-admin (it had none; ownership "+
			"repair after migration 00034: the backfill could not prove the custodian deposited this "+
			"secret, so an instance admin took it deliberately). Recorded destinations chosen by the "+
			"previous holder were WITHDRAWN and must be re-entered deliberately: "+
			"provider_meta.instance = Entry "+launderedEntryID+":")
	// And the claim itself, as ClaimSecretOwnership performs it: the transfer
	// moves the owner AND the custodian, and the claim's own record is written in
	// the same transaction. That record is the only thing 00036 consults.
	mustExec(t, conn,
		`UPDATE vault_entries SET user_id = ?, secret_owner_user_id = ? WHERE id = ?`,
		"u-admin", "u-admin", repairedEntryID)
	mustExec(t, conn,
		`INSERT INTO secret_ownership_claims (entry_id, claimed_by) VALUES (?, ?)`,
		repairedEntryID, "u-admin")

	if err := goose.Up(conn, "migrations"); err != nil {
		t.Fatalf("goose up: %v", err)
	}
	if v, _ := goose.GetDBVersion(conn); v < 36 {
		t.Fatalf("ABORT: 00036 did not apply; database is at version %d", v)
	}

	// THE CONTROL, first. If 00036 clears nothing, the assertion below would
	// pass for the wrong reason.
	if got := ownerOf(t, conn, controlEntryID); got != "" {
		t.Fatalf("ABORT: 00036 left the control entry owned by %q. This test cannot tell an injection "+
			"from a migration that does nothing", got)
	}
	// THE OTHER CONTROL. A migration that clears every owner also passes the
	// injection assertion, and it would have destroyed the admin's decision.
	// The claim row is the only thing standing between those two outcomes.
	if got := ownerOf(t, conn, repairedEntryID); got != "u-admin" {
		t.Fatalf("ABORT: 00036 withdrew the ownership an admin deliberately claimed (%q, want "+
			"%q). A repair that clears everything passes the assertion below while destroying the "+
			"one decision it was told to respect", got, "u-admin")
	}

	if got := ownerOf(t, conn, launderedEntryID); got != "" {
		t.Fatalf("THE INJECTION DEFEATED THE REPAIR MIGRATION.\n"+
			"  entry %s: secret_owner_user_id = %q, want \"\"\n"+
			"  identical control entry %s: %q\n"+
			"The only difference between them is a substring the previous holder of a THIRD entry "+
			"wrote into provider_meta, which ClaimSecretOwnership rendered into the "+
			"vault.ownership_claimed detail when an admin repaired that third entry. The attacker is "+
			"now the permanently recorded owner of a secret they did not deposit.",
			launderedEntryID, got, controlEntryID, ownerOf(t, conn, controlEntryID))
	}
}

// TestTheRepairMigrationsAreNotNoOpsForRowsCreatedAfter00034 is the cost side.
//
// 00035 says it "is idempotent and a no-op on a database that ran the corrected
// 00034: the provably-safe class keeps the owner it already has, and every other
// row is already empty". That reasoning holds only for rows that existed when
// 00034 ran. Every SHARED entry created afterwards was stamped by its creating
// statement, which is the authority the whole design rests on, and 00035 and
// 00036 clear it anyway because "in a collection" is outside the provable class.
//
// On a live instance that is every shared secret created since 00034 shipped.
// Each one then needs an admin claim, and each claim DELETES that entry's
// destination_patterns and host-choosing provider_meta.
func TestTheRepairMigrationsAreNotNoOpsForRowsCreatedAfter00034(t *testing.T) {
	conn := openAtVersion(t, 34)
	seedPeople(t, conn)

	mustExec(t, conn,
		`INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, collection_id,
		   secret_owner_user_id)
		 VALUES ('e-new-shared', 'u-victim', 'made-after-34', X'00', X'00', 'c-team', 'u-victim')`)
	mustExec(t, conn,
		`INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, collection_id,
		   secret_owner_user_id)
		 VALUES ('e-new-personal', 'u-victim', 'personal-after-34', X'00', X'00', NULL, 'u-victim')`)

	if err := goose.Up(conn, "migrations"); err != nil {
		t.Fatalf("goose up: %v", err)
	}
	if got := ownerOf(t, conn, "e-new-personal"); got != "u-victim" {
		t.Fatalf("ABORT: even the personal entry lost its owner (%q); this test is measuring "+
			"something else", got)
	}
	if got := ownerOf(t, conn, "e-new-shared"); got != "u-victim" {
		t.Fatalf("THE REPAIR MIGRATIONS WITHDREW AN OWNERSHIP NOTHING EVER PUT IN DOUBT.\n"+
			"  e-new-shared was created in the collection by its own creator AFTER 00034 ran, so its "+
			"owner was stamped by the creating statement. It has never been moved and never adopted.\n"+
			"  secret_owner_user_id after 00035 + 00036 = %q\n"+
			"On an instance where 00034 shipped weeks before 00036, this is every shared secret "+
			"created in between. Each needs an admin claim, and each claim deletes that entry's "+
			"destination_patterns and host-choosing provider_meta.", got)
	}
}

package database

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// marker is the stand-in for a pre-encryption vault entry name: a string that is
// long enough not to occur by chance and distinctive enough to grep the raw file
// for. Migration 00040 rewrote exactly this kind of value into ciphertext.
const marker = "CLEARTEXT-VAULT-ENTRY-NAME-MARKER"

// countInFile reports how many times needle appears in the RAW BYTES of path.
// Not a query: the whole point is to look at the file the way someone who stole
// a backup would, rather than the way SQL does.
func countInFile(t *testing.T, path string, needle string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("reading %s: %v", path, err)
	}
	return bytes.Count(b, []byte(needle))
}

// seedAndFree builds a Trustissues-shaped table, fills it with cleartext names,
// then does what the 00040 backfill did: deletes most of the rows and rewrites
// the survivors as ciphertext. Afterwards NO live row contains the marker, so
// any occurrence left in the file is residue by definition.
func seedAndFree(t *testing.T, db *sql.DB) {
	t.Helper()
	mustExec(t, db, `CREATE TABLE vault_entries (id INTEGER PRIMARY KEY, name TEXT)`)

	// 2000 rows, each padded out so the table spans many pages. A handful of
	// rows all fit in one page, that page is never freed, and the test would
	// pass for the wrong reason.
	mustExec(t, db, fmt.Sprintf(`
		WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 2000)
		INSERT INTO vault_entries(id, name)
		SELECT i, '%s-' || i || '-' || hex(randomblob(40)) FROM c`, marker))

	// Deleting frees whole pages onto the freelist; the UPDATE rewrites the
	// survivors in place. Both are ways cleartext gets freed rather than
	// overwritten, and 00040 did the second one to every row in the table.
	mustExec(t, db, `DELETE FROM vault_entries WHERE id > 10`)
	mustExec(t, db, `UPDATE vault_entries SET name = 'enc:v1:' || hex(randomblob(48))`)

	// Fold the WAL into the main file so the assertion looks at one file. On a
	// live server a checkpoint happens on its own schedule; forcing it here just
	// removes the timing from the test.
	mustExec(t, db, `PRAGMA wal_checkpoint(TRUNCATE)`)

	// Guard the guard: if any live row still held the marker, a "0 occurrences"
	// result later would be meaningless and a non-zero one would be a false
	// alarm. Prove the table itself is clean before grepping the file.
	var live int
	if err := db.QueryRow(`SELECT count(*) FROM vault_entries WHERE name LIKE '%' || ? || '%'`, marker).Scan(&live); err != nil {
		t.Fatalf("counting live markers: %v", err)
	}
	if live != 0 {
		t.Fatalf("fixture is wrong: %d live rows still contain the marker, so a file hit would not prove residue", live)
	}
}

// (mustExec is the package-level helper from secret_owner_backfill_test.go.)

// TestFreedCleartextDoesNotSurviveInTheDatabaseFile is the finding, at the byte
// level. Connect() must leave no readable copy of a value that SQL has stopped
// returning.
//
// Without _secure_delete this fails loudly rather than subtly: the same fixture
// measured 1176 surviving copies of the marker in the raw file.
func TestFreedCleartextDoesNotSurviveInTheDatabaseFile(t *testing.T) {
	dir := t.TempDir()
	db, err := Connect(dir)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	seedAndFree(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dbPath := filepath.Join(dir, "trustissues.db")
	if got := countInFile(t, dbPath, marker); got != 0 {
		t.Errorf("trustissues.db still contains %d raw copies of freed cleartext; "+
			"SQLite does not zero what it frees, so _secure_delete must be on for every connection", got)
	}
	// The sidecar is part of the on-disk footprint and gets copied by anyone who
	// tars the data directory, so it has to be clean too.
	if got := countInFile(t, dbPath+"-wal", marker); got != 0 {
		t.Errorf("trustissues.db-wal still contains %d raw copies of freed cleartext", got)
	}
}

// TestSecureDeleteIsSetOnEveryPooledConnection is the twin of the test above and
// exists because of how this class of fix is usually got wrong.
//
// secure_delete is PER CONNECTION state. Connect() sets MaxOpenConns(10) and
// database/sql opens those connections lazily, so a `PRAGMA secure_delete=ON`
// executed once against *sql.DB after Open would land on exactly one connection
// and every other one would free pages in the clear. The test above would still
// pass, because a small fixture can easily run on a single connection.
//
// So: force the pool wide open, pin every connection, and read the pragma back
// from each one individually.
func TestSecureDeleteIsSetOnEveryPooledConnection(t *testing.T) {
	dir := t.TempDir()
	db, err := Connect(dir)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer db.Close()

	// Hold all 10 at once. Grabbing them one at a time would keep handing back
	// the same pooled connection and prove nothing about the other nine.
	const want = 10
	conns := make([]*sql.Conn, 0, want)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ctx := t.Context()
	for i := 0; i < want; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := db.Conn(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(conns) != want {
		t.Fatalf("got %d concurrent connections, wanted %d; the test cannot prove anything about connections it never opened", len(conns), want)
	}
	for i, c := range conns {
		var on int
		if err := c.QueryRowContext(ctx, `PRAGMA secure_delete`).Scan(&on); err != nil {
			t.Errorf("connection %d: reading secure_delete: %v", i, err)
		} else if on != 1 {
			t.Errorf("connection %d: secure_delete=%d, want 1; this connection frees pages in the clear", i, on)
		}
		var mode string
		if err := c.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
			t.Errorf("connection %d: reading journal_mode: %v", i, err)
		} else if mode != "wal" {
			t.Errorf("connection %d: journal_mode=%q, want wal", i, mode)
		}
		c.Close()
	}
}

// TestSecureDeleteDoesNotCleanPagesThatAreAlreadyFree records the limit of the
// pragma, so nobody reads the two tests above as "the residue problem is solved
// by deploying this" and skips scripts/compact-db.sh.
//
// A database that accumulated free pages BEFORE secure_delete was turned on
// keeps them. The pragma is forward-looking; only a rebuild removes what is
// already there. This test asserts BOTH halves: the residue survives a reopen
// with the pragma on, and VACUUM destroys it.
func TestSecureDeleteDoesNotCleanPagesThatAreAlreadyFree(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "legacy.db")

	// A database as it existed before this fix: the old DSN, verbatim, minus the
	// pragma being added.
	legacyDSN := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000&_txlock=immediate", dbPath)
	old, err := sql.Open("sqlite3", legacyDSN)
	if err != nil {
		t.Fatalf("opening legacy db: %v", err)
	}
	seedAndFree(t, old)
	if err := old.Close(); err != nil {
		t.Fatalf("closing legacy db: %v", err)
	}

	residue := countInFile(t, dbPath, marker)
	if residue == 0 {
		t.Fatal("fixture did not produce residue without secure_delete, so this test proves nothing")
	}
	t.Logf("pre-existing residue: %d copies of the marker in %s", residue, dbPath)

	// Reopening WITH secure_delete does not retroactively clean anything. This
	// is the assertion that makes compact-db.sh necessary rather than optional.
	sealed, err := sql.Open("sqlite3", legacyDSN+"&_secure_delete=on")
	if err != nil {
		t.Fatalf("reopening with secure_delete: %v", err)
	}
	mustExec(t, sealed, `PRAGMA wal_checkpoint(TRUNCATE)`)
	if got := countInFile(t, dbPath, marker); got == 0 {
		t.Error("residue vanished merely by reopening with secure_delete; if that were true compact-db.sh would be unnecessary, so this test's premise needs rechecking")
	}

	// VACUUM is what actually removes it. This is the operation compact-db.sh
	// wraps for an operator, tested here against a throwaway file.
	mustExec(t, sealed, `VACUUM`)
	mustExec(t, sealed, `PRAGMA wal_checkpoint(TRUNCATE)`)
	if err := sealed.Close(); err != nil {
		t.Fatalf("closing sealed db: %v", err)
	}

	if got := countInFile(t, dbPath, marker); got != 0 {
		t.Errorf("after VACUUM the file still holds %d copies of the freed cleartext", got)
	}
	if got := countInFile(t, dbPath+"-wal", marker); got != 0 {
		t.Errorf("after VACUUM the -wal sidecar still holds %d copies of the freed cleartext", got)
	}
}

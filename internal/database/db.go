package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// Connect opens a SQLite database connection with WAL mode, foreign keys,
// and a busy timeout configured. The database file is created inside dataDir
// if it does not already exist.
func Connect(dataDir string) (*sql.DB, error) {
	// Ensure the data directory exists
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "trustissues.db")
	// _txlock=immediate is load-bearing, not a tuning knob.
	//
	// database/sql's BeginTx issues a plain BEGIN, which SQLite treats as
	// DEFERRED: the transaction takes a READ snapshot on its first statement and
	// only tries to upgrade to the write lock later. If any other connection
	// committed in between, SQLite fails that upgrade with SQLITE_BUSY_SNAPSHOT
	// and does NOT invoke the busy handler, so _busy_timeout never applies and
	// the caller sees "database is locked" in about 150 microseconds.
	//
	// vault.Update is read-then-write for any request that does not carry
	// custom_fields (i.e. every partial save: a value-only paste from the
	// extension, an MCP write, a script). Measured on the real binary: a
	// value-only PUT failed 19 of 60 times under light parallelism and 13 of 25
	// against a single concurrent write, rolling the save back and leaving the
	// vault holding a credential the operator had just revoked upstream.
	//
	// It does not even need another save to collide with: the auth middleware
	// stamps sessions.last_used_at on EVERY authenticated request, so ordinary
	// read traffic is a committing writer.
	//
	// BEGIN IMMEDIATE takes the write lock up front, which is what makes
	// _busy_timeout cover it. The cost is that transactions serialize; for a
	// single-team vault with three write paths that is the right trade.
	//
	// _secure_delete=on is a confidentiality control, not a tuning knob either.
	//
	// SQLite does not zero what it frees. A deleted row's bytes, and the OLD
	// bytes of any row an UPDATE rewrote, stay verbatim in the page they used to
	// occupy; a page that empties out goes on the freelist still holding its
	// content. Measured on a 2000-row fixture: delete the rows, checkpoint, and
	// 1176 copies of the cleartext were still greppable in the raw .db file.
	//
	// That is the whole point of migration 00040. It encrypted vault entry names
	// at rest, and the backfill sweep rewrote every row, which freed the old
	// cleartext rather than overwriting it. The column reads as ciphertext and
	// the file still holds the plaintext. THREAT-MODEL treats an off-host backup
	// as a lower-trust location than the host, and the snapshot is a copy of this
	// file, so sealing the column while leaving the residue seals nothing.
	//
	// With this on, SQLite zeroes freed content as it is freed. The cost is extra
	// page writes on delete and on update-in-place; for a vault whose write
	// volume is a few saves a day that is not a trade worth thinking about.
	//
	// It goes in the DSN rather than in a `PRAGMA secure_delete=ON` after
	// sql.Open ON PURPOSE. secure_delete is per-connection state, and the pool
	// below opens up to 10 connections lazily, on whichever goroutine needs one.
	// A pragma executed once against the pool lands on ONE arbitrary connection
	// and every other connection frees pages in the clear, silently. The driver
	// applies DSN pragmas in its own connect path, so every connection the pool
	// ever opens gets it. TestSecureDeleteIsSetOnEveryPooledConnection pins that.
	//
	// This is forward-looking only: it zeroes pages as they are freed from now
	// on and does nothing about pages that are ALREADY free. The residue that
	// exists today needs a one-time rebuild of the file, which takes a write lock
	// and is an operator decision, not something to run on boot. That is
	// scripts/compact-db.sh. Backups are handled separately: scripts/backup.sh
	// uses VACUUM INTO, which never copies the freelist.
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000&_txlock=immediate&_secure_delete=on", dbPath)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Verify the connection is alive
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	// SQLite in WAL mode supports many concurrent readers and a single writer.
	// A pool of 1 turns any stuck handler into a full outage because every
	// request blocks waiting for the only connection. 10 gives readers room
	// and lets _busy_timeout (5s) serialize writers without head-of-line
	// blocking the entire app.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	slog.Info("connected to SQLite", "path", dbPath)
	return db, nil
}

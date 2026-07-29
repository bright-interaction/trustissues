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
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000&_txlock=immediate", dbPath)

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

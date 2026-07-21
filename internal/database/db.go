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
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000", dbPath)

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

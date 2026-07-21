package database

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// RunMigrations applies pending database migrations using goose. Migrations
// are embedded in the binary, so a deploy is always self-contained: boot the
// server and the schema catches up.
func RunMigrations(db *sql.DB) error {
	goose.SetBaseFS(embeddedMigrations)

	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("setting goose dialect: %w", err)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("running goose migrations: %w", err)
	}

	slog.Info("migrations complete")
	return nil
}

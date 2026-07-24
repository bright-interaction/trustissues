package shield

import (
	"context"
	"database/sql"
	"time"
)

// SQLStore is a Store implementation backed by *sql.DB using SQLite-
// flavored SQL. atomicsite + dockyard both run SQLite so they can use
// this directly. Postgres-backed services (brightcrm) provide their
// own pgx-flavored Store.
type SQLStore struct {
	DB *sql.DB
}

// NewSQLStore wraps the given *sql.DB. The shield_sessions and
// shield_tokens tables must already exist; this struct does not own
// the schema.
func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{DB: db}
}

const sqlTimeFormat = "2006-01-02 15:04:05"

func (s *SQLStore) InsertSession(ctx context.Context, id string, expiresAt time.Time) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO shield_sessions (id, expires_at) VALUES (?, ?)`,
		id, expiresAt.UTC().Format(sqlTimeFormat))
	return err
}

func (s *SQLStore) GetSession(ctx context.Context, id string) (time.Time, bool, error) {
	var raw string
	row := s.DB.QueryRowContext(ctx, `SELECT expires_at FROM shield_sessions WHERE id = ?`, id)
	switch err := row.Scan(&raw); err {
	case nil:
		t, perr := time.Parse(sqlTimeFormat, raw)
		if perr != nil {
			return time.Time{}, false, perr
		}
		return t.UTC(), true, nil
	case sql.ErrNoRows:
		return time.Time{}, false, nil
	default:
		return time.Time{}, false, err
	}
}

func (s *SQLStore) UpdateSessionExpiry(ctx context.Context, id string, expiresAt time.Time) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE shield_sessions SET last_seen = datetime('now'), expires_at = ? WHERE id = ?`,
		expiresAt.UTC().Format(sqlTimeFormat), id)
	return err
}

func (s *SQLStore) SweepExpiredSessions(ctx context.Context, before time.Time) error {
	_, err := s.DB.ExecContext(ctx,
		`DELETE FROM shield_sessions WHERE expires_at < ?`,
		before.UTC().Format(sqlTimeFormat))
	return err
}

func (s *SQLStore) InsertToken(ctx context.Context, sessionID, token, kind, hint, ciphertext string) error {
	// INSERT OR IGNORE makes the call idempotent: the same (kind,
	// value) tuple within a session yields a deterministic token id,
	// so a re-tokenize is a no-op rather than a PRIMARY KEY conflict.
	// The existing row's ciphertext is correct (HMAC over the same
	// inputs produced the same id), so we don't need REPLACE.
	_, err := s.DB.ExecContext(ctx,
		`INSERT OR IGNORE INTO shield_tokens (token, session_id, kind, hint, ciphertext) VALUES (?, ?, ?, ?, ?)`,
		token, sessionID, kind, hint, ciphertext)
	return err
}

func (s *SQLStore) GetTokenCiphertext(ctx context.Context, sessionID, token string) (string, bool, error) {
	var ct string
	row := s.DB.QueryRowContext(ctx,
		`SELECT ciphertext FROM shield_tokens WHERE token = ? AND session_id = ?`,
		token, sessionID)
	switch err := row.Scan(&ct); err {
	case nil:
		return ct, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, err
	}
}

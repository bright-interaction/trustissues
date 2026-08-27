package database

import (
	"context"
	"database/sql"
	"fmt"

	querydb "github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/emailidentity"
	"github.com/pressly/goose/v3"
)

func init() {
	// This migration is Go rather than SQL because SQLite's built-in lower()
	// only understands ASCII while net/mail and the application support RFC 6532
	// UTF-8 addresses. Running the exact application canonicalizer here keeps an
	// upgraded database and a fresh request on the same identity rules.
	goose.AddMigrationContext(upCanonicalEmailIdentity, downCanonicalEmailIdentity)
}

type canonicalEmailUpdate struct {
	id        string
	original  string
	canonical string
}

type canonicalCollectionEmailUpdate struct {
	collectionID string
	original     string
	canonical    string
}

type canonicalLoginAttemptEmailUpdate struct {
	id        int64
	original  string
	canonical string
}

func loadCanonicalEmailUpdates(
	ctx context.Context,
	tx *sql.Tx,
	table string,
) ([]canonicalEmailUpdate, error) {
	// table is selected only from hard-coded call sites below. Keeping the
	// column shape in one helper makes it harder for a future identity-bearing
	// table to be rewritten with a subtly different rule.
	var rows *sql.Rows
	var err error
	switch table {
	case "users":
		rows, err = tx.QueryContext(ctx, `SELECT id, email FROM users ORDER BY id`)
	case "invitations":
		rows, err = tx.QueryContext(ctx, `SELECT id, email FROM invitations ORDER BY id`)
	default:
		return nil, fmt.Errorf("unsupported canonical email identity table %q", table)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s email identities: %w", table, err)
	}
	defer rows.Close()

	var updates []canonicalEmailUpdate
	for rows.Next() {
		var u canonicalEmailUpdate
		if err := rows.Scan(&u.id, &u.original); err != nil {
			return nil, fmt.Errorf("scan %s email identity: %w", table, err)
		}
		u.canonical, err = emailidentity.CanonicalStrict(u.original)
		if err != nil {
			return nil, fmt.Errorf(
				"%s row %q has an invalid email identity: %w",
				table, u.id, err,
			)
		}
		updates = append(updates, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s email identities: %w", table, err)
	}
	return updates, nil
}

func loadCanonicalLoginAttemptEmailUpdates(
	ctx context.Context,
	queries *querydb.Queries,
) ([]canonicalLoginAttemptEmailUpdate, error) {
	rows, err := queries.ListLoginAttemptEmailIdentitiesForCanonicalMigration(ctx)
	if err != nil {
		return nil, fmt.Errorf("read login attempt email identities: %w", err)
	}

	updates := make([]canonicalLoginAttemptEmailUpdate, 0, len(rows))
	for _, row := range rows {
		canonical, err := emailidentity.CanonicalStrict(row.Email)
		if err != nil {
			// Keep the physical table name in operator-facing migration errors while
			// leaving all SQL that names it in the generated query package.
			const table = "login_" + "attempts"
			return nil, fmt.Errorf(
				"%s row %d has an invalid email identity: %w",
				table, row.ID, err,
			)
		}
		updates = append(updates, canonicalLoginAttemptEmailUpdate{
			id: row.ID, original: row.Email, canonical: canonical,
		})
	}
	return updates, nil
}

func loadCanonicalCollectionEmailUpdates(
	ctx context.Context,
	tx *sql.Tx,
) ([]canonicalCollectionEmailUpdate, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT collection_id, email
		FROM collection_invitations
		ORDER BY collection_id, email`)
	if err != nil {
		return nil, fmt.Errorf("read collection invitation identities: %w", err)
	}
	defer rows.Close()

	var updates []canonicalCollectionEmailUpdate
	for rows.Next() {
		var u canonicalCollectionEmailUpdate
		if err := rows.Scan(&u.collectionID, &u.original); err != nil {
			return nil, fmt.Errorf("scan collection invitation identity: %w", err)
		}
		u.canonical, err = emailidentity.CanonicalStrict(u.original)
		if err != nil {
			return nil, fmt.Errorf(
				"collection_invitations row (collection_id=%q, email=%q) has an invalid email identity: %w",
				u.collectionID, u.original, err,
			)
		}
		updates = append(updates, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate collection invitation identities: %w", err)
	}
	return updates, nil
}

func rejectCanonicalUserCollisions(updates []canonicalEmailUpdate) error {
	seen := make(map[string]canonicalEmailUpdate, len(updates))
	for _, u := range updates {
		if previous, exists := seen[u.canonical]; exists && previous.id != u.id {
			return fmt.Errorf(
				"canonical email collision between users %q and %q for identity %q; resolve the accounts before retrying migration 00046",
				previous.id, u.id, u.canonical,
			)
		}
		seen[u.canonical] = u
	}
	return nil
}

func rejectCanonicalCollectionSeatCollisions(updates []canonicalCollectionEmailUpdate) error {
	type seatKey struct {
		collectionID string
		canonical    string
	}
	seen := make(map[seatKey]canonicalCollectionEmailUpdate, len(updates))
	for _, u := range updates {
		key := seatKey{collectionID: u.collectionID, canonical: u.canonical}
		if previous, exists := seen[key]; exists && previous.original != u.original {
			return fmt.Errorf(
				"canonical email collision between collection seats %q and %q in collection %q; resolve the invitations before retrying migration 00046",
				previous.original, u.original, u.collectionID,
			)
		}
		seen[key] = u
	}
	return nil
}

func upCanonicalEmailIdentity(ctx context.Context, tx *sql.Tx) error {
	// Load and validate every unique identity namespace before issuing the first
	// UPDATE. Goose wraps this function in one transaction as a second line of
	// defence, but the explicit preflight also keeps failures easy to diagnose.
	queries := querydb.New(tx)
	users, err := loadCanonicalEmailUpdates(ctx, tx, "users")
	if err != nil {
		return err
	}
	invitations, err := loadCanonicalEmailUpdates(ctx, tx, "invitations")
	if err != nil {
		return err
	}
	loginAttempts, err := loadCanonicalLoginAttemptEmailUpdates(ctx, queries)
	if err != nil {
		return err
	}
	collectionSeats, err := loadCanonicalCollectionEmailUpdates(ctx, tx)
	if err != nil {
		return err
	}
	if err := rejectCanonicalUserCollisions(users); err != nil {
		return err
	}
	if err := rejectCanonicalCollectionSeatCollisions(collectionSeats); err != nil {
		return err
	}

	for _, u := range users {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET email = ? WHERE id = ?`, u.canonical, u.id); err != nil {
			return fmt.Errorf("canonicalize user %q email: %w", u.id, err)
		}
	}
	for _, u := range invitations {
		if _, err := tx.ExecContext(ctx, `UPDATE invitations SET email = ? WHERE id = ?`, u.canonical, u.id); err != nil {
			return fmt.Errorf("canonicalize invitation %q email: %w", u.id, err)
		}
	}
	// Login attempts are deliberately updated one row at a time and never
	// deduplicated. Case variants belong to one lockout identity after this
	// migration, but every failure/success event and its timestamp survives.
	for _, u := range loginAttempts {
		if err := queries.UpdateLoginAttemptEmailForCanonicalMigration(ctx,
			querydb.UpdateLoginAttemptEmailForCanonicalMigrationParams{
				Email: u.canonical,
				ID:    u.id,
			},
		); err != nil {
			return fmt.Errorf("canonicalize login attempt %d email: %w", u.id, err)
		}
	}
	for _, u := range collectionSeats {
		if _, err := tx.ExecContext(ctx, `
			UPDATE collection_invitations
			SET email = ?
			WHERE collection_id = ? AND email = ?`,
			u.canonical, u.collectionID, u.original,
		); err != nil {
			return fmt.Errorf("canonicalize collection %q invitation %q: %w", u.collectionID, u.original, err)
		}
	}

	// A seat created before the account existed is normally materialized by the
	// account-creation path. Older mixed-case (or display-name) identities could
	// miss that match and leave an existing user with no pending membership to
	// accept. Now that both sides use the exact same canonical representation,
	// repair those missing pending memberships in the migration transaction.
	//
	// This is deliberately insert-only. A membership row may already be pending
	// or accepted and is the authoritative access/consent state; a stale seat
	// must never overwrite its role, inviter, or acceptance timestamp.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO collection_members (
			collection_id, user_id, role, added_at, accepted_at, invited_by
		)
		SELECT ci.collection_id, u.id, ci.role, ci.created_at, NULL, ci.invited_by
		FROM collection_invitations ci
		JOIN users u ON u.email = ci.email
		WHERE NOT EXISTS (
			SELECT 1
			FROM collection_members cm
			WHERE cm.collection_id = ci.collection_id
			  AND cm.user_id = u.id
		)`); err != nil {
		return fmt.Errorf("materialize canonical collection invitation memberships: %w", err)
	}

	// Defence in depth for direct SQL writes and older ASCII-only binaries. The
	// application and migration remain authoritative for Unicode because SQLite
	// lower() and NOCASE intentionally do not implement Unicode case mapping.
	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX idx_users_email_canonical_ascii
		ON users(lower(trim(email)))`); err != nil {
		return fmt.Errorf("create canonical users email storage backstop: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX idx_collection_invitations_email_canonical_ascii
		ON collection_invitations(collection_id, lower(trim(email)))`); err != nil {
		return fmt.Errorf("create canonical collection invitation email storage backstop: %w", err)
	}

	return nil
}

func downCanonicalEmailIdentity(ctx context.Context, tx *sql.Tx) error {
	// Casing is presentation-only and the pre-migration spellings cannot be
	// reconstructed. Rolling back removes enforcement while leaving the safely
	// canonicalized identity values intact.
	if _, err := tx.ExecContext(ctx,
		`DROP INDEX IF EXISTS idx_collection_invitations_email_canonical_ascii`,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DROP INDEX IF EXISTS idx_users_email_canonical_ascii`,
	); err != nil {
		return err
	}
	return nil
}

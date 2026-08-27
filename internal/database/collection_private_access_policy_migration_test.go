package database

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

const collectionPrivateAccessPolicyVersion = 44

// TestCollectionPrivateAccessPolicyMigrationIsCompatibleAndClosed proves that
// deploying the optional private-access feature neither changes existing
// collection reachability nor permits an unenforceable fourth policy value.
func TestCollectionPrivateAccessPolicyMigrationIsCompatibleAndClosed(t *testing.T) {
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
	if err := goose.UpTo(conn, "migrations", collectionPrivateAccessPolicyVersion-1); err != nil {
		t.Fatalf("up to pre-policy schema: %v", err)
	}
	if columnExists(t, conn, "collections", "private_access_policy") {
		t.Fatal("ABORT: private_access_policy exists before migration 44")
	}

	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, name, role) VALUES (?, ?, ?, ?, ?)`,
		"policy-owner", "policy-owner@example.com", "hash", "Owner", "user")
	mustExec(t, conn,
		`INSERT INTO collections (id, name, created_by) VALUES (?, ?, ?)`,
		"pre-policy", "Pre-policy collection", "policy-owner")

	if err := goose.UpTo(conn, "migrations", collectionPrivateAccessPolicyVersion); err != nil {
		t.Fatalf("apply policy migration: %v", err)
	}
	if !columnExists(t, conn, "collections", "private_access_policy") {
		t.Fatal("private_access_policy is absent after migration 44")
	}

	var got string
	if err := conn.QueryRow(
		`SELECT private_access_policy FROM collections WHERE id = ?`, "pre-policy",
	).Scan(&got); err != nil {
		t.Fatalf("read migrated collection: %v", err)
	}
	if got != "standard" {
		t.Fatalf("pre-existing collection policy = %q, want compatibility default standard", got)
	}

	// Inserts from an older binary/query omit the column and must remain valid.
	mustExec(t, conn,
		`INSERT INTO collections (id, name, created_by) VALUES (?, ?, ?)`,
		"post-policy-legacy-write", "Legacy write", "policy-owner")
	if err := conn.QueryRow(
		`SELECT private_access_policy FROM collections WHERE id = ?`, "post-policy-legacy-write",
	).Scan(&got); err != nil {
		t.Fatalf("read legacy-shaped write: %v", err)
	}
	if got != "standard" {
		t.Fatalf("legacy-shaped write policy = %q, want standard", got)
	}

	for _, valid := range []string{"standard", "sensitive_private", "fully_private"} {
		if _, err := conn.Exec(
			`UPDATE collections SET private_access_policy = ? WHERE id = ?`, valid, "pre-policy",
		); err != nil {
			t.Fatalf("valid policy %q rejected: %v", valid, err)
		}
	}
	var latch string
	if err := conn.QueryRow(
		`SELECT value FROM settings WHERE key = 'private_access_audit_ever_fully_private'`,
	).Scan(&latch); err != nil {
		t.Fatalf("fully-private policy did not set historical audit latch: %v", err)
	}
	if latch != "1" {
		t.Fatalf("historical audit latch = %q, want 1", latch)
	}

	// Downgrading or deleting the source collection cannot make append-only
	// activity/capability history public again. The latch is database-owned and
	// resists accidental maintenance writes as well as application bugs.
	mustExec(t, conn,
		`UPDATE collections SET private_access_policy = 'standard' WHERE id = 'pre-policy'`)
	mustExec(t, conn, `DELETE FROM collections WHERE id = 'pre-policy'`)
	if err := conn.QueryRow(
		`SELECT value FROM settings WHERE key = 'private_access_audit_ever_fully_private'`,
	).Scan(&latch); err != nil || latch != "1" {
		t.Fatalf("historical audit latch after downgrade/delete = %q, err=%v; want 1", latch, err)
	}
	if _, err := conn.Exec(
		`UPDATE settings SET value = '0' WHERE key = 'private_access_audit_ever_fully_private'`,
	); err == nil {
		t.Fatal("database allowed the historical audit latch to be downgraded")
	}
	if _, err := conn.Exec(
		`DELETE FROM settings WHERE key = 'private_access_audit_ever_fully_private'`,
	); err == nil {
		t.Fatal("database allowed the historical audit latch to be deleted")
	}
	if _, err := conn.Exec(
		`UPDATE collections SET private_access_policy = 'almost_private' WHERE id = 'post-policy-legacy-write'`,
	); err == nil {
		t.Fatal("database accepted an unknown collection private-access policy")
	}
	if _, err := conn.Exec(
		`INSERT INTO collections (id, name, private_access_policy) VALUES ('invalid-policy', 'Invalid', '')`,
	); err == nil {
		t.Fatal("database accepted a blank collection private-access policy")
	}

	// ALTER TABLE ADD COLUMN must have a real inverse: operators need to be able
	// to roll back and then re-apply the release without a duplicate-column error.
	if err := goose.DownTo(conn, "migrations", collectionPrivateAccessPolicyVersion-1); err != nil {
		t.Fatalf("roll policy migration back: %v", err)
	}
	if columnExists(t, conn, "collections", "private_access_policy") {
		t.Fatal("private_access_policy survived migration rollback")
	}
	if err := conn.QueryRow(
		`SELECT value FROM settings WHERE key = 'private_access_audit_ever_fully_private'`,
	).Scan(&latch); err != sql.ErrNoRows {
		t.Fatalf("historical audit latch survived migration rollback: value=%q err=%v", latch, err)
	}
	if err := goose.UpTo(conn, "migrations", collectionPrivateAccessPolicyVersion); err != nil {
		t.Fatalf("re-apply policy migration: %v", err)
	}
}

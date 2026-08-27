package database

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

const vaultNameScopeVersion = 45

func TestVaultNameScopeMigrationEnforcesPersonalAndCollectionNamespaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.db")
	conn, err := sql.Open("sqlite3", "file:"+path+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.UpTo(conn, "migrations", vaultNameScopeVersion-1); err != nil {
		t.Fatalf("up to pre-scope schema: %v", err)
	}

	for _, user := range []string{"scope-a", "scope-b"} {
		mustExec(t, conn, `INSERT INTO users (id,email,password_hash,name,role) VALUES (?,?,?,?,?)`,
			user, user+"@example.com", "hash", user, "user")
	}
	for _, collection := range []string{"scope-c1", "scope-c2"} {
		mustExec(t, conn, `INSERT INTO collections (id,name,created_by) VALUES (?,?,?)`,
			collection, collection, "scope-a")
	}
	insert := func(id, user, collection, token string) error {
		var coll any
		if collection != "" {
			coll = collection
		}
		_, err := conn.Exec(`INSERT INTO vault_entries
(id,user_id,secret_owner_user_id,name,name_bidx,collection_id,encrypted_value,nonce,encryption_version)
VALUES (?,?,?,?,?,?,X'01',X'02',2)`, id, user, user, "enc:v1:"+id, token, coll)
		return err
	}

	// Tokens written by 00040 were custodian-scoped and therefore distinct.
	for _, row := range []struct{ id, user, collection, token string }{
		{"legacy-personal", "scope-a", "", "legacy-personal-token"},
		{"legacy-c1-a", "scope-a", "scope-c1", "legacy-c1-a-token"},
		{"legacy-c1-b", "scope-b", "scope-c1", "legacy-c1-b-token"},
	} {
		if err := insert(row.id, row.user, row.collection, row.token); err != nil {
			t.Fatalf("insert pre-migration row %s: %v", row.id, err)
		}
	}
	if err := goose.UpTo(conn, "migrations", vaultNameScopeVersion); err != nil {
		t.Fatalf("apply name-scope migration: %v", err)
	}

	// The same logical name token is legal in unrelated scopes.
	const token = "same-opened-name-in-different-scopes"
	if err := insert("new-personal-a", "scope-a", "", token); err != nil {
		t.Fatalf("insert personal scoped name: %v", err)
	}
	if err := insert("new-c1-a", "scope-a", "scope-c1", token); err != nil {
		t.Fatalf("same user/name in collection was incorrectly joined to personal scope: %v", err)
	}
	if err := insert("new-c2-a", "scope-a", "scope-c2", token); err != nil {
		t.Fatalf("same user/name in a second collection was incorrectly joined to c1: %v", err)
	}
	if err := insert("new-personal-b", "scope-b", "", token); err != nil {
		t.Fatalf("same name in another user's personal vault was rejected: %v", err)
	}

	if err := insert("duplicate-personal-a", "scope-a", "", token); err == nil {
		t.Fatal("same user/name was accepted twice in one personal vault")
	}
	if err := insert("duplicate-c1-b", "scope-b", "scope-c1", token); err == nil {
		t.Fatal("same collection/name was accepted for a second custodian")
	}

	for _, index := range []string{
		"idx_vault_entries_personal_name_bidx",
		"idx_vault_entries_collection_name_bidx",
	} {
		var count int
		if err := conn.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&count); err != nil || count != 1 {
			t.Fatalf("index %s count=%d err=%v", index, count, err)
		}
	}

	// Remove deliberately synthetic equal cross-scope tokens before rollback;
	// real HMAC tokens include their scope and therefore differ here.
	mustExec(t, conn, `DELETE FROM vault_entries WHERE id LIKE 'new-%'`)
	if err := goose.DownTo(conn, "migrations", vaultNameScopeVersion-1); err != nil {
		t.Fatalf("roll name-scope migration back: %v", err)
	}
	if err := goose.UpTo(conn, "migrations", vaultNameScopeVersion); err != nil {
		t.Fatalf("re-apply name-scope migration: %v", err)
	}
}

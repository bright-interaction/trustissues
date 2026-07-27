package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
)

// newVaultTestDB opens an in-memory SQLite database with the vault schema
// (migration 00010) plus a minimal users table, for handler-level tests.
func newVaultTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	schema := `
	CREATE TABLE users (
		id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		name TEXT,
		role TEXT NOT NULL DEFAULT 'user',
		disabled INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE vault_entries (
		id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
		user_id TEXT NOT NULL DEFAULT '',
		name TEXT NOT NULL,
		encrypted_value BLOB NOT NULL,
		nonce BLOB NOT NULL,
		category TEXT DEFAULT '',
		notes TEXT DEFAULT '',
		rotation_interval_days INTEGER,
		expires_at DATETIME,
		last_rotated_at DATETIME,
		url TEXT DEFAULT '',
		username TEXT DEFAULT '',
		encryption_version INTEGER DEFAULT 2,
		alias_url TEXT DEFAULT '',
		auto_login INTEGER NOT NULL DEFAULT 0,
		provider TEXT DEFAULT '',
		provider_meta TEXT DEFAULT '{}',
		auto_rotate INTEGER DEFAULT 0,
		rotation_log TEXT DEFAULT '[]',
		last_rotation_error TEXT DEFAULT '',
		rotation_targets TEXT DEFAULT '[]',
		destination_patterns TEXT NOT NULL DEFAULT '[]',
		injection_spec TEXT NOT NULL DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, name)
	);
	CREATE INDEX idx_vault_entries_url ON vault_entries(url) WHERE url != '';
	CREATE INDEX idx_vault_entries_user ON vault_entries(user_id);
	`
	if _, err := conn.Exec(schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	return conn
}

// newTestVaultHandler builds a VaultHandler wired to an in-memory database.
func newTestVaultHandler(t *testing.T) (*VaultHandler, *sql.DB) {
	t.Helper()
	conn := newVaultTestDB(t)
	queries := db.New(conn)
	vh := NewVaultHandler(conn, queries, &config.Config{VaultKey: "test-vault-key"})
	return vh, conn
}

// TestVaultEncryptDecryptRoundTrip locks the core secret path: encrypt
// produces a fresh nonce per call and decrypt reverses it exactly, and
// DecryptValue with encVersion 2 matches.
func TestVaultEncryptDecryptRoundTrip(t *testing.T) {
	vh := NewVaultHandler(nil, nil, &config.Config{VaultKey: "test-vault-key"})

	plaintext := []byte("sup3r-s3cret-api-key")
	ct1, n1, err := vh.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct2, n2, err := vh.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}
	if string(n1) == string(n2) {
		t.Fatal("nonce reuse across encrypt calls")
	}
	if string(ct1) == string(plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	dec, err := vh.decrypt(ct1, n1)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(dec) != string(plaintext) {
		t.Fatalf("round-trip mismatch: %q", dec)
	}

	dec2, err := vh.DecryptValue(ct2, n2, 2)
	if err != nil || string(dec2) != string(plaintext) {
		t.Fatalf("DecryptValue v2 mismatch: %q (err %v)", dec2, err)
	}

	// A different key must not decrypt.
	other := NewVaultHandler(nil, nil, &config.Config{VaultKey: "other-key-material"})
	if _, err := other.decrypt(ct1, n1); err == nil {
		t.Fatal("decrypt succeeded with wrong key")
	}
}

// TestDecryptRejectsMalformedNonce guards the manual-rotate crash backstop:
// gcm.Open PANICS on a wrong-length (e.g. nil/empty) nonce, which chi's
// Recoverer turns into a bare HTTP 500. decrypt / decryptWithKey must instead
// return a handled error for any nonce that is not exactly gcm.NonceSize().
func TestDecryptRejectsMalformedNonce(t *testing.T) {
	vh := NewVaultHandler(nil, nil, &config.Config{VaultKey: "test-vault-key"})
	ct, goodNonce, err := vh.encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for _, bad := range [][]byte{nil, {}, {0x00}, make([]byte, len(goodNonce)-1), make([]byte, len(goodNonce)+1)} {
		if _, err := vh.decrypt(ct, bad); err == nil {
			t.Fatalf("decrypt accepted malformed nonce (len=%d), want error", len(bad))
		}
	}

	// decryptWithKey (the legacy-key path) shares the same guard.
	var key [32]byte
	if _, err := decryptWithKey(key, ct, nil); err == nil {
		t.Fatal("decryptWithKey accepted nil nonce, want error")
	}

	// Sanity: the correct nonce still round-trips.
	if _, err := vh.decrypt(ct, goodNonce); err != nil {
		t.Fatalf("decrypt with valid nonce failed: %v", err)
	}
}

// encryptWithKeyForTest mirrors the internal AES-256-GCM encryption with an
// explicit key, used to seed legacy v1 rows.
func encryptWithKeyForTest(t *testing.T, key [32]byte, plaintext []byte) (ciphertext, nonce []byte) {
	t.Helper()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce
}

// TestMigrateEncryption seeds a legacy v1 (SHA-256 key) entry and proves the
// startup migration re-encrypts it under the PBKDF2 key with version 2.
func TestMigrateEncryption(t *testing.T) {
	vh, conn := newTestVaultHandler(t)

	secret := []byte("legacy-v1-secret")
	ct, nonce := encryptWithKeyForTest(t, vh.legacyKey, secret)
	if _, err := conn.Exec(`INSERT INTO vault_entries
		(id, user_id, name, encrypted_value, nonce, encryption_version)
		VALUES ('legacy-1', 'u1', 'legacy-entry', ?, ?, 1)`, ct, nonce); err != nil {
		t.Fatalf("seed v1 row: %v", err)
	}

	if err := vh.MigrateEncryption(); err != nil {
		t.Fatalf("MigrateEncryption: %v", err)
	}

	var version int
	var newCT, newNonce []byte
	if err := conn.QueryRow(`SELECT encryption_version, encrypted_value, nonce FROM vault_entries WHERE id = 'legacy-1'`).
		Scan(&version, &newCT, &newNonce); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if version != 2 {
		t.Fatalf("encryption_version = %d, want 2", version)
	}
	dec, err := vh.DecryptValue(newCT, newNonce, 2)
	if err != nil || string(dec) != string(secret) {
		t.Fatalf("migrated value round-trip failed: %q (err %v)", dec, err)
	}

	// Idempotent: nothing left to migrate.
	if err := vh.MigrateEncryption(); err != nil {
		t.Fatalf("second MigrateEncryption: %v", err)
	}
}

// TestComputeRotationStatus covers the expiry/interval state machine.
func TestComputeRotationStatus(t *testing.T) {
	intPtr := func(v int) *int { return &v }
	strPtr := func(s string) *string { return &s }
	now := time.Now().UTC()
	fmtTime := func(t time.Time) *string {
		s := t.Format("2006-01-02 15:04:05")
		return &s
	}

	cases := []struct {
		name     string
		days     *int
		expires  *string
		lastRot  *string
		expected string
	}{
		{"no interval no expiry", nil, nil, nil, "fresh"},
		{"expired datetime", nil, fmtTime(now.Add(-24 * time.Hour)), nil, "expired"},
		{"expired rfc3339", nil, strPtr(now.Add(-time.Hour).Format(time.RFC3339)), nil, "expired"},
		{"future expiry", nil, fmtTime(now.Add(240 * time.Hour)), nil, "fresh"},
		{"interval never rotated", intPtr(30), nil, nil, "fresh"},
		{"interval recently rotated", intPtr(30), nil, fmtTime(now.Add(-24 * time.Hour)), "fresh"},
		{"interval due soon", intPtr(30), nil, fmtTime(now.Add(-25 * 24 * time.Hour)), "due_soon"},
		{"interval overdue", intPtr(30), nil, fmtTime(now.Add(-40 * 24 * time.Hour)), "overdue"},
		{"zero interval", intPtr(0), nil, fmtTime(now.Add(-400 * 24 * time.Hour)), "fresh"},
		{"unparseable last rotated", intPtr(30), nil, strPtr("not-a-time"), "fresh"},
	}
	for _, tc := range cases {
		if got := computeRotationStatus(tc.days, tc.expires, tc.lastRot, nil); got != tc.expected {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.expected)
		}
	}
}

// TestSharedNullHelpers covers the package-wide converters vault.go defines.
func TestSharedNullHelpers(t *testing.T) {
	if boolToInt64(true) != 1 || boolToInt64(false) != 0 {
		t.Fatal("boolToInt64 broken")
	}
	if nullInt64ToIntPtr(sql.NullInt64{}) != nil {
		t.Fatal("nullInt64ToIntPtr on invalid should be nil")
	}
	if v := nullInt64ToIntPtr(sql.NullInt64{Int64: 7, Valid: true}); v == nil || *v != 7 {
		t.Fatal("nullInt64ToIntPtr round-trip broken")
	}
	if intPtrToNullInt64(nil).Valid {
		t.Fatal("intPtrToNullInt64(nil) should be invalid")
	}
	seven := 7
	if got := intPtrToNullInt64(&seven); !got.Valid || got.Int64 != 7 {
		t.Fatal("intPtrToNullInt64 round-trip broken")
	}
	if stringPtrToNullTime(nil).Valid {
		t.Fatal("stringPtrToNullTime(nil) should be invalid")
	}
	for _, in := range []string{"2026-07-20 10:00:00", "2026-07-20T10:00:00Z", "2026-07-20"} {
		s := in
		if got := stringPtrToNullTime(&s); !got.Valid {
			t.Fatalf("stringPtrToNullTime failed to parse %q", in)
		}
	}
	bad := "garbage"
	if stringPtrToNullTime(&bad).Valid {
		t.Fatal("stringPtrToNullTime should reject garbage")
	}
	if nullTimePtr(sql.NullTime{}) != nil {
		t.Fatal("nullTimePtr on invalid should be nil")
	}
	tok, err := generateToken(32)
	if err != nil || len(tok) != 64 {
		t.Fatalf("generateToken: %q (err %v)", tok, err)
	}
}

// TestResolveReferences proves {{vault:NAME}} substitution is scoped to the
// owning user and leaves unknown references untouched.
func TestResolveReferences(t *testing.T) {
	vh, conn := newTestVaultHandler(t)

	ct, nonce, err := vh.encrypt([]byte("resolved-secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce)
		VALUES ('e1', 'user-a', 'MY_TOKEN', ?, ?)`, ct, nonce); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := vh.ResolveReferences("token={{vault:MY_TOKEN}}", "user-a")
	if out != "token=resolved-secret" {
		t.Fatalf("resolve for owner failed: %q", out)
	}

	// Another user's reference does not resolve (per-user scoping).
	out = vh.ResolveReferences("token={{vault:MY_TOKEN}}", "user-b")
	if out != "token={{vault:MY_TOKEN}}" {
		t.Fatalf("cross-user reference resolved: %q", out)
	}

	// Unknown name passes through.
	out = vh.ResolveReferences("x={{vault:NOPE}}", "user-a")
	if out != "x={{vault:NOPE}}" {
		t.Fatalf("unknown reference mutated: %q", out)
	}

	// Empty userID skips resolution entirely.
	out = vh.ResolveReferences("token={{vault:MY_TOKEN}}", "")
	if out != "token={{vault:MY_TOKEN}}" {
		t.Fatalf("empty user resolved: %q", out)
	}
}

package handlers

import (
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
)

// TestColumnCryptoRoundTrip locks the core invariant: encryptColumn produces a
// prefixed self-describing ciphertext that decryptColumn reverses exactly, and
// both helpers are idempotent (encrypt never double-wraps, decrypt passes
// cleartext through).
func TestColumnCryptoRoundTrip(t *testing.T) {
	vh := NewVaultHandler(nil, nil, &config.Config{VaultKey: "test-vault-key"})

	cases := []string{
		`{"key_id":"abc-123","account_id":"acct_999"}`,
		`[{"type":"webhook","webhook_url":"https://x","webhook_secret":"s3cr3t-hmac"}]`,
		"plain text",
	}
	for _, in := range cases {
		enc, err := vh.encryptColumn(in)
		if err != nil {
			t.Fatalf("encrypt %q: %v", in, err)
		}
		if !strings.HasPrefix(enc, vaultColumnEncPrefix) {
			t.Fatalf("ciphertext missing prefix: %q", enc)
		}
		if strings.Contains(enc, "s3cr3t-hmac") || strings.Contains(enc, "key_id") {
			t.Fatalf("cleartext leaked into ciphertext: %q", enc)
		}
		// encryptColumn is deliberately NOT content-idempotent: re-encrypting a
		// ciphertext wraps it again. See TestEncryptColumnIsNotADecryptionOracle.
		enc2, err := vh.encryptColumn(enc)
		if err != nil || enc2 == enc {
			t.Fatalf("encryptColumn must re-encrypt, not pass through: %q -> %q (err %v)", enc, enc2, err)
		}
		// The storage-side variant IS idempotent (backfill safety).
		encIf, err := vh.encryptColumnIfNeeded(enc)
		if err != nil || encIf != enc {
			t.Fatalf("encryptColumnIfNeeded not idempotent: %q -> %q (err %v)", enc, encIf, err)
		}
		dec, err := vh.decryptColumn(enc)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if dec != in {
			t.Fatalf("round-trip mismatch: got %q want %q", dec, in)
		}
	}

	// decryptColumn on cleartext (pre-migration row) returns it unchanged.
	if out, err := vh.decryptColumn(`{"still":"cleartext"}`); err != nil || out != `{"still":"cleartext"}` {
		t.Fatalf("decrypt cleartext passthrough failed: %q (err %v)", out, err)
	}
	// Empty input has nothing to protect and passes through; the empty-JSON
	// defaults are only skipped on the STORAGE side (encryptColumnIfNeeded).
	if out, _ := vh.encryptColumn(""); out != "" {
		t.Fatalf("encryptColumn should skip empty, got %q", out)
	}
	for _, empty := range []string{"", "{}", "[]"} {
		if out, _ := vh.encryptColumnIfNeeded(empty); out != empty {
			t.Fatalf("encryptColumnIfNeeded should skip %q, got %q", empty, out)
		}
	}
}

// TestEncryptColumnIsNotADecryptionOracle is the regression lock for the
// critical flaw where encryptColumn passed through any input that already
// carried the enc:v1 prefix. That let an attacker who held ciphertext from an
// offline DB copy submit it as a notes/url field and read back the plaintext,
// decrypted with the server's vault key: a universal decryption oracle that
// defeated at-rest encryption for every user's secrets.
//
// The invariant: a client-supplied string that LOOKS like ciphertext must be
// treated as opaque data and encrypted, so reading it back yields the attacker's
// own literal string, never the plaintext of the ciphertext they injected.
func TestEncryptColumnIsNotADecryptionOracle(t *testing.T) {
	vh := NewVaultHandler(nil, nil, &config.Config{VaultKey: "test-vault-key"})

	// A victim secret encrypted under the server key, as it sits in the DB.
	victim := "TOP_SECRET_ADMIN_ROOT_PW_9f3a"
	stolen, err := vh.encryptColumn(victim)
	if err != nil {
		t.Fatalf("seed victim ciphertext: %v", err)
	}

	// The attacker submits that ciphertext verbatim as their own field value.
	stored, err := vh.encryptColumn(stolen)
	if err != nil {
		t.Fatalf("encrypt attacker input: %v", err)
	}
	if stored == stolen {
		t.Fatal("ORACLE: attacker ciphertext was stored verbatim instead of being encrypted")
	}

	// Reading it back must yield the attacker's own input, not the victim secret.
	out, err := vh.decryptColumn(stored)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if out == victim {
		t.Fatalf("ORACLE: server decrypted injected ciphertext and leaked %q", out)
	}
	if out != stolen {
		t.Fatalf("round-trip mismatch: got %q want the attacker's literal input", out)
	}
	if strings.Contains(out, victim) {
		t.Fatalf("ORACLE: victim plaintext surfaced in %q", out)
	}
}

// TestBackfillMetadataEncryption is the migration dry-run: seed representative
// cleartext rows (as an older binary wrote them, including a real webhook
// secret), run the backfill, and prove every non-default column is now
// ciphertext at rest, decrypts back to the original, and that a second run is a
// no-op.
func TestBackfillMetadataEncryption(t *testing.T) {
	conn := newVaultTestDB(t)
	queries := db.New(conn)
	vh := NewVaultHandler(conn, queries, &config.Config{VaultKey: "test-vault-key"})

	const secretTargets = `[{"type":"webhook","webhook_url":"https://hook.example","webhook_secret":"TOP-SECRET-HMAC"}]`
	const meta = `{"key_id":"live-key-1","account_id":"acct_42"}`

	seed := func(id, pm, rt string) {
		enc, nonce, err := vh.EncryptValue([]byte("v"))
		if err != nil {
			t.Fatalf("encrypt seed value: %v", err)
		}
		if _, err := conn.Exec(`INSERT INTO vault_entries
			(id, name, encrypted_value, nonce, encryption_version, provider_meta, rotation_targets)
			VALUES (?, ?, ?, ?, 2, ?, ?)`, id, "e-"+id, enc, nonce, pm, rt); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("row-secret", meta, secretTargets) // both columns hold real cleartext
	seed("row-empty", "{}", "[]")           // empty defaults, must be left alone

	n, err := vh.BackfillMetadataEncryption()
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if n != 2 { // provider_meta + rotation_targets of row-secret
		t.Fatalf("backfill encrypted %d columns, want 2", n)
	}

	// At rest: the row's columns are now prefixed ciphertext with no cleartext.
	var pmRaw, rtRaw string
	if err := conn.QueryRow(`SELECT provider_meta, rotation_targets FROM vault_entries WHERE id='row-secret'`).
		Scan(&pmRaw, &rtRaw); err != nil {
		t.Fatalf("read row-secret: %v", err)
	}
	for _, raw := range []string{pmRaw, rtRaw} {
		if !strings.HasPrefix(raw, vaultColumnEncPrefix) {
			t.Fatalf("column not encrypted at rest: %q", raw)
		}
	}
	if strings.Contains(rtRaw, "TOP-SECRET-HMAC") || strings.Contains(pmRaw, "live-key-1") {
		t.Fatal("cleartext secret still present at rest after backfill")
	}
	// Decrypt round-trips to the originals.
	if got := vh.decryptColumnOrLog(pmRaw, "{}", "provider_meta"); got != meta {
		t.Fatalf("provider_meta round-trip: %q", got)
	}
	if got := vh.decryptColumnOrLog(rtRaw, "[]", "rotation_targets"); got != secretTargets {
		t.Fatalf("rotation_targets round-trip: %q", got)
	}

	// Empty-default row untouched.
	var emptyPM, emptyRT string
	if err := conn.QueryRow(`SELECT provider_meta, rotation_targets FROM vault_entries WHERE id='row-empty'`).
		Scan(&emptyPM, &emptyRT); err != nil {
		t.Fatalf("read row-empty: %v", err)
	}
	if emptyPM != "{}" || emptyRT != "[]" {
		t.Fatalf("empty-default row was modified: %q / %q", emptyPM, emptyRT)
	}

	// Idempotent: a second backfill encrypts nothing.
	if n2, err := vh.BackfillMetadataEncryption(); err != nil || n2 != 0 {
		t.Fatalf("second backfill not a no-op: n=%d err=%v", n2, err)
	}
}

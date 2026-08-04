package columncrypto

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

const testKey = "test-vault-key-with-enough-entropy-0123456789"

// testField is a declared field for this package's own round-trip tests.
//
// DecryptString demands one because it is a decryption, and a declaration is
// what puts a column in the ledger. Declaring one from a _test.go file is
// allowed and cannot be used to satisfy the production ledger:
// TestTheLedgerIsDeclaredByProductionCode fails on any entry whose declaration
// site ends in _test.go.
var testField = vaultfield.Declare(
	"columncrypto_test.roundtrip", vaultfield.InProcessOnly, "",
	"a declaration used only by this package's own round-trip tests. It opens no real column and exists "+
		"because the decrypt entry point refuses the zero Field.")

// TestRoundTripPreservesEveryInputShape covers the values this package actually
// holds: TOTP seeds, SMTP passwords, notification channel configs (JSON), and
// the vault key sentinel. A silent corruption here is unrecoverable, and this
// package shipped with no tests at all.
func TestRoundTripPreservesEveryInputShape(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"ascii":        "hunter2",
		"totp seed":    "JBSWY3DPEHPK3PXP",
		"json config":  `{"url":"https://hooks.example.com/x","secret":"s3cr3t"}`,
		"unicode":      "lösenord-密码-🔐",
		"newlines":     "line1\nline2\r\nline3",
		"nul bytes":    "a\x00b\x00c",
		"long":         strings.Repeat("A", 100_000),
		"looks base64": "aGVsbG8gd29ybGQ=",
		"looks marked": marker + "not-really-ciphertext",
	}

	for name, plaintext := range cases {
		enc, err := EncryptString(plaintext, testKey)
		if err != nil {
			t.Fatalf("%s: encrypt: %v", name, err)
		}
		if !strings.HasPrefix(enc, marker) {
			t.Fatalf("%s: ciphertext lost its marker: %q", name, enc[:min(len(enc), 40)])
		}
		// The plaintext must not survive inside the ciphertext. Skip the empty
		// case, where strings.Contains is trivially true.
		if plaintext != "" && strings.Contains(enc, plaintext) {
			t.Fatalf("%s: plaintext survives inside the ciphertext", name)
		}
		got, err := DecryptString(enc, testKey, testField)
		if err != nil {
			t.Fatalf("%s: decrypt: %v", name, err)
		}
		if got != plaintext {
			t.Fatalf("%s: round-trip changed the value (len %d -> %d)", name, len(plaintext), len(got))
		}
	}
}

// TestNonceIsNeverReused is the one that matters most. GCM catastrophically
// fails under nonce reuse with the same key: two ciphertexts leak the XOR of
// their plaintexts and the authentication key becomes forgeable. The nonce is
// random per call, so encrypting the same value twice must never produce the
// same output.
func TestNonceIsNeverReused(t *testing.T) {
	const plaintext = "the same secret every time"
	seen := make(map[string]bool)
	const n = 200
	for i := 0; i < n; i++ {
		enc, err := EncryptString(plaintext, testKey)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, marker))
		if err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		if len(raw) < 12 {
			t.Fatalf("ciphertext shorter than a GCM nonce: %d bytes", len(raw))
		}
		nonce := string(raw[:12])
		if seen[nonce] {
			t.Fatalf("NONCE REUSE after %d encryptions: GCM confidentiality and integrity both break", i)
		}
		seen[nonce] = true
	}
	if len(seen) != n {
		t.Fatalf("only %d distinct nonces across %d encryptions", len(seen), n)
	}
}

// TestWrongKeyAndTamperingAreRejected proves the authentication half of GCM is
// actually load-bearing: a different key must not decrypt, and a flipped bit
// anywhere must be detected rather than yielding garbage plaintext.
func TestWrongKeyAndTamperingAreRejected(t *testing.T) {
	const plaintext = "ROOT-DB-PASSWORD"
	enc, err := EncryptString(plaintext, testKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if got, err := DecryptString(enc, "a-completely-different-key", testField); err == nil {
		t.Fatalf("wrong key decrypted successfully, returning %q", got)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, marker))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Flip a bit in the nonce, in the body, and in the auth tag.
	for _, pos := range []int{0, len(raw) / 2, len(raw) - 1} {
		tampered := append([]byte(nil), raw...)
		tampered[pos] ^= 0x01
		bad := marker + base64.StdEncoding.EncodeToString(tampered)
		if got, err := DecryptString(bad, testKey, testField); err == nil {
			t.Fatalf("tampering at byte %d was NOT detected, returned %q", pos, got)
		}
	}
}

// TestMalformedInputErrorsRatherThanPanics matters because these values come
// out of a database that may be truncated, half-written, or hand-edited. A
// panic in a decrypt path takes down the request or the boot sequence.
func TestMalformedInputErrorsRatherThanPanics(t *testing.T) {
	bad := []string{
		marker,                      // marker only
		marker + "!!!not base64!!!", // undecodable
		marker + base64.StdEncoding.EncodeToString([]byte("short")), // shorter than a nonce
		"", // empty
		"plain cleartext that was never encrypted",
		marker + base64.StdEncoding.EncodeToString(make([]byte, 12)), // nonce, no body/tag
	}
	for _, in := range bad {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on malformed input %q: %v", in[:min(len(in), 30)], r)
				}
			}()
			if _, err := DecryptString(in, testKey, testField); err == nil {
				t.Logf("note: %q decrypted without error", in[:min(len(in), 30)])
			}
		}()
	}
}

// TestIsEncryptedIsAPureMarkerCheck pins the contract the boot-time TOTP
// migration depends on: it must answer without the key, and it must never claim
// cleartext is ciphertext. Getting this wrong is what turns a recoverable key
// mismatch into permanent corruption, because the migration decides whether to
// re-encrypt based on it.
func TestIsEncryptedIsAPureMarkerCheck(t *testing.T) {
	enc, err := EncryptString("seed", testKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !IsEncrypted(enc) {
		t.Fatal("real ciphertext not recognised: the migration would re-encrypt it and double-wrap")
	}
	// Answers without the key at all.
	if !IsEncrypted(enc) {
		t.Fatal("IsEncrypted is key-dependent")
	}
	for _, plain := range []string{"", "JBSWY3DPEHPK3PXP", "aGVsbG8=", "tienc:", "tienc:v2:x", "TIENC:V1:x"} {
		if IsEncrypted(plain) {
			t.Fatalf("cleartext %q was reported as ciphertext: the migration would skip encrypting it", plain)
		}
	}
}

// TestLegacyBareBase64StillDecrypts guards backward compatibility. Rows written
// before the marker existed are bare base64, and DecryptString strips the
// marker with TrimPrefix (a no-op when absent) precisely so those keep working.
// Breaking this orphans every pre-marker TOTP seed.
func TestLegacyBareBase64StillDecrypts(t *testing.T) {
	const plaintext = "legacy-totp-seed"
	enc, err := EncryptString(plaintext, testKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	legacy := strings.TrimPrefix(enc, marker) // exactly what an older binary stored
	if IsEncrypted(legacy) {
		t.Fatal("legacy form should NOT carry the marker, the test is not exercising the legacy path")
	}
	got, err := DecryptString(legacy, testKey, testField)
	if err != nil {
		t.Fatalf("legacy bare-base64 no longer decrypts: %v", err)
	}
	if got != plaintext {
		t.Fatalf("legacy round-trip returned %q", got)
	}
}

// TestKeyDerivationIsDeterministic is what makes decryption survive a restart:
// the same configured vault key must always derive the same AES key, and a
// different vault key must derive a different one.
func TestKeyDerivationIsDeterministic(t *testing.T) {
	a1, a2 := deriveKey(testKey), deriveKey(testKey)
	if a1 != a2 {
		t.Fatal("deriveKey is not deterministic: nothing would decrypt after a restart")
	}
	if len(a1) != 32 {
		t.Fatalf("derived key is %d bytes, want 32 for AES-256", len(a1))
	}
	if deriveKey("another-key") == a1 {
		t.Fatal("two different vault keys derive the same AES key")
	}
	// A value encrypted before a restart decrypts after one (same key in, same
	// key out).
	enc, _ := EncryptString("survives-restart", testKey)
	if got, err := DecryptString(enc, testKey, testField); err != nil || got != "survives-restart" {
		t.Fatalf("cross-instance decrypt failed: %q (err %v)", got, err)
	}
}

// TestDerivedKeyIsMemoizedPerSecret pins the caching contract.
//
// PBKDF2 at 600k iterations costs ~80ms and is a pure function of the secret,
// but it used to run on every single Encrypt/Decrypt. MigrateTOTPSecrets runs
// on every boot and decrypts every already-migrated seed just to log failures,
// so startup grew by ~80ms per TOTP user before the server accepted a
// connection, and every TOTP login and notification dispatch paid it again.
//
// The invariant that actually matters is correctness, not speed: memoizing must
// not let one secret's key be handed to another secret.
func TestDerivedKeyIsMemoizedPerSecret(t *testing.T) {
	const a = "cache-test-key-alpha"
	const b = "cache-test-key-bravo"

	first := time.Now()
	ka1 := deriveKey(a)
	coldA := time.Since(first)

	second := time.Now()
	ka2 := deriveKey(a)
	warmA := time.Since(second)

	if ka1 != ka2 {
		t.Fatal("memoized derivation returned a different key on the second call")
	}
	// The cold path runs the real KDF; the warm path must not. Compare against
	// the cold measurement rather than a fixed number so this holds on any
	// machine.
	if warmA > coldA/4 {
		t.Fatalf("second derivation took %v vs %v cold: the cache is not being used", warmA, coldA)
	}

	// A different secret must still derive its own key, not reuse the cached one.
	kb := deriveKey(b)
	if kb == ka1 {
		t.Fatal("KEY COLLISION: a second secret received the first secret's derived key")
	}

	// End to end: values encrypted under each key stay separated.
	encA, err := EncryptString("alpha-secret", a)
	if err != nil {
		t.Fatalf("encrypt a: %v", err)
	}
	if got, err := DecryptString(encA, a, testField); err != nil || got != "alpha-secret" {
		t.Fatalf("same-key round-trip broke under caching: %q (err %v)", got, err)
	}
	if got, err := DecryptString(encA, b, testField); err == nil {
		t.Fatalf("CROSS-KEY DECRYPT: key b opened key a's ciphertext, returning %q", got)
	}
}

// TestDeriveCacheIsBounded proves the cache cannot grow without limit if a
// caller passes many distinct secrets, and that correctness survives past the
// cap (uncached secrets simply recompute).
func TestDeriveCacheIsBounded(t *testing.T) {
	deriveCacheMu.Lock()
	deriveCache = make(map[[32]byte][32]byte)
	deriveCacheMu.Unlock()

	for i := 0; i < deriveCacheMax+5; i++ {
		secret := fmt.Sprintf("bounded-cache-secret-%d", i)
		k := deriveKey(secret)
		if len(k) != 32 {
			t.Fatalf("derived key %d is %d bytes", i, len(k))
		}
	}

	deriveCacheMu.RLock()
	size := len(deriveCache)
	deriveCacheMu.RUnlock()
	if size > deriveCacheMax {
		t.Fatalf("cache grew to %d entries, past the %d cap", size, deriveCacheMax)
	}

	// A secret beyond the cap still derives correctly, just without memoization.
	beyond := fmt.Sprintf("bounded-cache-secret-%d", deriveCacheMax+4)
	enc, err := EncryptString("still-works", beyond)
	if err != nil {
		t.Fatalf("encrypt beyond cap: %v", err)
	}
	if got, err := DecryptString(enc, beyond, testField); err != nil || got != "still-works" {
		t.Fatalf("uncached secret broke: %q (err %v)", got, err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Package columncrypto provides AES-256-GCM string encryption for sensitive
// database columns (TOTP seeds, notification channel configs, vault metadata).
// The key is derived from the configured vault key with PBKDF2-SHA256, copied
// from dockyard's audited value-encryption path so a raw DB-file leak never
// exposes these columns in cleartext.
package columncrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// marker is a short self-describing prefix stamped on every ciphertext this
// package produces. It lets a caller tell an already-encrypted value from
// cleartext WITHOUT holding the key (IsEncrypted), which is what makes the
// boot-time TOTP backfill safe: a marked value is known ciphertext and must
// never be re-encrypted, even when it fails to decrypt under a mismatched key
// (re-encrypting a marked-but-undecryptable seed is what turned a recoverable
// key mismatch into permanent corruption). Legacy rows written before the
// marker existed are bare base64; DecryptString still reads them.
const marker = "tienc:v1:"

// deriveKey derives a 32-byte key using PBKDF2-SHA256 with 600k iterations.
func deriveKey(secret string) []byte {
	salt := []byte("trustissues:column:v1")
	return pbkdf2.Key([]byte(secret), salt, 600_000, 32, sha256.New)
}

// IsEncrypted reports whether s carries this package's ciphertext marker.
// It is a pure prefix check: no key is needed and it never decrypts, so a
// caller can distinguish ciphertext from plaintext before deciding whether to
// encrypt. Legacy pre-marker ciphertext (bare base64) returns false; such rows
// are transparently upgraded on the next write.
func IsEncrypted(s string) bool {
	return strings.HasPrefix(s, marker)
}

// EncryptString encrypts a string value using AES-256-GCM with a
// PBKDF2-derived key. Output is marker + base64(nonce || ciphertext).
func EncryptString(plaintext, key string) (string, error) {
	derivedKey := deriveKey(key)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return marker + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts a value produced by EncryptString. It accepts both the
// current marked form (marker + base64) and legacy bare-base64 ciphertext
// written before the marker was introduced, so existing rows keep decrypting.
func DecryptString(encrypted, key string) (string, error) {
	derivedKey := deriveKey(key)
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, marker))
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

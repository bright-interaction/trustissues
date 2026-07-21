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

	"golang.org/x/crypto/pbkdf2"
)

// deriveKey derives a 32-byte key using PBKDF2-SHA256 with 600k iterations.
func deriveKey(secret string) []byte {
	salt := []byte("trustissues:column:v1")
	return pbkdf2.Key([]byte(secret), salt, 600_000, 32, sha256.New)
}

// EncryptString encrypts a string value using AES-256-GCM with a
// PBKDF2-derived key. Output is base64(nonce || ciphertext).
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
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts a base64-encoded ciphertext produced by
// EncryptString.
func DecryptString(encrypted, key string) (string, error) {
	derivedKey := deriveKey(key)
	data, err := base64.StdEncoding.DecodeString(encrypted)
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

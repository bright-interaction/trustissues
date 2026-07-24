package shield

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// encrypt encrypts plaintext with AES-256-GCM and returns base64
// ciphertext. Nonce is prepended to the ciphertext (standard GCM
// pattern). Empty plaintext is passed through.
func encrypt(plaintext string, key []byte) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if len(key) != 32 {
		return "", fmt.Errorf("shield: encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("shield: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("shield: create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("shield: nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// decrypt reverses encrypt. Empty input returns empty.
func decrypt(encoded string, key []byte) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if len(key) != 32 {
		return "", fmt.Errorf("shield: decryption key must be 32 bytes, got %d", len(key))
	}
	ct, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("shield: decode base64: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("shield: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("shield: create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ct) < nonceSize {
		return "", fmt.Errorf("shield: ciphertext too short")
	}
	nonce, body := ct[:nonceSize], ct[nonceSize:]
	pt, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return "", fmt.Errorf("shield: decrypt: %w", err)
	}
	return string(pt), nil
}

// newTokenID returns "tok_<8hex>" using crypto/rand. Kept for tests
// that intentionally want random ids; production Tokenize uses
// deterministicTokenID so the same value within a session always
// yields the same marker (recognise-but-don't-deanonymise).
func newTokenID() (string, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return "tok_" + hex.EncodeToString(b), nil
}

// derivedSessionKey computes a per-session subkey from the master so
// rotating the master invalidates every session, and per-session
// HMACs (used for deterministic token-id derivation) cannot be
// replayed across sessions.
func derivedSessionKey(master []byte, sessionID string) []byte {
	h := hmac.New(sha256.New, master)
	h.Write([]byte("shield/session/" + sessionID))
	return h.Sum(nil) // 32 bytes
}

// deterministicTokenID computes the marker id for (kind, value) such
// that the same input within the same session always produces the
// same id. 12 hex (48 bits) is collision-safe up to ~16M tokens per
// session at <1% birthday-collision risk. The HMAC PRF makes the id
// uncorrelated with the value, and per-session keying makes ids
// across sessions unlinkable, so an LLM seeing "tok_X" in session A
// and "tok_Y" in session B cannot tell whether they reference the
// same person.
func deterministicTokenID(sessionKey []byte, kind Kind, value string) string {
	h := hmac.New(sha256.New, sessionKey)
	h.Write([]byte(string(kind)))
	h.Write([]byte{0x00})
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return "tok_" + hex.EncodeToString(sum[:6])
}

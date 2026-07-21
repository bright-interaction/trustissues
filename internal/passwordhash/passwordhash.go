// Package passwordhash centralizes password hashing for Trustissues.
//
// New passwords are hashed with Argon2id (RFC 9106 winner of the PHC
// competition). Existing bcrypt hashes are still accepted on login so the
// migration is transparent: on a successful bcrypt verify, callers can
// check NeedsRehash and re-store the password with Hash.
//
// The encoded format for Argon2id matches the standard PHC string layout
// used by passlib, libsodium, etc:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
//
// Bcrypt hashes start with $2a$, $2b$, or $2y$. Verify dispatches based
// on the prefix.
package passwordhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Tunables. Memory and iteration costs are deliberately conservative for
// SQLite-on-VPS workloads. See RFC 9106 §4 for guidance.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen uint32 = 16
)

// ErrInvalidHash is returned when an encoded hash cannot be parsed.
var ErrInvalidHash = errors.New("passwordhash: invalid encoded hash")

// ErrIncompatibleVersion is returned when the encoded hash uses an
// argon2id parameter version we do not support.
var ErrIncompatibleVersion = errors.New("passwordhash: incompatible argon2 version")

// Hash returns an Argon2id-encoded password hash safe to persist.
func Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("passwordhash: empty password")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwordhash: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return encoded, nil
}

// Verify checks a candidate password against an encoded hash. It accepts
// both Argon2id PHC-format strings (new) and bcrypt strings (legacy).
// Returns true if the password matches.
func Verify(password, encoded string) (bool, error) {
	if encoded == "" {
		return false, ErrInvalidHash
	}
	if isBcrypt(encoded) {
		err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
		if err == nil {
			return true, nil
		}
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}
	if !strings.HasPrefix(encoded, "$argon2id$") {
		return false, ErrInvalidHash
	}
	return verifyArgon2id(password, encoded)
}

// NeedsRehash returns true when an encoded hash is in a legacy format
// (currently bcrypt) and should be replaced with a fresh Hash call after
// a successful Verify. Callers update the DB on next login transparently.
func NeedsRehash(encoded string) bool {
	return isBcrypt(encoded)
}

func isBcrypt(encoded string) bool {
	return strings.HasPrefix(encoded, "$2a$") ||
		strings.HasPrefix(encoded, "$2b$") ||
		strings.HasPrefix(encoded, "$2y$")
}

func verifyArgon2id(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 {
		return false, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrInvalidHash
	}
	if version != argon2.Version {
		return false, ErrIncompatibleVersion
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(want, got) == 1, nil
}

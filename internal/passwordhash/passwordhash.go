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
	"flag"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Tunables. Memory and iteration costs are deliberately conservative for
// SQLite-on-VPS workloads. See RFC 9106 §4 for guidance.
const (
	argonTimeProd    uint32 = 3
	argonMemoryProd  uint32 = 64 * 1024 // 64 MiB
	argonThreadsProd uint8  = 4
	argonKeyLen      uint32 = 32
	argonSaltLen     uint32 = 16
)

// Cost parameters, overridable ONLY from tests via SetTestCost.
//
// These are variables rather than constants because the production cost makes
// the handler test package unusable: 90 hash/verify calls at 64 MiB and t=3 put
// internal/handlers at ~51s, and ~228s under -race. Adding the rotation
// behaviour matrix on top would push it past Go's default 10-minute timeout,
// at which point the suite stops being run at all, which is a worse security
// outcome than a cheap KDF in tests.
//
// A wrong value here silently weakens every stored password, so SetTestCost
// refuses to run outside a test binary rather than trusting callers.
var (
	argonTime    = argonTimeProd
	argonMemory  = argonMemoryProd
	argonThreads = argonThreadsProd
)

// SetTestCost lowers the argon2id cost for the duration of a test binary.
//
// It panics if called from a non-test binary. That check is the whole point:
// an accidental import from production code must fail loudly at startup rather
// than quietly hashing every user password at a cost an attacker can brute
// force. Detection is by the test flag the go tool always defines, which is
// present only when the binary was built by `go test`.
func SetTestCost() {
	if flag.Lookup("test.v") == nil {
		panic("passwordhash: SetTestCost called outside a test binary; " +
			"this would weaken every stored password")
	}
	argonTime = 1
	argonMemory = 8 // 8 KiB
	argonThreads = 1
}

// ProdCost reports whether the production cost is in force. Tests that assert
// on hashing behaviour can use it to skip when the cost has been lowered.
func ProdCost() bool { return argonMemory == argonMemoryProd }

// ErrInvalidHash is returned when an encoded hash cannot be parsed.
var ErrInvalidHash = errors.New("passwordhash: invalid encoded hash")

// ErrIncompatibleVersion is returned when the encoded hash uses an
// argon2id parameter version we do not support.
var ErrIncompatibleVersion = errors.New("passwordhash: incompatible argon2 version")

// Hash returns an Argon2id-encoded password hash safe to persist.
func Hash(password string) (string, error) {
	release, err := acquireHashSlot()
	if err != nil {
		return "", err
	}
	defer release()
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
// hashSlots bounds how many Argon2 computations may run at once.
//
// Argon2id at the production cost allocates 64 MiB per call, and Hash/Verify are
// reachable from UNAUTHENTICATED endpoints (login, invitation redemption). The
// login rate limiter is 30 requests per 15 minutes PER IP, which bounds the rate
// from one source and does not bound concurrent memory at all: distributed
// sources multiply it, and an audit measured one source driving RSS from 74 MB
// to 1038 MB.
//
// A semaphore is the right control because the resource being exhausted is
// memory in flight, not requests per minute. Excess callers queue rather than
// allocate, which converts a memory-exhaustion crash into added latency under
// attack, and costs nothing at normal load.
//
// 4 is deliberate: at 64 MiB each that caps Argon2 at ~256 MiB regardless of
// traffic, and a single-team vault never has four people logging in at once.
var hashSlots = make(chan struct{}, 4)

// ErrBusy is returned when no Argon2 slot became free within the wait budget.
// Callers should surface it as 503, not 401: it says nothing about the password.
var ErrBusy = errors.New("passwordhash: too many concurrent password computations")

// hashWait is how long a caller queues for a slot before giving up.
//
// An UNBOUNDED wait would swap one exhaustion for another: under sustained load
// every blocked caller holds a goroutine and its whole request, so the queue
// grows without limit and the process dies of goroutines instead of Argon2
// buffers. Failing fast keeps the queue bounded by arrival rate over 2 seconds.
//
// 2s is comfortably above the ~50ms a production-cost hash takes even with four
// ahead of you, so a legitimate login never sees it.
const hashWait = 2 * time.Second

// acquireHashSlot waits for a slot and returns its release func, or ErrBusy.
func acquireHashSlot() (func(), error) {
	select {
	case hashSlots <- struct{}{}:
		return func() { <-hashSlots }, nil
	case <-time.After(hashWait):
		return nil, ErrBusy
	}
}

func Verify(password, encoded string) (bool, error) {
	release, err := acquireHashSlot()
	if err != nil {
		return false, err
	}
	defer release()
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

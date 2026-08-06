// Package totp implements RFC 6238 Time-Based One-Time Passwords
// for Trustissues' two-factor authentication, using only the standard
// library plus golang.org/x/crypto/bcrypt.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// timeStep is the TOTP period in seconds (RFC 6238 default).
	timeStep int64 = 30
	// codeDigits is the number of digits in a TOTP code.
	codeDigits = 6
	// recoveryCodeCount is how many recovery codes to generate.
	recoveryCodeCount = 8
	// recoveryCodeBytes is the number of random bytes per recovery code. 8 bytes
	// (64 bits, 16 hex chars) so the code space is not narrow enough to brute
	// force under a diluted per-IP login limiter (DY-31).
	recoveryCodeBytes = 8
)

// modulus is 10^codeDigits, used to truncate the HMAC result.
var modulus = new(big.Int).Exp(big.NewInt(10), big.NewInt(codeDigits), nil)

// recoveryCodeCost is the bcrypt cost for recovery-code hashes, overridable ONLY
// from tests via SetTestCost.
//
// This is the sibling of passwordhash's argon2 knob, and it was missing, which
// is the shape that keeps recurring here: one property, several doors, fixed at
// one of them. internal/handlers' TestMain lowers the argon2 cost and says in
// its own comment that without it the package "would approach Go's default
// 10-minute timeout". It approached it anyway. Enrolling 2FA mints eight bcrypt
// hashes at DefaultCost, a failed recovery code compares against all eight, and
// dozens of tests enrol, so the half nobody capped was the half that grew. The
// package measured 612s under -race with a 600s CI ceiling.
//
// A suite too slow to run is a worse security outcome than a cheap KDF in tests,
// which is the same argument passwordhash makes for the same reason.
var recoveryCodeCost = bcrypt.DefaultCost

// SetTestCost lowers the recovery-code bcrypt cost for the duration of a test
// binary.
//
// It panics if called from a non-test binary. That check is the whole point: an
// accidental import from production code must fail loudly at startup rather than
// quietly hashing every recovery code at a cost an attacker can brute force.
// Detection is by the test flag the go tool always defines.
func SetTestCost() {
	if flag.Lookup("test.v") == nil {
		panic("totp: SetTestCost called outside a test binary; " +
			"this would weaken every stored recovery code")
	}
	recoveryCodeCost = bcrypt.MinCost
}

// ProdCost reports whether the production bcrypt cost is in force.
func ProdCost() bool { return recoveryCodeCost == bcrypt.DefaultCost }

// GenerateSecret produces a 20-byte random secret encoded as an
// unpadded base32 string suitable for use with authenticator apps.
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("totp: generating secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// GenerateCode computes the 6-digit TOTP code for the given secret
// and point in time, following RFC 6238 / RFC 4226.
func GenerateCode(secret string, t time.Time) (string, error) {
	// Decode the base32 secret.
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("totp: decoding secret: %w", err)
	}

	// Compute the time-step counter as a big-endian uint64.
	counter := t.Unix() / timeStep
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], uint64(counter))

	// HMAC-SHA1(key, counter).
	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	h := mac.Sum(nil)

	// Dynamic truncation per RFC 4226 section 5.4.
	offset := h[len(h)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff

	// Reduce modulo 10^6 and zero-pad to 6 digits.
	code := truncated % uint32(modulus.Uint64())
	return fmt.Sprintf("%06d", code), nil
}

// ValidateCode checks a user-supplied code against the current and
// previous time steps, allowing a one-step tolerance for clock drift.
//
// Prefer ValidateCodeStep at any call site that can record the step. This form
// cannot tell the caller WHICH step matched, so it cannot be made single-use, and a
// captured code stays replayable for the whole 60-second window.
func ValidateCode(secret string, code string) bool {
	_, ok := ValidateCodeStep(secret, code)
	return ok
}

// ValidateCodeStep is ValidateCode plus the time step that matched, so the caller can
// spend it and refuse a replay.
//
// The window exists for clock drift and is not the problem; the problem was that
// nothing recorded which step had been used, so one observed code was good for the
// rest of its window: as many sessions as an attacker wanted, plus removing 2FA. The
// step is monotonic, so claiming it also rejects a replay of the drift step.
func ValidateCodeStep(secret string, code string) (int64, bool) {
	now := time.Now()
	for _, offset := range []int64{0, -1} {
		t := now.Add(time.Duration(offset*timeStep) * time.Second)
		expected, err := GenerateCode(secret, t)
		if err != nil {
			continue
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return t.Unix() / timeStep, true
		}
	}
	return 0, false
}

// GenerateOTPAuthURI returns an otpauth:// URI that can be rendered
// as a QR code for enrollment in authenticator apps.
func GenerateOTPAuthURI(email, issuer, secret string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer),
		url.PathEscape(email),
		secret,
		url.QueryEscape(issuer),
	)
}

// GenerateRecoveryCodes creates 8 single-use recovery codes. Each code is 16 hex
// characters (recoveryCodeBytes = 8 random bytes, 64 bits). Both the plaintext
// and bcrypt-hashed versions are returned so the caller can display the
// plaintext once and store only the hashes.
//
// This comment said "8 hex characters (4 random bytes)", describing the narrower
// code space from before DY-31 widened it. The constant is the truth; the
// sentence was two years of reassurance about the wrong number, and
// TestRecoveryCodesAreEightSingleUseCodes now pins the real width.
func GenerateRecoveryCodes() (plaintextCodes []string, hashedCodes []string, err error) {
	plaintextCodes = make([]string, 0, recoveryCodeCount)
	hashedCodes = make([]string, 0, recoveryCodeCount)

	for i := 0; i < recoveryCodeCount; i++ {
		buf := make([]byte, recoveryCodeBytes)
		if _, err = rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("totp: generating recovery code: %w", err)
		}

		plain := hex.EncodeToString(buf)
		hashed, err := bcrypt.GenerateFromPassword([]byte(plain), recoveryCodeCost)
		if err != nil {
			return nil, nil, fmt.Errorf("totp: hashing recovery code: %w", err)
		}

		plaintextCodes = append(plaintextCodes, plain)
		hashedCodes = append(hashedCodes, string(hashed))
	}

	return plaintextCodes, hashedCodes, nil
}

// ValidateRecoveryCode checks the input against a set of bcrypt-hashed
// recovery codes. On match it returns the remaining (unused) hashes and
// true; otherwise it returns the original set unchanged and false.
func ValidateRecoveryCode(hashedCodes []string, inputCode string) (remainingCodes []string, valid bool) {
	for i, h := range hashedCodes {
		if err := bcrypt.CompareHashAndPassword([]byte(h), []byte(inputCode)); err == nil {
			// Remove the matched code by concatenating the slices around it.
			remaining := make([]string, 0, len(hashedCodes)-1)
			remaining = append(remaining, hashedCodes[:i]...)
			remaining = append(remaining, hashedCodes[i+1:]...)
			return remaining, true
		}
	}
	return hashedCodes, false
}

// Package columncrypto provides AES-256-GCM string encryption for sensitive
// database columns (TOTP seeds, notification channel configs, vault metadata).
// The key is derived from the configured vault key with PBKDF2-SHA256, copied
// from dockyard's audited value-encryption path so a raw DB-file leak never
// exposes these columns in cleartext.
package columncrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/pbkdf2"

	"github.com/bright-interaction/trustissues/internal/vaultfield"
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

// deriveCache memoizes the PBKDF2 result per configured secret.
//
// 600k iterations is deliberately expensive: it costs ~80ms per call, which is
// the whole point when the input is a passphrase. But it is a PURE function of
// the secret, and this process only ever uses one or two secrets for the whole
// of its life, so paying it on every Encrypt/Decrypt bought nothing.
//
// It was not free either. MigrateTOTPSecrets runs on EVERY boot and decrypts
// every already-migrated seed just to log the ones that fail, so startup cost
// grew at ~80ms per user with TOTP before the server accepted a connection.
// Every TOTP login, every SMTP send and every notification dispatch paid it
// again.
//
// The map is keyed by sha256(secret) rather than the secret itself, so the
// configured vault key is not sitting in a map key. The derived key lives in
// process memory for the process lifetime, which is exactly where it already
// lived: the vault key it comes from is held in config for the same duration,
// so this adds no new exposure. It is bounded because deriveCacheMax caps it.
var (
	deriveCacheMu sync.RWMutex
	deriveCache   = make(map[[32]byte][32]byte)
)

// deriveCacheMax bounds the cache. Real deployments use one vault key; the cap
// only exists so a caller that somehow passes many distinct secrets cannot grow
// this without limit. Past the cap we simply stop memoizing and recompute.
const deriveCacheMax = 16

// deriveKey derives a 32-byte key using PBKDF2-SHA256 with 600k iterations,
// memoized per secret. The KDF cost is unchanged for the first call with a
// given secret; later calls reuse it.
func deriveKey(secret string) [32]byte {
	id := sha256.Sum256([]byte(secret))

	deriveCacheMu.RLock()
	cached, ok := deriveCache[id]
	deriveCacheMu.RUnlock()
	if ok {
		return cached
	}

	salt := []byte("trustissues:column:v1")
	var derived [32]byte
	copy(derived[:], pbkdf2.Key([]byte(secret), salt, 600_000, 32, sha256.New))

	deriveCacheMu.Lock()
	if len(deriveCache) < deriveCacheMax {
		deriveCache[id] = derived
	}
	deriveCacheMu.Unlock()
	return derived
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
//
// The AES itself is internal/vaultfield's, which is the one file in the module
// that imports crypto/aes and crypto/cipher. Sealing takes no Field: the ledger
// is about what becomes PLAINTEXT.
func EncryptString(plaintext, key string) (string, error) {
	packed, err := vaultfield.SealPacked(deriveKey(key), []byte(plaintext), rand.Reader)
	if err != nil {
		return "", err
	}
	return marker + base64.StdEncoding.EncodeToString(packed), nil
}

// DecryptStringAny tries every key in order and returns the first that opens
// the value. It is the dual-key read used while a master-key rotation is in
// flight: pass the CURRENT key first and TRUSTISSUES_VAULT_KEY_PREVIOUS second,
// so a store that is half-swept (or restored from a backup taken before the
// sweep) keeps reading instead of returning "[decryption error]" for every row.
//
// Order matters and current-first is deliberate. AES-GCM authenticates, so a
// wrong key cannot produce a false positive and the fallback is safe, but the
// common case must not pay two PBKDF2 lookups. Both are memoized anyway
// (deriveKey), so the second attempt costs one AES-GCM open.
//
// Empty keys are skipped rather than tried: an unset TRUSTISSUES_VAULT_KEY_PREVIOUS
// is the normal state and must not turn into a decrypt attempt under "".
// The error returned is the FIRST key's error, because that is the one the
// operator is configured on and the one they need to see.
//
// IT TAKES THE FIELD, and that is the whole point of this signature.
//
// Rotation and the field ledger were built in parallel on two branches and the
// naive merge of them compiled to neither: this function was calling
// DecryptString with two arguments while DecryptString had grown a third, so the
// tree did not build at all. The two easy repairs are both wrong. Dropping the
// field turns every rotation-era read back into a decryption that names no
// column, which is exactly the "keyed by CALL SITE" defect the ledger replaced,
// and it would do it silently on the read path that is about to become the
// common one. Dropping the multi-key attempt strands every value written under
// the previous key the moment a rotation is half-swept.
//
// So the field rides along and is passed to every attempt. It is an AAD input,
// not a key input: the same field is bound whichever key opens the value, so a
// row sealed under the previous key opens exactly when it should and is still
// counted against the column it belongs to.
func DecryptStringAny(encrypted string, f vaultfield.Field, keys ...string) (string, error) {
	var firstErr error
	for _, k := range keys {
		if k == "" {
			continue
		}
		plain, err := DecryptString(encrypted, k, f)
		if err == nil {
			return plain, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		return "", fmt.Errorf("no decryption key configured")
	}
	return "", firstErr
}

// DecryptString decrypts a value produced by EncryptString. It accepts both the
// current marked form (marker + base64) and legacy bare-base64 ciphertext
// written before the marker was introduced, so existing rows keep decrypting.
//
// It takes a vaultfield.Field because this is a DECRYPTION: it turns a stored
// column into plaintext, and every such door in this product names the column it
// opens so the ledger is a by-product of the decryption rather than a list kept
// beside it. Passing the zero Field is refused (vaultfield.ErrUndeclared).
//
// This function used to be generic over "some encrypted string", which is
// precisely how a family of four different columns (TOTP seeds, the boot
// sentinel, the SMTP relay password, the sampled probe blob) shared one entry
// keyed by CALL SITE in the old ledger. The call site is a property of the
// caller; the column is a property of the data.
func DecryptString(encrypted, key string, f vaultfield.Field) (string, error) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, marker))
	if err != nil {
		return "", err
	}
	plaintext, err := vaultfield.OpenPacked(deriveKey(key), data, f)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

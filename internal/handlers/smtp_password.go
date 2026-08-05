package handlers

import (
	"fmt"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
)

// resolveSMTPPassword turns the STORED smtp_password setting into the plaintext
// credential to hand to net/smtp.
//
// Every reader of smtp_password must go through here. There used to be two
// readers with two different behaviours: the invitation mailer decrypted, and
// the "send test email" handler passed the stored value straight through. Since
// the value is ciphertext at rest, the test path authenticated to the relay with
// "tienc:v1:<base64>" as the password. It failed 100% of the time on any
// authenticated relay while real invitation emails worked, which points an admin
// at a working credential and invites them to rotate it. It also shipped our
// ciphertext into a third party's auth-failure logs.
//
// The marker check is safe here because the input is a value read out of the
// settings table, never something a client hands us: rows written before at-rest
// encryption landed are still cleartext and must keep working. See
// secure-build-failure-patterns in Mesh for why that distinction matters.
//
// A decrypt failure is an error, never a fallback to the raw value. Falling back
// would send ciphertext as the password, which is the exact bug this replaces.
// vaultKeys is variadic so callers can pass the CURRENT key followed by
// TRUSTISSUES_VAULT_KEY_PREVIOUS. During a rotation the settings row is still
// sealed under the old key until the re-encrypt sweep runs, and without the
// fallback every invitation email would fail to send with a decrypt error for
// the whole window.
//
// The DECLARED FIELD rides along with the key list. It is what vaultfield
// demands before it will produce plaintext at all, and passing it to a multi-key
// read is what keeps a rotation-era decrypt from becoming the one family of
// decryptions that names no column. It is the same field on every attempt: the
// column being opened is settings.smtp_password whichever key happens to open
// it. See columncrypto.DecryptStringAny.
func resolveSMTPPassword(stored string, vaultKeys ...string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !columncrypto.IsEncrypted(stored) {
		// Legacy row written before at-rest encryption. Still a usable password.
		return stored, nil
	}
	plain, err := columncrypto.DecryptStringAny(stored, vaultFieldSMTPPassword, vaultKeys...)
	if err != nil {
		return "", fmt.Errorf("decrypt smtp password: %w", err)
	}
	return plain, nil
}

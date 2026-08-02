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
func resolveSMTPPassword(stored, vaultKey string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !columncrypto.IsEncrypted(stored) {
		// Legacy row written before at-rest encryption. Still a usable password.
		return stored, nil
	}
	plain, err := columncrypto.DecryptString(stored, vaultKey)
	if err != nil {
		return "", fmt.Errorf("decrypt smtp password: %w", err)
	}
	return plain, nil
}

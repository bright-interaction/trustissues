package handlers

import (
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/columncrypto"
)

// TestResolveSMTPPasswordNeverReturnsCiphertext locks the fix for the "send test
// email always fails" bug.
//
// smtp_password is encrypted at rest. The test-email handler used to hand the
// STORED value to smtp.PlainAuth, so it authenticated with "tienc:v1:<base64>".
// That failed against every authenticated relay while real invitation emails
// worked, so the visible symptom pointed an admin at a working credential.
//
// The invariant: no caller can ever receive something that still looks like
// ciphertext, and a decrypt failure is an error rather than a silent fallback to
// the raw stored value.
func TestResolveSMTPPasswordNeverReturnsCiphertext(t *testing.T) {
	const key = "test-vault-key"
	const secret = "hunter2-relay-password"

	stored, err := columncrypto.EncryptString(secret, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Guard the setup: if this is not real ciphertext the assertions below prove
	// nothing.
	if !columncrypto.IsEncrypted(stored) || stored == secret {
		t.Fatalf("ABORT: stored value is not ciphertext (%q), test would be vacuous", stored)
	}

	got, err := resolveSMTPPassword(stored, key)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != secret {
		t.Fatalf("resolved %q, want the plaintext password", got)
	}
	if columncrypto.IsEncrypted(got) || strings.HasPrefix(got, "tienc:") {
		t.Fatalf("CIPHERTEXT LEAKED to the SMTP client: %q", got)
	}

	// A legacy row written before at-rest encryption is cleartext and must keep
	// working, otherwise upgrading breaks everyone's existing relay config.
	if out, err := resolveSMTPPassword("legacy-cleartext-pw", key); err != nil || out != "legacy-cleartext-pw" {
		t.Fatalf("legacy cleartext row broke: %q (err %v)", out, err)
	}

	// Unset stays unset (no auth), and must not become a bogus credential.
	if out, err := resolveSMTPPassword("", key); err != nil || out != "" {
		t.Fatalf("empty password should stay empty: %q (err %v)", out, err)
	}

	// Wrong key must ERROR, never fall back to handing the ciphertext onward.
	// The fallback is exactly the bug this replaces.
	out, err := resolveSMTPPassword(stored, "a-different-vault-key")
	if err == nil {
		t.Fatal("wrong key silently succeeded; a fallback would send ciphertext as the password")
	}
	if out != "" {
		t.Fatalf("failed decrypt returned %q, want empty", out)
	}
}

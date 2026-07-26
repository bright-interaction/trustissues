package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/brightinteraction/trustissues/internal/columncrypto"
)

// TestVaultKeyCheckRefusesAWrongKey locks the boot gate.
//
// Before this existed, booting a data dir under a different but well-formed key
// started cleanly, answered /health with {"status":"ok"}, served every entry
// with blank url/username/category/notes, and let the first UI save overwrite
// the still-recoverable ciphertext with NULL. The mismatch has to be caught
// before any migration or backfill rewrites a row.
//
// The invariant: first boot writes the sentinel, the right key passes, a wrong
// key is reported as ErrVaultKeyMismatch (which the caller turns into a refusal
// to start), and detecting a mismatch never mutates the sentinel.
func TestVaultKeyCheckRefusesAWrongKey(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const keyA = "vault-key-alpha"
	const keyB = "vault-key-bravo"

	// First boot on a fresh database: no sentinel yet, so it is written and the
	// boot proceeds. This is what self-heals existing deployments.
	if err := VerifyVaultKey(ctx, queries, keyA); err != nil {
		t.Fatalf("first boot should write the sentinel and pass, got %v", err)
	}
	sealed, err := queries.GetSetting(ctx, vaultKeyCheckSetting)
	if err != nil {
		t.Fatalf("sentinel was not persisted: %v", err)
	}
	// Guard the setup: a sentinel stored in cleartext would make the wrong-key
	// assertion below meaningless.
	if !columncrypto.IsEncrypted(sealed) {
		t.Fatalf("ABORT: sentinel is not ciphertext (%q), the mismatch test would be vacuous", sealed)
	}
	if sealed == vaultKeyCheckPlaintext {
		t.Fatal("ABORT: sentinel stored in cleartext")
	}

	// Same key on every later boot: passes, and stays idempotent.
	if err := VerifyVaultKey(ctx, queries, keyA); err != nil {
		t.Fatalf("correct key rejected on second boot: %v", err)
	}
	if again, _ := queries.GetSetting(ctx, vaultKeyCheckSetting); again != sealed {
		t.Fatal("a passing check rewrote the sentinel; it must be stable")
	}

	// THE POINT: a different, perfectly well-formed key must be caught.
	err = VerifyVaultKey(ctx, queries, keyB)
	if err == nil {
		t.Fatal("WRONG KEY ACCEPTED: the server would boot healthy and the first save would destroy data")
	}
	if !errors.Is(err, ErrVaultKeyMismatch) {
		t.Fatalf("wrong key produced %v, want ErrVaultKeyMismatch so the caller can refuse to start", err)
	}

	// A failed check must not touch the sentinel, otherwise booting once on the
	// wrong key would overwrite the evidence and make the right key look wrong.
	after, err := queries.GetSetting(ctx, vaultKeyCheckSetting)
	if err != nil || after != sealed {
		t.Fatalf("mismatch path mutated the sentinel: %q -> %q (err %v)", sealed, after, err)
	}
	// And the original key still works afterwards.
	if err := VerifyVaultKey(ctx, queries, keyA); err != nil {
		t.Fatalf("correct key rejected after a failed attempt: %v", err)
	}
}

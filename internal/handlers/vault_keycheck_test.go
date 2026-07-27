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

// TestSentinelDoesNotBootstrapUnderTheWrongKey locks the fix for the gate
// failing open on the one boot it exists for.
//
// The sentinel is written on the first boot that finds it absent. That is
// exactly the upgrade boot of every EXISTING deployment, which already holds
// encrypted data. Sealing blindly meant that booting once under the wrong key
// stamped a sentinel for that wrong key, and from then on the CORRECT key was
// rejected forever while the real data sat there undecryptable. The safety
// mechanism failed open when it mattered, then locked out its own fix.
//
// The invariant: on a populated database, a key that cannot open the existing
// ciphertext is refused and NO sentinel is written, so the correct key still
// works afterwards.
func TestSentinelDoesNotBootstrapUnderTheWrongKey(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	// newCollectionAuthzEnv builds its handler with this key; the entry below is
	// therefore sealed under it. That makes it the "correct" key for this DB.
	const correctKey = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
	const wrongKey = "wrong-key-that-opens-nothing-here"

	owner := mustUser(t, queries, "o@example.com", "user", "")
	mustEntry(t, h, queries, "entry-preexisting", owner, "Prod DB", "IRREPLACEABLE-SECRET")

	// Guard the setup: there must be real ciphertext AND no sentinel yet, or
	// this test silently stops exercising the bootstrap path.
	if _, err := queries.GetSetting(ctx, vaultKeyCheckSetting); err == nil {
		t.Fatal("ABORT: a sentinel already exists, this is not the bootstrap boot")
	}
	probeHas, probeOpens, err := vaultKeyOpensExistingData(ctx, queries, correctKey)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !probeHas || !probeOpens {
		t.Fatalf("ABORT: setup did not produce openable ciphertext (has=%v opens=%v)", probeHas, probeOpens)
	}

	// THE BUG: bootstrapping under a wrong key must be refused, not sealed.
	if err := VerifyVaultKey(ctx, queries, wrongKey); !errors.Is(err, ErrVaultKeyMismatch) {
		t.Fatalf("a WRONG key bootstrapped the sentinel on a populated database (err=%v): "+
			"the correct key would be locked out forever and the data lost", err)
	}
	if _, err := queries.GetSetting(ctx, vaultKeyCheckSetting); err == nil {
		t.Fatal("the refused bootstrap still wrote a sentinel: the correct key is now locked out")
	}

	// The correct key must still be able to bootstrap, which is the self-heal
	// path for a real deployment upgrading into this feature.
	if err := VerifyVaultKey(ctx, queries, correctKey); err != nil {
		t.Fatalf("the CORRECT key was refused on a populated database: existing deployments could never start (%v)", err)
	}
	sealed, err := queries.GetSetting(ctx, vaultKeyCheckSetting)
	if err != nil || sealed == "" {
		t.Fatalf("the correct key did not write the sentinel: %v", err)
	}

	// And the gate now works in both directions.
	if err := VerifyVaultKey(ctx, queries, correctKey); err != nil {
		t.Fatalf("correct key rejected after sealing: %v", err)
	}
	if err := VerifyVaultKey(ctx, queries, wrongKey); !errors.Is(err, ErrVaultKeyMismatch) {
		t.Fatalf("wrong key accepted after sealing: %v", err)
	}
}

// TestSentinelStillBootstrapsOnAnEmptyDatabase guards the other direction: the
// probe must not turn a brand new install into a startup failure.
func TestSentinelStillBootstrapsOnAnEmptyDatabase(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	has, _, err := vaultKeyOpensExistingData(ctx, queries, "any-key-at-all")
	if err != nil {
		t.Fatalf("probe on an empty database errored: %v", err)
	}
	if has {
		t.Fatal("ABORT: the fresh database already reports ciphertext")
	}
	if err := VerifyVaultKey(ctx, queries, "any-key-at-all"); err != nil {
		t.Fatalf("a new install could not bootstrap: %v", err)
	}
}

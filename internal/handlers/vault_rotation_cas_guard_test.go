package handlers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRotateValueHasOneCallSite keeps the compare-and-swap chokepoint a
// chokepoint.
//
// The raw query took four parameters and one of them was easy to omit. It had
// two call sites that had to agree, and for three consecutive audit rounds they
// did not: the sweep bound the token and the manual handler did not, so manual
// rotation was 100% dead while the suite stayed green. A third entry point would
// have had the same coin flip.
//
// persistRotatedValue is now the only caller, and it refuses a missing token
// outright. This test fails if anyone reintroduces a direct call.
func TestRotateValueHasOneCallSite(t *testing.T) {
	const raw = "RotateVaultEntryValueUnchecked("
	const allowed = "vault_rotation_cas.go"

	var offenders []string
	seen := 0
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		base := filepath.Base(path)
		// Skip tests and sqlc output: the generated file necessarily declares it.
		if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, ".sql.go") || base == "querier.go" {
			return nil
		}
		src, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		if !strings.Contains(string(src), raw) {
			return nil
		}
		seen++
		if base != allowed {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// Fail closed: if the identifier vanished the guard is asserting nothing.
	if seen == 0 {
		t.Fatal("ABORT: the raw rotate query is referenced nowhere; this guard is vacuous " +
			"(was it renamed? update this test with it)")
	}
	for _, o := range offenders {
		t.Errorf("%s calls the raw rotate query directly.\n"+
			"Use persistRotatedValue: it refuses a missing compare-and-swap token, which is "+
			"the mistake that killed manual rotation for three audit rounds.", o)
	}
}

// TestPersistRotatedValueRefusesAMissingToken pins the fail-loud behaviour.
//
// Without the token the UPDATE matches zero rows, which is indistinguishable
// from a genuine conflict. Callers then reported it as 404 "vault entry not
// found" (round 12) and later as 409 "the secret changed" (round 13), both for
// an entry nobody had touched. An error is the only honest answer.
func TestPersistRotatedValueRefusesAMissingToken(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "cas-guard@example.com", "user", "")
	mustEntry(t, h, queries, "cas-guard-1", owner, "Entry", "v")

	for name, snap := range map[string]rotationSnapshot{
		"no token":    {EntryID: "cas-guard-1"},
		"no entry id": {UpdatedAtText: "2026-07-29 12:00:00"},
	} {
		applied, err := persistRotatedValue(ctx, queries, snap, []byte("ct"), []byte("nonce"))
		if !errors.Is(err, errNoCASToken) {
			t.Errorf("%s: got (applied=%v, err=%v), want errNoCASToken", name, applied, err)
		}
		if applied {
			t.Errorf("%s: reported the write as applied", name)
		}
	}

	// And the happy path still works through the same door.
	row, err := queries.GetVaultEntryForRotation(ctx, "cas-guard-1")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	ct, nonce, err := h.encrypt([]byte("NEW"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	applied, err := persistRotatedValue(ctx, queries,
		snapshotFromRotationRow("cas-guard-1", row.UpdatedAtText, row.EncryptedValue), ct, nonce)
	if err != nil || !applied {
		t.Fatalf("a valid snapshot did not apply: applied=%v err=%v", applied, err)
	}
}

// TestMayGenerateLocallyIsExhaustive pins the fail-closed belt over the local
// secret generator.
//
// An ablation sweep flipped mayGenerateLocally to `return true` and the entire
// suite stayed green, because the switch on providerRole in the handler already
// returns for every non-local role before the belt is reached. That is what a belt
// IS, and it is exactly why it needs its own test: it is unreachable while the
// braces hold, so the only thing standing behind a future fifth role is a line of
// code nothing exercises.
//
// Enumerated explicitly rather than looped over a range, so ADDING a role makes
// this fail to compile-or-pass until someone decides which side it belongs on.
func TestMayGenerateLocallyIsExhaustive(t *testing.T) {
	cases := []struct {
		role providerRole
		name string
		want bool
	}{
		{providerNone, "providerNone", true},
		{providerAuto, "providerAuto", false},
		{providerReminder, "providerReminder", false},
		{providerUnknown, "providerUnknown", false},
	}
	for _, c := range cases {
		if got := c.role.mayGenerateLocally(); got != c.want {
			t.Errorf("%s.mayGenerateLocally() = %v, want %v\n"+
				"Only an entry with NO provider is a local secret this server may regenerate. "+
				"Saying yes for any other role overwrites a real upstream credential with random "+
				"bytes and reports success.", c.name, got, c.want)
		}
	}
	// A new role must not silently default to "may generate". iota ordering makes
	// the highest known role the boundary.
	if next := providerUnknown + 1; next.mayGenerateLocally() {
		t.Errorf("an unrecognised providerRole (%d) may generate locally; the predicate must "+
			"name the permitted role rather than exclude the forbidden ones", int(next))
	}
}

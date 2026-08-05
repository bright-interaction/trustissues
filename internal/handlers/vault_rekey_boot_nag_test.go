package handlers

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestBootKeepsSayingTheRetiredKeyIsStillLoaded.
//
// The sweep logs "rotation complete, remove the previous key" exactly once, in
// whichever process happened to run it. After it re-seals the sentinel,
// SentinelOnPreviousKey answers false forever, so every later boot said nothing
// at all about the retired key still sitting in the environment.
//
// The admin UI covers this with a green banner, which is precisely no help to a
// headless deploy driven by TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT: those are the
// instances where nobody opens Settings, and they are the ones the flag exists
// for. A retired key that stays loaded still opens this data and still opens
// every backup taken before the sweep, which is the entire thing a rotation
// after a suspected compromise is supposed to end.
func TestBootKeepsSayingTheRetiredKeyIsStillLoaded(t *testing.T) {
	ctx := context.Background()
	dbConn, queries := newRekeyDB(t)
	seedUnderKey(t, rekeyHandler(dbConn, queries, rekeyOldKey, ""), queries)

	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	if _, err := rotating.RekeyVault(ctx); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	capture := func(vaultKeys ...string) string {
		var buf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		EnforceVaultKey(ctx, queries, vaultKeys...)
		return buf.String()
	}

	// Every boot, not just the first one after the sweep.
	for boot := 1; boot <= 3; boot++ {
		out := capture(rekeyNewKey, rekeyOldKey)
		if !strings.Contains(out, "TRUSTISSUES_VAULT_KEY_PREVIOUS") {
			t.Fatalf(`boot %d said nothing about the retired key still being loaded.

The sweep's own one-shot log line is long gone by now (it belonged to whichever
process ran the sweep). On a headless deploy this boot log is the ONLY surface
that could tell the operator the old key is still in the environment.

got: %q`, boot, out)
		}
	}

	// And it must go quiet once the key is actually gone, or the warning is
	// noise and gets filtered out within a week.
	out := capture(rekeyNewKey)
	if strings.Contains(out, "TRUSTISSUES_VAULT_KEY_PREVIOUS") {
		t.Fatalf("the boot still nags about the previous key when none is configured: %q", out)
	}
}

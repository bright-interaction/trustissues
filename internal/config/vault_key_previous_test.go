package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

const (
	testCurrentKey  = "0123456789abcdef0123456789abcdef"
	testPreviousKey = "fedcba9876543210fedcba9876543210"
)

func withBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TRUSTISSUES_JWT_SECRET", testCurrentKey)
	t.Setenv("TRUSTISSUES_VAULT_KEY", testCurrentKey)
	t.Setenv("TRUSTISSUES_VAULT_KEY_PREVIOUS", "")
	t.Setenv("TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT", "")
}

// TestAPreviousVaultKeyEqualToTheCurrentOneIsRefused.
//
// The one previous-key misconfiguration that must fail closed. It is not a weak
// key, it is a NO-OP that reports as a configured rotation on every status
// surface, and an operator who trusts that report deletes the old key from their
// password manager.
func TestAPreviousVaultKeyEqualToTheCurrentOneIsRefused(t *testing.T) {
	withBaseEnv(t)

	// Absent is fine: that is the steady state.
	if _, err := Load(); err != nil {
		t.Fatalf("no previous key should load cleanly: %v", err)
	}

	// A real second key is fine.
	t.Setenv("TRUSTISSUES_VAULT_KEY_PREVIOUS", testPreviousKey)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("a valid previous key was refused: %v", err)
	}
	if cfg.VaultKeyPrevious != testPreviousKey {
		t.Fatalf("VaultKeyPrevious = %q, want the configured value", cfg.VaultKeyPrevious)
	}

	t.Setenv("TRUSTISSUES_VAULT_KEY_PREVIOUS", testCurrentKey)
	_, err = Load()
	if err == nil {
		t.Fatal("a previous key identical to the current one was accepted; it reports as a configured " +
			"rotation while converting nothing")
	}
	if !strings.Contains(err.Error(), "identical") {
		t.Fatalf("error %q does not explain the problem", err)
	}
}

// TestAWeakPreviousVaultKeyIsWarnedAboutAndACCEPTED.
//
// The previous key describes data that already exists, which makes it unlike
// every other secret this file validates. Refusing a short or weak one protects
// nothing (the data is sealed under it either way) and blocks the single
// rotation that matters most: an instance whose key predates these checks, or
// was forced through with TRUSTISSUES_ALLOW_KEY_MISMATCH, cannot name that key
// as PREVIOUS and therefore cannot rotate away from it. That is the population
// holding the weakest key in the estate.
//
// So: accepted, and said out loud.
func TestAWeakPreviousVaultKeyIsWarnedAboutAndAccepted(t *testing.T) {
	withBaseEnv(t)

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	for _, tc := range []struct{ name, value string }{
		{"a key shorter than today's minimum", "short-old-key"},
		{"a key that looks like a placeholder", "changeme_changeme_changeme_change"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))

			t.Setenv("TRUSTISSUES_VAULT_KEY_PREVIOUS", tc.value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf(`%q was refused as a previous vault key: %v

Refusing it does not make the data safer, it is already encrypted with that key.
It only makes the rotation AWAY from that key impossible, for the instances that
need it most.`, tc.value, err)
			}
			if cfg.VaultKeyPrevious != tc.value {
				t.Fatalf("VaultKeyPrevious = %q, want %q", cfg.VaultKeyPrevious, tc.value)
			}
			if !strings.Contains(buf.String(), "TRUSTISSUES_VAULT_KEY_PREVIOUS") {
				t.Fatalf("no warning was logged for %q; accepting a weak key silently is how it stays "+
					"in the environment forever", tc.value)
			}
		})
	}
}

// TestRekeyOnBootRequiresAPreviousKey.
//
// The flag with no previous key is not a harmless no-op. The operator asked for
// a rotation to be completed at boot; the sweep would report "already current"
// for a store whose rows are all sealed under a key the process does not hold,
// and the boot would look successful.
func TestRekeyOnBootRequiresAPreviousKey(t *testing.T) {
	withBaseEnv(t)
	t.Setenv("TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT", "1")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "TRUSTISSUES_VAULT_KEY_PREVIOUS is empty") {
		t.Fatalf("boot sweep with no previous key should be refused, got %v", err)
	}

	t.Setenv("TRUSTISSUES_VAULT_KEY_PREVIOUS", testPreviousKey)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("boot sweep with a previous key was refused: %v", err)
	}
	if !cfg.RekeyOnBoot {
		t.Fatal("RekeyOnBoot did not parse as true")
	}
}

// TestRekeyOnBootAcceptsTheSpellingsOperatorsActuallyWrite.
//
// envInt already had this bug fixed once: a malformed value silently became the
// default and the operator had no way to tell. A boolean read as false when the
// operator wrote "TRUE" would skip a rotation they believe they ran.
func TestRekeyOnBootAcceptsTheSpellingsOperatorsActuallyWrite(t *testing.T) {
	withBaseEnv(t)
	t.Setenv("TRUSTISSUES_VAULT_KEY_PREVIOUS", testPreviousKey)

	for _, v := range []string{"1", "true", "TRUE", "True", "yes", "on", " true "} {
		t.Setenv("TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT", v)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if !cfg.RekeyOnBoot {
			t.Errorf("%q was not read as true; an operator who wrote it would silently get no rotation", v)
		}
	}
	for _, v := range []string{"0", "false", "FALSE", "no", "off"} {
		t.Setenv("TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT", v)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if cfg.RekeyOnBoot {
			t.Errorf("%q was read as true", v)
		}
	}
}

package config

import (
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

// TestPreviousVaultKeyIsHeldToTheSameBarAsTheCurrentOne.
//
// A malformed previous key is worse than an absent one. The operator believes
// the dual-key read is working, every status surface says a rotation is
// configured, and they find out otherwise when the sweep reports rows it cannot
// open, which is the middle of an incident.
func TestPreviousVaultKeyIsHeldToTheSameBarAsTheCurrentOne(t *testing.T) {
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

	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{
			name: "identical to the current key", value: testCurrentKey,
			// This is the dangerous one: it reports as a configured rotation
			// while being a no-op, and an operator who trusts that report deletes
			// the old key from their password manager.
			want: "identical",
		},
		{name: "too short", value: "short", want: "at least 32 characters"},
		{name: "obvious placeholder", value: "changeme_changeme_changeme_change", want: "placeholder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TRUSTISSUES_VAULT_KEY_PREVIOUS", tc.value)
			_, err := Load()
			if err == nil {
				t.Fatalf("%q was accepted as a previous vault key", tc.value)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not explain the problem (%q)", err, tc.want)
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

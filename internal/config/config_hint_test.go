package config

import (
	"os"
	"strings"
	"testing"
)

// TestHintLevelTyposAreRefused closes a fail-open.
//
// ParseHintLevel falls back to HintFull for anything it does not recognise. That is
// correct for an UNSET value and dangerous for a misspelled one: HintFull is the
// most verbose level, emitting the email domain, the exact value length and the
// personnummer century to the model provider. An operator writing "None" or
// "minimum" is trying to reduce what leaves the building and silently got the
// maximum. It was the only Shield setting with no validation.
//
// The rule: a recognised value is accepted, anything else refuses startup.
func TestHintLevelTyposAreRefused(t *testing.T) {
	// Keep the rest of the config valid so only the hint level decides.
	const key = "0123456789abcdef0123456789abcdef"
	for _, e := range [][2]string{
		{"TRUSTISSUES_JWT_SECRET", key}, {"TRUSTISSUES_VAULT_KEY", key},
	} {
		t.Setenv(e[0], e[1])
	}

	valid := []string{"full", "bucketed", "minimal", "none"}
	for _, v := range valid {
		t.Setenv("TRUSTISSUES_SHIELD_HINT_LEVEL", v)
		if _, err := Load(); err != nil && strings.Contains(err.Error(), "SHIELD_HINT_LEVEL") {
			t.Errorf("the valid level %q was refused: %v", v, err)
		}
	}

	// Every one of these is a plausible attempt to REDUCE disclosure.
	for _, bad := range []string{"None", "NONE", "nonw", "minimum", "bucket", "off", "0", "true", " none"} {
		t.Setenv("TRUSTISSUES_SHIELD_HINT_LEVEL", bad)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SHIELD_HINT_LEVEL") {
			t.Errorf("the level %q was accepted and silently becomes the MOST verbose level, "+
				"egressing exactly the metadata it was set to suppress (err=%v)", bad, err)
		}
	}

	// Unset must still work: the fallback is right when nothing was configured.
	os.Unsetenv("TRUSTISSUES_SHIELD_HINT_LEVEL")
	if _, err := Load(); err != nil && strings.Contains(err.Error(), "SHIELD_HINT_LEVEL") {
		t.Errorf("an UNSET hint level was refused; the default must remain valid: %v", err)
	}
}

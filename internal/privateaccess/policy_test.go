package privateaccess

import "testing"

func TestParseUsesOneClosedPolicyVocabulary(t *testing.T) {
	t.Parallel()

	for _, value := range []Policy{PolicyStandard, PolicySensitivePrivate, PolicyFullyPrivate} {
		got, ok := Parse(string(value))
		if !ok || got != value {
			t.Fatalf("Parse(%q) = %q, %v", value, got, ok)
		}
	}
	for _, value := range []string{"", "private", "STANDARD", " fully_private "} {
		if got, ok := Parse(value); ok {
			t.Fatalf("Parse(%q) accepted %q", value, got)
		}
	}

	if got, ok := ParseOrDefault(""); !ok || got != PolicyStandard {
		t.Fatalf("ParseOrDefault(empty) = %q, %v, want %q, true", got, ok, PolicyStandard)
	}
}

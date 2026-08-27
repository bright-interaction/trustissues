package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateSocketIsDisabledByDefault(t *testing.T) {
	withBaseEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.PrivateSocketPath != "" {
		t.Fatalf("PrivateSocketPath = %q, want disabled", cfg.PrivateSocketPath)
	}
}

func TestPrivateSocketAcceptsCleanAbsolutePath(t *testing.T) {
	withBaseEnv(t)
	path := "/tmp/trustissues-private-test.sock"
	t.Setenv("TRUSTISSUES_PRIVATE_SOCKET_PATH", path)
	t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", "https://vault-internal.example.test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.PrivateSocketPath != path {
		t.Fatalf("PrivateSocketPath = %q, want %q", cfg.PrivateSocketPath, path)
	}
}

func TestPrivateSocketRejectsAmbiguousOrUnportablePaths(t *testing.T) {
	withBaseEnv(t)

	cases := map[string]string{
		"relative":   "private.sock",
		"whitespace": " /run/trustissues/private.sock",
		"unclean":    "/run/trustissues/../private.sock",
		"too long":   "/" + strings.Repeat("a", 100),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TRUSTISSUES_PRIVATE_SOCKET_PATH", path)
			t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", "https://vault-internal.example.test")
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "TRUSTISSUES_PRIVATE_SOCKET_PATH") {
				t.Fatalf("Load() error = %v, want private-socket validation error", err)
			}
		})
	}
}

func TestPrivateSocketAndBaseURLAreOneConfigurationUnit(t *testing.T) {
	withBaseEnv(t)

	t.Run("socket needs URL", func(t *testing.T) {
		t.Setenv("TRUSTISSUES_PRIVATE_SOCKET_PATH", filepath.Join(t.TempDir(), "private.sock"))
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "TRUSTISSUES_PRIVATE_BASE_URL is required") {
			t.Fatalf("Load() error = %v, want missing private URL error", err)
		}
	})

	t.Run("URL needs socket", func(t *testing.T) {
		t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", "https://vault-internal.example.test")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "private ingress is disabled") {
			t.Fatalf("Load() error = %v, want disabled-ingress error", err)
		}
	})
}

func TestPrivateBaseURLRequiresExactHTTPSOrigin(t *testing.T) {
	withBaseEnv(t)
	path := filepath.Join(t.TempDir(), "private.sock")
	t.Setenv("TRUSTISSUES_PRIVATE_SOCKET_PATH", path)

	for _, raw := range []string{
		"http://vault-internal.example.test",
		"https://user@vault-internal.example.test",
		"https://vault-internal.example.test/app",
		"https://vault-internal.example.test?mode=private",
		"https://vault-internal.example.test:0443",
		"https://vault-internal.example.test:70000",
		"https://[0:0:0:0:0:0:0:1]",
		" https://vault-internal.example.test",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", raw)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "TRUSTISSUES_PRIVATE_BASE_URL") {
				t.Fatalf("Load() error = %v, want private URL validation error", err)
			}
		})
	}
}

func TestPrivateBaseURLRequiresSeparateHostname(t *testing.T) {
	withBaseEnv(t)
	t.Setenv("TRUSTISSUES_PRIVATE_SOCKET_PATH", "/tmp/trustissues-private-hostname-test.sock")
	t.Setenv("TRUSTISSUES_BASE_URL", "https://vault.example.test")

	for _, raw := range []string{
		"https://vault.example.test",
		"https://VAULT.example.test:8443",
		"https://vault.example.test.",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", raw)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "different hostname") {
				t.Fatalf("Load() error = %v, want same-host private URL refusal", err)
			}
		})
	}

	for _, pair := range []struct {
		publicURL  string
		privateURL string
	}{
		{"https://127.0.0.1", "https://127.1"},
		{"https://127.0.0.1", "https://0177.0.0.1"},
		{"https://127.0.0.1", "https://0x7f000001"},
		{"https://[::1]", "https://[0:0:0:0:0:0:0:1]"},
	} {
		t.Run(pair.publicURL+" vs "+pair.privateURL, func(t *testing.T) {
			t.Setenv("TRUSTISSUES_BASE_URL", pair.publicURL)
			t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", pair.privateURL)
			_, err := Load()
			if err == nil || (!strings.Contains(err.Error(), "canonical IP") &&
				!strings.Contains(err.Error(), "different hostname")) {
				t.Fatalf("Load() error = %v, want equivalent/ambiguous IP hostname refusal", err)
			}
		})
	}

	t.Setenv("TRUSTISSUES_BASE_URL", "https://vault.example.test:0443")
	t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", "https://vault-private.example.test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "canonical decimal") {
		t.Fatalf("noncanonical public port error = %v, want browser-origin-safe port refusal", err)
	}

	t.Setenv("TRUSTISSUES_BASE_URL", "https://våult.example.test")
	t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", "https://vault-private.example.test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ASCII") {
		t.Fatalf("Unicode boundary hostname error = %v, want explicit punycode/ASCII refusal", err)
	}

	t.Setenv("TRUSTISSUES_BASE_URL", "https://vault.example.test")
	t.Setenv("TRUSTISSUES_PRIVATE_BASE_URL", "https://vault-private.example.test")
	if _, err := Load(); err != nil {
		t.Fatalf("separate public/private hostnames should load: %v", err)
	}
}

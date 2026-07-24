// Package config centralizes all environment configuration for Trustissues.
// Every environment variable read in the application goes through this
// package; no other package calls os.Getenv directly. All variables use the
// TRUSTISSUES_ prefix.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Port is the HTTP listen port. Env: TRUSTISSUES_PORT (default 8080).
	Port int
	// BindHost is the interface the HTTP server listens on. Defaults to the
	// loopback address so a bare-metal deploy is never reachable off-host by
	// accident; put a TLS-terminating reverse proxy (Caddy) in front. In a
	// container the compose/Dockerfile overrides this to 0.0.0.0 because the
	// network namespace already isolates the listener.
	// Env: TRUSTISSUES_BIND_HOST (default 127.0.0.1).
	BindHost string
	// TrustedProxyHops is the number of trusted reverse-proxy hops in front of
	// the server. The client IP for rate limiting is derived by stripping this
	// many trusted hops from the right of the forwarding chain, so a client
	// cannot spoof X-Forwarded-For to evade limits. The intended deploy sits
	// behind one Caddy, hence the default of 1.
	// Env: TRUSTISSUES_TRUSTED_PROXY_HOPS (default 1).
	TrustedProxyHops int
	// JWTSecret signs session JWTs. Env: TRUSTISSUES_JWT_SECRET (required).
	JWTSecret string
	// VaultKey is the symmetric key protecting encrypted columns (vault
	// entries, TOTP seeds, notification channel configs).
	// Env: TRUSTISSUES_VAULT_KEY (required).
	VaultKey string
	// BaseURL is the externally reachable URL of this instance.
	// Env: TRUSTISSUES_BASE_URL (default http://localhost:8080).
	BaseURL string
	// DataDir holds the SQLite database. Env: TRUSTISSUES_DATA_DIR (default ./data).
	DataDir string
	// FrontendDir is the built frontend to serve.
	// Env: TRUSTISSUES_FRONTEND_DIR (default ./frontend/dist).
	FrontendDir string
	// LogLevel is one of debug, info, warn, error.
	// Env: TRUSTISSUES_LOG_LEVEL (default info).
	LogLevel string
}

// Load reads configuration from TRUSTISSUES_* environment variables.
// TRUSTISSUES_JWT_SECRET and TRUSTISSUES_VAULT_KEY are required; the process
// must refuse to start without them (auth and at-rest encryption are never
// optional). All other fields have defaults.
func Load() (*Config, error) {
	cfg := &Config{
		Port:             envInt("TRUSTISSUES_PORT", 8080),
		BindHost:         envStr("TRUSTISSUES_BIND_HOST", "127.0.0.1"),
		TrustedProxyHops: envInt("TRUSTISSUES_TRUSTED_PROXY_HOPS", 1),
		JWTSecret:        os.Getenv("TRUSTISSUES_JWT_SECRET"),
		VaultKey:         os.Getenv("TRUSTISSUES_VAULT_KEY"),
		BaseURL:          envStr("TRUSTISSUES_BASE_URL", "http://localhost:8080"),
		DataDir:          envStr("TRUSTISSUES_DATA_DIR", "./data"),
		FrontendDir:      envStr("TRUSTISSUES_FRONTEND_DIR", "./frontend/dist"),
		LogLevel:         envStr("TRUSTISSUES_LOG_LEVEL", "info"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SlogLevel converts the string log level to a slog.Level.
func (c *Config) SlogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Validate checks the configuration for errors and returns all found issues.
// Called at startup so misconfiguration fails fast instead of surfacing as
// runtime auth or crypto failures.
func (c *Config) Validate() error {
	var errs []string

	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, fmt.Sprintf("TRUSTISSUES_PORT must be between 1 and 65535 (got %d)", c.Port))
	}

	// Auth is never optional: refuse to start without the required secrets.
	// Length alone is not enough: a 32-char placeholder still boots a
	// predictable-key instance, so reject known placeholders and low-entropy
	// values too.
	if c.JWTSecret == "" {
		errs = append(errs, "TRUSTISSUES_JWT_SECRET is required (generate one: openssl rand -hex 32)")
	} else if len(c.JWTSecret) < 32 {
		errs = append(errs, "TRUSTISSUES_JWT_SECRET must be at least 32 characters")
	} else if isWeakSecret(c.JWTSecret) {
		errs = append(errs, "TRUSTISSUES_JWT_SECRET looks like a placeholder or low-entropy value (generate a real one: openssl rand -hex 32)")
	}

	if c.VaultKey == "" {
		errs = append(errs, "TRUSTISSUES_VAULT_KEY is required (generate one: openssl rand -hex 32)")
	} else if len(c.VaultKey) < 32 {
		errs = append(errs, "TRUSTISSUES_VAULT_KEY must be at least 32 characters")
	} else if isWeakSecret(c.VaultKey) {
		errs = append(errs, "TRUSTISSUES_VAULT_KEY looks like a placeholder or low-entropy value (generate a real one: openssl rand -hex 32)")
	}

	if c.BindHost == "" {
		errs = append(errs, "TRUSTISSUES_BIND_HOST is required (default 127.0.0.1)")
	}

	if c.TrustedProxyHops < 0 {
		errs = append(errs, fmt.Sprintf("TRUSTISSUES_TRUSTED_PROXY_HOPS must be zero or greater (got %d)", c.TrustedProxyHops))
	}

	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("TRUSTISSUES_BASE_URL is invalid: %v", err))
		} else if u.Scheme != "http" && u.Scheme != "https" {
			errs = append(errs, "TRUSTISSUES_BASE_URL must use http or https scheme")
		}
	}

	if c.DataDir == "" {
		errs = append(errs, "TRUSTISSUES_DATA_DIR is required")
	}

	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if c.LogLevel != "" && !validLogLevels[strings.ToLower(c.LogLevel)] {
		errs = append(errs, fmt.Sprintf("TRUSTISSUES_LOG_LEVEL must be one of: debug, info, warn, error (got %q)", c.LogLevel))
	}

	if len(errs) > 0 {
		return errors.New("config validation failed:\n  - " + strings.Join(errs, "\n  - "))
	}
	return nil
}

// WarnWeakConfig logs warnings for configuration that works but may be
// insecure. Call after Validate() succeeds.
func (c *Config) WarnWeakConfig() {
	if strings.Contains(c.BaseURL, "localhost") || strings.Contains(c.BaseURL, "127.0.0.1") {
		slog.Warn("TRUSTISSUES_BASE_URL is set to localhost, update for production use")
	}
	if strings.HasPrefix(c.BaseURL, "http://") && !strings.Contains(c.BaseURL, "localhost") && !strings.Contains(c.BaseURL, "127.0.0.1") {
		slog.Warn("TRUSTISSUES_BASE_URL uses HTTP instead of HTTPS, session cookies carry the Secure flag and will not be sent over plain HTTP")
	}
}

// isWeakSecret reports whether s is an obvious placeholder or a low-entropy
// value that must never be accepted as a real JWT/vault key. It catches the
// shipped .env.example placeholders, common "changeme"/"replace me" markers,
// all-same-character strings, and strings with too few distinct bytes to be a
// real random key. A genuine openssl rand -hex 32 value passes easily.
func isWeakSecret(s string) bool {
	l := strings.ToLower(s)
	for _, bad := range []string{
		"changeme", "change_me", "replace_me", "replaceme", "example",
		"placeholder", "openssl_rand", "your_", "secret_here", "xxxx",
	} {
		if strings.Contains(l, bad) {
			return true
		}
	}

	// All-same-character (e.g. "aaaa...", "0000...").
	distinct := map[rune]struct{}{}
	for _, r := range s {
		distinct[r] = struct{}{}
	}
	if len(distinct) < 6 {
		return true
	}
	return false
}

// envStr returns the value of an environment variable or a default.
func envStr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// envInt returns the value of an environment variable as int or a default.
func envInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}

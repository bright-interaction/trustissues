// Package config centralizes all environment configuration for Trustissues.
// Every environment variable read in the application goes through this
// package; no other package calls os.Getenv directly. All variables use the
// TRUSTISSUES_ prefix.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bright-interaction/trustissues/internal/shield"
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
	// TrustedProxyPeers is the comma-separated set of direct peer IPs/CIDRs that
	// may supply forwarding headers. Private address space is intentionally not
	// trusted wholesale because container networks are often shared.
	// Env: TRUSTISSUES_TRUSTED_PROXY_PEERS (default loopback only).
	TrustedProxyPeers string
	// PrivateSocketPath enables the optional private-ingress listener when set.
	// It is a Unix-domain socket rather than a TCP port so only a local overlay
	// connector explicitly given filesystem access can reach it. Requests on
	// this listener are application-stamped private; no header, Host value, or
	// source IP can select that trust zone.
	// Env: TRUSTISSUES_PRIVATE_SOCKET_PATH (default empty/disabled).
	PrivateSocketPath string
	// PrivateBaseURL is the HTTPS browser origin routed by the optional overlay
	// connector to PrivateSocketPath. Keeping it distinct in configuration lets
	// CSRF accept the private SPA without also accepting that origin on public
	// ingress (or accepting the public origin on private ingress).
	// Env: TRUSTISSUES_PRIVATE_BASE_URL (required when the private socket is set).
	PrivateBaseURL string
	// JWTSecret signs session JWTs. Env: TRUSTISSUES_JWT_SECRET (required).
	JWTSecret string
	// VaultKey is the symmetric key protecting encrypted columns (vault
	// entries, TOTP seeds, notification channel configs).
	// Env: TRUSTISSUES_VAULT_KEY (required).
	VaultKey string
	// VaultKeyPrevious is the master key this data directory was encrypted with
	// BEFORE the current one. Set it only while a rotation is in flight.
	//
	// It exists because changing TRUSTISSUES_VAULT_KEY in place used to orphan
	// every encrypted value: the boot gate refused to start (correctly, the data
	// was still recoverable), and the only documented way forward was a manual
	// export / re-import. That is not a recovery path you want to discover during
	// a suspected key compromise. With this set, every decrypt tries the current
	// key and then this one, so a store that is unswept, half-swept, or restored
	// from a backup taken before the sweep keeps serving.
	//
	// It is NOT a permanent setting. Leaving it configured means the old key is
	// still live in the environment and still opens everything, which is the
	// opposite of what rotating after a compromise is for. Run the re-encrypt
	// sweep, confirm the status page reports the store fully on the current key,
	// then remove it.
	// Env: TRUSTISSUES_VAULT_KEY_PREVIOUS (optional).
	VaultKeyPrevious string
	// RekeyOnBoot runs the re-encrypt sweep once at startup, before the server
	// accepts traffic. The interactive path (admin UI / API) is the primary one,
	// because a rotation is an incident and the operator wants to see the report.
	// This flag exists for headless deploys where nobody logs in: set the new
	// key, set the previous key, set this to 1, restart, then remove both.
	// Env: TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT (default false).
	RekeyOnBoot bool
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
	// ShieldKey enables LLM-boundary tokenization (Shield). When set (32+ hex
	// chars, its own key so a leak does not touch the vault), PII crossing to an
	// external LLM through the AI gateway or MCP boundary is tokenized and
	// resolved server-side. Empty = Shield off (data passes through unchanged).
	// Env: TRUSTISSUES_SHIELD_KEY (optional).
	ShieldKey string
	// ShieldHintLevel dials how much value-derived metadata a marker exposes to
	// the model: full | bucketed | minimal | none. Default full.
	// Env: TRUSTISSUES_SHIELD_HINT_LEVEL (default full).
	ShieldHintLevel string
}

// Load reads configuration from TRUSTISSUES_* environment variables.
// TRUSTISSUES_JWT_SECRET and TRUSTISSUES_VAULT_KEY are required; the process
// must refuse to start without them (auth and at-rest encryption are never
// optional). All other fields have defaults.
func Load() (*Config, error) {
	cfg := &Config{
		Port:              envInt("TRUSTISSUES_PORT", 8080),
		BindHost:          envStr("TRUSTISSUES_BIND_HOST", "127.0.0.1"),
		TrustedProxyHops:  envInt("TRUSTISSUES_TRUSTED_PROXY_HOPS", 1),
		TrustedProxyPeers: envStrAllowEmpty("TRUSTISSUES_TRUSTED_PROXY_PEERS", "127.0.0.1/32,::1/128"),
		PrivateSocketPath: os.Getenv("TRUSTISSUES_PRIVATE_SOCKET_PATH"),
		PrivateBaseURL:    os.Getenv("TRUSTISSUES_PRIVATE_BASE_URL"),
		JWTSecret:         os.Getenv("TRUSTISSUES_JWT_SECRET"),
		VaultKey:          os.Getenv("TRUSTISSUES_VAULT_KEY"),
		VaultKeyPrevious:  os.Getenv("TRUSTISSUES_VAULT_KEY_PREVIOUS"),
		RekeyOnBoot:       envBool("TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT", false),
		BaseURL:           envStr("TRUSTISSUES_BASE_URL", "http://localhost:8080"),
		DataDir:           envStr("TRUSTISSUES_DATA_DIR", "./data"),
		FrontendDir:       envStr("TRUSTISSUES_FRONTEND_DIR", "./frontend/dist"),
		LogLevel:          envStr("TRUSTISSUES_LOG_LEVEL", "info"),
		ShieldKey:         os.Getenv("TRUSTISSUES_SHIELD_KEY"),
		ShieldHintLevel:   envStr("TRUSTISSUES_SHIELD_HINT_LEVEL", "full"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ShieldEnabled reports whether LLM-boundary tokenization is configured.
func (c *Config) ShieldEnabled() bool { return c.ShieldKey != "" }

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

	// An unrecognised hint level must not silently become the most verbose one.
	// See shield.ValidHintLevel: a misspelled "none" used to egress the full
	// value-derived metadata it was set to suppress.
	if !shield.ValidHintLevel(c.ShieldHintLevel) {
		errs = append(errs, fmt.Sprintf(
			"TRUSTISSUES_SHIELD_HINT_LEVEL must be one of %s (got %q); an unrecognised value "+
				"would fall back to the most verbose level and egress the metadata you were "+
				"trying to suppress",
			strings.Join(shield.HintLevelNames, ", "), c.ShieldHintLevel))
	}

	if c.VaultKey == "" {
		errs = append(errs, "TRUSTISSUES_VAULT_KEY is required (generate one: openssl rand -hex 32)")
	} else if len(c.VaultKey) < 32 {
		errs = append(errs, "TRUSTISSUES_VAULT_KEY must be at least 32 characters")
	} else if isWeakSecret(c.VaultKey) {
		errs = append(errs, "TRUSTISSUES_VAULT_KEY looks like a placeholder or low-entropy value (generate a real one: openssl rand -hex 32)")
	}

	// The previous key describes data that ALREADY EXISTS. That is what makes it
	// different from every other secret validated here, and why strength is a
	// warning rather than a refusal.
	//
	// Refusing a short or weak previous key does not make anything safer: the
	// data is already sealed under it either way. All it does is make the one
	// rotation that matters most impossible. An instance whose key was set before
	// these checks existed, or forced through with TRUSTISSUES_ALLOW_KEY_MISMATCH,
	// cannot name that key as PREVIOUS, so it cannot rotate away from it, and
	// that is exactly the population with the weakest key in the estate. The
	// operator is told, loudly, and then allowed to proceed.
	//
	// Equal-to-current stays a hard error. It is not a weak key, it is a no-op
	// that REPORTS as a configured rotation on every status surface, which is
	// precisely the state in which somebody deletes the old key from their
	// password manager believing the rotation is set up.
	if c.VaultKeyPrevious != "" {
		switch {
		case c.VaultKeyPrevious == c.VaultKey:
			errs = append(errs, "TRUSTISSUES_VAULT_KEY_PREVIOUS is identical to TRUSTISSUES_VAULT_KEY; "+
				"that is a no-op that reports as a configured rotation. Set it to the OLD key, or unset it")
		case len(c.VaultKeyPrevious) < 32:
			slog.Warn("config: TRUSTISSUES_VAULT_KEY_PREVIOUS is shorter than 32 characters. " +
				"Accepted, because it is the key your existing data is already sealed under and refusing it " +
				"would block the rotation away from it. Complete the re-encrypt sweep, then remove it.")
		case isWeakSecret(c.VaultKeyPrevious):
			slog.Warn("config: TRUSTISSUES_VAULT_KEY_PREVIOUS looks like a placeholder or low-entropy value. " +
				"Accepted, because it is the key your existing data is already sealed under and refusing it " +
				"would block the rotation away from it. Complete the re-encrypt sweep, then remove it.")
		}
	}

	// A boot sweep with nothing to sweep from is a misconfiguration, not a
	// no-op: the operator set the flag expecting a rotation to happen, and
	// without the previous key the sweep can only ever report "already current"
	// while every row sealed under the old key stays orphaned.
	if c.RekeyOnBoot && c.VaultKeyPrevious == "" {
		errs = append(errs, "TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT is set but TRUSTISSUES_VAULT_KEY_PREVIOUS is empty; "+
			"the sweep would have no old key to convert from")
	}

	// Shield is optional, but if enabled its key must be a real AES-256 key. It
	// is used directly (not derived), so it must be EXACTLY 32 bytes. Fail closed
	// rather than silently disabling: an operator who set the key expects PII to
	// be tokenized, and a silently-off shield would leak it.
	if c.ShieldKey != "" {
		if len(c.ShieldKey) != 32 {
			errs = append(errs, fmt.Sprintf("TRUSTISSUES_SHIELD_KEY must be exactly 32 bytes for AES-256 (got %d); generate one with: openssl rand -hex 16", len(c.ShieldKey)))
		} else if isWeakSecret(c.ShieldKey) {
			errs = append(errs, "TRUSTISSUES_SHIELD_KEY looks like a placeholder or low-entropy value")
		}
	}
	if c.BindHost == "" {
		errs = append(errs, "TRUSTISSUES_BIND_HOST is required (default 127.0.0.1)")
	}

	if c.TrustedProxyHops < 0 {
		errs = append(errs, fmt.Sprintf("TRUSTISSUES_TRUSTED_PROXY_HOPS must be zero or greater (got %d)", c.TrustedProxyHops))
	}

	if c.PrivateSocketPath != "" {
		switch {
		case strings.TrimSpace(c.PrivateSocketPath) != c.PrivateSocketPath:
			errs = append(errs, "TRUSTISSUES_PRIVATE_SOCKET_PATH must not have leading or trailing whitespace")
		case !filepath.IsAbs(c.PrivateSocketPath):
			errs = append(errs, "TRUSTISSUES_PRIVATE_SOCKET_PATH must be an absolute path")
		case filepath.Clean(c.PrivateSocketPath) != c.PrivateSocketPath:
			errs = append(errs, "TRUSTISSUES_PRIVATE_SOCKET_PATH must be a clean absolute path (without . or .. components)")
		case len([]byte(c.PrivateSocketPath)) > 100:
			// sockaddr_un is 104 bytes on macOS and 108 on Linux. A 100-byte
			// ceiling leaves room for the terminating NUL on every supported
			// deployment platform instead of accepting a path that only fails
			// after the rest of startup has completed.
			errs = append(errs, "TRUSTISSUES_PRIVATE_SOCKET_PATH must be at most 100 bytes for portable Unix-socket support")
		}
	}
	if c.PrivateSocketPath == "" && c.PrivateBaseURL != "" {
		errs = append(errs, "TRUSTISSUES_PRIVATE_BASE_URL is set but TRUSTISSUES_PRIVATE_SOCKET_PATH is empty; private ingress is disabled")
	}
	if c.PrivateSocketPath != "" {
		if c.PrivateBaseURL == "" {
			errs = append(errs, "TRUSTISSUES_PRIVATE_BASE_URL is required when TRUSTISSUES_PRIVATE_SOCKET_PATH enables private ingress")
		} else if err := validatePrivateBaseURL(c.PrivateBaseURL); err != nil {
			errs = append(errs, "TRUSTISSUES_PRIVATE_BASE_URL "+err.Error())
		}
	}

	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("TRUSTISSUES_BASE_URL is invalid: %v", err))
		} else if u.Scheme != "http" && u.Scheme != "https" {
			errs = append(errs, "TRUSTISSUES_BASE_URL must use http or https scheme")
		} else if u.Hostname() == "" {
			errs = append(errs, "TRUSTISSUES_BASE_URL must include a hostname")
		} else if c.PrivateSocketPath != "" && c.PrivateBaseURL != "" {
			privateURL, privateErr := url.Parse(c.PrivateBaseURL)
			if privateErr == nil && privateURL.Hostname() != "" {
				publicHost, publicCanonical := privateBoundaryHostname(u.Hostname())
				privateHost, privateCanonical := privateBoundaryHostname(privateURL.Hostname())
				switch {
				case !publicCanonical || !privateCanonical:
					errs = append(errs, "public/private hostnames must use ASCII (punycode) and canonical IP spelling so browser cookie-origin equivalence can be checked safely")
				case !hasCanonicalBrowserPort(u) || !hasCanonicalBrowserPort(privateURL):
					errs = append(errs, "public/private URL ports must use canonical decimal spelling in the range 1-65535 so browser origins match CSRF configuration")
				case publicHost == privateHost:
					errs = append(errs, "TRUSTISSUES_PRIVATE_BASE_URL must use a different hostname from TRUSTISSUES_BASE_URL; ports do not isolate host-only session cookies")
				}
			}
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

// privateBoundaryHostname canonicalizes the hostname properties browsers use
// for host-only cookie/storage isolation. A trailing DNS root dot is routing-
// equivalent and cannot manufacture a second boundary. Unicode is refused when
// the private feature is enabled because browsers convert it to IDNA/punycode;
// asking operators to spell that ASCII form keeps this comparison explicit
// without maintaining a second IDNA implementation in configuration code.
//
// IP literals need a second normalization step. Browsers serialize equivalent
// IPv6 spellings to one host and accept legacy IPv4 spellings such as 127.1,
// 0177.0.0.1 and 0x7f000001. Go's net/url intentionally leaves those spellings
// alone, so comparing its Hostname strings directly could accept two configured
// URLs that the browser collapses to one origin. netip gives canonical modern
// IP spelling; legacy numeric IPv4 forms are rejected rather than reimplemented.
func privateBoundaryHostname(host string) (string, bool) {
	for _, r := range host {
		if r > 127 {
			return "", false
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", false
		}
		canonical := addr.String()
		if host != canonical {
			return "", false
		}
		return canonical, true
	}
	if strings.Contains(host, ":") || looksLikeLegacyIPv4(host) {
		return "", false
	}
	return host, true
}

// looksLikeLegacyIPv4 recognizes the numeric host grammar browsers may treat
// as IPv4 even when it is not a canonical dotted quad. A normal DNS name can
// contain digits; it is considered numeric only when every label is decimal or
// explicitly hexadecimal. Rejecting these rare spellings is safer than trying
// to duplicate the evolving WHATWG host parser in security configuration.
func looksLikeLegacyIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		digits := part
		base := byte(10)
		if len(digits) > 2 && strings.HasPrefix(digits, "0x") {
			digits = digits[2:]
			base = 16
		}
		if digits == "" {
			return false
		}
		for i := 0; i < len(digits); i++ {
			c := digits[i]
			if c >= '0' && c <= '9' {
				continue
			}
			if base == 16 && c >= 'a' && c <= 'f' {
				continue
			}
			return false
		}
	}
	return true
}

func hasCanonicalBrowserPort(u *url.URL) bool {
	port := u.Port()
	if port == "" {
		return true
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == port
}

func validatePrivateBaseURL(raw string) error {
	if strings.TrimSpace(raw) != raw {
		return errors.New("must not have leading or trailing whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if err == nil {
			err = errors.New("URL has no host")
		}
		return fmt.Errorf("is invalid: %v", err)
	}
	if u.Scheme != "https" {
		return errors.New("must use https so Secure session cookies and credentials are never sent in cleartext")
	}
	if _, canonical := privateBoundaryHostname(u.Hostname()); !canonical {
		return errors.New("must use an ASCII (punycode) hostname and canonical IP spelling")
	}
	if !hasCanonicalBrowserPort(u) {
		return errors.New("port must use canonical decimal spelling in the range 1-65535")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an origin only (https://host[:port], with no credentials, path, query, or fragment)")
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

// envStrAllowEmpty distinguishes an unset variable from an explicitly empty
// one. The trusted-proxy peer parser gives empty a security-relevant meaning
// (trust nobody), so silently replacing it with loopback trust would widen an
// operator's stated trust boundary.
func envStrAllowEmpty(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultVal
}

// envBool returns the value of an environment variable as a bool or a default.
// Accepts the usual 1/true/yes/on spellings (case-insensitive). A value that is
// set but unrecognised is logged and treated as the default rather than silently
// read as false: an operator who wrote REKEY_ON_BOOT=TRUE and got no rotation
// would have no way to tell why.
func envBool(key string, defaultVal bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return defaultVal
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	slog.Error("config: ignoring malformed boolean env var, using the default",
		"key", key, "value", v, "default", defaultVal)
	return defaultVal
}

// envInt returns the value of an environment variable as int or a default.
func envInt(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		// A malformed value is not the same as an unset one.
		//
		// This silently returned the default, so TRUSTISSUES_TRUSTED_PROXY_HOPS=
		// "1 " or PORT="8080\n" behaved exactly like not setting them at all,
		// and the operator had no way to tell. For the proxy-hop setting in
		// particular that silently changes which address every rate limit,
		// lockout and audit row is attributed to. Log it loudly and keep the
		// default, which is the safe value, rather than refusing to boot over a
		// stray space.
		slog.Error("config: ignoring malformed integer env var, using the default",
			"key", key, "value", v, "default", defaultVal)
		return defaultVal
	}
	return n
}

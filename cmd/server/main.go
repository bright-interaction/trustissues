// Trustissues server: a self-hosted, single-team password manager and
// API-key rotation service extracted from the Dockyard vault engine.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/brightinteraction/trustissues/internal/alerts"
	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/database"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/flarereport"
	"github.com/brightinteraction/trustissues/internal/handlers"
	timw "github.com/brightinteraction/trustissues/internal/middleware"
	"github.com/brightinteraction/trustissues/internal/shield"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// Version is stamped at build time via -ldflags "-X main.Version=...".
var Version = "dev"

// Request body limits. The global cap is 1 MB; CSV vault imports and the
// capability proxy get larger budgets (the proxy handler additionally caps
// forwarded bodies at 16 MiB internally).
const (
	defaultBodyLimit = int64(1 << 20)
	importBodyLimit  = int64(10 << 20)
	proxyBodyLimit   = int64(17 << 20)
)

// bodyLimits applies http.MaxBytesReader with a per-path budget. A single
// middleware (instead of stacking timw.MaxBodySize per route) because
// MaxBytesReader wrappers compose to the smallest limit, which would make a
// larger per-route override ineffective under a global 1 MB wrap.
func bodyLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := defaultBodyLimit
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/vault/import/"):
			limit = importBodyLimit
		case strings.HasPrefix(r.URL.Path, "/proxy/"):
			limit = proxyBodyLimit
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// csrfOriginCheck rejects cross-site state-changing requests as defense in
// depth behind the session cookie's SameSite=Strict attribute. SameSite is a
// single browser-side control: a browser that does not enforce it, or any
// future need to relax it, leaves every cookie-authenticated POST/PUT/PATCH/
// DELETE (first-run register included) open to a blind cross-site submit.
//
// The check is deliberately fail-open for non-browser clients. A browser always
// attaches at least one of Origin, Referer, or Sec-Fetch-Site to a
// state-changing request, so their absence means the caller is not a browser
// and cannot be a CSRF vector; requiring them would break the CLI, the MCP
// connector, and service containers for no gain. When one IS present it must
// point at us.
//
// An accepted origin is either the configured BaseURL host or the host the
// request was actually addressed to. The second is what keeps a stale or unset
// TRUSTISSUES_BASE_URL from breaking the SPA: a browser sets Origin itself and
// a cross-site page can never make it equal our own Host.
func csrfOriginCheck(baseURL string) func(http.Handler) http.Handler {
	configuredHost := hostOfURL(baseURL)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			default:
				next.ServeHTTP(w, r)
				return
			}

			// Header-authenticated callers (browser extension, CLI, MCP,
			// service containers) are exempt: a cross-site page cannot attach
			// X-API-Key or X-Service-Key without a CORS preflight we never
			// approve, and these callers carry no ambient cookie to ride on.
			// The exemption requires that no session cookie is present, so it
			// can never be used to launder a cookie-authenticated request.
			if _, err := r.Cookie(timw.SessionCookieName); err != nil {
				if r.Header.Get("X-API-Key") != "" || r.Header.Get("X-Service-Key") != "" {
					next.ServeHTTP(w, r)
					return
				}
			}

			if origin := r.Header.Get("Origin"); origin != "" {
				if !csrfHostAllowed(hostOfURL(origin), configuredHost, r) {
					rejectCrossSite(w, r, "origin")
					return
				}
			} else if referer := r.Header.Get("Referer"); referer != "" {
				if !csrfHostAllowed(hostOfURL(referer), configuredHost, r) {
					rejectCrossSite(w, r, "referer")
					return
				}
			}

			// Sec-Fetch-Site is set by the browser and cannot be forged from a
			// page. "none" is a user-initiated request (typed URL, bookmark),
			// which is not cross-site. "same-site" is NOT accepted: a
			// neighbouring subdomain is a different trust boundary here.
			switch r.Header.Get("Sec-Fetch-Site") {
			case "", "same-origin", "none":
			default:
				rejectCrossSite(w, r, "sec-fetch-site")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// hostOfURL reduces a URL (or an Origin header) to its lowercased host:port.
// Returns an empty string for anything unparseable or host-less, including the
// literal "null" origin, which callers then treat as not allowed.
func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

// csrfHostAllowed reports whether a request-supplied host is one of ours.
func csrfHostAllowed(got, configuredHost string, r *http.Request) bool {
	if got == "" {
		return false
	}
	return got == configuredHost || got == strings.ToLower(r.Host)
}

func rejectCrossSite(w http.ResponseWriter, r *http.Request, source string) {
	slog.Warn("cross-site state-changing request blocked",
		"source", source, "path", r.URL.Path, "method", r.Method)
	http.Error(w, `{"error":"cross-site request blocked"}`, http.StatusForbidden)
}

// randomRequestID assigns each request a random id stored under chi's
// RequestIDKey (so chimiddleware.Logger and handlers pick it up via
// middleware.GetReqID). Unlike chimiddleware.RequestID it derives no part of
// the id from os.Hostname(), and it ignores any inbound X-Request-Id so a
// client cannot reflect chosen content back through the logs.
// accessLog replaces chi's DefaultLogger, which wrote the query string.
//
// chi's formatter emits r.RequestURI verbatim, which is the raw request-target
// INCLUDING the query. The autofill route GET /match takes the page URL there
// (vault.go: rawURL := r.URL.Query().Get("url")), and migration
// 00011_metadata_at_rest.sql exists precisely so that value is not stored in the
// clear: it replaced LIKE matching with a keyed blind index because those
// columns "previously sat in cleartext next to the encrypted secret, so a raw
// DB-file leak exposed which sites a user has logins for". THREAT-MODEL.md
// repeats the promise. Writing the same URL to stdout on every request rebuilds
// the browsing history the blind index was built to avoid, in a place with
// looser access than the database file, and container logs are shipped off-box.
//
// So: PATH only, never RawQuery. Also on slog rather than chi's own
// log.New(os.Stdout, ...), which ignored the configured log level entirely.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		reqID, _ := r.Context().Value(chimiddleware.RequestIDKey).(string)
		slog.Info("http",
			"method", r.Method,
			// r.URL.Path, never r.RequestURI or r.URL.String().
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", reqID,
		)
	})
}

func randomRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqID string
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			reqID = strconv.FormatInt(time.Now().UnixNano(), 36)
		} else {
			reqID = base64.RawURLEncoding.EncodeToString(b)
		}
		ctx := context.WithValue(r.Context(), chimiddleware.RequestIDKey, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// secureDataDir best-effort tightens the data directory to 0700 and every
// regular file inside it to 0600. The directory holds the SQLite database and
// its WAL/SHM sidecars, which contain encrypted secrets; nothing but the
// service user should read them. Errors are logged, not fatal: a running
// instance with slightly loose perms is better than a boot loop, and the umask
// set in main already covers freshly created files.
func secureDataDir(dir string) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Warn("could not create data dir", "dir", dir, "error", err)
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		slog.Warn("could not chmod data dir", "dir", dir, "error", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn("could not read data dir", "dir", dir, "error", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Chmod(filepath.Join(dir, e.Name()), 0o600); err != nil {
			slog.Warn("could not chmod data file", "name", e.Name(), "error", err)
		}
	}
}

func main() {
	// Load configuration. This hard-fails when TRUSTISSUES_JWT_SECRET or
	// TRUSTISSUES_VAULT_KEY is missing: auth and at-rest encryption are
	// never optional.
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Error reporting + liveness beacon to Flare. No-op unless FLARE_DSN is set
	// (injected by the Hephaestus flare-provision deploy step), so dev runs and
	// self-hosts are unaffected. Before 2026-07-31 trustissues had no reporting
	// at all: a live product with a provisioned Flare project that had never sent
	// a single event, and which Flare's silence rule could never flag because
	// that rule needs a prior activity baseline to notice the absence of one.
	flarereport.InitFlare("trustissues", Version)

	// Structured logging only.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.SlogLevel(),
	}))
	slog.SetDefault(logger)
	cfg.WarnWeakConfig()

	// Everything this process creates (the SQLite DB, its WAL/SHM sidecars,
	// any temp files) holds secrets, so force user-only permissions on
	// creation. umask 0o077 makes new files 0600 and new dirs 0700.
	syscall.Umask(0o077)

	// Derive rate-limit client IPs from the configured trusted-proxy hop count
	// so X-Forwarded-For cannot be spoofed to evade limits.
	timw.ConfigureProxy(cfg.TrustedProxyHops, false)

	// Ensure the data dir is 0700 and tighten any pre-existing files to 0600
	// (older deploys may have created the DB before umask hardening).
	secureDataDir(cfg.DataDir)

	// Open SQLite (WAL) and run embedded migrations.
	dbConn, err := database.Connect(cfg.DataDir)
	if err != nil {
		slog.Error("database error", "error", err)
		os.Exit(1)
	}
	defer dbConn.Close()

	if err := database.RunMigrations(dbConn); err != nil {
		slog.Error("migration error", "error", err)
		os.Exit(1)
	}

	// Re-tighten after Connect/migrations in case the DB and its WAL/SHM were
	// just created (belt-and-suspenders alongside the umask above).
	secureDataDir(cfg.DataDir)

	queries := db.New(dbConn)

	// Prove the configured vault key actually matches this data directory BEFORE
	// anything rewrites a row under it. Without this, a wrong-but-valid key boots
	// "healthy", shows every entry as blank, and the first UI save overwrites
	// still-recoverable ciphertext with NULL. Self-heals on first boot by writing
	// the sentinel. Exits on mismatch unless TRUSTISSUES_ALLOW_KEY_MISMATCH=1.
	handlers.EnforceVaultKey(context.Background(), queries, cfg.VaultKey)

	// appCtx scopes background workers and dispatcher work to the server's
	// lifetime; cancelled on shutdown.
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	// Handlers owned by the platform.
	authHandler := handlers.NewAuthHandler(queries, cfg)
	userHandler := handlers.NewUserHandler(queries, cfg)
	settingsHandler := handlers.NewSettingsHandler(queries, cfg)
	activityHandler := handlers.NewActivityHandler(queries)
	apiKeyHandler := handlers.NewAPIKeyHandler(queries)

	// Encrypt any plaintext TOTP seeds at rest (idempotent).
	if err := authHandler.MigrateTOTPSecrets(); err != nil {
		slog.Error("totp secret migration failed", "error", err)
	}

	// Vault core. MigrateEncryption upgrades legacy v1 rows to v2 and must
	// succeed before the vault serves traffic; the metadata backfill is
	// best-effort (idempotent, retried next boot on failure).
	vaultHandler := handlers.NewVaultHandler(dbConn, queries, cfg)
	if err := vaultHandler.MigrateEncryption(); err != nil {
		slog.Error("vault encryption migration failed", "error", err)
		os.Exit(1)
	}
	// Disabling an account detaches that user's rotation delivery targets, so
	// the user handler needs the vault. Wired here because the vault handler is
	// constructed after it.
	userHandler.SetVault(vaultHandler)
	if _, err := vaultHandler.BackfillMetadataEncryption(); err != nil {
		slog.Error("vault metadata backfill failed", "error", err)
	}
	// Encrypt free-text metadata (url/alias_url/username/category/notes) at rest
	// and (re)compute the URL blind indexes. Best-effort and idempotent (the
	// enc:v1: prefix guards it), retried next boot on failure.
	if _, err := vaultHandler.BackfillMetadataAtRest(); err != nil {
		slog.Error("vault metadata-at-rest backfill failed", "error", err)
	}
	// Built after vaultHandler: the collection handler needs it to decrypt and
	// re-encrypt rotation_targets when purging a departing member's endpoints.
	collectionHandler := handlers.NewCollectionHandler(queries, vaultHandler)
	vaultImportHandler := handlers.NewVaultImportHandler(dbConn, vaultHandler)

	// Capability bridge + service identities. The vault handler doubles as
	// the alerts.ConfigDecrypter for both.
	capabilityHandler, err := handlers.NewCapabilityHandler(dbConn, vaultHandler, cfg.VaultKey)
	if err != nil {
		slog.Error("capability handler init failed", "error", err)
		os.Exit(1)
	}
	serviceSecretsHandler := handlers.NewServiceSecretsHandler(queries, vaultHandler)

	// Shield LLM-boundary tokenization store, shared by the AI gateway (and the
	// MCP boundary). nil when TRUSTISSUES_SHIELD_KEY is unset (Shield off).
	var shieldStore shield.Store
	if cfg.ShieldEnabled() {
		shieldStore = shield.NewSQLStore(dbConn)
		slog.Info("shield enabled", "hint_level", cfg.ShieldHintLevel)
	}
	aiGatewayHandler := handlers.NewAIGatewayHandler(queries, cfg, vaultHandler, shieldStore)

	// Alert channel dispatcher + notification-channel admin CRUD.
	dispatcher := alerts.NewChannelDispatcher(appCtx, queries, vaultHandler)
	notificationChannelsHandler := handlers.NewNotificationChannelsHandler(queries, vaultHandler, dispatcher)

	// Background workers, all cancelled via appCtx on shutdown:
	// scheduled auto-rotation, expiring-secret reminders, and the
	// capability replay-nonce sweep.
	go handlers.RunScheduledRotations(appCtx, dbConn, queries, vaultHandler)
	go handlers.RunExpiryReminders(appCtx, queries, dispatcher)
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-appCtx.Done():
				return
			case <-ticker.C:
				if _, err := capabilityHandler.PruneSpentNonces(appCtx); err != nil {
					slog.Error("capability nonce sweep failed", "error", err)
				}
			}
		}
	}()

	// Shield sessions and their tokens are never otherwise deleted. The AI
	// gateway opens a session with a fresh random id per request, so the
	// revive-and-sweep branch in shield.NewSession (which only fires for an id it
	// has seen before) is unreachable on that path and nothing ever calls
	// SweepExpired. The rows are AES-GCM ciphertext and cannot be redeemed by any
	// caller (resolve is scoped to the session id), so this is data minimisation
	// rather than a leak: prompt-derived PII should not accumulate for the life
	// of the deployment.
	if shieldStore != nil {
		go func() {
			t := time.NewTicker(30 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-appCtx.Done():
					return
				case <-t.C:
					if err := shield.SweepExpired(appCtx, shieldStore); err != nil {
						slog.Error("shield janitor: sweep failed", "error", err)
					}
				}
			}
		}()
	}

	// Rate limiters (same budgets as dockyard). Unlock gets its own budget:
	// the UI re-locks the vault after every mutation, so the 5/15min
	// sensitive-op budget would 429 normal editing sessions.
	loginLimiter := timw.NewRateLimiter(30, 15*time.Minute)
	apiLimiter := timw.NewRateLimiter(500, 1*time.Minute)
	sensitiveOpLimiter := timw.NewRateLimiter(5, 15*time.Minute)
	// The capability bridge needs its own bucket. It shared the 5-per-15-minutes
	// bucket with rotate and validate, and it is keyed by IP, so an agent behind
	// one egress address could mint only 5 single-use tokens per 15 minutes
	// across the whole team: the tokens are deliberately single-use and
	// short-lived, so ordinary use exhausts it in a minute and then also locks
	// out manual rotation from that address. A limit that makes the feature
	// unusable is not a security control, it is an outage.
	capabilityLimiter := timw.NewRateLimiter(60, time.Minute)
	unlockLimiter := timw.NewRateLimiter(30, 15*time.Minute)
	// The capability proxy is mounted on the root router, outside /api and its
	// apiLimiter, because it authenticates with a capability token instead of a
	// session. That left it with no limiter at all, so it gets its own budget:
	// one token is single-use, so an agent's real traffic is bounded by minting,
	// and anything above this is flooding.
	proxyLimiter := timw.NewRateLimiter(120, 1*time.Minute)

	// MCP shares the sensitive-op budget with POST /api/secrets/issue: its
	// use_secret tool mints capability tokens by calling the Issue handler
	// in-process, which would otherwise skip the route's rate-limit middleware.
	mcpHandler := handlers.NewMCPHandler(queries, cfg, capabilityHandler, shieldStore, capabilityLimiter)

	// Build router.
	r := chi.NewRouter()

	// Global middleware. randomRequestID replaces chimiddleware.RequestID,
	// whose default id prefix embeds os.Hostname() and would leak the host
	// name into logs and any echoed request id.
	r.Use(randomRequestID)
	r.Use(accessLog)
	r.Use(chimiddleware.Recoverer)
	// AFTER Recoverer so the panic is captured before Recoverer renders the 500.
	// Re-panics, so Recoverer still owns the response. No-op when InitFlare was.
	r.Use(flarereport.FlareRecoverer)
	r.Use(chimiddleware.Compress(5))
	r.Use(timw.SecurityHeaders)
	r.Use(bodyLimits)

	// Health check (basic liveness).
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`, Version)
	})

	// Capability bridge proxy: AI agents send requests to /proxy/{host}/{path}
	// with `Authorization: Capability <token>`. Auth is the signed token
	// (verified inside the handler); mounted on the root router OUTSIDE /api
	// and outside session middleware so external HTTP clients reach it
	// directly (dockyard main.go:668-669 pattern). Being outside /api also puts
	// it outside apiLimiter, hence the dedicated proxyLimiter: these routes are
	// reachable anonymously, so they need a budget of their own.
	r.With(timw.RateLimit(proxyLimiter)).HandleFunc("/proxy/{host}/*", capabilityHandler.Proxy)
	r.With(timw.RateLimit(proxyLimiter)).HandleFunc("/proxy/{host}", capabilityHandler.Proxy)

	// API routes.
	r.Route("/api", func(r chi.Router) {
		r.Use(timw.RateLimit(apiLimiter))
		// CSRF defense in depth for every state-changing /api route, including
		// the public ones (first-run register is the sharpest case). Applied
		// here rather than globally so the capability proxy, which is not
		// cookie-authenticated and is called by non-browser agents, is
		// untouched.
		r.Use(csrfOriginCheck(cfg.BaseURL))

		// Public routes (no auth), tightly rate limited.
		r.With(timw.RateLimit(loginLimiter)).Get("/auth/status", authHandler.Status)
		r.With(timw.RateLimit(loginLimiter)).Post("/auth/login", authHandler.Login)
		r.With(timw.RateLimit(loginLimiter)).Post("/auth/register", authHandler.Register)
		r.With(timw.RateLimit(loginLimiter)).Post("/invitations/redeem", userHandler.RedeemInvitation)

		// Service fetch-on-boot: X-Service-Key auth lives inside the handler
		// (service containers call this with no session and no cookie), so it
		// sits inside /api for the shared rate limit but OUTSIDE the
		// session-auth group (dockyard main.go:754 pattern).
		r.Post("/service-identities/me/secrets", serviceSecretsHandler.FetchOwnSecrets)

		// Authenticated routes (JWT via header or session cookie, or X-API-Key).
		r.Group(func(r chi.Router) {
			r.Use(timw.JWTOrAPIKeyAuth(cfg.JWTSecret, dbConn))

			// Auth/self-service (available to every role incl. vault_only).
			r.Route("/auth", func(r chi.Router) {
				r.Get("/me", authHandler.Me)
				r.Patch("/me", authHandler.UpdateMe)
				r.Post("/logout", authHandler.Logout)
				r.Post("/change-password", authHandler.ChangePassword)
				r.Post("/totp/setup", authHandler.TOTPSetup)
				r.Post("/totp/verify", authHandler.TOTPVerify)
				r.Post("/totp/disable", authHandler.TOTPDisable)
			})

			// Settings. Vault policy reads are open to every authenticated
			// role (the vault UI needs the auto-lock deadline); everything
			// else is admin only.
			r.Route("/settings", func(r chi.Router) {
				r.Get("/vault-policy", settingsHandler.GetVaultPolicy)
				r.Group(func(r chi.Router) {
					r.Use(timw.AdminOnly())
					r.Put("/vault-policy", settingsHandler.UpdateVaultPolicy)
					r.Get("/session-duration", settingsHandler.GetSessionDuration)
					r.Put("/session-duration", settingsHandler.UpdateSessionDuration)
					r.Get("/smtp", settingsHandler.GetSMTP)
					r.Put("/smtp", settingsHandler.UpdateSMTP)
					r.Post("/smtp/test", settingsHandler.TestSMTP)
				})
			})

			// API keys for programmatic clients (the browser extension).
			// Per-user and available to every authenticated role, since a
			// vault_only teammate also needs to connect the extension.
			r.Route("/api-keys", func(r chi.Router) {
				r.Get("/", apiKeyHandler.List)
				r.Post("/", apiKeyHandler.Create)
				r.Delete("/{keyId}", apiKeyHandler.Delete)
			})

			// Activity log + exports (admin only).
			r.Group(func(r chi.Router) {
				r.Use(timw.AdminOnly())
				r.Get("/activity", activityHandler.List)
				r.Get("/activity/export/csv", activityHandler.ExportCSV)
				r.Get("/activity/export/json", activityHandler.ExportJSON)
			})

			// Admin user + invitation + notification-channel management.
			r.Route("/admin", func(r chi.Router) {
				r.Use(timw.AdminOnly())

				r.Route("/users", func(r chi.Router) {
					r.Get("/", userHandler.List)
					r.Post("/", userHandler.Create)
					r.Patch("/{id}", userHandler.Update)
					r.Delete("/{id}", userHandler.Delete)
					r.Post("/{id}/reset-password", userHandler.ResetPassword)
					// Incident response: an admin must be able to see and cut
					// off another user's API keys (a stolen extension key
					// otherwise survives every action the victim can take).
					r.Get("/{id}/api-keys", apiKeyHandler.AdminList)
					r.Post("/{id}/api-keys/revoke-all", apiKeyHandler.AdminRevokeAll)
					r.Post("/{id}/api-keys/{keyId}/revoke", apiKeyHandler.AdminRevoke)
				})

				r.Route("/invitations", func(r chi.Router) {
					r.Get("/", userHandler.ListInvitations)
					r.Post("/", userHandler.CreateInvitation)
					r.Delete("/{id}", userHandler.DeleteInvitation)
					r.Post("/{id}/resend", userHandler.ResendInvitation)
				})

				r.Route("/notification-channels", func(r chi.Router) {
					r.Get("/", notificationChannelsHandler.List)
					r.Post("/", notificationChannelsHandler.Create)
					r.Patch("/{id}", notificationChannelsHandler.Update)
					r.Delete("/{id}", notificationChannelsHandler.Delete)
					r.Post("/{id}/test", notificationChannelsHandler.Test)
				})
			})

			// Vault (all roles incl. vault_only; per-entry ownership is
			// enforced in the handlers). Mirrors dockyard main.go:899-912.
			r.Route("/vault", func(r chi.Router) {
				r.Get("/", vaultHandler.List)
				r.Post("/", vaultHandler.Create)
				r.Get("/providers", vaultHandler.Providers)
				r.Get("/match", vaultHandler.Match)
				r.With(timw.RateLimit(unlockLimiter)).Post("/unlock", vaultHandler.Unlock)
				r.Put("/{id}", vaultHandler.Update)
				r.Delete("/{id}", vaultHandler.Delete)
				r.With(timw.RateLimit(sensitiveOpLimiter)).Post("/{id}/rotate", vaultHandler.Rotate)
				r.With(timw.RateLimit(sensitiveOpLimiter)).Post("/{id}/validate", vaultHandler.ValidateKey)
				r.Get("/{id}/targets", vaultHandler.GetTargets)
				r.Put("/{id}/targets", vaultHandler.UpdateTargets)
				r.Put("/{id}/schedule", vaultHandler.UpdateSchedule)
				r.Put("/{id}/collection", vaultHandler.MoveToCollection)
				r.Post("/import/preview", vaultImportHandler.ImportPreview)
				r.Post("/import/confirm", vaultImportHandler.ImportConfirm)
			})

			// Shared team vaults (collections) + membership. Any authenticated
			// role may hold a collection membership, so this sits in the general
			// group; the handlers enforce per-collection manager rights for
			// mutations and 404 non-members.
			r.Route("/collections", func(r chi.Router) {
				r.Get("/", collectionHandler.List)
				r.Post("/", collectionHandler.Create)
				// Membership is an invitation: a pending row grants nothing
				// until the invitee accepts here.
				r.Get("/invitations", collectionHandler.ListPendingInvites)
				r.Route("/{id}", func(r chi.Router) {
					r.Get("/", collectionHandler.Get)
					r.Put("/", collectionHandler.Update)
					r.Delete("/", collectionHandler.Delete)
					r.Get("/members", collectionHandler.ListMembers)
					r.Post("/members", collectionHandler.AddMember)
					r.Delete("/members/{userId}", collectionHandler.RemoveMember)
					r.Post("/accept", collectionHandler.AcceptInvite)
					r.Post("/decline", collectionHandler.DeclineInvite)
				})
			})

			// AI gateway: proxy LLM calls to Claude/OpenAI with the team's
			// provider key injected server-side and PII tokenized via Shield.
			// The key itself is never exposed. Non-streaming only in v1.
			//
			// NOT open to vault_only. That role is what RedeemInvitation hands
			// out over the PUBLIC invite endpoint, and it exists to let a
			// teammate use the browser extension against their own secrets, not
			// to spend the team's Claude/OpenAI budget. The handler has no role
			// check of its own, and VaultOnlyBlock's doc says to mount it on
			// every group that is not part of the vault surface; it was on
			// /service-identities alone.
			r.Group(func(r chi.Router) {
				r.Use(timw.VaultOnlyBlock())
				r.HandleFunc("/ai/{provider}/*", aiGatewayHandler.Proxy)
			})

			// AI gateway + MCP config: any user reads status + connection URLs;
			// only an admin points a provider at a key.
			r.Get("/settings/ai", aiGatewayHandler.GetConfig)
			r.With(timw.AdminOnly()).Put("/settings/ai", aiGatewayHandler.UpdateConfig)

			// Remote HTTP MCP endpoint (JSON-RPC) for Claude/ChatGPT connectors:
			// list_secrets + use_secret, with Shield tokenizing tool results.
			r.Post("/mcp", mcpHandler.Handle)

			// Capability bridge token minting (dockyard main.go:894-896).
			// Sensitive op: rate limited hard.
			r.Route("/secrets", func(r chi.Router) {
				r.With(timw.RateLimit(capabilityLimiter)).Post("/issue", capabilityHandler.Issue)
			})

			// Service identities: admin-only mint + list + revoke + delete +
			// audit (the handlers enforce admin; VaultOnlyBlock keeps
			// vault_only users off this non-vault surface). Mirrors dockyard
			// main.go:864-868.
			r.Route("/service-identities", func(r chi.Router) {
				r.Use(timw.VaultOnlyBlock())
				r.Get("/", serviceSecretsHandler.ListServiceIdentities)
				r.Post("/", serviceSecretsHandler.CreateServiceIdentity)
				r.Post("/{id}/revoke", serviceSecretsHandler.RevokeServiceIdentity)
				r.Delete("/{id}", serviceSecretsHandler.DeleteServiceIdentity)
				r.Get("/{id}/audit", serviceSecretsHandler.GetServiceIdentityAudit)
			})
		})
	})

	// Serve frontend static files with SPA fallback (same pattern as dockyard).
	frontendDir := cfg.FrontendDir
	if _, err := os.Stat(frontendDir); err == nil {
		fileServer := http.FileServer(http.Dir(frontendDir))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}
			if _, err := fs.Stat(os.DirFS(frontendDir), path); err != nil {
				// SPA fallback: serve index.html for unmatched routes
				http.ServeFile(w, r, frontendDir+"/index.html")
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	} else {
		slog.Warn("frontend directory not found, static serving disabled", "dir", frontendDir)
	}

	// Start server.
	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.BindHost, cfg.Port),
		Handler:           r,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		// Go's default is 1 MB for a SINGLE header value, and User-Agent is
		// stored verbatim in the append-only activity_log, so that default was
		// the size of one audit row an authenticated caller could choose. The
		// column is bounded now too (truncateAudit), but bounding it here as
		// well means the bytes never reach a handler and never sit in memory
		// 500 times a minute. 16 KB is generous for real headers.
		MaxHeaderBytes: 16 << 10,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
	}

	// Graceful shutdown.
	//
	// drained is what makes the 10s budget real. Shutdown closes the listeners
	// immediately, so ListenAndServe returns ErrServerClosed straight away and
	// main used to return ~0.3s after SIGTERM with the drain still in progress:
	// the budget was dead code and every in-flight request was reset on every
	// deploy. The sharp case is a rotation caught between the provider minting
	// the successor key and the vault persisting it.
	drained := make(chan struct{})
	go func() {
		defer close(drained)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		slog.Info("shutting down...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "error", err)
		}
		// Rotation delivery runs detached from the request, so Shutdown does not
		// know about it. Waiting here means a restart cannot land between "value
		// stored, old key revoked upstream" and "delivery finished", which would
		// otherwise record the rotation as a clean success while the consumer
		// never got the new key.
		// 20s, comfortably under the 45s stop_grace_period in docker-compose.yml
		// and well over a normal delivery. An unbounded wait would just get the
		// process SIGKILLed at the container's grace period instead.
		if !vaultHandler.WaitForDelivery(20 * time.Second) {
			slog.Warn("shutdown: rotation delivery did not finish in time; " +
				"a rotated value may be stored without having reached its targets, " +
				"check last_rotation_error after restart")
		}

		// AFTER the drain, not before: cancelling first would kill the
		// dispatcher and background work that a still-draining handler depends
		// on, which is the opposite of draining.
		appCancel()
		slog.Info("drain complete")
	}()

	slog.Info("Trustissues is running", "addr", srv.Addr, "version", Version)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
	// Wait for the drain before main returns, or the deferred dbConn.Close()
	// and appCancel() fire while handlers are still mid-write.
	<-drained
}

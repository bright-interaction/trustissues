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

// randomRequestID assigns each request a random id stored under chi's
// RequestIDKey (so chimiddleware.Logger and handlers pick it up via
// middleware.GetReqID). Unlike chimiddleware.RequestID it derives no part of
// the id from os.Hostname(), and it ignores any inbound X-Request-Id so a
// client cannot reflect chosen content back through the logs.
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

	// appCtx scopes background workers and dispatcher work to the server's
	// lifetime; cancelled on shutdown.
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	// Handlers owned by the platform.
	authHandler := handlers.NewAuthHandler(queries, cfg)
	userHandler := handlers.NewUserHandler(queries, cfg)
	settingsHandler := handlers.NewSettingsHandler(queries)
	activityHandler := handlers.NewActivityHandler(queries)
	apiKeyHandler := handlers.NewAPIKeyHandler(queries)
	collectionHandler := handlers.NewCollectionHandler(queries)

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
	if _, err := vaultHandler.BackfillMetadataEncryption(); err != nil {
		slog.Error("vault metadata backfill failed", "error", err)
	}
	// Encrypt free-text metadata (url/alias_url/username/category/notes) at rest
	// and (re)compute the URL blind indexes. Best-effort and idempotent (the
	// enc:v1: prefix guards it), retried next boot on failure.
	if _, err := vaultHandler.BackfillMetadataAtRest(); err != nil {
		slog.Error("vault metadata-at-rest backfill failed", "error", err)
	}
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
	mcpHandler := handlers.NewMCPHandler(queries, cfg, capabilityHandler, shieldStore)

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

	// Rate limiters (same budgets as dockyard). Unlock gets its own budget:
	// the UI re-locks the vault after every mutation, so the 5/15min
	// sensitive-op budget would 429 normal editing sessions.
	loginLimiter := timw.NewRateLimiter(30, 15*time.Minute)
	apiLimiter := timw.NewRateLimiter(500, 1*time.Minute)
	sensitiveOpLimiter := timw.NewRateLimiter(5, 15*time.Minute)
	unlockLimiter := timw.NewRateLimiter(30, 15*time.Minute)

	// Build router.
	r := chi.NewRouter()

	// Global middleware. randomRequestID replaces chimiddleware.RequestID,
	// whose default id prefix embeds os.Hostname() and would leak the host
	// name into logs and any echoed request id.
	r.Use(randomRequestID)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
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
	// directly (dockyard main.go:668-669 pattern).
	r.HandleFunc("/proxy/{host}/*", capabilityHandler.Proxy)
	r.HandleFunc("/proxy/{host}", capabilityHandler.Proxy)

	// API routes.
	r.Route("/api", func(r chi.Router) {
		r.Use(timw.RateLimit(apiLimiter))

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
				r.Route("/{id}", func(r chi.Router) {
					r.Get("/", collectionHandler.Get)
					r.Put("/", collectionHandler.Update)
					r.Delete("/", collectionHandler.Delete)
					r.Get("/members", collectionHandler.ListMembers)
					r.Post("/members", collectionHandler.AddMember)
					r.Delete("/members/{userId}", collectionHandler.RemoveMember)
				})
			})

			// AI gateway: proxy LLM calls to Claude/OpenAI with the team's
			// provider key injected server-side and PII tokenized via Shield.
			// Any authenticated caller (session or API key) may use it; the key
			// itself is never exposed. Non-streaming only in v1.
			r.HandleFunc("/ai/{provider}/*", aiGatewayHandler.Proxy)

			// Remote HTTP MCP endpoint (JSON-RPC) for Claude/ChatGPT connectors:
			// list_secrets + use_secret, with Shield tokenizing tool results.
			r.Post("/mcp", mcpHandler.Handle)

			// Capability bridge token minting (dockyard main.go:894-896).
			// Sensitive op: rate limited hard.
			r.Route("/secrets", func(r chi.Router) {
				r.With(timw.RateLimit(sensitiveOpLimiter)).Post("/issue", capabilityHandler.Issue)
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
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		slog.Info("shutting down...")
		appCancel() // stop background workers + dispatcher work

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "error", err)
		}
	}()

	slog.Info("Trustissues is running", "addr", srv.Addr, "version", Version)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

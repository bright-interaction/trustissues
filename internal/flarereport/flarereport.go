// Package flarereport wires this service's error reporting + liveness beacon to
// the house Flare instance (Sentry-wire protocol).
//
// This is the estate's established per-project pattern, adapted from
// dockyard/internal/observability (the reference implementation named in the
// 2026-07-02 estate SDK rollout). The copies are deliberate rather than a shared
// module: eight of these products publish as public mirrors, so a `replace`
// directive pointing outside the subtree would break `go install` for external
// consumers, and mesh additionally keeps sentry out of its AGPL core this way.
//
// Only the core is carried over: init, heartbeat and the request scrubber.
// dockyard's log shipper, tracing middleware and Prometheus metrics are its own
// concerns and are deliberately not duplicated here.
//
// trustissues had NO error reporting at all until 2026-07-31 despite being a
// live product with a provisioned Flare project.
package flarereport

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// InitFlare turns on error reporting when FLARE_DSN is set. The DSN is injected
// by the Hephaestus flare-provision deploy step; without it this is a no-op, so
// dev runs and self-hosts boot unchanged. Returns whether reporting is live.
func InitFlare(service, release string) bool {
	dsn := os.Getenv("FLARE_DSN")
	if dsn == "" {
		return false
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:        dsn,
		Release:    release,
		ServerName: service,
		// Scrub request context before it crosses the tenant -> shared-store
		// boundary: query strings carry short-lived OAuth codes/state and reset
		// tokens, cookies carry the session, headers carry bearer creds and API
		// keys. Keep method + path for triage.
		//
		// BeforeSend covers error/message events; transaction envelopes route
		// through BeforeSendTransaction, a SEPARATE hook. Register the same scrub
		// on both so the invariant cannot silently regress if tracing is ever
		// enabled here.
		BeforeSend: func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			return scrubRequestEvent(event)
		},
		BeforeSendTransaction: func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			return scrubRequestEvent(event)
		},
	})
	if err != nil {
		slog.Warn("flare: error reporting disabled (sentry init failed)", "error", err)
		return false
	}
	slog.Info("flare: error reporting enabled", "service", service)
	startHeartbeat(service)
	return true
}

// FlareRecoverer captures panics to Flare and re-panics so the existing recovery
// middleware still renders the 500. Mount it AFTER the recoverer in the chain so
// it sees the panic first. Safe to mount when InitFlare was a no-op: capture
// calls on an uninitialized hub do nothing.
func FlareRecoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				hub := sentry.CurrentHub().Clone()
				hub.Scope().SetRequest(r)
				hub.RecoverWithContext(r.Context(), rec)
				hub.Flush(2 * time.Second)
				panic(rec)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CaptureErr reports a handled error that should still page someone. No-op when
// reporting is disabled.
func CaptureErr(err error) {
	if err == nil {
		return
	}
	sentry.CaptureException(err)
}

// Flush drains the send queue. Call from shutdown so an error captured on the
// way out is not lost. Note sentry's ok=true means the QUEUE drained, not that
// the server accepted the event.
func Flush(d time.Duration) bool { return sentry.Flush(d) }

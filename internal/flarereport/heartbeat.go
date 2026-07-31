package flarereport

import (
	"os"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// heartbeatInterval is how often a live service emits its liveness beacon.
// Short enough that a crashed service's silence shows up within one watchdog
// tick, long enough to keep the beacon volume negligible.
const heartbeatInterval = 2 * time.Minute

// startHeartbeat emits a periodic info-level "service-up" beacon so a healthy,
// low-error service can be told apart from a dead or misconfigured one, and so
// Flare's silence detection has an activity baseline to watch.
//
// This is not decoration. Flare's silenceReason() returns "" when a project has
// fewer than `threshold` events in 24h, so a project that has NEVER reported can
// never trip silence detection and stays invisible forever. On 2026-07-31, nine
// of twenty-one estate projects were in exactly that state; the two that DID
// page (flare, atomicsite) only did so because they had a beacon history to
// lose. A service without this cannot be missed.
//
// info-level events never page and are excluded from the estate Overview; they
// only keep the project observably alive. Called from InitFlare after
// sentry.Init succeeds, so it runs only when reporting is enabled. Runs for the
// process lifetime. Set FLARE_HEARTBEAT=off to disable.
func startHeartbeat(service string) {
	if os.Getenv("FLARE_HEARTBEAT") == "off" {
		return
	}
	emit := func() {
		sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelInfo)
			scope.SetFingerprint([]string{"service-up", service})
			sentry.CaptureMessage("service-up:" + service)
		})
	}
	go func() {
		emit()
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for range t.C {
			emit()
		}
	}()
}

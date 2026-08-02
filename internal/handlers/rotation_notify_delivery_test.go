package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
	_ "github.com/mattn/go-sqlite3"
)

// The "Notify only" target must reach a real channel, through the real dispatcher.
//
// This exists because the FIRST guard for this fix was vacuous and an ablation proved
// it. rotation_contract_test.go swaps dispatchRotationSuccess for a recorder, so it
// asserts the rotation core calls the hook; gutting the real implementation behind that
// hook, and disabling the event, both passed it clean. The seam introduced for
// testability was exactly where the remaining bug could live.
//
// Same lesson this codebase keeps producing in new costumes: a guard cannot verify the
// thing it stubs. So this one drives dispatchRotationSuccessReal into a real SQLite
// database with the real notification_channels DDL and a real enabled channel.
//
// A slog channel rather than a webhook because ChannelDispatcher.client is package
// private (the alerts test swaps it from inside the package) and the SSRF guard refuses
// loopback. sendSlog needs no network, and delivery is what is under test, not egress.
func TestNotifyOnlyTargetActuallyReachesAChannel(t *testing.T) {
	q := newNotifyChannelDB(t, defaultChannelEvents)

	rec := &slogRecorder{done: make(chan string, 8)}
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dispatchRotationSuccessReal(context.Background(), q, nil,
		"Prod DB password", "rotated, no delivery targets configured")

	select {
	case got := <-rec.done:
		if !strings.Contains(got, "Prod DB password") {
			t.Errorf("a notification was sent but not about the rotated secret: %s", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a rotation success reached NO notification channel.\n" +
			"'Notify only' transmits nothing by design, so the notification IS the whole " +
			"feature: the credential rotates, the predecessor is revoked, and the person who " +
			"asked to be told hears nothing while the log records a clean success.")
	}
}

// The default event set a new channel is created with must include the success event.
//
// Seeding with defaultChannelEvents verbatim above is deliberate: if that constant ever
// drops vault.rotation_succeeded, every channel an operator creates through the UI
// silently stops subscribing and the notify target is a no-op again, with nothing else
// in the suite noticing. This asserts the same constant is also accepted as valid, so
// the two lists cannot drift apart.
func TestSuccessEventIsSubscribedByDefaultAndValid(t *testing.T) {
	if !strings.Contains(defaultChannelEvents, alerts.EventRotationSucceeded) {
		t.Errorf("defaultChannelEvents (%q) does not include %q, so a new channel does not "+
			"subscribe and 'Notify only' notifies nobody", defaultChannelEvents, alerts.EventRotationSucceeded)
	}
	if !validChannelEvents[alerts.EventRotationSucceeded] {
		t.Errorf("%q is not an accepted channel event, so an operator cannot subscribe to it "+
			"even deliberately", alerts.EventRotationSucceeded)
	}
}

// slogRecorder captures the first record the slog channel emits.
type slogRecorder struct {
	mu   sync.Mutex
	done chan string
}

func (r *slogRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *slogRecorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *slogRecorder) WithGroup(string) slog.Handler            { return r }

func (r *slogRecorder) Handle(_ context.Context, rec slog.Record) error {
	var sb strings.Builder
	sb.WriteString(rec.Message)
	rec.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	line := sb.String()
	if !strings.Contains(line, "trustissues alert") {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case r.done <- line:
	default:
	}
	return nil
}

// newNotifyChannelDB builds a real database with one enabled slog channel.
func newNotifyChannelDB(t *testing.T, events string) *db.Queries {
	t.Helper()
	conn, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "notify.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ddl, err := os.ReadFile(filepath.Join("..", "database", "migrations", "00006_notification_channels.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	stmt := string(ddl)
	if i := strings.Index(stmt, "-- +goose Down"); i > 0 {
		stmt = stmt[:i]
	}
	for _, marker := range []string{"-- +goose Up", "-- +goose StatementBegin", "-- +goose StatementEnd"} {
		stmt = strings.ReplaceAll(stmt, marker, "")
	}
	if _, err := conn.Exec(stmt); err != nil {
		t.Fatalf("apply notification_channels DDL: %v", err)
	}
	if _, err := conn.Exec(
		`INSERT INTO notification_channels (id, name, type, config, events, enabled)
		 VALUES ('ch1', 'ops log', 'slog', '{}', ?, 1)`, events); err != nil {
		t.Fatalf("seed channel: %v", err)
	}

	q := db.New(conn)
	// Guard the fixture: with zero enabled channels every assertion above would
	// pass for the wrong reason.
	rows, err := q.ListEnabledNotificationChannels(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("ABORT: fixture has %d enabled channels (err=%v); the test would be vacuous",
			len(rows), err)
	}
	return q
}

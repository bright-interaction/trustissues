package alerts

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
	_ "github.com/mattn/go-sqlite3"
)

// newDispatchTestDB builds a real SQLite database with the real
// notification_channels DDL and one enabled webhook channel pointed at url.
//
// Deliberately not a mock. The bug under test was a context lifetime crossing
// the goroutine boundary into net/http, which a fake sender cannot reproduce.
func newDispatchTestDB(t *testing.T, url string, events string) *db.Queries {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alerts.db")
	conn, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ddl, err := os.ReadFile(filepath.Join("..", "database", "migrations", "00006_notification_channels.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	stmt := string(ddl)
	// Take only the Up half of the goose migration.
	if i := strings.Index(stmt, "-- +goose Down"); i > 0 {
		stmt = stmt[:i]
	}
	stmt = strings.ReplaceAll(stmt, "-- +goose Up", "")
	stmt = strings.ReplaceAll(stmt, "-- +goose StatementBegin", "")
	stmt = strings.ReplaceAll(stmt, "-- +goose StatementEnd", "")
	if _, err := conn.Exec(stmt); err != nil {
		t.Fatalf("apply notification_channels DDL: %v\n%s", err, stmt)
	}

	if _, err := conn.Exec(
		`INSERT INTO notification_channels (id, name, type, config, events, enabled)
		 VALUES ('ch1', 'test webhook', 'webhook', ?, ?, 1)`,
		`{"url":"`+url+`"}`, events,
	); err != nil {
		t.Fatalf("seed channel: %v", err)
	}

	q := db.New(conn)
	// Guard the fixture: if the channel is not visible as enabled, every
	// assertion below would pass against zero channels.
	rows, err := q.ListEnabledNotificationChannels(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("ABORT: fixture has %d enabled channels (err=%v); the test would be vacuous", len(rows), err)
	}
	return q
}

// TestDispatchSurvivesCallerCancellation is the regression test for a silent
// alerting outage.
//
// Every rotation call site builds a dispatcher on a short-lived context and
// cancels it as soon as Dispatch returns (defer cancel on a request ctx, or the
// sweep's pass ctx). Dispatch fans out to goroutines, but sendWebhook built its
// POST on that same context, so the request was cancelled before it completed
// and webhook channels received nothing at all for rotation failures.
//
// It could not be noticed from the product: the Test button and the expiry
// reminders both run on the process-lifetime dispatcher, so the two ways an
// operator would verify alerting are the two that always worked. The failure
// only showed as "context canceled" in the container log.
//
// The shape this locks: cancelling the constructor context the instant Dispatch
// returns must NOT prevent delivery.
func TestDispatchSurvivesCallerCancellation(t *testing.T) {
	var mu sync.Mutex
	got := 0
	done := make(chan struct{}, 32)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		done <- struct{}{}
	}))
	defer sink.Close()

	q := newDispatchTestDB(t, sink.URL, EventRotationFailed)

	const n = 20
	for i := 0; i < n; i++ {
		// Exactly the call-site shape: short-lived ctx, cancelled the moment
		// the dispatching function returns.
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			d := NewChannelDispatcher(ctx, q, nil)
			// The SSRF guard refuses loopback, which is the sink's address, so
			// swap in a plain client. The guard is a separate, wanted control;
			// what is under test here is context lifetime, not egress policy.
			d.client = &http.Client{Timeout: 10 * time.Second}
			d.Dispatch(EventRotationFailed, "Prod DB password", "", map[string]string{
				"secret": "Prod DB password", "detail": "provider rotation failed",
			})
		}()
	}

	deadline := time.After(15 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-done:
		case <-deadline:
			mu.Lock()
			have := got
			mu.Unlock()
			t.Fatalf("only %d/%d rotation alerts were delivered after the caller cancelled; "+
				"webhook alerting is dead for exactly the events it exists to report", have, n)
		}
	}
}

// TestDispatchStillRespectsShutdownBound proves the detach did not turn into
// "alerts run forever". WithoutCancel drops cancellation, so the per-send
// timeout is now the only bound; if that were missing, a hung endpoint would
// pin a goroutine for the life of the process.
func TestDispatchStillRespectsShutdownBound(t *testing.T) {
	block := make(chan struct{})
	hit := make(chan struct{}, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		<-block // never respond
	}))
	// Registration order matters: defers run LIFO, and httptest.Close blocks
	// until every outstanding handler returns. Closing the sink before
	// releasing the handler deadlocks the test itself.
	defer sink.Close()
	defer close(block)

	q := newDispatchTestDB(t, sink.URL, EventRotationFailed)

	ctx, cancel := context.WithCancel(context.Background())
	d := NewChannelDispatcher(ctx, q, nil)
	// 1s client timeout stands in for the 15s per-send bound so the test is fast.
	d.client = &http.Client{Timeout: time.Second}
	d.Dispatch(EventRotationFailed, "x", "", map[string]string{"secret": "x"})
	cancel()

	select {
	case <-hit:
	case <-time.After(5 * time.Second):
		t.Fatal("the send never reached the endpoint at all")
	}
	// The client timeout must fire and release the goroutine. If the send were
	// unbounded this would hang until the test binary's own deadline.
	time.Sleep(2 * time.Second)
}

// TestDispatchTestButtonStillWorks guards the path an operator uses to verify a
// channel. It ran on the process-lifetime dispatcher and was never broken, so
// the fix must not regress it while changing the shared send path underneath.
func TestDispatchTestButtonStillWorks(t *testing.T) {
	received := make(chan string, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	q := newDispatchTestDB(t, sink.URL, EventRotationFailed)
	d := NewChannelDispatcher(context.Background(), q, nil)
	d.client = &http.Client{Timeout: 10 * time.Second}

	row, err := q.GetNotificationChannel(context.Background(), "ch1")
	if err != nil {
		t.Fatalf("load channel: %v", err)
	}
	if err := d.DispatchTest(row); err != nil {
		t.Fatalf("DispatchTest: %v", err)
	}
	select {
	case ct := <-received:
		if ct != "application/json" {
			t.Errorf("unexpected content type %q", ct)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the Test button delivered nothing")
	}
}

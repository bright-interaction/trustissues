package flarereport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// flushTimeout is the value FlareRecoverer passes to hub.Flush. Kept here as a
// named constant so the timing assertions below read against the real budget
// rather than a magic number, and so a change to it fails loudly.
const flushTimeout = 2 * time.Second

// stalledTransport stands in for a Flare endpoint that is not answering
// promptly: it records every event handed to it and makes Flush burn its whole
// deadline. That is what turns a capture on this path into the measured
// multi-second hold of a goroutine and its client socket, and it is why the
// abort case asserts on elapsed time and not only on the event count.
type stalledTransport struct {
	mu     sync.Mutex
	events []*sentry.Event
}

func (t *stalledTransport) Configure(sentry.ClientOptions) {}

func (t *stalledTransport) SendEvent(event *sentry.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, event)
}

func (t *stalledTransport) Flush(timeout time.Duration) bool {
	time.Sleep(timeout)
	return false
}

func (t *stalledTransport) FlushWithContext(ctx context.Context) bool {
	<-ctx.Done()
	return false
}

func (t *stalledTransport) Close() {}

func (t *stalledTransport) captured() []*sentry.Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*sentry.Event(nil), t.events...)
}

// bindStalledFlare wires the real ClientOptions (so BeforeSend and the rest of
// production's hooks are in the path) to a stalled transport and binds it to
// the hub FlareRecoverer clones from. Reporting is genuinely live for the
// duration of the test, which is the only way "no event was reported" means
// anything.
func bindStalledFlare(t *testing.T) *stalledTransport {
	t.Helper()
	tr := &stalledTransport{}
	opts := ClientOptions("https://public@flare.example/1", "trustissues-test", "test")
	opts.Transport = tr
	// Keep Flush on the transport path instead of the batch-processor path so
	// the stall this test measures is the one production pays.
	opts.DisableLogs = true
	opts.DisableMetrics = true
	client, err := sentry.NewClient(opts)
	if err != nil {
		t.Fatalf("building the capturing sentry client: %v", err)
	}
	prev := sentry.CurrentHub().Client()
	sentry.CurrentHub().BindClient(client)
	t.Cleanup(func() { sentry.CurrentHub().BindClient(prev) })
	return tr
}

// serveAndRecover drives a panicking handler through FlareRecoverer and returns
// what came back out of the middleware plus how long the middleware held on to
// the goroutine.
func serveAndRecover(t *testing.T, panicWith any) (recovered any, elapsed time.Duration) {
	t.Helper()
	h := FlareRecoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(panicWith)
	}))
	req := httptest.NewRequest(http.MethodPost, "/proxy/api.example/v1/thing?code=abc", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Capability tok")
	rec := httptest.NewRecorder()

	start := time.Now()
	func() {
		defer func() { recovered = recover() }()
		h.ServeHTTP(rec, req)
	}()
	return recovered, time.Since(start)
}

// TestFlareRecovererDoesNotReportAbortHandler is the fix.
//
// handlers.proxyCapability panics with http.ErrAbortHandler on purpose when an
// upstream reflects the injected credential past the streaming hold-back. That
// is a working control firing, remotely triggerable up to the proxy limiter's
// rate, so it must not cost a synchronous multi-second flush per firing and
// must not file itself in the shared estate error store as a crash.
func TestFlareRecovererDoesNotReportAbortHandler(t *testing.T) {
	tr := bindStalledFlare(t)

	recovered, elapsed := serveAndRecover(t, http.ErrAbortHandler)

	// The abort must still propagate: net/http's server is what actually drops
	// the connection, and swallowing it here would hand the caller a truncated
	// body as a clean one.
	if recovered != http.ErrAbortHandler {
		t.Fatalf("FlareRecoverer must re-panic the abort so net/http still drops the connection; got %v", recovered)
	}
	if got := tr.captured(); len(got) != 0 {
		t.Errorf("a deliberate connection abort was reported to Flare as a crash (%d event(s)); real panics get triaged as noise once this is routine traffic", len(got))
	}
	if elapsed >= flushTimeout/4 {
		t.Errorf("the abort path held the goroutine and its socket for %v; the exemption must return immediately, not wait on a %v flush", elapsed, flushTimeout)
	}
}

// TestFlareRecovererStillReportsRealPanics is the control for the test above.
//
// Without it, an exemption and a middleware that reports nothing at all look
// identical: both produce zero events and return instantly. This half proves
// reporting is live on the same hub, with the same stalled transport, and that
// the multi-second hold the abort case measures is real rather than an artifact
// of a transport that never stalls.
func TestFlareRecovererStillReportsRealPanics(t *testing.T) {
	tr := bindStalledFlare(t)
	boom := errors.New("a real panic, not a control action")

	recovered, elapsed := serveAndRecover(t, boom)

	if err, ok := recovered.(error); !ok || !errors.Is(err, boom) {
		t.Fatalf("FlareRecoverer must re-panic so chi's Recoverer still renders the 500; got %v", recovered)
	}
	events := tr.captured()
	if len(events) != 1 {
		t.Fatalf("a genuine panic must produce exactly one Flare event, got %d", len(events))
	}
	if ex := events[0].Exception; len(ex) == 0 || !strings.Contains(ex[0].Value, "a real panic") {
		t.Errorf("the reported event does not carry the panic value: %+v", events[0].Exception)
	}
	// The request must ride along or the report is not triageable, and it must
	// have been through the scrubber on the way (scrub_test.go owns the detail).
	if events[0].Request == nil || events[0].Request.Method != http.MethodPost {
		t.Errorf("the reported event lost its request context: %+v", events[0].Request)
	}
	if events[0].Request != nil && events[0].Request.QueryString != "" {
		t.Errorf("the reported event kept its query string: %q", events[0].Request.QueryString)
	}
	// The instrument check: this is the cost the abort path must not pay.
	if elapsed < flushTimeout {
		t.Fatalf("the reporting path returned in %v against a %v flush budget, so the stalled transport is not stalling and the abort case's timing assertion proves nothing", elapsed, flushTimeout)
	}
}

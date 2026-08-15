package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"

	"github.com/bright-interaction/trustissues/internal/flarereport"
)

// flareCaptureTransport stands in for the network so a test can read the event
// that WOULD have been shipped to the shared estate Flare store.
type flareCaptureTransport struct{ events []*sentry.Event }

func (t *flareCaptureTransport) Configure(sentry.ClientOptions)        {}
func (t *flareCaptureTransport) SendEvent(e *sentry.Event)             { t.events = append(t.events, e) }
func (t *flareCaptureTransport) Flush(time.Duration) bool              { return true }
func (t *flareCaptureTransport) FlushWithContext(context.Context) bool { return true }
func (t *flareCaptureTransport) Close()                                {}

// installFlareCapture binds a client built from the REAL production options to
// the current hub, so what the test observes is the wiring cmd/server installs
// and not a copy of it declared here.
func installFlareCapture(t *testing.T) *flareCaptureTransport {
	t.Helper()
	tr := &flareCaptureTransport{}
	opts := flarereport.ClientOptions("http://ab12cd34ab12cd34ab12cd34ab12cd34@127.0.0.1:19000/42", "trustissues-test", "test")
	opts.Transport = tr
	client, err := sentry.NewClient(opts)
	if err != nil {
		t.Fatalf("building the flare client: %v", err)
	}
	sentry.CurrentHub().BindClient(client)
	t.Cleanup(func() { sentry.CurrentHub().BindClient(nil) })
	return tr
}

// assertNoTraceOf fails if any 16-character window of secret appears anywhere in
// the serialized report. Checking the whole string only would pass on a report
// that truncated the credential, and a truncated credential is still most of a
// credential.
func assertNoTraceOf(t *testing.T, report, secret, what string) {
	t.Helper()
	const window = 16
	for i := 0; i+window <= len(secret); i++ {
		if frag := secret[i : i+window]; strings.Contains(report, frag) {
			t.Fatalf("the Flare report carries %s: fragment %q at offset %d is present in the outbound event", what, frag, i)
		}
	}
}

// TestServiceSecretsPanicShipsNoServiceKey is the P1-5 proof. It panics inside
// the real FetchOwnSecrets handler with a real-shaped service key in the header
// that authenticates the route, and asserts the report that would leave this
// host carries no piece of it.
//
// The route matters: POST /api/service-identities/me/secrets is the one endpoint
// whose whole job is returning plaintext vault values, so its credential is the
// single worst one to hand to a store with a wider audience than the vault.
func TestServiceSecretsPanicShipsNoServiceKey(t *testing.T) {
	const serviceKey = ServiceKeyPrefix + "9f3c1a7e5b2d804613fa27ce90d8b45172ea6c3f0918d7b4e25a6c8f13407d9e"

	tr := installFlareCapture(t)

	// A nil *db.Queries makes the first query panic, which is the shape of any
	// unexpected nil or index fault on this route.
	h := NewServiceSecretsHandler(nil, nil)
	// FlareRecoverer is what cmd/server mounts; it captures then re-panics.
	srv := flarereport.FlareRecoverer(http.HandlerFunc(h.FetchOwnSecrets))

	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets?key="+serviceKey, nil)
	req.Header.Set("X-Service-Key", serviceKey)
	req.Header.Set("User-Agent", "trustissues-boot/1.0")
	req.Header.Set("Cookie", "ti_session=should-not-travel")

	func() {
		defer func() {
			if rec := recover(); rec == nil {
				t.Fatal("the route did not panic, so this test proves nothing; pick a fault that still panics")
			}
		}()
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}()

	if len(tr.events) != 1 {
		t.Fatalf("expected exactly 1 captured event, got %d; without an event the assertion below is vacuous", len(tr.events))
	}
	raw, err := json.Marshal(tr.events[0])
	if err != nil {
		t.Fatalf("marshalling the captured event: %v", err)
	}
	report := string(raw)

	assertNoTraceOf(t, report, serviceKey, "the live X-Service-Key credential")

	// The report still has to be worth having.
	if !strings.Contains(report, "/api/service-identities/me/secrets") {
		t.Error("the report lost the request path, so nobody can triage the panic")
	}
	if !strings.Contains(report, "trustissues-boot/1.0") {
		t.Error("the report lost the user agent, so the scrub is over-broad")
	}
}

// TestCapturedRequestBodyNeverShips covers the other field on the same struct.
// Scope.SetRequest buffers up to 10 KiB of the request body and ApplyToEvent
// copies it into Request.Data, which on a vault entry create is the plaintext
// secret.
//
// Note what this test does NOT claim. Routed through FlareRecoverer as it is
// mounted today, Data always arrives empty, because SetRequest runs inside the
// deferred recover after the handler has drained r.Body, so the buffering
// wrapper never sees a byte. A test that panicked through the middleware would
// therefore pass with or without the fix, which is a test that proves nothing.
// This one puts the body on the scope with SetRequestBody, the SDK's own API for
// bytes already in memory, so it exercises the state the field is in whenever
// the capture point sits above the handler (sentryhttp, or SetRequest being
// hoisted). That is the change this assertion exists to survive.
func TestCapturedRequestBodyNeverShips(t *testing.T) {
	const plaintext = "sk-ant-api03-4Qm7Zx1LpR8vT2nB6yH0wKdE5sJfA9cG3uX7iO1lM4rY8tN2bV6zQ5wS"

	tr := installFlareCapture(t)

	req := httptest.NewRequest(http.MethodPost, "/api/vault/entries", nil)
	req.Header.Set("Content-Type", "application/json")

	hub := sentry.CurrentHub().Clone()
	hub.Scope().SetRequest(req)
	hub.Scope().SetRequestBody([]byte(`{"name":"anthropic","value":"` + plaintext + `"}`))
	hub.RecoverWithContext(req.Context(), "boom on a write route")

	if len(tr.events) != 1 {
		t.Fatalf("expected exactly 1 captured event, got %d", len(tr.events))
	}
	raw, err := json.Marshal(tr.events[0])
	if err != nil {
		t.Fatalf("marshalling the captured event: %v", err)
	}
	assertNoTraceOf(t, string(raw), plaintext, "the plaintext request body")
}

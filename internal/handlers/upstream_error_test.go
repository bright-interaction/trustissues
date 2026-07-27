package handlers

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// TestUpstreamErrorNeverCarriesTheResponseBody locks the fix for the
// last_rotation_error leak.
//
// The path that matters: a provider or delivery target gets a non-2xx, the
// error becomes DeliveryResult.Error, summarizeDelivery folds it into
// last_rotation_error, the API returns that field, RotationManager renders it
// verbatim in the browser, and dispatchRotationAlert ships the same string to
// notification channels (Slack, webhook, email) OFF-BOX.
//
// It used to be built as fmt.Errorf("HTTP %d: %s", status, body[:200]). The code
// did run it through redactUpstreamError first, but that only rewrites
// *url.Error, so a non-2xx fell through to err.Error() with the upstream body
// attached. An upstream body can echo a token, name an internal host, or dump
// the request.
//
// The invariant: nothing derived from the response body may survive into the
// string that gets persisted or transmitted.
func TestUpstreamErrorNeverCarriesTheResponseBody(t *testing.T) {
	const leaked = "ghp_SUPERSECRET_TOKEN_ECHOED_BACK"
	body := []byte(`{"error":"bad credentials","token":"` + leaked + `","host":"10.0.0.7"}`)

	err := newUpstreamHTTPError(401, body)

	// Guard the setup: if the body were empty every assertion below would pass
	// for the wrong reason.
	if len(body) < 20 {
		t.Fatal("ABORT: test body too short to be a meaningful leak probe")
	}

	msg := err.Error()
	if strings.Contains(msg, leaked) {
		t.Fatalf("LEAK: upstream token reached the persisted error string: %q", msg)
	}
	if strings.Contains(msg, "10.0.0.7") {
		t.Fatalf("LEAK: internal host reached the persisted error string: %q", msg)
	}
	if strings.Contains(msg, "bad credentials") {
		t.Fatalf("LEAK: upstream body text reached the persisted error string: %q", msg)
	}
	// It must still say something useful.
	if !strings.Contains(msg, "401") {
		t.Fatalf("error dropped the status code, operators lose the only signal: %q", msg)
	}

	// redactUpstreamError is what actually runs before persisting. It must not
	// reintroduce the body.
	if got := redactUpstreamError(err); strings.Contains(got, leaked) {
		t.Fatalf("LEAK via redactUpstreamError: %q", got)
	}

	// The body is still reachable for server-side logging, which is the whole
	// point of keeping it on the struct.
	var ue *upstreamHTTPError
	if !errors.As(err, &ue) {
		t.Fatal("upstreamHTTPError is not recoverable with errors.As, logging loses the body")
	}
	if !strings.Contains(ue.Body, leaked) {
		t.Fatal("the body was dropped entirely; server-side debuggability is gone")
	}
	if ue.Status != 401 {
		t.Fatalf("status not preserved: %d", ue.Status)
	}

	// Oversized bodies are truncated rather than retained whole.
	huge := newUpstreamHTTPError(500, []byte(strings.Repeat("A", 5000)))
	var he *upstreamHTTPError
	errors.As(huge, &he)
	if len(he.Body) != upstreamBodyLogLimit {
		t.Fatalf("body not truncated to %d, got %d", upstreamBodyLogLimit, len(he.Body))
	}
}

// TestRedactUpstreamErrorStillHidesTransportURLs guards the other half, which
// was already correct and must stay correct: a transport failure embeds the
// full target URL, including SSRF-revealing internal addresses and any
// credentials in userinfo or query.
func TestRedactUpstreamErrorStillHidesTransportURLs(t *testing.T) {
	uerr := &url.Error{
		Op:  "Post",
		URL: "https://user:hunter2@10.1.2.3:8080/hook?token=abcdef",
		Err: errors.New("dial tcp 10.1.2.3:8080: connect: connection refused"),
	}

	got := redactUpstreamError(uerr)
	for _, secret := range []string{"hunter2", "token=abcdef"} {
		if strings.Contains(got, secret) {
			t.Fatalf("LEAK: %q survived redaction: %q", secret, got)
		}
	}
	if got == "" {
		t.Fatal("redaction produced an empty string, operators get no signal at all")
	}
}

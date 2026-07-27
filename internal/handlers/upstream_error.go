package handlers

import (
	"fmt"
	"log/slog"
)

// upstreamBodyLogLimit caps how much of an upstream response body we keep for
// the server log. It never reaches a client.
const upstreamBodyLogLimit = 200

// upstreamHTTPError is what provider rotation and delivery targets return when
// an upstream answers with a non-2xx status.
//
// Error() deliberately omits the response body. That string is not private: it
// flows into DeliveryResult.Error, then summarizeDelivery folds it into
// last_rotation_error, which the API returns and RotationManager renders
// verbatim in the browser. Worse, the same summary is handed to
// dispatchRotationAlert, so it egresses to whatever Slack/webhook/email channel
// is configured. An upstream body can carry a token echo, an internal hostname,
// or a request dump, so none of it may travel that path.
//
// The body is still available to the server: LogValue puts it in the slog
// record, so `slog.Error(..., "error", err)` keeps full debuggability while the
// persisted and transmitted string stays structural.
//
// This existed as an intent before it existed as a mechanism. Both call sites
// already ran errors through redactUpstreamError, but that only rewrites
// *url.Error (a transport failure), and a non-2xx was built with fmt.Errorf, so
// it fell through to err.Error() with the body attached.
type upstreamHTTPError struct {
	Status int
	Body   string
}

func (e *upstreamHTTPError) Error() string {
	return fmt.Sprintf("upstream returned HTTP %d (response body in server logs)", e.Status)
}

// LogValue makes the body visible to slog and only to slog.
func (e *upstreamHTTPError) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("status", e.Status),
		slog.String("body", e.Body),
	)
}

// newUpstreamHTTPError builds the error for a non-2xx upstream response.
// Callers pass the raw body; it is truncated and kept for logging only.
func newUpstreamHTTPError(status int, body []byte) error {
	if len(body) > upstreamBodyLogLimit {
		body = body[:upstreamBodyLogLimit]
	}
	return &upstreamHTTPError{Status: status, Body: string(body)}
}

package handlers

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	// A nil body means the read was REFUSED, not that the upstream said nothing.
	// readProviderBody now returns nil on overflow and on a partial read, and the
	// thirteen provider sites that build this error pass that nil straight
	// through, so without a marker the log line for exactly the requests that
	// failed hardest would carry an empty Body and read like a silent upstream.
	// The delivery twin (upstreamErrorFromResponse, below) has always said so;
	// this is the same courtesy on the provider path.
	if body == nil {
		return &upstreamHTTPError{Status: status, Body: "<response body not read: refused by the read ceiling>"}
	}
	if len(body) > upstreamBodyLogLimit {
		body = body[:upstreamBodyLogLimit]
	}
	return &upstreamHTTPError{Status: status, Body: string(body)}
}

// maxUpstreamErrorBody caps how much of a non-2xx upstream response this process
// will pull into memory.
//
// The number comes from what the body is FOR, not from taste. Everything read on
// this path goes straight to newUpstreamHTTPError, which keeps
// upstreamBodyLogLimit bytes (200) for the server log and throws the rest away;
// nothing parses it and nothing else ever looks at it. The bodies that
// legitimately arrive are small JSON error objects: a Forgejo secret PUT that
// fails answers with {"message":...,"url":...} in the low hundreds of bytes, and
// a webhook target's error page is the same order. 4 KiB is twenty times the
// excerpt that survives and an order of magnitude above the largest real error
// object, so no honest upstream notices the ceiling, while a hostile one can no
// longer choose how much memory a live credential vault allocates.
const maxUpstreamErrorBody = 4096

// errUpstreamBodyOverLimit reports that the upstream sent more than
// maxUpstreamErrorBody bytes. It is a sentinel with no upstream-controlled text
// in it, so it is safe on the paths that render an error to a human.
var errUpstreamBodyOverLimit = errors.New("response body exceeded the read ceiling")

// readUpstreamErrorBody reads a non-2xx upstream response with a hard ceiling,
// and treats HITTING the ceiling as a failure rather than as a short body.
//
// It reads ONE byte past the ceiling on purpose. io.LimitReader stops silently,
// so a plain LimitReader at the ceiling hands back a body that is
// indistinguishable from a genuine one of exactly that length: the caller
// records the upstream's "message" from bytes that were cut mid-sentence, and if
// the truncation happens to land somewhere that still parses, the lie is
// complete. Reading n+1 makes the overflow observable, and an overflowing body
// is then reported as an error instead of being handed on.
func readUpstreamErrorBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxUpstreamErrorBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxUpstreamErrorBody {
		return nil, errUpstreamBodyOverLimit
	}
	return b, nil
}

// upstreamErrorFromResponse is the ONE way to turn a non-2xx response into an
// error. It reads the body under readUpstreamErrorBody's ceiling and builds the
// error in a single step, so no call site can reintroduce the unbounded read by
// forgetting the helper.
//
// A read that fails or overflows still produces an *upstreamHTTPError carrying
// the real status, because the delivery genuinely did fail with that status and
// callers (capability.go's redaction allowlist, vault_rotation.go's logging)
// match on that type. What it does NOT do is pass off bytes it could not read in
// full as the upstream's message: the Body then says so in a fixed structural
// string, which is slog-only exactly like every other body on this path.
func upstreamErrorFromResponse(resp *http.Response) error {
	body, err := readUpstreamErrorBody(resp.Body)
	if err != nil {
		return &upstreamHTTPError{
			Status: resp.StatusCode,
			Body:   fmt.Sprintf("<response body not read: %v>", err),
		}
	}
	return newUpstreamHTTPError(resp.StatusCode, body)
}

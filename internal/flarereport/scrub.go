package flarereport

import (
	"strings"

	sentry "github.com/getsentry/sentry-go"
)

// scrubRequestEvent strips request context that must not egress to the shared
// Flare store: the query string (short-lived OAuth codes/state, setup and reset
// tokens), the cookies (session), and auth headers (bearer creds, API keys). It
// keeps the method + path for triage.
//
// Shared by BeforeSend (errors) and BeforeSendTransaction (traces) so both event
// kinds are covered by the identical rule. This matters more here than in most
// services: trustissues brokers third-party API keys, so an unscrubbed request
// on an error path would ship live credentials into the shared estate store,
// where anyone with Flare read access could replay them.
func scrubRequestEvent(event *sentry.Event) *sentry.Event {
	if event != nil && event.Request != nil {
		event.Request.QueryString = ""
		event.Request.Cookies = ""
		if event.Request.Headers != nil {
			for _, h := range []string{"Authorization", "Cookie", "X-Api-Key", "X-API-Key", "Mcp-Session-Id"} {
				delete(event.Request.Headers, h)
			}
		}
		if i := strings.IndexByte(event.Request.URL, '?'); i >= 0 {
			event.Request.URL = event.Request.URL[:i]
		}
	}
	return event
}

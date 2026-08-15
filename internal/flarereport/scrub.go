package flarereport

import (
	"strings"

	sentry "github.com/getsentry/sentry-go"
)

// reportableHeaders is the ALLOW-list of request header names that may cross the
// tenant -> shared-store boundary inside a Flare report. Keys are lower-case and
// the lookup lower-cases before matching, so casing cannot be used to walk past
// it.
//
// It is an allow-list for exactly the reason capability.go's forwardableHeaders
// is one: a deny-list only ever blocks the names somebody thought of. This
// function WAS a deny-list of five names ("Authorization", "Cookie", "X-Api-Key",
// "X-API-Key", "Mcp-Session-Id"), and X-Service-Key was not among them. That is
// the credential for POST /api/service-identities/me/secrets, the single route
// whose whole job is handing plaintext vault values to a service container, so a
// panic anywhere on it shipped a live service key into the shared estate store
// where every holder of Flare read access could replay it against this server.
// The header was not forgotten by accident: under a deny-list every auth header
// added after the list was written is born leaking, and this tree has since
// grown X-Service-Key, X-Vault-Signature, X-Trustissues-Signature and a row of
// provider credentials. Under an allow-list a new header is born scrubbed, and
// the cost of forgetting one is a missing triage line rather than a live
// credential.
//
// Membership test for anything added here: could this header's value be pasted
// into a public issue tracker? Content negotiation, the client's user agent, the
// body's shape and the request id all pass. Authorization, any API or service
// key, cookies, request signatures, session ids and Referer (which carries the
// very query string this function strips off the URL) do not.
var reportableHeaders = map[string]struct{}{
	"accept":            {},
	"accept-encoding":   {},
	"accept-language":   {},
	"content-length":    {},
	"content-type":      {},
	"host":              {},
	"origin":            {},
	"user-agent":        {},
	"x-forwarded-proto": {},
	"x-request-id":      {},
}

// headerReportable reports whether a header name may appear in a Flare report.
//
// Matching is case-insensitive on purpose. HTTP header names are case-insensitive
// by spec and net/http canonicalises what it parses off the wire, but
// event.Request.Headers is a plain map[string]string that any capture path may
// fill with whatever casing it happens to hold, and this tree really does write
// header names in lower case (vault_providers.go sets "x-api-key" and "apikey").
// An exact-match check against canonical spellings is a check that can be
// side-stepped by a caller that never went through http.Header.
func headerReportable(name string) bool {
	_, ok := reportableHeaders[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// scrubRequestEvent strips request context that must not egress to the shared
// Flare store: the query string (short-lived OAuth codes/state, setup and reset
// tokens), the cookies (session), the buffered request body, and every header
// not on reportableHeaders. It keeps the method + path for triage.
//
// Clearing Data is defence in depth, and the honest description of it is that it
// is not load-bearing TODAY. Scope.SetRequest buffers up to 10 KiB of the
// request body and Scope.ApplyToEvent copies that buffer into
// event.Request.Data, which would be the plaintext value on a vault entry
// create or the password on a login. It arrives empty here only because
// FlareRecoverer calls SetRequest from inside the deferred recover, after the
// handler has already drained r.Body, so the buffering wrapper never sees a
// byte. That is an accident of one line's position, not a designed property:
// adopting sentryhttp, or moving SetRequest above next.ServeHTTP so the report
// gains a body on purpose, turns the field on with nothing else to stop it.
// One line here means that change cannot become a leak.
//
// Shared by BeforeSend (errors) and BeforeSendTransaction (traces) so both event
// kinds are covered by the identical rule. This matters more here than in most
// services: trustissues brokers third-party API keys, so an unscrubbed request
// on an error path would ship live credentials into the shared estate store,
// where anyone with Flare read access could replay them.
//
// This is the SECOND of the two layers standing between a request and the store.
// The first is inside the SDK: sentry's newRequest drops its own hard-coded
// sensitiveHeaders set (authorization, cookie, x-api-key, ...) whenever
// SendDefaultPII is off, which it is here. That set is fixed by the vendored SDK
// version, knows nothing about this product's header names, and grew none of
// them; it did not contain x-service-key, which is why relying on it was not
// enough. Treat this layer as the only one that knows what trustissues issues.
func scrubRequestEvent(event *sentry.Event) *sentry.Event {
	if event == nil || event.Request == nil {
		return event
	}
	req := event.Request
	req.QueryString = ""
	req.Cookies = ""
	req.Data = ""
	for name := range req.Headers {
		if !headerReportable(name) {
			delete(req.Headers, name)
		}
	}
	if i := strings.IndexByte(req.URL, '?'); i >= 0 {
		req.URL = req.URL[:i]
	}
	return event
}

package handlers

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

// upstreamRoute is one allowed (method, path) shape on an LLM provider API.
// prefix routes exist for the handful of endpoints that carry an id in the path
// (GET /v1/models/{model}); everything else is matched exactly.
type upstreamRoute struct {
	method string
	path   string
	prefix bool
}

// Inference routes only, per provider.
//
// Trustissues holds the OPERATOR's provider key and injects it server-side, so
// whatever path and method a caller names is executed with the operator's full
// account rights. There was no per-caller scoping at all: any role-'user'
// account with an API key could reach any path with any verb, so
//
//	curl -X DELETE -H 'X-API-Key: ti_<client>' https://host/api/ai/openai/v1/files/file-abc123
//
// deleted an object on the operator's OpenAI account, and the same shape reaches
// fine-tuning jobs, assistants, uploads and the batch API. Unlimited POSTs to
// anything bill the operator. A vault_only caller is already refused by
// VaultOnlyBlock on the gateway route group, but role 'user' is the role every
// client of a shared instance gets.
//
// So the surface is cut to what a non-streaming inference client actually needs:
// send a completion, count its tokens, and discover which models exist. Anything
// else is refused before the key is even resolved. New endpoints are added here
// deliberately rather than inherited by default.
var (
	anthropicRoutes = []upstreamRoute{
		{method: "POST", path: "/v1/messages"},
		{method: "POST", path: "/v1/messages/count_tokens"},
		// Legacy text completions, still live for older SDKs.
		{method: "POST", path: "/v1/complete"},
		{method: "GET", path: "/v1/models"},
		{method: "GET", path: "/v1/models/", prefix: true},
	}
	openaiRoutes = []upstreamRoute{
		{method: "POST", path: "/v1/chat/completions"},
		{method: "POST", path: "/v1/responses"},
		{method: "POST", path: "/v1/embeddings"},
		{method: "POST", path: "/v1/moderations"},
		// Legacy text completions, still live for older SDKs.
		{method: "POST", path: "/v1/completions"},
		{method: "GET", path: "/v1/models"},
		{method: "GET", path: "/v1/models/", prefix: true},
	}
)

// providerInferenceRoutes keys the allowlist by the provider's API HOST, not by
// a gateway-local provider name, because the AI gateway is not the only door
// onto the same property.
//
// The capability bridge (POST /api/secrets/issue plus /proxy/{host}/{path...})
// mints a token for a vault entry and injects that entry's decrypted value into
// an outbound request the CALLER addresses. The entry an admin points
// ai_key_openai at is an ordinary vault entry, and the natural way to manage a
// team key is to keep it in a collection, at which point every accepted member
// resolves it through accessibleEntriesPredicate. So a role-'user' client could
// mint for api.openai.com/v1/files with DELETE and spend the operator's key
// there, while the gateway's own allowlist watched a door the caller never used.
// One property, two doors: both now ask this table.
var providerInferenceRoutes = map[string][]upstreamRoute{
	"api.anthropic.com": anthropicRoutes,
	"api.openai.com":    openaiRoutes,
}

// safeUpstreamSegment is the shape of the ONE remainder segment a prefix route
// may carry: a model id, e.g. "gpt-4" or "ft:gpt-4o-mini-2024-07-18:acme::9abc".
//
// It is the only place a caller gets to put free text into an upstream path
// (every other route is matched against a literal), so it is where the charset
// rule belongs. No '%' survives it, which is what closes percent-encoded
// traversal: "%2e%2e" and the double-encoded "%252e%252e" are refused rather
// than matched as one string and resolved as another at the provider. No '?',
// '#' or control byte gets through either, so nothing can smuggle a query or a
// second path onto the request we build.
var safeUpstreamSegment = regexp.MustCompile(`^[A-Za-z0-9._~:-]+$`)

// normalizeUpstreamPath turns the raw path a caller sent into the single string
// that is BOTH matched against the allowlist and forwarded to the provider.
//
// The live bypass it closes: chi routes on r.URL.RawPath when that is set, so
// chi.URLParam(r, "*") hands back the ESCAPED path, and path.Clean does not
// collapse "%2e%2e". Cleaning an escaped path therefore matched
// "/v1/models/%2e%2e/%2e%2e/v1/files" against the allowed GET /v1/models/
// prefix and forwarded it verbatim, where the PROVIDER decoded it to
// "/v1/files" and served it with the operator's key attached. Reproduced at
// HTTP 200 with "Authorization: Bearer sk-..." on the wire, for every encoding
// of the same trick ("..%2f..%2f", "%2e%2e", "%252e%252e").
//
// The fix is NOT to decode. A decode would have to prove that re-encoding the
// decoded value reproduces exactly what goes on the wire, for every layer that
// decodes again (chi has already decoded once by the time we see some of these).
// Nothing legitimate on an inference API needs an escape, so this refuses them
// instead: every route is either matched against a literal or ends in one plain
// segment (safeUpstreamSegment), and plain text encodes to itself. What is
// matched is therefore exactly what is sent, which is the property that was
// claimed and missing.
//
// path.Clean handles the traversals that need no encoding at all: "/v1/models/.."
// is a single, charset-clean segment under an allowed prefix, and the provider
// resolves it to "/v1". Cleaning first turns it into "/v1", which matches no
// route. Deciding on one string and sending another is how path allowlists
// usually fail, so the cleaned value is returned and every caller forwards THAT.
func normalizeUpstreamPath(raw string) string {
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return path.Clean(raw)
}

// allowedUpstreamRoute reports whether (method, rawPath) is on the given
// allowlist and returns the normalized path to forward. The returned path is the
// one that was matched: callers must forward it rather than the raw input.
func allowedUpstreamRoute(routes []upstreamRoute, method, rawPath string) (string, bool) {
	clean := normalizeUpstreamPath(rawPath)
	for _, rt := range routes {
		if rt.method != method {
			continue
		}
		if rt.prefix {
			if !strings.HasPrefix(clean, rt.path) {
				continue
			}
			// Exactly ONE more segment, and a plain one. That refusal covers
			// three things at once: "/v1/models/" alone does not slip through as
			// an id, "/v1/models/a/b" cannot walk deeper into the API, and
			// "/v1/models/%2e%2e/v1/files" cannot pass as an id that the
			// provider will decode into a different endpoint.
			if !safeUpstreamSegment.MatchString(clean[len(rt.path):]) {
				continue
			}
			return clean, true
		}
		// Exact routes need no charset rule: the caller's path has to BE the
		// literal, so nothing of theirs survives into the forwarded string.
		if clean == rt.path {
			return clean, true
		}
	}
	return "", false
}

// providerAPIHost normalizes a host for the providerInferenceRoutes lookup.
func providerAPIHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(h, ":"); i >= 0 {
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i] // explicit port
		}
	}
	return h
}

// allowedProviderRoute is the ONE gate every call site that can carry an LLM
// provider key to a provider must pass.
//
// isProvider says whether host is a provider this table knows about; allowed
// says whether the call is on its inference allowlist; clean is the normalized
// path to forward. Callers that always speak to a provider (the AI gateway)
// must treat isProvider == false as a refusal, so adding a provider without
// adding its routes fails closed instead of proxying everything.
//
// TestProviderEgressCallSitesAreRegistered fails when a new outbound call site
// appears in this package without being routed through here, because the same
// key reaching the same host through a second door is exactly how this got
// missed the first time.
func allowedProviderRoute(host, method, rawPath string) (clean string, isProvider, allowed bool) {
	routes, ok := providerInferenceRoutes[providerAPIHost(host)]
	if !ok {
		return "", false, false
	}
	clean, allowed = allowedUpstreamRoute(routes, strings.ToUpper(method), rawPath)
	return clean, true, allowed
}

// displayUpstreamPath renders a refused path for the audit trail and the error
// body. It echoes the string as SENT (still escaped) and caps its length: the
// decoded form is attacker-controlled and this value is persisted to
// activity_log, so it is not the shape to paste anywhere.
func displayUpstreamPath(raw string) string {
	const max = 200
	runes := []rune(raw)
	if len(runes) <= max {
		return raw
	}
	return string(runes[:max]) + "..."
}

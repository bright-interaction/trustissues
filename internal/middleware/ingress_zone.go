package middleware

import (
	"context"
	"io"
	"net/http"
)

// IngressZone identifies the application-owned listener through which a
// request entered TrustIssues. It is deliberately not derived from Host,
// RemoteAddr, forwarding headers, or any overlay-provider header: all of those
// are request data, whereas the listener/router construction is the trust
// boundary.
type IngressZone uint8

const (
	// IngressPublic is the untrusted/default ingress. The zero value is public
	// so an unstamped request can never acquire private privileges by accident.
	IngressPublic IngressZone = iota
	// IngressPrivate is an ingress reachable through an administrator-selected
	// private transport, such as a Tailscale or Headscale listener.
	IngressPrivate
)

// PrivateIngressRequiredCode is the stable machine-readable error code
// returned by RequirePrivateIngress.
const PrivateIngressRequiredCode = "private_ingress_required"

// ingressZoneContextKey is intentionally private. Handlers may inspect the
// zone through IngressZoneFromContext or IsPrivateIngress, but cannot mint a
// private request by writing a context value directly.
type ingressZoneContextKey struct{}

// privateIngressConfiguredContextKey carries deployment state owned by router
// construction. It is deliberately separate from the request's ingress zone:
// one says which listener accepted THIS request; the other says whether the
// deployment has made the optional private listener available at all.
// Request headers, hostnames and peer addresses can mint neither value.
type privateIngressConfiguredContextKey struct{}

// IngressZoneFromContext returns the listener-stamped ingress zone. Missing,
// malformed, and future/unknown values all fail closed to IngressPublic.
func IngressZoneFromContext(ctx context.Context) IngressZone {
	if ctx == nil {
		return IngressPublic
	}
	zone, ok := ctx.Value(ingressZoneContextKey{}).(IngressZone)
	if ok && zone == IngressPrivate {
		return IngressPrivate
	}
	return IngressPublic
}

// IsPrivateIngress reports whether the request was explicitly stamped by the
// private listener. An unstamped or malformed context always returns false.
func IsPrivateIngress(ctx context.Context) bool {
	return IngressZoneFromContext(ctx) == IngressPrivate
}

// IsPrivateIngressConfigured reports whether server configuration enabled the
// optional private listener. Missing, malformed, and the zero value all mean
// disabled so direct handler tests and deployments without a connector retain
// the compatibility policy.
func IsPrivateIngressConfigured(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	configured, ok := ctx.Value(privateIngressConfiguredContextKey{}).(bool)
	return ok && configured
}

// StampPrivateIngressConfigured stamps immutable deployment state at router
// construction. Mount it once from trusted config, never from request data.
// Like the listener zone stamp, the first stamp wins so nested middleware
// cannot rewrite the server's decision.
func StampPrivateIngressConfigured(configured bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(privateIngressConfiguredContextKey{}) != nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), privateIngressConfiguredContextKey{}, configured)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// StampIngressZone stamps every request handled by next with the zone owned by
// the listener/router construction.
//
// Mount this at the OUTERMOST http.Server.Handler boundary, independently for
// the public and private listeners. Do not select a zone inside route
// middleware and do not select it from request headers, Host, or peer IP.
//
// The first stamp wins. This makes the listener authoritative even if a nested
// router is accidentally wrapped in another stamp: in particular, a nested
// IngressPrivate stamp cannot upgrade a request already classified public.
// Unknown zone values are normalized to IngressPublic.
func StampIngressZone(zone IngressZone) func(http.Handler) http.Handler {
	if zone != IngressPrivate {
		zone = IngressPublic
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Any existing value seals the decision. The key is private to this
			// package, and preserving even a malformed value makes corruption
			// fail closed when IngressZoneFromContext reads it.
			if r.Context().Value(ingressZoneContextKey{}) != nil {
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), ingressZoneContextKey{}, zone)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePrivateIngress rejects requests that did not enter through an
// explicitly private-stamped listener. Authentication and authorization still
// apply separately; this is an additional transport admission gate.
//
// The response is a stable JSON API contract so web and extension clients can
// distinguish a private-ingress policy refusal from ordinary authorization.
func RequirePrivateIngress() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsPrivateIngress(r.Context()) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"error":"private ingress required","code":"`+
					PrivateIngressRequiredCode+`"}`+"\n")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

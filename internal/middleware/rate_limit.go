package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Proxy trust configuration for clientIP. Set once at startup via
// ConfigureProxy before the server starts serving. Defaults match the
// intended deploy: one trusted Caddy hop, X-Real-IP ignored.
var (
	trustedProxyHops = 1
	trustXRealIP     = false
)

// ConfigureProxy sets how the rate limiter derives the client IP from the
// forwarding chain. hops is the number of trusted reverse-proxy hops in front
// of the server (0 means trust only the direct socket peer). trustRealIP
// enables honoring a single X-Real-IP header; it stays false unless the
// operator explicitly opts in, because X-Real-IP is client-controlled.
func ConfigureProxy(hops int, trustRealIP bool) {
	if hops < 0 {
		hops = 0
	}
	trustedProxyHops = hops
	trustXRealIP = trustRealIP
}

// visitor tracks the request count and window start time for a single IP.
type visitor struct {
	mu       sync.Mutex
	count    int
	windowAt time.Time
}

// RateLimiter implements a simple in-memory per-IP rate limiter. Each IP is
// allowed maxRequests within a sliding window. Once the window expires the
// counter resets automatically.
type RateLimiter struct {
	maxRequests int
	window      time.Duration
	visitors    sync.Map // map[string]*visitor
}

// NewRateLimiter creates a rate limiter that allows maxRequests per IP within
// the given window duration. For example, NewRateLimiter(100, time.Minute)
// allows 100 requests per minute per IP address.
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		maxRequests: maxRequests,
		window:      window,
	}

	// Start a background goroutine to periodically clean up stale entries
	// so the map does not grow unbounded.
	go rl.cleanup()

	return rl
}

// allow checks whether the given IP is within its rate limit. It returns true
// if the request is allowed or false if the limit has been exceeded.
func (rl *RateLimiter) allow(ip string) bool {
	now := time.Now()

	val, loaded := rl.visitors.LoadOrStore(ip, &visitor{
		count:    1,
		windowAt: now,
	})

	if !loaded {
		// New visitor, first request is always allowed.
		return true
	}

	v := val.(*visitor)
	v.mu.Lock()
	defer v.mu.Unlock()

	// If the window has expired, reset the counter.
	if now.Sub(v.windowAt) > rl.window {
		v.count = 1
		v.windowAt = now
		return true
	}

	// Increment and check against the limit.
	v.count++
	return v.count <= rl.maxRequests
}

// cleanup runs every window duration and removes visitors whose windows have
// fully expired. This prevents memory from growing without bound.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		rl.visitors.Range(func(key, value any) bool {
			v := value.(*visitor)
			v.mu.Lock()
			expired := now.Sub(v.windowAt) > rl.window*2
			v.mu.Unlock()
			if expired {
				rl.visitors.Delete(key)
			}
			return true
		})
	}
}

// RateLimit returns HTTP middleware that enforces the given rate limiter.
// Requests exceeding the limit receive a 429 Too Many Requests response.
func RateLimit(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)

			if !limiter.allow(ip) {
				slog.Debug("rate limit exceeded", "ip", ip)
				w.Header().Set("Retry-After", limiter.window.String())
				http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client's IP address from the request for rate
// limiting. It derives the client from the RIGHTMOST untrusted hop of the
// forwarding chain, never the client-controlled leftmost X-Forwarded-For entry
// and never a bare X-Real-IP. Proxy headers are honored only when the direct
// socket peer is loopback/private (i.e. our own reverse proxy) AND a positive
// trusted-hop count is configured; otherwise the socket peer is the client.
//
// The full hop chain, closest-to-us last, is [xff..., RemoteAddr]. RemoteAddr
// is trusted hop #1, so stripping trustedProxyHops trusted hops from the right
// puts the client at xff[len(xff)-trustedProxyHops]. Any entries an attacker
// prepends to X-Forwarded-For land left of that index and are ignored. This
// mirrors the rightmost-hop reasoning in
// internal/handlers/service_secrets.go requestRemoteIP.
// ClientIP is the exported form of clientIP. It is the SINGLE client-IP
// derivation for the whole codebase: rate limiting, login lockouts, and every
// audit row must agree on who the caller is, and must agree on a value the
// caller cannot choose. Handlers call this rather than rolling their own, since
// a second implementation that trusts the leftmost X-Forwarded-For entry (or
// X-Real-IP unconditionally) lets an attacker reset their own throttle bucket
// and write a forged source IP into the audit trail.
func ClientIP(r *http.Request) string { return clientIP(r) }

func clientIP(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	parsed := net.ParseIP(remoteIP)
	trustedPeer := parsed != nil && (parsed.IsLoopback() || parsed.IsPrivate())
	if trustedProxyHops <= 0 || !trustedPeer {
		// Not behind a configured trusted proxy: the socket peer is the client.
		return remoteIP
	}

	// X-Real-IP is client-controlled; honor it only when explicitly enabled.
	if trustXRealIP {
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			return xri
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteIP
	}
	parts := strings.Split(xff, ",")
	idx := len(parts) - trustedProxyHops
	if idx < 0 || idx >= len(parts) {
		// More trusted hops configured than entries present: the chain is
		// shorter than expected (misconfig or spoof attempt). Fall back to the
		// direct socket peer, which is never attacker-controlled.
		return remoteIP
	}
	if ip := strings.TrimSpace(parts[idx]); ip != "" {
		return ip
	}
	return remoteIP
}

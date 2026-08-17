package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
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

// maxVisitors hard-caps the number of distinct IPs a RateLimiter tracks at
// once. allow() creates a visitor entry unconditionally for every never-seen
// IP, and cleanup() only reclaims entries whose window ended more than
// 2*window ago (time-gated, not size-gated), so without a cap a sufficiently
// distributed flood of unique source IPs (botnet, IPv6 rotation) could grow
// the map without bound between cleanup ticks on this public-facing service.
// At ~150-250 bytes per entry (visitor struct + sync.Map overhead + IP key),
// 50,000 entries bounds one RateLimiter to roughly 10MB in the worst case,
// which is generous for legitimate distinct-visitor traffic within a single
// cleanup window.
const maxVisitors = 50_000

// evictSampleSize is how many entries evictOldestSample inspects before
// dropping the oldest of the sample. A full scan for the true oldest entry
// would make every insert at the cap cost O(n), the same quadratic shape as
// gating a periodic sweep on "the map is full" (see the estate's rate
// limiter gotcha on this exact tradeoff). Sampling bounds eviction cost to a
// constant regardless of map size.
const evictSampleSize = 8

// RateLimiter implements a simple in-memory per-IP rate limiter. Each IP is
// allowed maxRequests within a sliding window. Once the window expires the
// counter resets automatically. The number of distinct IPs tracked is capped
// at maxVisitors; see allow() for the eviction policy once at capacity.
type RateLimiter struct {
	maxRequests int
	window      time.Duration
	visitors    sync.Map     // map[string]*visitor
	numVisitors atomic.Int64 // live entry count; sync.Map has no O(1) len
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

	val, ok := rl.visitors.Load(ip)
	if !ok {
		// Genuinely new-looking IP. Bound the map before adding an entry: at
		// capacity, evict the oldest of a small sample rather than either
		// denying the request (an attacker floods the map with throwaway
		// source IPs and the limiter starts rejecting real visitors, turning
		// the control into the outage it exists to prevent) or letting the
		// new IP bypass tracking (fail-open defeats the limit entirely).
		if rl.numVisitors.Load() >= maxVisitors {
			rl.evictOldestSample()
		}

		var loaded bool
		val, loaded = rl.visitors.LoadOrStore(ip, &visitor{
			count:    1,
			windowAt: now,
		})
		if !loaded {
			rl.numVisitors.Add(1)
			// New visitor, first request is always allowed.
			return true
		}
		// Lost the race: another goroutine stored this IP first. Fall
		// through and apply the normal increment/expire logic to its entry.
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

// evictOldestSample removes the oldest visitor among a small random sample
// of currently tracked IPs. Called only when allow() is about to insert a
// new entry at the cap, so its cost is bounded by evictSampleSize regardless
// of map size, unlike a full scan for the true oldest entry.
func (rl *RateLimiter) evictOldestSample() {
	var oldestKey any
	var oldestAt time.Time
	sampled := 0

	rl.visitors.Range(func(key, value any) bool {
		v := value.(*visitor)
		v.mu.Lock()
		at := v.windowAt
		v.mu.Unlock()

		if oldestKey == nil || at.Before(oldestAt) {
			oldestKey, oldestAt = key, at
		}
		sampled++
		return sampled < evictSampleSize
	})

	if oldestKey != nil {
		if _, deleted := rl.visitors.LoadAndDelete(oldestKey); deleted {
			rl.numVisitors.Add(-1)
		}
	}
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
				if _, deleted := rl.visitors.LoadAndDelete(key); deleted {
					rl.numVisitors.Add(-1)
				}
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
				// Retry-After is delta-seconds or an HTTP-date (RFC 9110), never
				// a Go duration string: window.String() emits "1m0s", which no
				// client can parse, so every well-behaved client and every SDK
				// with retry support ignored the hint and hammered the endpoint
				// at whatever interval it chose.
				w.Header().Set("Retry-After",
					strconv.Itoa(int(limiter.window.Seconds())))
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
	remoteIP, trusted := peerIsTrustedProxy(r)
	if !trusted {
		// Not behind a configured trusted proxy: the socket peer is the client.
		return remoteIP
	}

	// X-Real-IP is client-controlled; honor it only when explicitly enabled.
	// Single-valued by convention, but read through the same flattener so that
	// a second line cannot hide behind Get returning only the first.
	if trustXRealIP {
		if xri := forwardedChain(r.Header, "X-Real-IP"); len(xri) > 0 {
			return xri[0]
		}
	}

	// The WHOLE chain, across every X-Forwarded-For line, not just the first
	// one Get would return. Reading one line let a caller who sent their own
	// line keep the proxy's appended line out of the count and land the index
	// on a value they chose; see the header comment in forwarded.go.
	parts := forwardedChain(r.Header, "X-Forwarded-For")
	if len(parts) == 0 {
		return remoteIP
	}
	idx := len(parts) - trustedProxyHops
	if idx < 0 || idx >= len(parts) {
		// More trusted hops configured than entries present: the chain is
		// shorter than expected (misconfig or spoof attempt). Fall back to the
		// direct socket peer, which is never attacker-controlled.
		return remoteIP
	}
	// IT MUST PARSE AS AN IP. The selected element is caller-influenced text,
	// and it flows verbatim into login_attempts.ip_address, activity_log and
	// service_secret_audit, all TEXT columns behind no-update/no-delete
	// triggers, so a forged value is permanent, and into a slog attribute,
	// where an embedded newline forges a whole log line. Nothing downstream
	// validates it, so it is validated here.
	//
	// This also restores a backstop that dropping empty elements removed: the
	// old code fell back whenever the selected element was blank, and this
	// covers that case plus "unknown", "_hidden", host:port forms and hostnames.
	if net.ParseIP(parts[idx]) == nil {
		return remoteIP
	}
	return parts[idx]
}

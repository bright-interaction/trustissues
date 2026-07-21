package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

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

// clientIP extracts the client's IP address from the request. It only trusts
// X-Forwarded-For and X-Real-IP headers when the direct connection comes from
// a loopback or private address (i.e. a trusted reverse proxy).
func clientIP(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// Only trust proxy headers when the direct peer is a private/loopback address
	if parsed := net.ParseIP(remoteIP); parsed != nil && (parsed.IsLoopback() || parsed.IsPrivate()) {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}

	return remoteIP
}

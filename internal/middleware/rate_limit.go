package middleware

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
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
	// Trust loopback only until startup installs the operator's explicit set.
	// In particular, RFC1918 is not a proxy identity: shared container bridges
	// routinely contain workloads that must not be allowed to forge XFF.
	trustedProxyPeers = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("::1/128"),
	}
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

// ConfigureTrustedProxyPeers sets the direct socket peers that may supply
// forwarding headers. Entries may be CIDRs or bare IP addresses. An empty
// specification trusts nobody; malformed input leaves the previous set intact.
// Hop count and peer identity are deliberately separate: hops describes the
// chain shape, while this set decides whether the chain is believed at all.
func ConfigureTrustedProxyPeers(spec string) error {
	prefixes, err := parseTrustedProxyPeers(spec)
	if err != nil {
		return err
	}
	trustedProxyPeers = prefixes
	return nil
}

func parseTrustedProxyPeers(spec string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0)
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil || addr.Zone() != "" {
			return nil, fmt.Errorf("TRUSTISSUES_TRUSTED_PROXY_PEERS: %q is neither a CIDR nor an unzoned IP address", raw)
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
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
// At ~150-250 bytes per entry (visitor struct + sync.Map overhead + IP key,
// measured at 183), 50,000 entries bounds one RateLimiter to roughly 10MB.
//
// THAT BOUND IS ONLY REAL BECAUSE ADMISSION IS SERIALISED. This comment
// previously made the same claim while allow() enforced the cap by
// check-then-act on a lock-free map, which is a soft statistical bound and not
// a bound at all: goroutines all read a stale count below the cap, all skipped
// or lost eviction, and all inserted anyway. Measured under a 32-goroutine
// flood of 1,280,000 distinct IPs, the map held 592,613 to 724,403 live
// entries, about 46-57% of the flood, at 136.6 MB resident against the ~9.2 MB
// claimed here. Retention stayed near 45-55% across a 9x range of flood
// volumes, so the map grew roughly LINEARLY with the flood instead of
// converging on the cap. See allow() for what makes it one decision now.
//
// Per limiter. cmd/server/main.go constructs 8 independent RateLimiters, each
// with its own cap, so the process-wide figure is 8x this, around 73MB of LIVE
// ENTRIES. Sizing this constant is therefore an 8x decision, not a 1x one.
//
// Live bytes are not footprint: measured under the flood that actually produces
// the bound, 8 full limiters were 71.9MB of heapAlloc but 210MB heapInuse and
// 229MB RSS, because the allocation churn that fills the maps is itself the peak.
// Budget for roughly 3x the number above when sizing a container.
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

	// admit serialises the admission of a NEVER-SEEN ip, and nothing else.
	//
	// The cap is a bound on a decision ("may this new entry exist"), and that
	// decision reads a count, possibly evicts, and inserts. Split across a
	// lock-free map those are three separate operations that concurrent
	// goroutines interleave freely, which is how the cap became a soft
	// statistical bound holding 12x its limit. Under this mutex they are one.
	//
	// The hot path does not touch it: an EXISTING visitor is served entirely by
	// the lock-free sync.Map load above (43 ns/op, unchanged). Only a new IP
	// pays, which is exactly the path a distinct-IP flood drives and exactly
	// the path that has to be bounded.
	//
	// THIS LOCK IS LOAD-BEARING FOR THE CAP, AND ONLY A BARRIER TEST SEES IT.
	//
	// A review measured the mutex removed and the cap still exact under a
	// 32-goroutine, 1,280,000-IP flood, and concluded the fix was
	// over-determined. That measurement reproduces; the conclusion does not
	// follow. A distributed flood spreads arrival times, so admitters almost
	// never sit at the cap boundary at the same instant and the check-then-act
	// window is barely entered. Concentrate them instead, which is what
	// TestVisitorCapHoldsWhenAdmittersArriveTogether does by filling to cap-1
	// and releasing hundreds of goroutines off one barrier: without this mutex
	// they all read the same under-cap count, all skip eviction, and all insert.
	//
	// A flood benchmark is therefore not evidence that this lock is redundant,
	// whatever it measures. The barrier test is the one that can see it.
	//
	// The eviction loop and the insert gate ARE largely redundant with each
	// other, and all three are kept because the redundancy costs nanoseconds on
	// a cold path. This lock is redundant with nothing. Do not delete it on the
	// strength of a flood benchmark.
	admit sync.Mutex
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
		// capacity, evict rather than either denying the request (an attacker
		// floods the map with throwaway source IPs and the limiter starts
		// rejecting real visitors, turning the control into the outage it
		// exists to prevent) or letting the new IP bypass tracking (fail-open
		// defeats the limit entirely).
		//
		// COUNT, EVICT AND INSERT ARE ONE DECISION, TAKEN UNDER admit.
		//
		// They used to be three operations on a lock-free map, which does not
		// enforce a cap at all: every goroutine in a flood read the same stale
		// count below the limit, so they all skipped eviction, and the ones
		// that did evict computed the SAME victim (sync.Map.Range walks
		// deterministically from the same root) so one won the delete and the
		// rest freed nothing, and then all of them inserted regardless because
		// evictOldestSample returned nothing for allow() to test. Measured
		// result: 592,613 live entries against a 50,000 cap.
		admitted, existing := rl.admitNewVisitor(ip, now)
		if admitted {
			// New visitor, first request is always allowed.
			return true
		}
		// Lost the race: another goroutine stored this IP first. Fall through
		// and apply the normal increment/expire logic to its entry.
		val = existing
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

// evictOldestSample removes the oldest visitor among the first evictSampleSize
// entries sync.Map.Range yields, and REPORTS WHETHER IT FREED A SLOT.
//
// The return value is not bookkeeping. Without it allow() could not tell an
// eviction that freed a slot from one that freed nothing, so it inserted either
// way and the cap was never enforced. Callers must gate the insert on it.
//
// "the oldest of a SAMPLE", not "the oldest".
//
// The previous comment called the sample random and the policy oldest-first,
// and neither was true. sync.Map.Range on Go 1.26's HashTrieMap walks
// deterministically from the same root, so over an unmutated map it returns a
// byte-identical sample on every call (measured: 200 of 200 samples identical).
// "No ordering guarantee" is not "random". The age comparison below was
// therefore inert as a GLOBAL policy: two cohorts separated in time died at
// identical rates (19.93% of the strictly-oldest cohort survived, exactly
// 50,000/250,000, indistinguishable from uniform), and inverting Before to
// After left the whole suite green.
//
// What is true, and what TestEvictionPrefersTheOldestOfTheSample pins so the
// comparator is falsifiable rather than decorative, is the LOCAL claim: among
// the entries this call actually saw, the one with the earliest windowAt is the
// one that goes. Across calls the choice of sample is age-blind, so the
// observable global behaviour is approximately arbitrary eviction. That is
// acceptable here and is deliberately not dressed up: cleanup() is what removes
// entries by age, and this function exists only to make room under a flood.
//
// Cost is bounded by evictSampleSize regardless of map size. A full scan for
// the true oldest entry would make every insert at the cap O(n), the same
// quadratic shape as gating a periodic sweep on "the map is full"; real
// oldest-first ordering needs an index (heap or LRU list) maintained on the hot
// path, which is a bigger change than the property is worth for a map whose
// stale entries are already reclaimed on a timer.
func (rl *RateLimiter) evictOldestSample() bool {
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

	if oldestKey == nil {
		// The map is empty. Nothing to free, and saying so is what stops
		// allow() looping forever against a count that cannot come down.
		return false
	}
	if _, deleted := rl.visitors.LoadAndDelete(oldestKey); deleted {
		rl.numVisitors.Add(-1)
		return true
	}
	// Someone else deleted it first (cleanup(), concurrently). No slot was
	// freed BY THIS CALL, and the count they decremented is already visible to
	// the caller's loop condition, so reporting false is both honest and
	// non-blocking.
	return false
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
// socket peer is in the operator's explicit proxy allowlist AND a positive
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
		//
		// The FALLBACK is correct and stays; what was missing is that it is
		// silent. A 2026-08-17 review read this branch as an attacker landing on
		// their own value, and a verifier refuted it: production ingress really
		// is two appending hops, and a client sending one entry yields
		// len(parts)=1, idx=-1, and this fallback rather than their value. But a
		// chain persistently shorter than TRUSTED_PROXY_HOPS means every request
		// is being attributed to the proxy's socket peer, so per-IP limiting has
		// silently collapsed to per-proxy limiting, and nothing said so. Debug
		// level would be invisible in exactly the deployment that needs it.
		// ONCE PER PROCESS.
		//
		// This is a CONFIGURATION fact, not a request fact: it reports that the
		// deployed hop count does not match the real ingress chain, which is
		// either true for every request or none. Logged per request it fired
		// 2-4 times per request (clientIP runs once per limiter in the chain
		// plus once per handler-side ClientIP call), measured at 2.1 lines per
		// request on a two-limiter route: about 9 million lines and 2.8 GB a day
		// at a modest 50 req/s. The message even said "if this repeats" while
		// doing nothing about it, and every line after the first carried no
		// distinguishing field, so they were pure duplicates. An operator
		// misconfiguration must not also be a log-volume incident.
		shortChainWarnOnce.Do(func() {
			slog.Warn("rate limit: X-Forwarded-For is shorter than TRUSTED_PROXY_HOPS, "+
				"falling back to the socket peer. Logged once per process: if the chain is "+
				"persistently short, the configured hop count does not match the real ingress "+
				"chain and per-IP limits are being applied per-proxy",
				"chain_entries", len(parts), "trusted_hops", trustedProxyHops)
		})
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

// shortChainWarnOnce keeps the forwarding-chain misconfiguration warning to one
// line per process. See clientIP.
var shortChainWarnOnce sync.Once

// resyncVisitorCount recounts the live entries and stores the result.
//
// Only reachable from allow()'s at-cap path, with admit held, and only when
// eviction reported that it could free nothing while the counter claimed the map
// was full. That combination should be impossible: every increment happens under
// admit immediately after a Store whose absence was established under the same
// lock, and both decrements are gated on LoadAndDelete reporting a deletion.
//
// It exists because the consequence of being wrong is a silent outage of the
// rate limiter rather than a memory overrun. A counter stuck above the cap makes
// every admission drain the map and insert anyway, so the limiter ends up
// tracking almost nobody and allowing almost everything. Recounting is O(live),
// runs at most once per admission in a state that should never occur, and
// restores the invariant instead of logging about it.
func (rl *RateLimiter) resyncVisitorCount() {
	var live int64
	rl.visitors.Range(func(_, _ any) bool { live++; return true })
	rl.numVisitors.Store(live)
	slog.Warn("rate limit: visitor counter disagreed with the map at capacity; resynced",
		"counted", live, "cap", maxVisitors)
}

// admitNewVisitor performs the whole at-capacity admission decision for an IP
// the caller just failed to find, under admit, and reports whether it inserted.
//
// Extracted so the critical section is bounded by ONE defer rather than by two
// hand-placed Unlock calls. Both were correct, but the blast radius of getting
// it wrong is total and silent: a panic or an early return added inside the
// section by a later edit (a metrics counter, a log line, a helper call) leaves
// admit held forever, and then EVERY never-seen IP on that limiter blocks
// permanently while the existing-visitor hot path keeps serving, so the process
// looks healthy. No test would see it. A defer costs about a nanosecond on a
// path that already costs ~570.
//
// Returns (true, nil) when it inserted, or (false, entry) when another goroutine
// admitted the same IP first and the caller should fall through to the normal
// increment/expire logic on that entry.
func (rl *RateLimiter) admitNewVisitor(ip string, now time.Time) (bool, any) {
	rl.admit.Lock()
	defer rl.admit.Unlock()

	// Re-check under the lock. Another goroutine may have admitted this same IP
	// between the caller's lock-free Load and here, and inserting over it would
	// drop that visitor's accumulated count, handing an attacker a budget reset
	// for the price of two concurrent requests.
	if existing, loaded := rl.visitors.Load(ip); loaded {
		return false, existing
	}
	// Evict until there is genuinely room. One eviction attempt can
	// free nothing (the sampled key may be deleted concurrently by
	// cleanup), and inserting anyway is precisely how the cap was
	// exceeded before. It terminates because each success decrements
	// the count by one and no other goroutine can insert while admit is
	// held.
	//
	// THE break IS AN UNREACHABLE-STATE ESCAPE, AND ITS DEGRADATION IS
	// FAIL-OPEN, NOT OVER-CAP. An earlier version of this comment said a
	// bookkeeping bug here "degrades to an over-cap map"; that is
	// backwards and was reassuring in the wrong direction. If the
	// counter ever sat above the cap while the map held fewer entries,
	// every admission would drain the map and then insert, so the steady
	// state is a nearly EMPTY map with the counter stuck high, every
	// request read as never-seen, and the rate limit effectively gone.
	// That is a control outage rather than a memory problem, which is
	// why the resync below exists instead of a bare break: the counter
	// is authoritative for the cap, so if it disagrees with the map it
	// is the counter that gets corrected.
	for rl.numVisitors.Load() >= maxVisitors {
		if rl.evictOldestSample() {
			continue
		}
		// Nothing could be freed while the counter says we are at
		// capacity. Recount and believe the map, then stop; a second
		// pass cannot do better because the map is not growing under
		// this lock.
		rl.resyncVisitorCount()
		break
	}
	// Store, not LoadOrStore: absence was just established under the
	// lock, and only this goroutine can be inserting.
	rl.visitors.Store(ip, &visitor{count: 1, windowAt: now})
	rl.numVisitors.Add(1)
	return true, nil
}

package middleware

import (
	"fmt"
	"testing"
	"time"
)

// TestRateLimiter_VisitorMapBounded drives the limiter with far more
// distinct IPs than any single deployment should see between cleanup ticks
// and asserts the live visitor count never grows past the hard cap. Before
// the cap was added, allow() created one entry per never-seen IP
// unconditionally, and cleanup() only reclaimed entries whose window ended
// more than 2*window ago (time-gated, not size-gated), so a distributed
// flood of unique source IPs could grow the map without bound between
// cleanup ticks: a memory-exhaustion vector on a public-facing service.
func TestRateLimiter_VisitorMapBounded(t *testing.T) {
	// Long window so the background cleanup ticker cannot fire mid-test and
	// muddy the result; the cap must hold on its own.
	rl := NewRateLimiter(100, time.Hour)

	const flood = 150_000 // 3x the cap
	for i := 0; i < flood; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		rl.allow(ip)
	}

	live := 0
	rl.visitors.Range(func(_, _ any) bool { live++; return true })

	if live > maxVisitors {
		t.Fatalf("visitor map grew to %d entries after %d distinct IPs, want <= %d (the hard cap)", live, flood, maxVisitors)
	}
	if live == 0 {
		t.Fatal("visitor map is empty after the flood; eviction removed everything")
	}

	if got := rl.numVisitors.Load(); got != int64(live) {
		t.Fatalf("numVisitors counter (%d) drifted from the actual live entry count (%d)", got, live)
	}
}

// TestRateLimiter_AllowDenyUnderCap is a regression check that the core
// sliding-window allow/deny logic for entries under the cap is unchanged by
// the eviction path.
func TestRateLimiter_AllowDenyUnderCap(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	ip := "192.0.2.1"

	for i := 0; i < 3; i++ {
		if !rl.allow(ip) {
			t.Fatalf("request %d for %s: want allowed, got denied", i+1, ip)
		}
	}
	if rl.allow(ip) {
		t.Fatalf("4th request within window for %s: want denied, got allowed", ip)
	}

	// A distinct IP is tracked independently and gets its own budget.
	other := "192.0.2.2"
	if !rl.allow(other) {
		t.Fatalf("first request for a different IP %s: want allowed, got denied", other)
	}
	if !rl.allow(other) {
		t.Fatalf("second request for %s within its own limit: want allowed, got denied", other)
	}

	// After the window elapses the original IP's counter resets.
	rl2 := NewRateLimiter(1, 10*time.Millisecond)
	if !rl2.allow(ip) {
		t.Fatal("first request: want allowed, got denied")
	}
	if rl2.allow(ip) {
		t.Fatal("second request within window: want denied, got allowed")
	}
	time.Sleep(20 * time.Millisecond)
	if !rl2.allow(ip) {
		t.Fatal("request after window expiry: want allowed, got denied")
	}
}

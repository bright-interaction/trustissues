package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// THE CAP UNDER CONCURRENCY, WHICH IS THE ONLY WAY IT WAS EVER BROKEN.
//
// The single-goroutine flood in rate_limit_cap_test.go passed against the
// original fix while the cap was holding 592,613 entries in production
// conditions, because check-then-act only fails when something else is acting.
// Every assertion here therefore runs the flood from many goroutines at once.

// floodConcurrently drives n distinct IPs through rl from `workers` goroutines
// and returns the live entry count and the counter, read after every worker has
// finished so neither is a torn mid-flight sample.
func floodConcurrently(tb testing.TB, rl *RateLimiter, workers, n int) (live int, counted int64) {
	tb.Helper()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < n; i += workers {
				rl.allow(fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff))
			}
		}(w)
	}
	wg.Wait()

	rl.visitors.Range(func(_, _ any) bool { live++; return true })
	return live, rl.numVisitors.Load()
}

// TestVisitorCapHoldsUnderAConcurrentFlood is the HIGH-2 repro, inverted into a
// guard. Before admission was serialised this reported roughly 46-57% of the
// flood as live, growing linearly with flood size rather than converging on the
// cap.
func TestVisitorCapHoldsUnderAConcurrentFlood(t *testing.T) {
	// A long window keeps the cleanup ticker out of the measurement: the cap
	// has to hold on its own, not with a sweeper's help.
	rl := NewRateLimiter(100, time.Hour)

	const (
		workers = 32
		flood   = 400_000 // 8x the cap
	)
	live, counted := floodConcurrently(t, rl, workers, flood)

	// Absolute first, deliberately not derived from maxVisitors: a cap raised
	// 100x must fail this line. See rate_limit_cap_test.go for why that matters.
	const absoluteCeiling = 60_000
	if live > absoluteCeiling {
		t.Errorf("%d workers x %d distinct IPs left %d live entries, want <= %d "+
			"(roughly %d MB here, 8x across the process): the cap is a soft statistical bound again",
			workers, flood, live, absoluteCeiling, live*183/(1<<20))
	}
	if live > maxVisitors {
		t.Errorf("live entries %d exceed the hard cap %d after a concurrent flood", live, maxVisitors)
	}
	if live == 0 {
		t.Fatal("the map is empty after the flood; eviction removed everything")
	}
	if counted != int64(live) {
		t.Errorf("numVisitors (%d) drifted from the real live count (%d) under concurrency", counted, live)
	}
}

// TestVisitorCapDoesNotGrowWithFloodSize is the shape of the defect rather than
// one measurement of it. A soft bound retains a roughly constant FRACTION of
// whatever it is given, so it grows with the flood; a real bound does not move.
func TestVisitorCapDoesNotGrowWithFloodSize(t *testing.T) {
	const workers = 32
	small, _ := floodConcurrently(t, NewRateLimiter(100, time.Hour), workers, 120_000)
	large, _ := floodConcurrently(t, NewRateLimiter(100, time.Hour), workers, 960_000)

	if large > small+1_000 {
		t.Errorf("an 8x larger flood left %d live entries against %d for the smaller one; "+
			"the map is tracking flood size instead of the cap", large, small)
	}
}

// TestAdmissionDoesNotResetAnExistingVisitorsBudget covers the race the re-check
// under the admit lock exists for. Concurrent FIRST requests from one IP must
// produce ONE entry with every request counted: inserting over the winner hands
// an attacker a fresh budget for the price of a concurrent request.
//
// THE BARRIER AND THE ROUNDS ARE THE TEST.
//
// A first draft just spawned goroutines in a loop and let them run. It stayed
// green with the re-check deleted, because by the time goroutine 2 was
// scheduled goroutine 1 had usually already stored the entry, so the contended
// window was never entered and the test proved nothing. Every worker now blocks
// on a barrier and is released together onto a COLD key, and the scenario runs
// many rounds, so the window is entered rather than hoped for.
func TestAdmissionDoesNotResetAnExistingVisitorsBudget(t *testing.T) {
	const (
		workers = 64
		each    = 50
		rounds  = 40
	)

	for round := 0; round < rounds; round++ {
		rl := NewRateLimiter(1_000_000, time.Hour)
		ip := fmt.Sprintf("203.0.113.%d", round)

		var ready, start, done sync.WaitGroup
		ready.Add(workers)
		done.Add(workers)
		start.Add(1)
		for w := 0; w < workers; w++ {
			go func() {
				defer done.Done()
				ready.Done()
				start.Wait() // every worker's FIRST allow() lands together
				for i := 0; i < each; i++ {
					rl.allow(ip)
				}
			}()
		}
		ready.Wait()
		start.Done()
		done.Wait()

		live := 0
		rl.visitors.Range(func(_, _ any) bool { live++; return true })
		if live != 1 {
			t.Fatalf("round %d: one IP produced %d entries, want exactly 1", round, live)
		}
		// A double admission increments the counter twice for one entry, which
		// is a permanent drift: the limiter believes it holds visitors it does
		// not have and evicts on every new IP forever.
		if got := rl.numVisitors.Load(); got != 1 {
			t.Fatalf("round %d: numVisitors is %d for a single tracked IP, want 1", round, got)
		}

		val, ok := rl.visitors.Load(ip)
		if !ok {
			t.Fatalf("round %d: the IP is not tracked at all", round)
		}
		v := val.(*visitor)
		v.mu.Lock()
		got := v.count
		v.mu.Unlock()

		// A lost admission race shows up as a count short of the total by
		// however many requests were discarded when an entry replaced the first.
		if want := workers * each; got != want {
			t.Fatalf("round %d: counted %d requests for %s, want %d: an admission overwrote "+
				"an existing visitor's budget, resetting it mid-window", round, got, ip, want)
		}
	}
}

// TestEvictionReportsWhetherItFreedASlot pins the return value HIGH-2 turns on.
// allow() gates its insert on this, so a version that always reported success
// would restore the original defect exactly.
func TestEvictionReportsWhetherItFreedASlot(t *testing.T) {
	rl := NewRateLimiter(100, time.Hour)

	if rl.evictOldestSample() {
		t.Error("evicting from an empty map reported that it freed a slot")
	}
	if got := rl.numVisitors.Load(); got != 0 {
		t.Errorf("an empty-map eviction moved the counter to %d", got)
	}

	rl.allow("198.51.100.1")
	if !rl.evictOldestSample() {
		t.Error("evicting from a map with one entry reported that it freed nothing")
	}
	if got := rl.numVisitors.Load(); got != 0 {
		t.Errorf("counter is %d after evicting the only entry, want 0", got)
	}
	if _, ok := rl.visitors.Load("198.51.100.1"); ok {
		t.Error("the entry survived an eviction that reported success")
	}
}

// TestEvictionPrefersTheOldestOfTheSample makes the age comparator FALSIFIABLE.
//
// It was previously inert as a global policy and no test could see it: two
// cohorts separated in time died at identical rates, and inverting Before to
// After left the whole suite green. The honest claim is local, so this asserts
// the local claim: among the entries one call actually samples, the earliest
// windowAt is the one that goes. Inverting the comparator turns this red.
func TestEvictionPrefersTheOldestOfTheSample(t *testing.T) {
	rl := NewRateLimiter(100, time.Hour)

	// Fewer entries than evictSampleSize, so the sample IS the whole map and
	// "oldest of the sample" and "oldest" coincide. That is what makes the
	// assertion decidable without depending on Range's walk order.
	if evictSampleSize < 3 {
		t.Skipf("evictSampleSize is %d; this test needs at least 3", evictSampleSize)
	}
	base := time.Now()
	ages := map[string]time.Duration{
		"192.0.2.10": -30 * time.Minute, // the oldest, must be evicted
		"192.0.2.11": -20 * time.Minute,
		"192.0.2.12": -10 * time.Minute,
	}
	for ip, age := range ages {
		rl.visitors.Store(ip, &visitor{count: 1, windowAt: base.Add(age)})
		rl.numVisitors.Add(1)
	}

	if !rl.evictOldestSample() {
		t.Fatal("eviction reported that it freed nothing from a three-entry map")
	}
	if _, ok := rl.visitors.Load("192.0.2.10"); ok {
		var survived []string
		rl.visitors.Range(func(k, _ any) bool { survived = append(survived, k.(string)); return true })
		t.Errorf("the oldest entry survived; the map still holds %v. The comparator is inert "+
			"or inverted: it must evict the earliest windowAt among the entries it sampled", survived)
	}
	if got := rl.numVisitors.Load(); got != 2 {
		t.Errorf("counter is %d after one eviction from three entries, want 2", got)
	}
}

// TestCleanupDecrementsTheCounter exercises the decrement in cleanup(), which
// every other test in this package leaves untouched because they all use hour
// or minute windows so the ticker never fires. Reverting the decrement left the
// suite green, and a regression there drives the counter monotonically upward
// and pins the limiter at permanent at-capacity eviction, unnoticed.
func TestCleanupDecrementsTheCounter(t *testing.T) {
	// NewRateLimiter starts cleanup() on this window, so the ticker really does
	// fire during the test rather than being simulated.
	rl := NewRateLimiter(100, 10*time.Millisecond)

	for i := 0; i < 20; i++ {
		rl.allow(fmt.Sprintf("198.51.100.%d", i))
	}
	if got := rl.numVisitors.Load(); got != 20 {
		t.Fatalf("counter is %d after 20 distinct IPs, want 20", got)
	}

	// cleanup() reclaims entries whose window ended more than 2*window ago, so
	// wait past that and give the ticker several chances to fire.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rl.numVisitors.Load() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	live := 0
	rl.visitors.Range(func(_, _ any) bool { live++; return true })
	counted := rl.numVisitors.Load()

	if live != 0 {
		t.Errorf("cleanup left %d entries alive well past 2*window", live)
	}
	if counted != 0 {
		t.Errorf("cleanup removed the entries but left the counter at %d; the limiter now believes "+
			"it is holding %d visitors it does not have and will evict on every new IP forever",
			counted, counted)
	}
}

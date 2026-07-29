package passwordhash

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSetTestCostRoundTripsAndIsGuarded checks the two things that matter about
// a knob which, if reached from production, silently weakens every stored
// password: that lowering the cost still produces a verifiable hash, and that
// the production guard exists.
func TestSetTestCostRoundTripsAndIsGuarded(t *testing.T) {
	if ProdCost() {
		SetTestCost()
	}
	if ProdCost() {
		t.Fatal("SetTestCost did not lower the cost")
	}

	h, err := Hash("CorrectHorseBatteryStaple1!")
	if err != nil {
		t.Fatalf("hash at test cost: %v", err)
	}
	ok, err := Verify("CorrectHorseBatteryStaple1!", h)
	if err != nil || !ok {
		t.Fatalf("verify at test cost: ok=%v err=%v", ok, err)
	}
	bad, err := Verify("wrong password", h)
	if err != nil || bad {
		t.Fatalf("a wrong password verified: ok=%v err=%v", bad, err)
	}
	// The encoded parameters must reflect the cost actually used, or a hash
	// written under test cost would be re-read as a production-cost hash.
	if !strings.Contains(h, "m=8,") {
		t.Errorf("encoded hash does not record the test cost: %q", h)
	}
}

// TestProductionCostIsUnchanged pins the shipped parameters. If someone tunes
// them, that should be a deliberate, reviewed change and not a side effect.
func TestProductionCostIsUnchanged(t *testing.T) {
	if argonTimeProd != 3 || argonMemoryProd != 64*1024 || argonThreadsProd != 4 {
		t.Errorf("production argon2id cost changed: t=%d m=%d p=%d (want 3 / 65536 / 4)",
			argonTimeProd, argonMemoryProd, argonThreadsProd)
	}
}

// TestHashSlotsBoundConcurrency proves the memory cap actually caps.
//
// Argon2id allocates 64 MiB per call and Hash/Verify are reachable from
// UNAUTHENTICATED endpoints. The login rate limiter is per-IP and per-minute, so
// it bounds the rate from one source and not the concurrent memory: an audit
// measured RSS going 74 MB -> 1038 MB from a single source. A semaphore is the
// matching control, because the exhausted resource is memory in flight.
func TestHashSlotsBoundConcurrency(t *testing.T) {
	var (
		mu       sync.Mutex
		inFlight int
		peak     int
	)
	// Wrap the slot so we can observe how many run at once.
	const callers = 40
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			release, aErr := acquireHashSlot()
			if aErr != nil {
				return
			}
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()

	if peak > cap(hashSlots) {
		t.Errorf("%d Argon2 computations ran concurrently, cap is %d: at 64 MiB each that is "+
			"%d MiB of unbounded allocation from an unauthenticated endpoint",
			peak, cap(hashSlots), peak*64)
	}
	if peak == 0 {
		t.Fatal("ABORT: nothing ran, the probe is measuring nothing")
	}
	t.Logf("peak concurrent hashes: %d (cap %d)", peak, cap(hashSlots))
}

// TestVerifyStillWorksUnderContention guards the obvious way to break this:
// a semaphore that is acquired and never released deadlocks every login.
func TestVerifyStillWorksUnderContention(t *testing.T) {
	if ProdCost() {
		SetTestCost()
	}
	h, err := Hash("CorrectHorseBatteryStaple1!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := Verify("CorrectHorseBatteryStaple1!", h)
			if err != nil || !ok {
				errs <- err
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("verifies did not complete: the hash semaphore is leaking slots and every login " +
			"would eventually block forever")
	}
	close(errs)
	for e := range errs {
		t.Errorf("concurrent verify failed: %v", e)
	}
}

// TestBusyRatherThanQueueingForever pins the bound on the wait.
//
// An unbounded semaphore swaps one exhaustion for another: every blocked caller
// holds a goroutine and its whole request, so under sustained load the process
// dies of goroutines instead of Argon2 buffers. Failing fast keeps the queue
// bounded by arrival rate over the wait budget.
//
// The caller contract matters as much as the bound: login must surface ErrBusy
// as 503 and NOT as a failed attempt, or an attacker saturating the semaphore
// could drive any account to its lockout threshold without guessing anything.
func TestBusyRatherThanQueueingForever(t *testing.T) {
	// Fill every slot and hold them.
	var releases []func()
	for i := 0; i < cap(hashSlots); i++ {
		rel, err := acquireHashSlot()
		if err != nil {
			t.Fatalf("ABORT: could not fill slot %d (%v); the test would not be measuring saturation", i, err)
		}
		releases = append(releases, rel)
	}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()

	start := time.Now()
	rel, err := acquireHashSlot()
	elapsed := time.Since(start)
	if err == nil {
		rel()
		t.Fatal("acquired a slot while all were held; the semaphore is not bounding anything")
	}
	if !errors.Is(err, ErrBusy) {
		t.Errorf("got %v, want ErrBusy", err)
	}
	if elapsed > hashWait+time.Second {
		t.Errorf("waited %v before giving up, budget is %v", elapsed, hashWait)
	}
}

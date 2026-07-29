package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestUpdateDoesNotWriteActivityInsideTheTransaction locks a regression I
// introduced with the round-8 atomicity fix and caught before it was audited.
//
// LogActivityFromRequest deliberately runs on its own background context, so a
// cancelled request still gets audited. That means its own connection. Calling
// it while Update held an open write transaction made the two contend for the
// SQLite write lock: measured HTTP 200 after 5.13s (the full _busy_timeout=5000)
// with the activity row silently LOST to SQLITE_BUSY.
//
// So the fix for a data-loss bug introduced an audit-loss bug plus a five-second
// stall on every destination_patterns save. Activity rows are now queued and
// written after commit, which also stops the audit trail claiming a change that
// later rolled back.
func TestUpdateDoesNotWriteActivityInsideTheTransaction(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "txlock@example.com", "user", "")
	mustEntry(t, h, queries, "tx-lock", owner, "Probe", "v")

	count := func() int {
		t.Helper()
		var n int
		if err := h.db.QueryRow(
			`SELECT COUNT(*) FROM activity_log WHERE action = 'vault.destinations_updated'`).Scan(&n); err != nil {
			t.Fatalf("count activity: %v", err)
		}
		return n
	}

	before := count()
	start := time.Now()
	rec := updateEntry(t, h, owner, "tx-lock", map[string]any{
		"destination_patterns": []any{"api.example.com/*"},
	})
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("update failed: %d %s", rec.Code, rec.Body.String())
	}
	// The stall was the full busy timeout. Anything near it means the activity
	// write is fighting the transaction's write lock again.
	if elapsed > 2*time.Second {
		t.Errorf("the update took %v; an activity write inside the transaction is contending "+
			"for the SQLite write lock", elapsed)
	}
	if got := count(); got == before {
		t.Error("the vault.destinations_updated activity row was lost; " +
			"changing an agent's destination ceiling would leave no audit trace")
	}
}

// TestUpdateEnrollingAProviderDoesNotStall covers the second member of the same
// family: seedCapabilityDefaults reached for h.queries (the pool) while Update
// held an open write transaction, so the two contended on separate connections.
// Measured 5.3s of DB-wide write stall, a stale provider_meta read, and the seed
// then silently dropped while the request returned 200, leaving the secret with
// destination_patterns='[]' and no API path to enrol it afterwards.
//
// Three separate audit lenses found this independently, and it is the same shape
// as the activity-log write above. Both are consequences of wrapping a long
// handler in a transaction without auditing what its helpers do.
func TestUpdateEnrollingAProviderDoesNotStall(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "seedtx@example.com", "user", "")
	mustEntry(t, h, queries, "seed-tx", owner, "Cloudflare", "v")

	start := time.Now()
	rec := updateEntry(t, h, owner, "seed-tx", map[string]any{"provider": "cloudflare"})
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("enrolling a provider failed: %d %s", rec.Code, rec.Body.String())
	}
	if elapsed > 2*time.Second {
		t.Errorf("enrolling a provider took %v; the capability seed is contending with the "+
			"transaction's write lock on a second connection", elapsed)
	}

	meta, err := queries.GetVaultEntryMeta(ctx, "seed-tx")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if meta.DestinationPatterns == "" || meta.DestinationPatterns == "[]" {
		t.Errorf("the capability seed was silently discarded (destination_patterns=%q); "+
			"the secret can never mint an agent token and there is no API way back",
			meta.DestinationPatterns)
	}
}

// TestUpdateFailsLoudlyOnAWriteError proves a write that cannot land no longer
// returns 200.
//
// Inside the transaction, ten column writes logged their error and carried on,
// so the handler committed whatever HAD landed and reported success. Under write
// contention that silently discarded custom_fields (imported TOTP seeds and
// recovery PINs) and provider metadata. A dropped table forces the same error
// deterministically.
func TestUpdateFailsLoudlyOnAWriteError(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "loud@example.com", "user", "")
	mustEntry(t, h, queries, "loud-1", owner, "Entry", "v")

	before, err := queries.GetVaultEntryMeta(ctx, "loud-1")
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	// Make the custom_fields write fail: rename the column out from under it.
	if _, err := h.db.Exec(`ALTER TABLE vault_entries RENAME COLUMN custom_fields TO custom_fields_x`); err != nil {
		t.Skipf("cannot simulate a write failure on this SQLite build: %v", err)
	}

	rec := updateEntry(t, h, owner, "loud-1", map[string]any{
		"notes":         "changed",
		"custom_fields": []any{map[string]any{"label": "pin", "value": "1234", "secret": true}},
	})

	// Restore the column BEFORE reading anything back: GetVaultEntryMeta selects
	// custom_fields, so asserting while it is renamed would fail on the fixture
	// rather than on the behaviour under test.
	if _, err := h.db.Exec(`ALTER TABLE vault_entries RENAME COLUMN custom_fields_x TO custom_fields`); err != nil {
		t.Fatalf("restore column: %v", err)
	}

	if rec.Code == http.StatusOK {
		t.Error("a failed column write returned 200; the user is told the save succeeded while " +
			"their custom fields were discarded")
	}

	// And the rollback must have undone the notes write that DID land.
	after, err := queries.GetVaultEntryMeta(ctx, "loud-1")
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if after.Notes != before.Notes {
		t.Error("a partially applied update was committed despite the failure")
	}
}

// TestClearingExpiryAndIntervalActuallyClears locks the three-state JSON fix.
//
// Both fields were `*string` / `*int`, so an explicit null (what the edit form
// sends to CLEAR a field) decoded to nil, identical to the key being absent. The
// handler's `if req.X != nil` read that as "unchanged", so emptying the expiry
// date did nothing while the UI toasted "Secret updated" and the old date
// reappeared on reload.
func TestClearingExpiryAndIntervalActuallyClears(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "clearfields@example.com", "user", "")
	mustEntry(t, h, queries, "clear-1", owner, "Entry", "v")

	if rec := updateEntry(t, h, owner, "clear-1", map[string]any{
		"expires_at": "2026-12-31T00:00:00Z", "rotation_interval_days": 90,
	}); rec.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", rec.Code, rec.Body.String())
	}
	seeded, err := queries.GetVaultEntryMeta(ctx, "clear-1")
	if err != nil {
		t.Fatalf("read seeded: %v", err)
	}
	if !seeded.ExpiresAt.Valid || !seeded.RotationIntervalDays.Valid {
		t.Fatalf("ABORT: the fixture did not set both fields, so clearing proves nothing")
	}

	// What the edit form sends when both inputs are emptied.
	if rec := updateEntry(t, h, owner, "clear-1", map[string]any{
		"expires_at": nil, "rotation_interval_days": nil,
	}); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	cleared, err := queries.GetVaultEntryMeta(ctx, "clear-1")
	if err != nil {
		t.Fatalf("read cleared: %v", err)
	}
	if cleared.ExpiresAt.Valid {
		t.Error(`emptying "Expiry date" did nothing while the UI reported success`)
	}
	if cleared.RotationIntervalDays.Valid {
		t.Error("emptying the rotation interval did nothing while the UI reported success")
	}

	// Omitting the keys entirely must still mean "unchanged", or every partial
	// update would wipe fields it never mentioned.
	if rec := updateEntry(t, h, owner, "clear-1", map[string]any{
		"expires_at": "2027-01-01T00:00:00Z",
	}); rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	if rec := updateEntry(t, h, owner, "clear-1", map[string]any{"notes": "unrelated"}); rec.Code != http.StatusOK {
		t.Fatalf("partial: %d %s", rec.Code, rec.Body.String())
	}
	after, err := queries.GetVaultEntryMeta(ctx, "clear-1")
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !after.ExpiresAt.Valid {
		t.Error("a partial update that never mentioned expires_at wiped it")
	}
}

// TestWaitForDeliveryIsBounded locks the shutdown drain against the failure mode
// the first version had.
//
// The delivery goroutine runs on a 15-minute context, and the first version of
// this wait was unbounded. Docker SIGKILLs 10 seconds after SIGTERM by default,
// so an unbounded wait did not protect the delivery at all: it guaranteed the
// process was killed hard mid-delivery instead of exiting cleanly, which is
// worse than not waiting. The wait is now bounded and the compose file gives the
// container a grace period longer than the budget.
func TestWaitForDeliveryIsBounded(t *testing.T) {
	h, _ := newCollectionAuthzEnv(t)

	// Nothing in flight: returns immediately and reports a clean drain.
	start := time.Now()
	if !h.WaitForDelivery(2 * time.Second) {
		t.Error("WaitForDelivery reported an incomplete drain with nothing in flight")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("an empty drain took %v; it should return at once", elapsed)
	}

	// A delivery that outlives the budget must NOT hold the process open.
	h.delivery.Add(1)
	defer h.delivery.Done()
	start = time.Now()
	if h.WaitForDelivery(200 * time.Millisecond) {
		t.Error("WaitForDelivery claimed a clean drain while a delivery was still running")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the bounded wait blocked for %v; a slow delivery would hold shutdown "+
			"past the container grace period and get the process SIGKILLed", elapsed)
	}
}

package handlers

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
)

// TestPartialSaveSurvivesConcurrentWrites locks the DSN fix.
//
// database/sql's BeginTx issues a plain BEGIN, which SQLite treats as DEFERRED.
// vault.Update is read-then-write for any request that does NOT carry
// custom_fields, which is every partial save: a value-only paste from the
// browser extension, an MCP write, any script following the documented
// "omit to leave unchanged" contract. The transaction took a read snapshot
// first, then failed the upgrade to the write lock with SQLITE_BUSY_SNAPSHOT,
// which does not invoke the busy handler at all, so _busy_timeout never applied.
// The save rolled back with a generic 500 and the vault kept a credential the
// operator had just revoked upstream.
//
// The React edit form always sends custom_fields first, so it takes the
// write-first path and never saw this, which is how it survived nine rounds.
//
// _txlock=immediate takes the write lock up front so the busy timeout covers it.
func TestPartialSaveSurvivesConcurrentWrites(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "conc@example.com", "user", "")

	const entries = 6
	for i := 0; i < entries; i++ {
		mustEntry(t, h, queries, fmt.Sprintf("conc-%d", i), owner, fmt.Sprintf("Entry %d", i), "orig")
	}

	// Value-only bodies: no custom_fields, so the first statement inside the
	// transaction is a SELECT. This is the shape that used to fail.
	var mu sync.Mutex
	failures := 0
	var wg sync.WaitGroup
	for round := 0; round < 10; round++ {
		wg.Add(entries)
		for i := 0; i < entries; i++ {
			go func(i, round int) {
				defer wg.Done()
				rec := updateEntry(t, h, owner, fmt.Sprintf("conc-%d", i), map[string]any{
					"value": fmt.Sprintf("rotated-%d-%d", i, round),
				})
				if rec.Code != http.StatusOK {
					mu.Lock()
					failures++
					mu.Unlock()
				}
			}(i, round)
		}
		wg.Wait()
	}

	if failures > 0 {
		t.Errorf("%d/%d concurrent value-only saves failed; a paste of a freshly rotated "+
			"credential returns 500 and the vault silently keeps the revoked one",
			failures, entries*10)
	}
}

// TestPartialSaveRacesOrdinaryReadTraffic is the sharper case: it needs no other
// SAVE at all. The auth middleware stamps sessions.last_used_at on every
// authenticated request, so plain dashboard traffic is a committing writer. One
// user with the vault open plus a script paste was enough.
func TestPartialSaveRacesOrdinaryReadTraffic(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "conc2@example.com", "user", "")
	mustEntry(t, h, queries, "conc-solo", owner, "Solo", "orig")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// A committing write on an unrelated table, the shape the auth
				// middleware produces on every request.
				_, _ = h.db.Exec(`UPDATE users SET name = name WHERE id = ?`, owner)
			}
		}
	}()

	failures := 0
	for i := 0; i < 25; i++ {
		rec := updateEntry(t, h, owner, "conc-solo", map[string]any{
			"value": fmt.Sprintf("v-%d", i),
		})
		if rec.Code != http.StatusOK {
			failures++
		}
	}
	close(stop)
	wg.Wait()

	if failures > 0 {
		t.Errorf("%d/25 value-only saves failed against ordinary background write traffic", failures)
	}
}

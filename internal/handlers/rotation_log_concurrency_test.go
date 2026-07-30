package handlers

import (
	"context"
	"encoding/json"
	"testing"
)

// TestConcurrentRotationLogAppendsDoNotLoseEachOther locks the lost-update fix.
//
// rotation_log is read-modify-written: unmarshal the array, append one entry, trim to
// 50, write the whole column back. With a plain UPDATE that is a classic lost update,
// and the window is not theoretical: the sweep snapshots at pass start and can be up
// to 90s per earlier entry behind by the time it writes. A user clicking Rotate on the
// same entry mid-pass had their SUCCESSFUL rotation erased from history and replaced
// by the sweep's conflict error, with an EventRotationFailed alert dispatched about a
// rotation that had actually succeeded. The user saw a red error on the entry they had
// just correctly rotated.
//
// The property: N appends produce N entries, whatever order they land in. Asserted by
// writing from a STALE snapshot deliberately, which is exactly what the sweep does.
func TestConcurrentRotationLogAppendsDoNotLoseEachOther(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	deps := rotationDeps{queries: queries, vault: h}

	owner := mustUser(t, queries, "lograce@example.com", "user", "")
	const id = "log-race-entry"
	mustEntry(t, h, queries, id, owner, "Race", "V0")

	// Snapshot the log the way the sweep does, BEFORE anything is appended.
	stale, err := queries.GetVaultEntryRotationLog(ctx, id)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// A first append lands (think: the user's manual rotation completing).
	appendRotationLog(ctx, deps, id, "Race", RotationLogEntry{Timestamp: "t1", Status: "success", Method: "manual"})

	// Now the holder of the stale snapshot appends (the sweep, minutes later). With a
	// snapshot-based write this overwrites the first entry; with the CAS it must
	// append on top of it.
	appendRotationLog(ctx, deps, id, "Race", RotationLogEntry{Timestamp: "t2", Status: "partial", Method: "auto"})

	row, err := queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	var entries []RotationLogEntry
	if err := json.Unmarshal([]byte(row.RotationLog.String), &entries); err != nil {
		t.Fatalf("unmarshal log %q: %v", row.RotationLog.String, err)
	}

	if len(entries) != 2 {
		t.Fatalf("rotation_log holds %d entries, want 2 (%s)\n"+
			"An append from a stale snapshot overwrote an earlier one. On the real paths that "+
			"erases a successful manual rotation from history and replaces it with the sweep's "+
			"conflict error.", len(entries), row.RotationLog.String)
	}
	// Order matters for a history view: the later append must be last.
	if entries[0].Timestamp != "t1" || entries[1].Timestamp != "t2" {
		t.Errorf("entries are out of order: got %q then %q, want t1 then t2",
			entries[0].Timestamp, entries[1].Timestamp)
	}
	// And the stale snapshot must not have been used as the base.
	if stale != "" && len(entries) == 1 {
		t.Errorf("the stale snapshot %q was used as the base", stale)
	}
}

// TestRotationLogAppendKeepsTheTrim guards the other direction.
//
// AppendRotationLog caps the array at 50. Moving the append under a CAS could easily
// have dropped that, turning an audit column into unbounded growth on a hot entry.
func TestRotationLogAppendKeepsTheTrim(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	deps := rotationDeps{queries: queries, vault: h}

	owner := mustUser(t, queries, "logtrim@example.com", "user", "")
	const id = "log-trim-entry"
	mustEntry(t, h, queries, id, owner, "Trim", "V0")

	for i := 0; i < 60; i++ {
		appendRotationLog(ctx, deps, id, "Trim", RotationLogEntry{
			Timestamp: "t", Status: "success", Method: "auto",
		})
	}

	row, err := queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	var entries []RotationLogEntry
	if err := json.Unmarshal([]byte(row.RotationLog.String), &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 50 {
		t.Errorf("rotation_log holds %d entries after 60 appends, want the 50-entry cap; "+
			"an audit column that grows without bound is its own problem", len(entries))
	}
}

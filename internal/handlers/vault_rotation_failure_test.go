package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestRecordRotationFailureLeavesEvidenceEverywhere locks the fix for the
// invisible-rotation-failure finding.
//
// The auto sweep had six failure paths that each recorded something different.
// Four wrote NOTHING (unknown provider, encrypt failure, persist failure, and
// the sweep-level query error), one wrote only last_rotation_error, one wrote
// last_rotation_error plus rotation_log. None wrote an activity row and none
// dispatched a notification, which is why alerts.EventRotationFailed was
// defined, documented and default-enabled while firing from nowhere.
//
// The invariant: after a failure, an operator can find out from any of the
// three surfaces they actually look at, not just the container log.
func TestRecordRotationFailureLeavesEvidenceEverywhere(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "owner@example.com", "user", "")
	const entryID = "entry-rot-fail"
	mustEntry(t, h, queries, entryID, owner, "Prod DB password", "s3cr3t")

	recordRotationFailure(ctx, queries, h, entryID, "Prod DB password", "acme", "", rotFailEncrypt, "auto", nil)

	// 1. last_rotation_error, which the vault list and RotationManager read.
	meta, err := queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		t.Fatalf("get entry meta: %v", err)
	}
	if meta.LastRotationError.String != rotFailEncrypt {
		t.Fatalf("last_rotation_error = %q, want %q", meta.LastRotationError.String, rotFailEncrypt)
	}

	// 2. rotation_log keeps the attempt in history (only the rotation query
	// selects that column).
	row, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("get entry for rotation: %v", err)
	}
	var logEntries []RotationLogEntry
	if err := json.Unmarshal([]byte(row.RotationLog.String), &logEntries); err != nil {
		t.Fatalf("rotation_log is not valid JSON (%q): %v", row.RotationLog.String, err)
	}
	if len(logEntries) != 1 {
		t.Fatalf("expected 1 rotation_log entry, got %d", len(logEntries))
	}
	if logEntries[0].Status != "error" {
		t.Fatalf("rotation_log status = %q, want \"error\"", logEntries[0].Status)
	}
	if logEntries[0].Provider != "acme" || logEntries[0].Method != "auto" {
		t.Fatalf("rotation_log lost provider/method: %+v", logEntries[0])
	}
	if logEntries[0].Timestamp == "" {
		t.Fatal("rotation_log entry has no timestamp, history is unorderable")
	}

	// 3. activity_log, so it reaches the Activity page.
	entries, err := queries.ListActivityEntries(ctx, db.ListActivityEntriesParams{Limit: 50, Offset: 0})
	if err != nil {
		t.Fatalf("list activity: %v", err)
	}
	var found *db.ListActivityEntriesRow
	for i := range entries {
		if entries[i].Action == "vault.rotation_failed" {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no vault.rotation_failed activity row: the failure is invisible on the Activity page")
	}
	if !strings.Contains(found.Detail.String, "Prod DB password") {
		t.Fatalf("activity detail does not name the secret: %q", found.Detail.String)
	}

	// The secret VALUE must never appear on any surface.
	for _, surface := range []string{meta.LastRotationError.String, row.RotationLog.String, found.Detail.String} {
		if strings.Contains(surface, "s3cr3t") {
			t.Fatalf("SECRET VALUE LEAKED into a rotation-failure surface: %q", surface)
		}
	}

	// A second failure appends rather than replacing, so history survives. This
	// one is the manual path, so it records the acting user and method "manual".
	recordRotationFailure(ctx, queries, h, entryID, "Prod DB password", "acme", row.RotationLog.String, rotFailProvider, "manual", &owner)
	row2, err := queries.GetVaultEntryForRotation(ctx, entryID)
	if err != nil {
		t.Fatalf("get entry for rotation after second failure: %v", err)
	}
	var logEntries2 []RotationLogEntry
	if err := json.Unmarshal([]byte(row2.RotationLog.String), &logEntries2); err != nil {
		t.Fatalf("rotation_log invalid after second failure: %v", err)
	}
	if len(logEntries2) != 2 {
		t.Fatalf("second failure did not append, got %d entries", len(logEntries2))
	}
	// The manual path must be distinguishable from the scheduler in history,
	// otherwise "did a person do this or did the sweep?" is unanswerable.
	if logEntries2[1].Method != "manual" {
		t.Fatalf("manual rotation recorded method %q, want \"manual\"", logEntries2[1].Method)
	}
	if logEntries2[0].Method != "auto" {
		t.Fatalf("the earlier scheduled failure lost its method: %q", logEntries2[0].Method)
	}
	// And the manual failure must attribute the acting user, not show as system.
	acts, err := queries.ListActivityEntries(ctx, db.ListActivityEntriesParams{Limit: 50, Offset: 0})
	if err != nil {
		t.Fatalf("list activity: %v", err)
	}
	var attributed bool
	for _, a := range acts {
		if a.Action == "vault.rotation_failed" && a.UserID.Valid && a.UserID.String == owner {
			attributed = true
		}
	}
	if !attributed {
		t.Fatal("manual rotation failure was not attributed to the acting user")
	}
	meta2, err := queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		t.Fatalf("get entry meta after second failure: %v", err)
	}
	if meta2.LastRotationError.String != rotFailProvider {
		t.Fatalf("last_rotation_error not updated to the newest reason: %q", meta2.LastRotationError.String)
	}
}

// TestRotationFailureReasonsAreStructural guards the strings themselves.
//
// They are the only thing an operator sees, and they travel further than most
// error text: into last_rotation_error, into rotation_log, into the activity
// detail rendered verbatim on the Activity page, and out to notification
// channels off-box. So they must describe the failure class and never carry a
// value, a URL, or a raw error.
func TestRotationFailureReasonsAreStructural(t *testing.T) {
	reasons := map[string]string{
		"unknown provider": rotFailUnknownProvider,
		"decrypt":          rotFailDecrypt,
		"provider":         rotFailProvider,
		"encrypt":          rotFailEncrypt,
		"persist":          rotFailPersist,
	}
	for name, reason := range reasons {
		if reason == "" {
			t.Fatalf("%s: empty reason tells an operator nothing", name)
		}
		// No URLs, no scheme, no host, no bracketed error dumps.
		for _, banned := range []string{"http://", "https://", "://", "0x"} {
			if strings.Contains(reason, banned) {
				t.Fatalf("%s: reason looks like it carries a location or dump: %q", name, reason)
			}
		}
		// Anything that gave up should point the operator at the real detail.
		if !strings.Contains(reason, "server logs") && !strings.Contains(reason, "not registered") {
			t.Fatalf("%s: reason neither self-explanatory nor pointing at the logs: %q", name, reason)
		}
	}

	// The two "key may already exist upstream" cases must SAY so, because that
	// is the difference between a retry and a manual reconcile at the provider.
	for _, r := range []string{rotFailEncrypt, rotFailPersist} {
		if !strings.Contains(r, "already issued a replacement key") {
			t.Fatalf("reason hides the out-of-sync hazard, operator will not know to reconcile: %q", r)
		}
	}
}

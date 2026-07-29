package handlers

import (
	"testing"
	"time"
)

func rotStrPtr(s string) *string { return &s }
func rotIntP(i int) *int         { return &i }

// The exact state the Cloudflare entry was in on 2026-07-27: recently stamped
// (so age says fresh) but auto-rotation had failed 50 consecutive hourly runs.
// Both the UI badge and the MCP resource reported `fresh`, which is how a dead
// rotation went unnoticed. A recorded failure must win over a healthy age.
func TestRotationStatusFailingRotationIsNeverFresh(t *testing.T) {
	// last rotated "now", 90 day interval -> age alone would say fresh
	got := computeRotationStatus(rotIntP(90), nil, rotStrPtr(rotNowStamp()), nil, rotStrPtr("identify token: token verification failed"))
	if got == "fresh" {
		t.Fatal("an entry with a recorded rotation error must never report fresh")
	}
	if got != "error" {
		t.Errorf("status = %q, want error", got)
	}
}

// A manual value save stamps last_rotated_at (UpdateVaultEntryValue), so a
// fresh timestamp is not evidence rotation works. Same assertion from the other
// direction: no error means age decides as before.
func TestRotationStatusNoErrorFallsBackToAge(t *testing.T) {
	if got := computeRotationStatus(rotIntP(90), nil, rotStrPtr(rotNowStamp()), nil, nil); got != "fresh" {
		t.Errorf("no error + recent = %q, want fresh", got)
	}
	if got := computeRotationStatus(rotIntP(90), nil, rotStrPtr(rotNowStamp()), nil, rotStrPtr("")); got != "fresh" {
		t.Errorf("empty error string must be treated as no error, got %q", got)
	}
	if got := computeRotationStatus(rotIntP(90), nil, rotStrPtr(rotNowStamp()), nil, rotStrPtr("   ")); got != "fresh" {
		t.Errorf("whitespace-only error must be treated as no error, got %q", got)
	}
}

// An already-expired credential is the worse fact, so expiry still outranks a
// rotation failure.
func TestRotationStatusExpiredOutranksError(t *testing.T) {
	got := computeRotationStatus(rotIntP(90), rotStrPtr("2020-01-01 00:00:00"), rotStrPtr(rotNowStamp()), nil, rotStrPtr("boom"))
	if got != "expired" {
		t.Errorf("status = %q, want expired to outrank error", got)
	}
}

// A failing rotation must surface even when there is no rotation interval set,
// which previously short-circuited straight to fresh.
func TestRotationStatusErrorSurfacesWithoutInterval(t *testing.T) {
	if got := computeRotationStatus(nil, nil, rotStrPtr(rotNowStamp()), nil, rotStrPtr("boom")); got == "fresh" {
		t.Error("no interval must not mask a recorded rotation failure")
	}
}

// The layout computeRotationStatus parses first.
func rotNowStamp() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}

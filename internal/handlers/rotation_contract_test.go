package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
)

// Rotation behaviour matrix.
//
// This file exists because thirteen audit rounds found the same feature broken
// three times, and each time the test written alongside the fix covered exactly
// the path just fixed:
//
//   round 11: asserted "a conflict is DETECTED". A compare-and-swap that ALWAYS
//             fails satisfies that perfectly, and that is what shipped: every
//             scheduled rotation reported a conflict and persisted nothing.
//   round 12: fixed the sweep, tested the sweep. The manual handler still bound
//             an empty token, so manual rotation 404'd on every entry.
//   round 13: fixed the manual handler using a PROVIDER-LESS entry, so the test
//             never entered the branch where the handler's own provider_meta
//             write invalidates its own swap. Provider-backed rotation stayed
//             100% dead.
//
// Three rounds, three cells of the same two-by-two, three green suites. The
// fix for that is not a better assertion, it is asserting the same
// POST-CONDITIONS across both execution paths and every input class, so a
// divergence fails on the commit that introduces it.
//
// The shared checker deliberately asserts what the FEATURE promises (the stored
// value changed, no error was recorded, the log gained an entry) rather than
// what any particular fix did.

// rotationOutcome is what both paths must agree on.
type rotationOutcome struct {
	valueChanged  bool   // the stored ciphertext now decrypts to something new
	errorRecorded bool   // last_rotation_error is non-empty
	logStatus     string // status of the newest rotation_log entry, "" to skip
}

type rotationCase struct {
	name string
	// provider configures the entry. "" means a local secret with no provider.
	provider string
	// sweepApplicable is false when the due query structurally cannot select
	// this entry. The due query requires auto_rotate=1 AND provider!='' AND
	// rotation_interval_days>0, so a provider-less entry is manual-only. Being
	// explicit about this is the point: a symmetric cross product would be a
	// lie, and pretending otherwise is how a matrix gives false confidence.
	sweepApplicable bool
	want            rotationOutcome
	// wantManualStatus is the HTTP status the manual path must return. The sweep
	// has no HTTP surface, which is why this is not in rotationOutcome.
	wantManualStatus int
}

func rotationCases() []rotationCase {
	return []rotationCase{
		{
			name:             "local secret, no provider",
			provider:         "",
			sweepApplicable:  false,
			wantManualStatus: http.StatusOK,
			want:             rotationOutcome{valueChanged: true, errorRecorded: false, logStatus: "success"},
		},
		{
			name:             "auto-rotating provider",
			provider:         "shared-secret",
			sweepApplicable:  true,
			wantManualStatus: http.StatusOK,
			want:             rotationOutcome{valueChanged: true, errorRecorded: false, logStatus: "success"},
		},
		{
			name:             "auto-rotating generated key",
			provider:         "generated-key-32",
			sweepApplicable:  true,
			wantManualStatus: http.StatusOK,
			want:             rotationOutcome{valueChanged: true, errorRecorded: false, logStatus: "success"},
		},
	}
}

// TestRotationContract drives every case through BOTH paths and applies the
// same post-conditions to each.
func TestRotationContract(t *testing.T) {
	for _, tc := range rotationCases() {
		tc := tc
		t.Run("manual/"+tc.name, func(t *testing.T) {
			env := newRotationEnv(t, tc.provider)
			rec := env.driveManual(t)
			if rec.Code != tc.wantManualStatus {
				t.Fatalf("manual rotate returned %d, want %d: %s",
					rec.Code, tc.wantManualStatus, rec.Body.String())
			}
			env.assertOutcome(t, "manual", tc.want)
		})

		t.Run("sweep/"+tc.name, func(t *testing.T) {
			if !tc.sweepApplicable {
				t.Skip("the due query cannot select this entry shape (needs provider + auto_rotate + interval)")
			}
			env := newRotationEnv(t, tc.provider)
			env.driveSweep(t)
			env.assertOutcome(t, "sweep", tc.want)
		})
	}
}

// rotationEnv is one seeded entry plus the handles both drivers need.
type rotationEnv struct {
	h       *VaultHandler
	queries *db.Queries
	owner   string
	entryID string
	before  string // plaintext before rotation
}

const rotationTestPassword = "CorrectHorseBatteryStaple1!"

func newRotationEnv(t *testing.T, provider string) *rotationEnv {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, fmt.Sprintf("rot-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	entryID := "rot-" + randomHex(6)
	const before = "ORIGINAL-VALUE"
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, before)

	if provider != "" {
		if err := queries.UpdateVaultEntryProvider(ctx, db.UpdateVaultEntryProviderParams{
			Provider:     toNullString(provider),
			ProviderMeta: toNullString("{}"),
			AutoRotate:   sql.NullInt64{Int64: 1, Valid: true},
			ID:           entryID,
		}); err != nil {
			t.Fatalf("set provider %q: %v", provider, err)
		}
		if err := queries.UpdateVaultEntryRotationInterval(ctx, db.UpdateVaultEntryRotationIntervalParams{
			RotationIntervalDays: sql.NullInt64{Int64: 1, Valid: true}, ID: entryID,
		}); err != nil {
			t.Fatalf("set interval: %v", err)
		}
	}
	// Age the row so it is due AND so updated_at differs from the snapshot the
	// handler is about to take. Without the ageing, a handler that bumps
	// updated_at itself can land in the same second and pass for the wrong
	// reason, which is exactly how round 13 hid.
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET last_rotated_at = datetime('now','-30 days'),
		 updated_at = datetime('now','-1 hour') WHERE id = ?`, entryID); err != nil {
		t.Fatalf("age entry: %v", err)
	}

	return &rotationEnv{h: h, queries: queries, owner: owner, entryID: entryID, before: before}
}

func (e *rotationEnv) driveManual(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	e.h.Rotate(rec, vaultAuthzRequest("POST", "/api/vault/"+e.entryID+"/rotate",
		e.owner, "user", e.entryID, `{"password":"`+rotationTestPassword+`"}`))
	e.h.WaitForDelivery(5 * 1e9) // 5s, drains the detached delivery goroutine
	return rec
}

func (e *rotationEnv) driveSweep(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	due, err := e.queries.ListVaultEntriesNeedingRotation(ctx)
	if err != nil {
		t.Fatalf("due list: %v", err)
	}
	var row *db.ListVaultEntriesNeedingRotationRow
	for i := range due {
		if due[i].ID == e.entryID {
			row = &due[i]
			break
		}
	}
	if row == nil {
		// Fail loudly. A sweep driver that silently rotates nothing would make
		// every post-condition pass vacuously.
		t.Fatalf("ABORT: entry %s is not in the due list (%d due), so the sweep would be a no-op "+
			"and this case would assert nothing", e.entryID, len(due))
	}
	rotateOneEntry(ctx, e.queries, e.h, *row)
}

// assertOutcome applies the SAME post-conditions regardless of which path ran.
func (e *rotationEnv) assertOutcome(t *testing.T, path string, want rotationOutcome) {
	t.Helper()
	ctx := context.Background()

	row, err := e.queries.GetVaultEntryForRotation(ctx, e.entryID)
	if err != nil {
		t.Fatalf("%s: reload: %v", path, err)
	}
	plain, err := e.h.DecryptValue(row.EncryptedValue, row.Nonce, 2)
	if err != nil {
		t.Fatalf("%s: decrypt: %v", path, err)
	}
	changed := string(plain) != e.before
	if changed != want.valueChanged {
		t.Errorf("%s: stored value changed=%v, want %v (still %q)", path, changed, want.valueChanged, string(plain))
	}

	meta, err := e.queries.GetVaultEntryMeta(ctx, e.entryID)
	if err != nil {
		t.Fatalf("%s: meta: %v", path, err)
	}
	recorded := strings.TrimSpace(meta.LastRotationError.String) != ""
	if recorded != want.errorRecorded {
		t.Errorf("%s: last_rotation_error set=%v, want %v (%q)",
			path, recorded, want.errorRecorded, meta.LastRotationError.String)
	}

	if want.logStatus != "" {
		var entries []RotationLogEntry
		_ = json.Unmarshal([]byte(row.RotationLog.String), &entries)
		if len(entries) == 0 {
			t.Errorf("%s: rotation_log is empty, want a %q entry", path, want.logStatus)
		} else if got := entries[len(entries)-1].Status; got != want.logStatus {
			t.Errorf("%s: newest rotation_log status = %q, want %q", path, got, want.logStatus)
		}
	}
}

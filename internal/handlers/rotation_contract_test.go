package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/brightinteraction/trustissues/internal/alerts"
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
	// alertWanted is whether a rotation alert must have been dispatched.
	//
	// Not folded into errorRecorded, because the revoke-failure bug produced
	// THREE independent symptoms (error wiped, log said success, no alert) and a
	// test asserting only the database would have caught two of them while
	// leaving operators un-notified.
	alertWanted bool
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
		{
			// A provider name this build does not know.
			//
			// "internal:postgres" is not hypothetical: trustissues is a fork of
			// dockyard and the fork DELETED the five internal:* providers (see
			// cred_rotation.go). Nothing validates provider against the registry
			// when an entry is written, so a database carried over from dockyard
			// holds entries in exactly this state.
			//
			// The secret is a REAL credential that only the upstream system can
			// rotate. Generating 32 bytes locally does not rotate it: it discards
			// the real credential, stores something that authenticates nowhere,
			// and leaves the live one in place. Both paths must refuse.
			name:             "provider not in this build's registry",
			provider:         "internal:postgres",
			sweepApplicable:  true,
			wantManualStatus: http.StatusConflict,
			want:             rotationOutcome{valueChanged: false, errorRecorded: true, logStatus: "error"},
		},
		{
			// Reminder-only: the provider exists but cannot rotate itself. Same
			// hazard as above, reached by a different branch, which is why it gets
			// its own row rather than being folded in.
			name:             "reminder-only provider",
			provider:         "github",
			sweepApplicable:  true,
			wantManualStatus: http.StatusConflict,
			want:             rotationOutcome{valueChanged: false, errorRecorded: false, logStatus: "reminder"},
		},
		{
			// The new value IS stored, but the predecessor key could not be
			// destroyed upstream, so both keys are still live.
			//
			// The rotation is therefore NOT a success, and this is the ordinary
			// happy path plus one failed HTTP call, not a rare condition: resend,
			// sendgrid and neon all defer a DELETE for the old key, and that DELETE
			// authenticates with the NEW key, which providers routinely reject
			// until permissions propagate.
			//
			// Manual recorded the failure and then overwrote it with success, with
			// no alert. The operator most likely to hit this is the one rotating a
			// key they believe is compromised.
			name:             "old key revoke fails, predecessor still live",
			provider:         revokeFailProvider,
			sweepApplicable:  true,
			wantManualStatus: http.StatusOK,
			want: rotationOutcome{
				valueChanged: true, errorRecorded: true, logStatus: "partial", alertWanted: true,
			},
		},
	}
}

// revokeFailProvider is a registered fake that rotates successfully and then
// defers a revoke that cannot succeed.
const revokeFailProvider = "test-revoke-fails"

// unreachableRevokeURL is refused by providerHTTP at DIAL time (the guarded
// client blocks private ranges), which makes the failure deterministic and needs
// no network and no httptest server. Precedent: TestDeferredRevokeFailureIsNeverSilent.
const unreachableRevokeURL = "http://10.0.0.1/keys/old"

type revokeFailingProvider struct{}

func (p *revokeFailingProvider) Name() string                            { return revokeFailProvider }
func (p *revokeFailingProvider) CanAutoRotate() bool                     { return true }
func (p *revokeFailingProvider) DashboardURL(_ map[string]string) string { return "" }

func (p *revokeFailingProvider) Validate(_ context.Context, _ string, _ map[string]string) (bool, error) {
	return true, nil
}

func (p *revokeFailingProvider) Rotate(_ context.Context, _ string, meta map[string]string) (string, error) {
	// Mint a successor, then register the revoke of the predecessor exactly the
	// way resend/sendgrid/neon do.
	meta["key_id"] = "new-" + randomHex(4)
	deferRevokeOldProviderKey(meta, "DELETE", unreachableRevokeURL)
	return "ROTATED-" + randomHex(8), nil
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
	alerts  *alertRecorder
}

// alertRecorder counts rotation alerts. Pointer-shared with the swapped
// dispatchRotationAlert so both drivers observe the same counter, including the
// manual path's detached delivery goroutine.
type alertRecorder struct {
	mu     sync.Mutex
	events []string
}

func (a *alertRecorder) record(detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, detail)
}

func (a *alertRecorder) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

// installRotationFakes registers the test provider and swaps the alert dispatcher,
// restoring both. The registry is package-global, so the cleanup is not optional:
// TestProviderRegistryReducedSet walks every entry and would fail on a leaked one.
func installRotationFakes(t *testing.T) *alertRecorder {
	t.Helper()

	ProviderRegistry[revokeFailProvider] = &revokeFailingProvider{}
	providerLabels[revokeFailProvider] = "Revoke-failing test provider"
	t.Cleanup(func() {
		delete(ProviderRegistry, revokeFailProvider)
		delete(providerLabels, revokeFailProvider)
	})

	rec := &alertRecorder{}
	prev := dispatchRotationAlert
	dispatchRotationAlert = func(_ context.Context, _ *db.Queries, _ alerts.ConfigDecrypter, _, detail string) {
		rec.record(detail)
	}
	t.Cleanup(func() { dispatchRotationAlert = prev })
	return rec
}

const rotationTestPassword = "CorrectHorseBatteryStaple1!"

func newRotationEnv(t *testing.T, provider string) *rotationEnv {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	rec := installRotationFakes(t)

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

	return &rotationEnv{h: h, queries: queries, owner: owner, entryID: entryID, before: before, alerts: rec}
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

	if got := e.alerts.count() > 0; got != want.alertWanted {
		t.Errorf("%s: rotation alert dispatched=%v, want %v (events: %v)\n"+
			"An operator who is not told is an operator who does not act. This is a "+
			"separate symptom from the database record, deliberately.",
			path, got, want.alertWanted, e.alerts.events)
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

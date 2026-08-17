package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
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
	// metaWrites is how many times provider_meta may be written, -1 to skip.
	//
	// Asserting the END STATE is useless here: the buggy manual path wrote meta
	// twice and the second write REMOVED the transient markers, so a post-rotation
	// read is clean with the bug fully present. Only counting the writes, and
	// inspecting each version, can see it.
	metaWrites int
	// metaWriteKeepsRevokeMarkers is whether the ONE write above is required to
	// still carry pending_revoke_method/url/auth, for a case where the deferred
	// revoke genuinely failed.
	//
	// performPendingRevoke used to strip those markers unconditionally, before the
	// revoke attempt even started, so a FAILED attempt's write came out looking as
	// clean as a successful one: last_revoke_error was set, but the coordinates a
	// retry would need to act on were already gone, with nothing left recording
	// what to revoke or how. Fixed by clearing the markers only once the attempt is
	// a confirmed success. This is distinct from d226c7306's crash-between-two-
	// writes bug (a stale write from an aliased map, now structurally impossible
	// since there is only one write): this field is about the one write a genuine
	// revoke failure produces, which must show the markers, not hide them.
	metaWriteKeepsRevokeMarkers bool
	// rowDeleted means the entry is gone by assert time, so the DB-derived
	// post-conditions cannot be read. Only the out-of-band ones (the alert) are
	// checked, and the alert assertion is what keeps the row from being vacuous.
	rowDeleted bool
	// logMethod is the Method the newest rotation_log entry must carry, "" to skip.
	//
	// Asserted because a user-clicked rotation of a provider-backed entry was
	// recorded as "auto": the audit trail attributed a human action to the
	// scheduler, and the failure path produced "Auto-rotation failed for X" while
	// simultaneously naming the acting user. "auto" vs "manual" answers WHO
	// TRIGGERED THIS, which is the only question an audit trail is asked about a
	// secret.
	logMethod string
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
	// failPersist injects a failure into the ONE write that stores the rotated
	// value, so the branch that reports a persist error can be reached without a
	// broken CAS token (a NULL updated_at would instead make the due query fail
	// its scan and abort the sweep driver, testing nothing).
	failPersist bool
	// revokeSucceeds points the fake provider's deferred revoke at a sink that
	// answers 200, so the rotation completes CLEANLY with a real revoke behind
	// it.
	//
	// It exists to give the "no version may carry the markers" branch of the
	// metaWrites assertion a live subject. Every other case that sets
	// metaWrites > 0 also sets metaWriteKeepsRevokeMarkers, so that branch was
	// unreachable: a table-driven forbid gated behind an opt-out flag that every
	// qualifying case sets is dead code, and the assertion it guards had never
	// once run.
	revokeSucceeds bool
	// callerDiesAfterCAS cancels the caller's context at the moment the rotation
	// has already committed. Everything after that point must still complete: the
	// revoke, the meta write, and the outcome record.
	callerDiesAfterCAS bool
	// deleteDuringPostCAS removes the row inside the post-commit window, which is
	// what makes the response fetch fail on a rotation that already happened.
	deleteDuringPostCAS bool
	// corruptTargets makes rotation_targets undecryptable, which used to read as
	// "no targets configured" and produce a clean success with no delivery.
	corruptTargets bool
	// notifyTarget adds a "Notify only" delivery target, whose entire purpose is to
	// tell the operator so they can update a consumer by hand.
	notifyTarget bool
	want         rotationOutcome
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
			// logMethod is per-driver, so it is set by the driver below rather than
			// here: the same entry is "manual" when a person clicks and "auto" when
			// the sweep picks it up. That is the one field the two paths MUST differ
			// on, which is why it cannot be a shared constant.
			want: rotationOutcome{valueChanged: true, errorRecorded: false, logStatus: "success"},
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
			// alertWanted because an entry that can NEVER rotate is exactly what an
			// operator has to be told about: nothing else will ever mention it, and
			// the secret sits there going stale forever.
			want: rotationOutcome{valueChanged: false, errorRecorded: true, logStatus: "error", alertWanted: true},
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
			// The rotated value cannot be written at all.
			//
			// A provider-backed entry has already minted its successor upstream by
			// the time this fails, and the handler discards the meta holding its key
			// id, so the new key exists at the provider with nobody holding it. The
			// sweep records rotFailPersist; manual returned 500 and recorded nothing,
			// leaving the entry looking untouched in the UI.
			name:             "the rotated value cannot be written",
			provider:         "shared-secret",
			sweepApplicable:  true,
			failPersist:      true,
			wantManualStatus: http.StatusInternalServerError,
			want: rotationOutcome{
				valueChanged: false, errorRecorded: true, logStatus: "error", alertWanted: true,
			},
		},
		{
			// The caller goes away the instant the value is committed.
			//
			// A closed tab, a client timeout or a proxy hang-up. The rotation has
			// already happened, so the bookkeeping is not optional: without it the
			// entry reads as freshly rotated and clean while the old key is still
			// live upstream and the successor's id was never stored.
			//
			// Same assertions as the revoke-failure row, because the revoke here
			// fails too (dead context, then an unreachable host). What this row adds
			// is that a dead CALLER changes none of it.
			name:               "caller goes away right after the value is committed",
			provider:           revokeFailProvider,
			sweepApplicable:    true,
			callerDiesAfterCAS: true,
			wantManualStatus:   http.StatusOK,
			want: rotationOutcome{
				valueChanged: true, errorRecorded: true, logStatus: "partial", alertWanted: true,
				metaWrites: 1, metaWriteKeepsRevokeMarkers: true,
			},
		},
		{
			// A "Notify only" target must actually notify.
			//
			// It transmits nothing, so the delivery loop skips it, and its comment
			// claimed the caller handled the notification. No caller did, and the
			// alerts catalogue had no success event at all, so the one target type
			// whose entire purpose is notification never notified anybody: the
			// credential rotated, the predecessor was revoked, and the person who had
			// asked to be told heard nothing.
			name:             "notify-only target",
			provider:         "shared-secret",
			sweepApplicable:  true,
			notifyTarget:     true,
			wantManualStatus: http.StatusOK,
			want: rotationOutcome{
				valueChanged: true, errorRecorded: false, logStatus: "success", alertWanted: true,
			},
		},
		{
			// rotation_targets will not decrypt.
			//
			// The value IS rotated and the predecessor IS revoked, so this is a
			// PARTIAL rotation: every configured webhook and Actions secret still
			// holds a credential that no longer works. It used to record a clean
			// success with last_rotation_error NULL and no alert, because an
			// undecryptable column degraded to "[]".
			name:             "rotation_targets cannot be decrypted",
			provider:         "shared-secret",
			sweepApplicable:  true,
			corruptTargets:   true,
			wantManualStatus: http.StatusOK,
			want: rotationOutcome{
				valueChanged: true, errorRecorded: true, logStatus: "partial", alertWanted: true,
			},
		},
		{
			// The entry is deleted inside the post-commit window.
			//
			// The value is already rotated and the predecessor key is already
			// destroyed upstream, so the outcome MUST still be recorded: the
			// response body is cosmetic and its absence is not a reason to skip
			// delivery, the log, the error field and the alert. Delete needs no
			// re-auth, so a second tab or another collection editor reaches this.
			name:                "entry deleted inside the post-commit window",
			provider:            revokeFailProvider,
			sweepApplicable:     false,
			deleteDuringPostCAS: true,
			wantManualStatus:    http.StatusOK,
			want: rotationOutcome{
				// valueChanged and the log are unreadable once the row is gone, so the
				// assertion is the ALERT: the operator must be told that a rotation
				// committed and could not be finished. Before the fix the handler
				// returned 500 from the response fetch and dispatched nothing.
				rowDeleted: true, alertWanted: true,
			},
		},
		{
			// The new value IS stored, but the predecessor key could not be
			// destroyed upstream, so both keys are still live.
			//
			// The rotation is therefore NOT a success, and this is the ordinary happy
			// path plus one failed HTTP call, not a rare condition: resend, sendgrid
			// and neon all defer a DELETE for the old key, and that DELETE
			// authenticates with the NEW key, which providers routinely reject until
			// permissions propagate.
			//
			// Manual recorded the failure and then overwrote it with success, with no
			// alert. The operator most likely to hit this is the one rotating a key
			// they believe is compromised.
			name:             "old key revoke fails, predecessor still live",
			provider:         revokeFailProvider,
			sweepApplicable:  true,
			wantManualStatus: http.StatusOK,
			want: rotationOutcome{
				valueChanged: true, errorRecorded: true, logStatus: "partial", alertWanted: true,
				metaWrites: 1, metaWriteKeepsRevokeMarkers: true,
			},
		},
		{
			// THE LIVE SUBJECT FOR THE FORBID BRANCH.
			//
			// The same deferring provider as the two rows above, with a revoke
			// that actually succeeds. It is the only case in this table that
			// asserts the markers are ABSENT from the single write, which is
			// what vault_providers.go documents and what nothing checked: both
			// other metaWrites rows are revoke FAILURES and set
			// metaWriteKeepsRevokeMarkers, so the branch forbidding a persisted
			// marker had no case that entered it.
			//
			// It is also the clean-path counterpart of the deferral itself: one
			// write, no markers in it, no error, no alert.
			name:             "old key revoke succeeds, nothing transient is persisted",
			provider:         revokeFailProvider,
			sweepApplicable:  true,
			revokeSucceeds:   true,
			wantManualStatus: http.StatusOK,
			want: rotationOutcome{
				valueChanged: true, errorRecorded: false, logStatus: "success",
				metaWrites: 1, metaWriteKeepsRevokeMarkers: false,
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

// revokeTargetURL is where the fake provider aims its deferred revoke. Rows that
// need to observe the revoke (rather than just have it fail) point this at an
// httptest sink. Reset by installRotationFakes.
var revokeTargetURL = unreachableRevokeURL

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
	deferRevokeOldProviderKey(meta, "DELETE", revokeTargetURL, revokeAuthBearer)
	return "ROTATED-" + randomHex(8), nil
}

// TestRotationContract drives every case through BOTH paths and applies the
// same post-conditions to each.
func TestRotationContract(t *testing.T) {
	for _, tc := range rotationCases() {
		tc := tc
		t.Run("manual/"+tc.name, func(t *testing.T) {
			// The one post-condition that MUST differ between the paths, so it is
			// derived from the driver rather than written in the case: the same entry
			// is "manual" when a person clicks it and "auto" when the sweep takes it.
			want := tc.want
			if want.logStatus != "" {
				want.logMethod = "manual"
			}
			env := newRotationEnv(t, tc)
			rec := env.driveManual(t, tc)
			if rec.Code != tc.wantManualStatus {
				t.Fatalf("manual rotate returned %d, want %d: %s",
					rec.Code, tc.wantManualStatus, rec.Body.String())
			}
			env.assertOutcome(t, "manual", want)
		})

		t.Run("sweep/"+tc.name, func(t *testing.T) {
			want := tc.want
			if want.logStatus != "" {
				want.logMethod = "auto"
			}
			if !tc.sweepApplicable {
				t.Skip("the due query cannot select this entry shape (needs provider + auto_rotate + interval)")
			}
			env := newRotationEnv(t, tc)
			env.driveSweep(t, tc)
			env.assertOutcome(t, "sweep", want)
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
	// killCaller is set for the callerDiesAfterCAS row. The httptest revoke sink
	// invokes it, which cancels the request context at a point where the rotation
	// has already committed.
	killCaller func()
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

	revokeTargetURL = unreachableRevokeURL
	t.Cleanup(func() { revokeTargetURL = unreachableRevokeURL })

	ProviderRegistry[revokeFailProvider] = &revokeFailingProvider{}
	providerLabels[revokeFailProvider] = "Revoke-failing test provider"
	// A registered provider declares where its secret may go, and a test provider
	// is not exempt: providerDo refuses an undeclared host, which is exactly the
	// fail-closed posture that makes a real provider added without a declaration
	// unable to reach the network. Resolved through the live revokeTargetURL so a
	// case that points the revoke at an httptest sink is covered without this
	// hardcoding a port.
	providerEgress[revokeFailProvider] = providerEgressDecl{
		hosts: func(map[string]string) []string {
			u, err := url.Parse(revokeTargetURL)
			if err != nil || u.Hostname() == "" {
				return nil
			}
			return []string{u.Hostname()}
		},
		why: "test provider: its deferred revoke targets whatever revokeTargetURL names",
	}
	t.Cleanup(func() {
		delete(ProviderRegistry, revokeFailProvider)
		delete(providerLabels, revokeFailProvider)
		delete(providerEgress, revokeFailProvider)
	})

	// BOTH dispatchers. dispatchRotationAlert fires EventRotationPartial (a
	// rotation that stored its value but was not fully clean); recordRotationFailure
	// goes through dispatchRotationFailure for EventRotationFailed. Swapping one and
	// not the other reports "nobody was notified" about a path that did notify, which
	// is a false finding pointing at working code.
	rec := &alertRecorder{}
	prevAlert, prevFail, prevOK := dispatchRotationAlert, dispatchRotationFailure, dispatchRotationSuccess
	dispatchRotationAlert = func(_ context.Context, _ *db.Queries, _ alerts.ConfigDecrypter, _, detail string) {
		rec.record("partial: " + detail)
	}
	dispatchRotationFailure = func(_ context.Context, _ *db.Queries, _ alerts.ConfigDecrypter, _, detail string) {
		rec.record("failed: " + detail)
	}
	dispatchRotationSuccess = func(_ context.Context, _ *db.Queries, _ alerts.ConfigDecrypter, _, detail string) {
		rec.record("succeeded: " + detail)
	}
	t.Cleanup(func() {
		dispatchRotationAlert = prevAlert
		dispatchRotationFailure = prevFail
		dispatchRotationSuccess = prevOK
	})
	return rec
}

const rotationTestPassword = "CorrectHorseBatteryStaple1!"

func newRotationEnv(t *testing.T, tc rotationCase) *rotationEnv {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	rec := installRotationFakes(t)
	provider := tc.provider

	owner := mustUser(t, queries, fmt.Sprintf("rot-%s@example.com", randomHex(6)), "user", rotationTestPassword)
	entryID := "rot-" + randomHex(6)
	const before = "ORIGINAL-VALUE"
	mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, before)

	if provider != "" {
		if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
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

	if tc.notifyTarget {
		enc, encErr := h.encryptColumn(`[{"type":"notify"}]`)
		if encErr != nil {
			t.Fatalf("encrypt targets: %v", encErr)
		}
		if _, err := h.db.Exec(`UPDATE vault_entries SET rotation_targets = ? WHERE id = ?`,
			enc, entryID); err != nil {
			t.Fatalf("seed notify target: %v", err)
		}
	}

	if tc.corruptTargets {
		// Ciphertext-shaped but undecryptable: the prefix makes decryptColumn try,
		// and the body is not valid base64 under our key. Writing cleartext instead
		// would take the "not encrypted, pass through" path and test nothing.
		if _, err := h.db.Exec(
			`UPDATE vault_entries SET rotation_targets = ? WHERE id = ?`,
			"enc:v1:bm90LXJlYWxseS1jaXBoZXJ0ZXh0", entryID); err != nil {
			t.Fatalf("corrupt rotation_targets: %v", err)
		}
	}

	if tc.want.metaWrites > 0 {
		// Capture EVERY version of provider_meta as it is written, not just the
		// final one. See rotationOutcome.metaWrites.
		if _, err := h.db.Exec(`CREATE TABLE meta_writes (n INTEGER PRIMARY KEY, val TEXT)`); err != nil {
			t.Fatalf("create meta_writes: %v", err)
		}
		if _, err := h.db.Exec(`CREATE TRIGGER capture_meta
			AFTER UPDATE OF provider_meta ON vault_entries
			BEGIN INSERT INTO meta_writes (val) VALUES (NEW.provider_meta); END`); err != nil {
			t.Fatalf("install meta-capture trigger: %v", err)
		}
		t.Cleanup(func() { _, _ = h.db.Exec(`DROP TRIGGER IF EXISTS capture_meta`) })
	}

	env := &rotationEnv{h: h, queries: queries, owner: owner, entryID: entryID, before: before, alerts: rec}

	if tc.revokeSucceeds {
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(sink.Close)
		revokeTargetURL = sink.URL + "/keys/old"

		// The guarded client blocks loopback at dial time, correct in production
		// and useless for reaching a test server.
		prevHTTP := providerHTTP
		providerHTTP = &http.Client{}
		t.Cleanup(func() { providerHTTP = prevHTTP })
	}

	if tc.callerDiesAfterCAS || tc.deleteDuringPostCAS {
		// The revoke runs FIRST in the post-CAS phase, so a sink that cancels the
		// caller lands the cancellation squarely in the window under test: the meta
		// write and every outcome write come after it.
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// The revoke runs FIRST in the post-CAS phase, so whatever this handler
			// does lands squarely inside the window under test.
			if tc.callerDiesAfterCAS && env.killCaller != nil {
				env.killCaller()
			}
			if tc.deleteDuringPostCAS {
				// Exactly what a second tab calling DELETE does: a hard delete with
				// no re-auth, mid-rotation.
				if _, dErr := h.db.Exec(`DELETE FROM vault_entries WHERE id = ?`, entryID); dErr != nil {
					t.Errorf("ablation delete failed: %v", dErr)
				}
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(sink.Close)
		revokeTargetURL = sink.URL + "/keys/old"

		// The guarded client blocks loopback at dial time, which is correct in
		// production and useless for reaching a test server.
		prevHTTP := providerHTTP
		providerHTTP = &http.Client{}
		t.Cleanup(func() { providerHTTP = prevHTTP })
	}

	if tc.failPersist {
		// Fail exactly the write that stores the rotated value, and nothing else.
		//
		// Scoped to encrypted_value on purpose: UpdateVaultEntryRotationError and
		// UpdateVaultEntryRotationLog never SET that column, so the bookkeeping the
		// failure path is supposed to perform still succeeds and can be asserted.
		// That is the difference between testing the error branch and testing a
		// database that refuses everything.
		if _, err := h.db.Exec(`CREATE TRIGGER fail_rotate_persist
			BEFORE UPDATE OF encrypted_value ON vault_entries
			BEGIN SELECT RAISE(ABORT, 'injected persist failure'); END`); err != nil {
			t.Fatalf("install persist-failure trigger: %v", err)
		}
		t.Cleanup(func() { _, _ = h.db.Exec(`DROP TRIGGER IF EXISTS fail_rotate_persist`) })
	}

	return env
}

func (e *rotationEnv) driveManual(t *testing.T, tc rotationCase) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := vaultAuthzRequest("POST", "/api/vault/"+e.entryID+"/rotate",
		e.owner, "user", e.entryID, `{"password":"`+rotationTestPassword+`"}`)

	if tc.callerDiesAfterCAS {
		// Give the request a context we can kill, and hand the cancel to the revoke
		// sink so it fires once the rotation has already committed.
		reqCtx, cancel := context.WithCancel(req.Context())
		e.killCaller = cancel
		t.Cleanup(cancel)
		req = req.WithContext(reqCtx)
	}

	e.h.Rotate(rec, req)
	e.h.WaitForDelivery(5 * 1e9) // 5s, drains the detached delivery goroutine
	return rec
}

func (e *rotationEnv) driveSweep(t *testing.T, tc rotationCase) {
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
	passCtx := ctx
	if tc.callerDiesAfterCAS {
		// The sweep's equivalent of a dead caller is a dead PASS context. Its
		// context.WithoutCancel must survive it, which is the same property the
		// handler now has.
		dead, cancel := context.WithCancel(ctx)
		cancel()
		passCtx = dead
	}
	rotateOneEntry(passCtx, e.queries, e.h, *row)
}

// assertOutcome applies the SAME post-conditions regardless of which path ran.
func (e *rotationEnv) assertOutcome(t *testing.T, path string, want rotationOutcome) {
	t.Helper()
	ctx := context.Background()

	row, err := e.queries.GetVaultEntryForRotation(ctx, e.entryID)
	if err != nil {
		if !want.rowDeleted {
			t.Fatalf("%s: reload: %v", path, err)
		}
		// The row is gone by design for this case. Everything below reads it, so
		// only the out-of-band assertions apply.
		if got := e.alerts.count() > 0; got != want.alertWanted {
			t.Errorf("%s: rotation alert dispatched=%v, want %v (events: %v)\n"+
				"The rotation COMMITTED and the predecessor key was destroyed upstream. If the "+
				"row then vanished, the one remaining way to tell anyone is the alert.",
				path, got, want.alertWanted, e.alerts.events)
		}
		return
	}
	if want.rowDeleted {
		t.Fatalf("%s: the row was expected to be gone by assert time but is still present, "+
			"so this case is not exercising the post-commit-window deletion it claims to", path)
	}
	plain, err := e.h.openForTest(row.EncryptedValue, row.Nonce)
	if err != nil {
		t.Fatalf("%s: decrypt: %v", path, err)
	}
	changed := !plain.EqualsString(e.before)
	if changed != want.valueChanged {
		t.Errorf("%s: stored value changed=%v, want %v", path, changed, want.valueChanged)
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

	if want.metaWrites > 0 {
		rows, qErr := e.h.db.Query(`SELECT val FROM meta_writes ORDER BY n`)
		if qErr != nil {
			t.Fatalf("%s: read meta_writes: %v", path, qErr)
		}
		var versions []string
		for rows.Next() {
			var v string
			if sErr := rows.Scan(&v); sErr != nil {
				t.Fatalf("%s: scan meta_writes: %v", path, sErr)
			}
			versions = append(versions, v)
		}
		rows.Close()

		if len(versions) != want.metaWrites {
			t.Errorf("%s: provider_meta written %d times, want %d\n"+
				"One logical change is one write. Two writes means the transient revoke "+
				"markers were persisted and then cleaned up, and it bumps updated_at twice.",
				path, len(versions), want.metaWrites)
		}
		// A version may carry the pending-revoke markers ONLY when the case says
		// the revoke genuinely failed (metaWriteKeepsRevokeMarkers): the markers
		// are then the only surviving record of what to revoke and how, and
		// performPendingRevoke must have left them for a retry. Otherwise, no
		// version may carry them: vault_providers.go documents them as cleared
		// once the revoke is a confirmed success.
		for i, v := range versions {
			plain := e.h.decryptColumnOrLog(v, "{}", vaultFieldProviderMeta)
			for _, marker := range []string{pendingRevokeMethod, pendingRevokeURL, pendingRevokeAuth} {
				has := strings.Contains(plain, marker)
				if want.metaWriteKeepsRevokeMarkers {
					if !has {
						t.Errorf("%s: provider_meta write #%d dropped the transient marker %q on a "+
							"failed revoke\n  value: %s\n"+
							"A failed revoke must leave pending_revoke_method/url/auth in place: they "+
							"are the only record of what to revoke and how, and stripping them here "+
							"strands the old key at the provider with no way to retry.",
							path, i+1, marker, plain)
					}
					continue
				}
				if has {
					t.Errorf("%s: provider_meta write #%d persisted the transient marker %q\n"+
						"  value: %s\n"+
						"These are stripped by performPendingRevoke once the revoke is a confirmed "+
						"success; a crash between the mint and the single write must never leave them "+
						"behind on a write that was not a failed revoke.",
						path, i+1, marker, plain)
				}
			}
		}
	}

	if want.logStatus != "" {
		var entries []RotationLogEntry
		_ = json.Unmarshal([]byte(row.RotationLog.String), &entries)
		if len(entries) == 0 {
			t.Errorf("%s: rotation_log is empty, want a %q entry", path, want.logStatus)
		} else if got := entries[len(entries)-1].Status; got != want.logStatus {
			t.Errorf("%s: newest rotation_log status = %q, want %q", path, got, want.logStatus)
		}
		if want.logMethod != "" && len(entries) > 0 {
			if got := entries[len(entries)-1].Method; got != want.logMethod {
				t.Errorf("%s: newest rotation_log method = %q, want %q\n"+
					"This field says WHO triggered the rotation. Recording a user's click as "+
					"\"auto\" attributes a human action to the scheduler.", path, got, want.logMethod)
			}
		}
	}
}

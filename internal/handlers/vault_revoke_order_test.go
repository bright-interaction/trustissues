package handlers

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestRevokeIsDeferredUntilAfterPersist locks the ordering fix.
//
// The provider Rotate bodies used to DELETE the old key upstream before
// returning, so the window between "old key destroyed at the provider" and "new
// key committed to our database" was covered by an encrypt step and a DB write.
// Any failure in that window (encrypt error, disk full, SQLITE_BUSY, the process
// being killed) left the old credential dead upstream and the new one
// discarded: the secret was gone with no copy anywhere, while the entry still
// held a value that no longer authenticated.
//
// Rotate now only RECORDS the revoke; the caller runs it once the new value is
// durably stored. The same failure then leaves BOTH keys live, which is
// recoverable and already reported as a partial rotation.
//
// This drives the attempt against a real httptest server via withFakeUpstream
// (the same fixture the auth-scheme contract tests use), using a real
// registered provider ("resend") so declaredProviderEgress actually resolves a
// host and the exit succeeds. An earlier version of this test passed provider
// "manual" here, which is itself a registered provider declared with NO API at
// all (see providerEgress in egress_authority.go), so the exit refused before
// ever reaching the network and this test was silently exercising a failure,
// not the success path its name and assertions claimed. That only stayed
// invisible because performPendingRevoke used to delete the pending-revoke
// markers unconditionally, on every path; now that it only clears them on
// confirmed success, a wrongly-failing "success" fixture fails loudly instead
// of passing by accident.
func TestRevokeIsDeferredUntilAfterPersist(t *testing.T) {
	meta := map[string]string{"key_id": "old-key-id"}

	// Step 1: defer. Nothing may be destroyed upstream yet.
	deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/old-key-id", revokeAuthBearer)

	if meta[pendingRevokeMethod] != "DELETE" || meta[pendingRevokeURL] == "" {
		t.Fatal("the pending revoke was not recorded: the old key would stay live at the provider forever")
	}
	if meta[pendingRevokeAuth] != revokeAuthBearer {
		t.Fatalf("the auth scheme was not recorded: got %q, want %q", meta[pendingRevokeAuth], revokeAuthBearer)
	}
	if meta["last_revoke_error"] != "" {
		t.Fatalf("deferring recorded a failure without attempting anything: %q", meta["last_revoke_error"])
	}
	// Deferring must not have touched the network, so no outcome is known yet.
	// Guard the setup: if the markers were absent the assertions below would
	// pass against a no-op.
	if len(meta) != 4 {
		t.Fatalf("unexpected meta after defer: %+v", meta)
	}

	var hits int
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})

	// The new secret must NEVER be written into meta: provider_meta is persisted.
	performPendingRevoke(context.Background(), meta, "resend", testPlaintext("NEW-SECRET-VALUE"))
	if hits != 1 {
		t.Fatalf("ABORT: the fake upstream saw %d requests, want 1; this is not exercising a real revoke "+
			"attempt", hits)
	}
	for k, v := range meta {
		if strings.Contains(v, "NEW-SECRET-VALUE") {
			t.Fatalf("meta[%q] carries the new secret and would be persisted to the database", k)
		}
	}
	if meta["last_revoke_error"] != "" {
		t.Fatalf("a successful revoke recorded an error: %q", meta["last_revoke_error"])
	}

	// Step 2 succeeded, so the transient markers must be gone: leaving them
	// would re-run the revoke on every later rotation and would be persisted.
	if meta[pendingRevokeMethod] != "" || meta[pendingRevokeURL] != "" || meta[pendingRevokeAuth] != "" {
		t.Fatalf("transient revoke markers survived a successful revoke: %+v", meta)
	}
	// key_id must be untouched by the revoke machinery.
	if meta["key_id"] != "old-key-id" {
		t.Fatalf("revoke machinery clobbered key_id: %q", meta["key_id"])
	}
}

// TestDeferredRevokeFailureIsNeverSilent proves an erroring provider surfaces
// AND that the pending-revoke coordinates survive the failure.
//
// Both-keys-live is the safe outcome, but it must not be quiet: the
// predecessor stays usable and nobody would know to go delete it. And it must
// not be a DEAD END: performPendingRevoke used to delete
// pending_revoke_method/url/auth unconditionally, before the attempt even
// started, so the caller (revokeOldKeyAndPersistMeta) persisted meta right
// after with last_revoke_error set but no record left of what to revoke or
// how. A failed attempt must leave those markers in place so a future retry
// mechanism has something to act on.
//
// This drives the attempt against a real httptest server returning a non-2xx,
// via withFakeUpstream, so the failure comes from the actual revoke call
// (revokeOldProviderKey), not from an unrelated setup mistake.
func TestDeferredRevokeFailureIsNeverSilent(t *testing.T) {
	var hits int
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	})

	meta := map[string]string{"key_id": "old"}
	deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/old", revokeAuthBearer)

	performPendingRevoke(context.Background(), meta, "resend", testPlaintext("NEW-SECRET-VALUE"))

	if hits != 1 {
		t.Fatalf("ABORT: the fake upstream saw %d requests, want 1; this is not exercising a failed "+
			"revoke attempt", hits)
	}
	if meta["last_revoke_error"] == "" {
		t.Fatal("a failed revoke was silent: the old key is still live and nothing reports it")
	}
	// The message reaches last_rotation_error, the browser and notification
	// channels, so it must not carry the secret.
	if strings.Contains(meta["last_revoke_error"], "NEW-SECRET-VALUE") {
		t.Fatalf("the revoke error leaked the new secret: %q", meta["last_revoke_error"])
	}
	// The pending-revoke coordinates must survive a failed attempt: the caller
	// persists meta right after this returns, and losing them here means the
	// old key is stranded at the provider with no surviving record of what to
	// revoke or how.
	if meta[pendingRevokeMethod] == "" || meta[pendingRevokeURL] == "" || meta[pendingRevokeAuth] == "" {
		t.Fatalf("a failed revoke discarded its pending-revoke coordinates: %+v", meta)
	}
}

// TestB2RevokeFailureKeepsPendingMarkers is the B2-scheme twin of
// TestDeferredRevokeFailureIsNeverSilent.
//
// B2's pending_revoke_url does NOT carry a request URL, it carries the OLD key
// id (see deferRevokeOldProviderKey's doc), and its failure surfaces through
// backblazeRevokeOldKey rather than revokeOldProviderKey, so it needs its own
// proof that a failed attempt still leaves the coordinates for a retry instead
// of just relying on the non-B2 case above.
func TestB2RevokeFailureKeepsPendingMarkers(t *testing.T) {
	var authorizeHits int
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		authorizeHits++
		// Fail the authorize round trip itself; b2_delete_key must never be
		// reached without a token from it.
		w.WriteHeader(http.StatusUnauthorized)
	})

	// meta["key_id"] already holds the NEW key id, same as backblaze's Rotate
	// writes before deferring.
	meta := map[string]string{"key_id": "0021new"}
	deferRevokeOldProviderKey(meta, "DELETE", "0021old", revokeAuthB2)

	performPendingRevoke(context.Background(), meta, "backblaze", testPlaintext("K0newSecret"))

	if authorizeHits != 1 {
		t.Fatalf("ABORT: b2_authorize_account was hit %d times, want 1", authorizeHits)
	}
	if meta["last_revoke_error"] == "" {
		t.Fatal("a failed b2 authorize was silent: the old key is still live and nothing reports it")
	}
	if meta[pendingRevokeMethod] == "" || meta[pendingRevokeURL] == "" || meta[pendingRevokeAuth] == "" {
		t.Fatalf("a failed b2 revoke discarded its pending-revoke coordinates: %+v", meta)
	}
	if meta[pendingRevokeURL] != "0021old" {
		t.Fatalf("pending_revoke_url changed from the old key id a retry must target: %q", meta[pendingRevokeURL])
	}
}

// TestPerformPendingRevokeIsANoOpWithoutAPendingRevoke guards the common path:
// a first rotation, or a provider with no revoke API, has nothing to revoke and
// must not error or mutate anything.
func TestPerformPendingRevokeIsANoOpWithoutAPendingRevoke(t *testing.T) {
	meta := map[string]string{"key_id": "abc"}
	performPendingRevoke(context.Background(), meta, "manual", testPlaintext("NEW"))
	if meta["last_revoke_error"] != "" {
		t.Fatalf("no-op revoke recorded an error: %q", meta["last_revoke_error"])
	}
	if len(meta) != 1 || meta["key_id"] != "abc" {
		t.Fatalf("no-op revoke mutated meta: %+v", meta)
	}
}

// TestNoProviderRevokesBeforeReturning is the structural guard: it fails if any
// Rotate body ever calls an immediate revoke instead of deferring.
//
// There is NO exception any more. Backblaze used to be the one: it called
// backblazeRevokeOldKey directly, inline, right before Rotate returned,
// commented as "best-effort... because b2_delete_key needs an authorize step
// first" and treated by an earlier version of this very test as legitimate.
// That inline call is the P0 this file exists to close: it ran BEFORE the
// caller encrypted or persisted the new value and BEFORE the caller's
// compare-and-swap could even run, so a CAS conflict on the write (a
// concurrent edit, a lost race) destroyed the old key at Backblaze while the
// newly minted key was discarded. Nobody was left holding a working
// credential, and the 409 response the caller got back claimed "the old key is
// still live and the new one is stranded upstream", which was false.
// TestBackblazeCASConflictLeavesThePredecessorLive is the runtime proof; this
// is the structural guard that stops it from being reintroduced by a future
// edit, which no unit test would otherwise catch until a credential was
// destroyed in production.
func TestNoProviderRevokesBeforeReturning(t *testing.T) {
	src := mustReadSource(t, "vault_providers.go")

	// Every registered provider's Rotate body, extracted the same way
	// TestPredecessorFateMatchesTheCode does, so a new adapter is covered on
	// the day it is written rather than the day someone remembers to add it to
	// a marker list.
	rotateRe := regexp.MustCompile(`(?s)func \(p \*(\w+)\) Rotate\(ctx context\.Context.*?\n\}\n`)
	matches := rotateRe.FindAllStringSubmatch(src, -1)
	if len(matches) < 8 {
		t.Fatalf("ABORT: only %d Rotate bodies matched; the matcher has drifted and this guard is "+
			"vacuous", len(matches))
	}
	for _, m := range matches {
		typ, body := m[1], m[0]
		for _, fn := range []string{"revokeOldProviderKey(", "backblazeRevokeOldKey("} {
			if strings.Contains(body, fn) {
				t.Errorf("%s.Rotate calls %s inline: the old key would be destroyed at the provider "+
					"before the caller's compare-and-swap has persisted the new one. A CAS conflict "+
					"then leaves the old key dead upstream and the new one discarded, with nobody "+
					"holding a working credential. Use deferRevokeOldProviderKey instead.", typ, fn)
			}
		}
	}
	// And the deferral must still be present, or nothing revokes at all.
	if !strings.Contains(src, "deferRevokeOldProviderKey(meta,") {
		t.Error("no provider defers a revoke: old keys would never be revoked")
	}
	// Backblaze specifically must have moved to the deferred path: this is the
	// fix this test exists to lock, named explicitly so a revert reads as a
	// revert rather than a mysterious new failure.
	if !strings.Contains(src, `deferRevokeOldProviderKey(meta, "DELETE", keyID, revokeAuthB2)`) {
		t.Error("backblaze no longer defers its revoke via the b2 scheme; it may have reverted to " +
			"an inline call")
	}
}

// mustReadSource reads a file from this package's directory for structural
// assertions that no runtime test can make.
func mustReadSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("ABORT: could not read %s (%v); the structural guard would pass vacuously", name, err)
	}
	if len(b) < 1000 {
		t.Fatalf("ABORT: %s is suspiciously short (%d bytes)", name, len(b))
	}
	return string(b)
}

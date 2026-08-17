package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// THE PRESERVED RECORD HAS TO BE READ BY SOMETHING.
//
// Keeping a failed revoke's coordinates is only worth the surface it costs if
// something later acts on them. The only reader is performPendingRevoke, which
// ran AFTER the mint, while deferRevokeOldProviderKey overwrote all three
// markers unconditionally DURING that mint. So a stranded key's coordinates
// were destroyed one rotation later having never been retried once: the outcome
// the deferral exists to prevent, delayed by a cycle rather than avoided.
//
// retryOutstandingRevokeBeforeMint runs the outstanding revoke first, with the
// entry's current value. These tests pin that ordering, the success and failure
// outcomes, and the no-op case.

// TestOutstandingRevokeIsRetriedBeforeTheNextMint is the MEDIUM-2 closure: a
// revoke that failed on rotation N is attempted again at the start of rotation
// N+1, and on success its coordinates are cleared rather than clobbered.
func TestOutstandingRevokeIsRetriedBeforeTheNextMint(t *testing.T) {
	// Rotation N: the revoke fails with a 503, the ordinary failure the whole
	// deferral exists for.
	failing := withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	_ = failing

	meta := map[string]string{"key_id": "key-2"}
	deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/key-1", revokeAuthBearer)
	performPendingRevoke(context.Background(), meta, "resend", testPlaintext("re_SECOND"))

	if meta["last_revoke_error"] == "" {
		t.Fatal("ABORT: the fixture's revoke did not fail, so there is nothing outstanding to retry")
	}
	if meta[pendingRevokeURL] != "https://api.resend.com/api-keys/key-1" {
		t.Fatalf("ABORT: the failed revoke did not preserve its coordinates: %+v", meta)
	}

	// Rotation N+1. The upstream is healthy again.
	var revoked []string
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			revoked = append(revoked, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})

	warn := retryOutstandingRevokeBeforeMint(context.Background(), meta, "the-entry", "resend",
		testPlaintext("re_SECOND"))

	if warn != "" {
		t.Errorf("a successful retry reported a warning: %q", warn)
	}
	if len(revoked) != 1 || !strings.HasSuffix(revoked[0], "/key-1") {
		t.Fatalf("the outstanding revoke was not retried against key-1; upstream saw %v", revoked)
	}
	// Cleared, so the mint that follows records ITS coordinates over nothing.
	for _, k := range []string{pendingRevokeMethod, pendingRevokeURL, pendingRevokeAuth} {
		if _, ok := meta[k]; ok {
			t.Errorf("a confirmed successful retry left %s behind: %+v", k, meta)
		}
	}
	if _, ok := meta["last_revoke_error"]; ok {
		t.Errorf("a successful retry left an error flag: %+v", meta)
	}
}

// TestAFailedRetryKeepsTheCoordinatesAndWarns covers the other branch. The
// predecessor is still live, so the record must survive AND the caller must be
// told, because the mint that follows is about to overwrite it.
func TestAFailedRetryKeepsTheCoordinatesAndWarns(t *testing.T) {
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	meta := map[string]string{"key_id": "key-2"}
	deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/key-1", revokeAuthBearer)

	warn := retryOutstandingRevokeBeforeMint(context.Background(), meta, "the-entry", "resend",
		testPlaintext("re_SECOND"))

	if warn == "" {
		t.Fatal("a failed retry was silent: an older key is still live upstream and its retry record " +
			"is about to be overwritten by the next mint, with nothing reporting either fact")
	}
	if !strings.Contains(warn, "earlier key") {
		t.Errorf("the warning does not say which key it is about: %q", warn)
	}
	if meta[pendingRevokeURL] != "https://api.resend.com/api-keys/key-1" {
		t.Errorf("a failed retry discarded the coordinates: %+v", meta)
	}
	// The flag is lifted into the return value, not left in the map, so the
	// post-mint revoke's own outcome is read unambiguously.
	if _, ok := meta["last_revoke_error"]; ok {
		t.Errorf("the retry left last_revoke_error in the map, where it will be misread as the "+
			"post-mint revoke's outcome: %+v", meta)
	}
}

// TestRetryBeforeMintIsANoOpWithNothingOutstanding guards the common path: a
// first rotation, or any rotation following a clean one, must not touch the
// network or the map.
func TestRetryBeforeMintIsANoOpWithNothingOutstanding(t *testing.T) {
	var hits int
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})

	meta := map[string]string{"key_id": "abc"}
	if warn := retryOutstandingRevokeBeforeMint(context.Background(), meta, "e", "resend",
		testPlaintext("NEW")); warn != "" {
		t.Errorf("a no-op retry reported %q", warn)
	}
	if hits != 0 {
		t.Errorf("a no-op retry made %d upstream requests", hits)
	}
	if len(meta) != 1 || meta["key_id"] != "abc" {
		t.Errorf("a no-op retry mutated meta: %+v", meta)
	}

	// And with a nil map, which the rotation paths can reach for an entry with
	// no provider configured.
	if warn := retryOutstandingRevokeBeforeMint(context.Background(), nil, "e", "", testPlaintext("NEW")); warn != "" {
		t.Errorf("a nil-meta retry reported %q", warn)
	}
}

// TestRevokeTreats404AsAlreadyRevokedInBothArms holds the two revoke arms to one
// rule.
//
// revokeOldProviderKey has always exempted 404: the key being gone is the state
// a revoke is trying to reach. backblazeRevokeOldKey did not, so a B2 key
// already deleted upstream was recorded as a permanently failed revoke, the
// markers were preserved forever, and the entry sat in partial rotation
// retrying a key that does not exist. The doc comment in performPendingRevoke
// asserted the property for both arms while only one had it.
func TestRevokeTreats404AsAlreadyRevokedInBothArms(t *testing.T) {
	t.Run("bearer arm", func(t *testing.T) {
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		meta := map[string]string{"key_id": "new"}
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/gone", revokeAuthBearer)
		performPendingRevoke(context.Background(), meta, "resend", testPlaintext("re_NEW"))

		if e := meta["last_revoke_error"]; e != "" {
			t.Errorf("a 404 was recorded as a failure: %q", e)
		}
		if _, ok := meta[pendingRevokeURL]; ok {
			t.Errorf("a 404 left the coordinates behind, so this key is retried forever: %+v", meta)
		}
	})

	t.Run("b2 arm", func(t *testing.T) {
		// The authorize round trip succeeds; b2_delete_key answers 404 because
		// the key is already gone.
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "b2_delete_key") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authorizationToken":"tok","apiInfo":{"storageApi":{"apiUrl":"https://api.backblazeb2.com"}}}`))
		})
		meta := map[string]string{"key_id": "0021new"}
		deferRevokeOldProviderKey(meta, "DELETE", "0021gone", revokeAuthB2)
		performPendingRevoke(context.Background(), meta, "backblaze", testPlaintext("K0newSecret"))

		if e := meta["last_revoke_error"]; e != "" {
			t.Errorf("a b2 404 was recorded as a failure: %q; the twin arm treats it as already-revoked", e)
		}
		if _, ok := meta[pendingRevokeURL]; ok {
			t.Errorf("a b2 404 left the coordinates behind, so this key is retried forever: %+v", meta)
		}
	})
}

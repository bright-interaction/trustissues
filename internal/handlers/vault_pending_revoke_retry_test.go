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
// retryOutstandingRevoke runs the outstanding revoke first, with the
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
	deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/key-1", revokeAuthBearer, "key-1")
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

	warn := retryOutstandingRevoke(context.Background(), meta, "the-entry", "resend",
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
	deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/key-1", revokeAuthBearer, "key-1")

	warn := retryOutstandingRevoke(context.Background(), meta, "the-entry", "resend",
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
	if warn := retryOutstandingRevoke(context.Background(), meta, "e", "resend",
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
	if warn := retryOutstandingRevoke(context.Background(), nil, "e", "", testPlaintext("NEW")); warn != "" {
		t.Errorf("a nil-meta retry reported %q", warn)
	}
}

// TestRevokeTreats404ByWhereTheKeyIdTRAVELS holds each revoke arm to the rule its
// own request shape justifies, and pins that the two are NOT twins on this point.
//
// A previous pass "fixed" an asymmetry that was correct. revokeOldProviderKey
// issues DELETE https://vendor/api-keys/{id}: the key id is IN THE URL, so a 404
// genuinely names the key and already-revoked is a sound reading.
// backblazeRevokeOldKey POSTs applicationKeyId in the BODY to a fixed
// /b2api/v3/b2_delete_key endpoint on a host read from the authorize response,
// so a 404 there names the PATH and says nothing about the key. Backblaze
// documents 200/400/401 for that call and no 404 at all.
//
// Unifying them imported a false success into the one place it is dangerous: an
// endpoint 404 cleared last_revoke_error, performPendingRevoke deleted all three
// markers, the rotation recorded a clean success with no alert, and the old key
// stayed live at Backblaze with its only surviving identifier erased from the
// row. A loud wrong state became a silent one.
func TestRevokeTreats404ByWhereTheKeyIdTravels(t *testing.T) {
	t.Run("bearer arm: the id is in the URL, so 404 is already-revoked", func(t *testing.T) {
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		meta := map[string]string{"key_id": "new"}
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/gone", revokeAuthBearer, "gone")
		performPendingRevoke(context.Background(), meta, "resend", testPlaintext("re_NEW"))

		if e := meta["last_revoke_error"]; e != "" {
			t.Errorf("a 404 naming the key was recorded as a failure: %q", e)
		}
		if _, ok := meta[pendingRevokeURL]; ok {
			t.Errorf("a 404 naming the key left the coordinates behind, so it is retried forever: %+v", meta)
		}
	})

	t.Run("b2 arm: the id is in the BODY, so 404 is a FAILURE", func(t *testing.T) {
		// The authorize round trip succeeds; b2_delete_key answers 404 because
		// that host does not serve the path. The key is untouched and still live.
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "b2_delete_key") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authorizationToken":"tok","apiInfo":{"storageApi":{"apiUrl":"https://api.backblazeb2.com"}}}`))
		})
		meta := map[string]string{"key_id": "0021new"}
		deferRevokeOldProviderKey(meta, "DELETE", "0021STILL_LIVE", revokeAuthB2, "0021STILL_LIVE")
		performPendingRevoke(context.Background(), meta, "backblaze", testPlaintext("K0newSecret"))

		if meta["last_revoke_error"] == "" {
			t.Error("a b2 endpoint 404 was recorded as a successful revoke. The key id travels in the " +
				"request BODY, so a 404 cannot mean the key is gone, and treating it as success " +
				"deletes the only record of a key that is still live upstream")
		}
		if meta[pendingRevokeURL] != "0021STILL_LIVE" {
			t.Errorf("a b2 endpoint 404 discarded the coordinates of a live key: %+v", meta)
		}
	})

	t.Run("b2 arm: a real 2xx still clears the coordinates", func(t *testing.T) {
		// The positive control. Without it, "b2 never succeeds" would satisfy
		// the subtest above.
		withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authorizationToken":"tok","apiInfo":{"storageApi":{"apiUrl":"https://api.backblazeb2.com"}}}`))
		})
		meta := map[string]string{"key_id": "0021new"}
		deferRevokeOldProviderKey(meta, "DELETE", "0021gone", revokeAuthB2, "0021gone")
		performPendingRevoke(context.Background(), meta, "backblaze", testPlaintext("K0newSecret"))

		if e := meta["last_revoke_error"]; e != "" {
			t.Errorf("a successful b2 revoke recorded an error: %q", e)
		}
		if _, ok := meta[pendingRevokeURL]; ok {
			t.Errorf("a successful b2 revoke left the coordinates behind: %+v", meta)
		}
	})
}

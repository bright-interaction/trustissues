package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// oversizedUpstreamBytes is how much a hostile target sends. It is far past
// maxUpstreamErrorBody and past anything a real error page contains, so the
// allocation it causes is unmistakable in the numbers below.
const oversizedUpstreamBytes = 32 << 20 // 32 MiB

// floodingUpstream is a delivery target that answers every request with status
// and then oversizedUpstreamBytes of body.
//
// It writes from ONE reused megabyte, so the memory this test measures is the
// client's, not the fixture's. It also stops as soon as the client hangs up,
// which is what a bounded reader makes happen.
func floodingUpstream(t *testing.T, status int) *httptest.Server {
	t.Helper()
	chunk := strings.Repeat("A", 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		for sent := 0; sent < oversizedUpstreamBytes; sent += len(chunk) {
			if _, err := io.WriteString(w, chunk); err != nil {
				return // the client stopped reading: exactly the intended outcome
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// measureAlloc reports how many bytes fn caused to be allocated in total,
// including memory already freed again. TotalAlloc is cumulative and is not
// reduced by a GC, so it measures the PEAK DEMAND fn placed on the heap, which
// is the thing an unbounded read exhausts.
func measureAlloc(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// allocCeiling is the budget a delivery is allowed for a 32 MiB hostile
// response. Bounded, the read costs maxUpstreamErrorBody plus the fixed cost of
// one HTTP round trip; unbounded, io.ReadAll's doubling growth costs upwards of
// 64 MiB for this body. 8 MiB sits in the wide gap between the two, so the
// assertion is not measuring noise in either direction.
const allocCeiling = 8 << 20

// TestWebhookDeliveryRefusesAnOversizedUpstreamErrorBody is the attack, run.
//
// deliverToWebhook POSTs a freshly rotated secret to a URL the target's
// configurer chose, so the host answering is one the product never vetted. It
// used to read the failure response with `body, _ := io.ReadAll(resp.Body)`:
// no ceiling, so the answer to "how much memory does this vault allocate" was
// given by the machine on the other end, and a 32 MiB reply (or a 32 GiB one)
// was read in full into a single-process credential store.
func TestWebhookDeliveryRefusesAnOversizedUpstreamErrorBody(t *testing.T) {
	swapProviderHTTP(t)
	srv := floodingUpstream(t, http.StatusInternalServerError)

	target := RotationTarget{Type: "webhook", WebhookURL: srv.URL}
	ctx := testExitCtx(context.Background(), "webhook fixture",
		hostSetFor(t, srv.URL))

	var err error
	used := measureAlloc(func() {
		err = deliverToWebhook(ctx, target, "my-entry", testPlaintext("the-new-key"))
	})

	if err == nil {
		t.Fatal("the delivery reported success against an upstream that answered 500")
	}
	if used > allocCeiling {
		t.Errorf("delivering to a hostile target allocated %d bytes for a %d byte response "+
			"(ceiling for this test is %d). The upstream is still choosing how much memory this "+
			"process commits, which is the finding", used, oversizedUpstreamBytes, allocCeiling)
	}
	assertBodyWasNotSwallowed(t, err, http.StatusInternalServerError)
}

// TestForgejoDeliveryRefusesAnOversizedUpstreamErrorBody is the same attack on
// the second call site.
//
// Both reads were fixed together on purpose: patching one and leaving its twin
// is how this estate loses fix passes. target.Instance is an operator-supplied
// Forgejo URL, so the host is no more trusted than the webhook's.
func TestForgejoDeliveryRefusesAnOversizedUpstreamErrorBody(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "flood-owner@example.com", "user", "")
	mustEntry(t, h, queries, "entry-flood", owner, "flood-app", "seed")
	mustEntry(t, h, queries, "entry-flood-pat", owner, "flood-pat", "PAT_VALUE")

	srv := floodingUpstream(t, http.StatusInternalServerError)
	target := RotationTarget{
		Type: "forgejo_secret", Instance: srv.URL, Repo: "o/r", SecretName: "S",
		AuthToken: "flood-pat", ConfiguredBy: owner,
	}

	var err error
	used := measureAlloc(func() {
		err = deliverToForgejoSecret(ctx, h, target,
			h.MintedEntrySecret([]byte("new"), "entry-flood", "flood-app"), owner)
	})

	if err == nil {
		t.Fatal("the delivery reported success against an upstream that answered 500")
	}
	// Guard the setup: if the exits refused, the request never left and this
	// test measured nothing about the read.
	var ue *upstreamHTTPError
	if !errors.As(err, &ue) {
		t.Fatalf("ABORT: the delivery failed before the HTTP response was read (%v), so the "+
			"oversized body was never reached and this test proves nothing", err)
	}
	if used > allocCeiling {
		t.Errorf("delivering to a hostile forgejo instance allocated %d bytes for a %d byte "+
			"response (ceiling for this test is %d)", used, oversizedUpstreamBytes, allocCeiling)
	}
	assertBodyWasNotSwallowed(t, err, http.StatusInternalServerError)
}

// assertBodyWasNotSwallowed pins the second half of the finding: what the
// process does with a body it could not read in full.
//
// The old code discarded the read error (`body, _ :=`) and handed whatever it
// had to newUpstreamHTTPError, so a truncated or failed read became the
// upstream's "message" with nothing marking it as incomplete. A bounded read
// that silently truncates has the same defect in a smaller package. So the log
// record must say the body was not read, and must not contain the attacker's
// bytes presented as the upstream's words.
func assertBodyWasNotSwallowed(t *testing.T, err error, wantStatus int) {
	t.Helper()
	var ue *upstreamHTTPError
	if !errors.As(err, &ue) {
		t.Fatalf("delivery error is %T (%v), want *upstreamHTTPError: capability.go's redaction "+
			"allowlist and vault_rotation.go's logging both match on that type", err, err)
	}
	if ue.Status != wantStatus {
		t.Errorf("status = %d, want %d", ue.Status, wantStatus)
	}
	if !strings.Contains(ue.Body, "not read") {
		t.Errorf("logged body = %q, want a structural note saying the body was not read. An "+
			"over-ceiling body must be reported as a failure to read, never passed off as a short "+
			"body the upstream actually sent", ue.Body)
	}
	if strings.Contains(ue.Body, strings.Repeat("A", 32)) {
		t.Errorf("logged body carries the upstream's flood bytes: %q", ue.Body)
	}
}

// TestReadUpstreamErrorBodyBoundary pins the three outcomes at the ceiling,
// which is where a limit is either honest or silently wrong.
func TestReadUpstreamErrorBodyBoundary(t *testing.T) {
	t.Run("under the ceiling is returned whole", func(t *testing.T) {
		want := strings.Repeat("x", maxUpstreamErrorBody-1)
		got, err := readUpstreamErrorBody(strings.NewReader(want))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != want {
			t.Fatalf("got %d bytes, want %d", len(got), len(want))
		}
	})

	t.Run("exactly at the ceiling is returned whole", func(t *testing.T) {
		want := strings.Repeat("x", maxUpstreamErrorBody)
		got, err := readUpstreamErrorBody(strings.NewReader(want))
		if err != nil {
			t.Fatalf("a body OF the ceiling is legal and must not error: %v", err)
		}
		if len(got) != maxUpstreamErrorBody {
			t.Fatalf("got %d bytes, want %d", len(got), maxUpstreamErrorBody)
		}
	})

	t.Run("one byte over the ceiling is an error, not a short body", func(t *testing.T) {
		got, err := readUpstreamErrorBody(strings.NewReader(strings.Repeat("x", maxUpstreamErrorBody+1)))
		if !errors.Is(err, errUpstreamBodyOverLimit) {
			t.Fatalf("err = %v, want errUpstreamBodyOverLimit. A plain io.LimitReader would have "+
				"returned %d bytes here with no error, which is indistinguishable from an upstream "+
				"that genuinely sent that much", err, len(got))
		}
		if got != nil {
			t.Errorf("an over-ceiling read returned %d bytes; a truncated body that happens to "+
				"parse is worse than an error", len(got))
		}
	})

	t.Run("a read failure is not an empty body", func(t *testing.T) {
		boom := errors.New("connection reset mid-body")
		got, err := readUpstreamErrorBody(io.MultiReader(strings.NewReader("{\"messa"), errReader{boom}))
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the read failure. `body, _ := io.ReadAll(...)` turned this "+
				"case into a successful empty body", err)
		}
		if got != nil {
			t.Errorf("a failed read returned %d bytes as if they were the whole answer", len(got))
		}
	})
}

// errReader fails on the first Read.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// hostSetFor is the destination set a rotation target's owner authorised, for
// the one host these fixtures deliver to.
func hostSetFor(t *testing.T, rawURL string) secretexit.HostSet {
	t.Helper()
	return secretexit.HostSet{Hosts: []string{hostOf(t, rawURL)}}
}

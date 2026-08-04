package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A RESPONSE THAT WITHHOLDS SOMETHING HAS TO SAY IT WITHHELD IT.
//
// Rotate returns the freshly minted plaintext so the operator can copy it into
// whatever consumes the credential, and round 7 routed that release through the
// exit, correctly: handing a value back to a principal is a release and the
// entry's owner decides who it goes to.
//
// What it did with a REFUSAL was the defect. The rotation is already committed
// and the predecessor may already be dead upstream, so unwinding is not an
// option and the code was right about that. But it logged the refusal
// server-side and returned HTTP 200 with `{"value": ""}`. The operator gets a
// success toast and an empty field, and cannot tell
//
//	"we rotated your key and cannot hand you the value"
//
// from
//
//	"the new value is an empty string"
//
// on a credential that has just been rolled at the provider. Same family as
// round 5's accept-then-silent, one layer up: the truth was recorded where
// nobody was looking and the caller was handed a shape that reads as success.
//
// THE REFUSAL IS REACHABLE, and this drives it rather than asserting a struct
// tag. A DEMOTED ADMIN WITH A LIVE SESSION is the case: entryAccess reads
// middleware.IsAdmin, which is the role the session was minted with, so the
// rotation is authorised and runs; the exit reads instanceAdminByRecord, which
// is the users ROW, so the release is refused. That split is deliberate (round
// 5: two sources for one fact is how the halves disagreed) and it is exactly the
// window where a rotation succeeds and its value cannot be handed over.

func TestRotateSaysSoWhenItWithholdsTheValue(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)

	const password = "rotator-pw"
	owner := mustUser(t, queries, "withheld-owner@example.com", "user", password)
	mustEntry(t, h, queries, "entry-withheld", owner, "app-key", "seed-value")

	// POSITIVE CONTROL FIRST, so a green run of the case below is not just "the
	// field is always set".
	ok := httptest.NewRecorder()
	h.Rotate(ok, vaultAuthzRequest(http.MethodPost, "/api/vault/entry-withheld/rotate",
		owner, "user", "entry-withheld", `{"password":`+quote(password)+`}`))
	if ok.Code != http.StatusOK {
		t.Fatalf("the owner could not rotate their own entry (%d: %s)", ok.Code, ok.Body.String())
	}
	var good struct {
		Value         string `json:"value"`
		ValueWithheld string `json:"value_withheld"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &good); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if good.Value == "" || good.Value == "seed-value" {
		t.Fatalf("the ordinary rotation did not return the new value: %q", good.Value)
	}
	if good.ValueWithheld != "" {
		t.Errorf("a successful rotation claimed something was withheld: %q", good.ValueWithheld)
	}

	// THE REFUSAL. Somebody whose SESSION says admin and whose users row says
	// plain user, rotating an entry they neither own nor share a collection with.
	demoted := mustUser(t, queries, "withheld-demoted@example.com", "user", password)

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/entry-withheld/rotate",
		demoted, "admin", "entry-withheld", `{"password":`+quote(password)+`}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the rotation itself did not succeed (%d: %s). The defect under test is a "+
			"rotation that SUCCEEDS and cannot hand over its value; if the request fails outright "+
			"this test is measuring something else.", rec.Code, rec.Body.String())
	}

	var out struct {
		Value         string `json:"value"`
		ValueWithheld string `json:"value_withheld"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Value != "" {
		t.Fatalf("the exit refused the release and the value came back anyway: %q", out.Value)
	}
	if out.ValueWithheld == "" {
		t.Fatal("THE ROTATION SUCCEEDED, THE VALUE WAS WITHHELD, AND THE BODY SAYS NOTHING.\n" +
			"  The caller gets 200 with {\"value\": \"\"} and a success toast, on a credential that has " +
			"just been rolled at the provider. They cannot tell 'we cannot hand you the value' from " +
			"'the new value is empty'. Say it in the body, not only in the server log.")
	}
	if !strings.Contains(out.ValueWithheld, "rotated and stored") {
		t.Errorf("the reason does not say the rotation SUCCEEDED, which is the one fact the operator "+
			"needs before they go looking for a value that does not exist: %q", out.ValueWithheld)
	}
	t.Logf("rotate contract: success value=%d bytes withheld=%q; refusal value=%q withheld=%q",
		len(good.Value), good.ValueWithheld, out.Value, out.ValueWithheld)
}

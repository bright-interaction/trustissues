package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// ONE RULE, EVERY PRINCIPAL CLASS, ON THE WIRE.
//
// The round-6 break was a VIEWER on a path nobody had modelled, so the fix is
// only worth anything if the answer does not depend on which door the principal
// came through. This drives the SAME cross-entry exfiltration as every principal
// class the product has, against a real HTTP sink, and asserts on what the sink
// received.
//
// It is deliberately a matrix rather than six separate tests: six tests drift,
// and a matrix that refuses to pass on a vacuous run cannot.

// TestTheOwnerRuleAnswersEveryPrincipalClassTheSameWay is the cross-entry
// exfiltration attempt, driven as each principal in turn.
func TestTheOwnerRuleAnswersEveryPrincipalClassTheSameWay(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	victim := mustUser(t, queries, "matrix-victim@example.com", "user", "")
	admin := mustUser(t, queries, "matrix-admin@example.com", "admin", "")
	viewer := mustUser(t, queries, "matrix-viewer@example.com", "vault_only", "")
	editor := mustUser(t, queries, "matrix-editor@example.com", "vault_only", "")
	manager := mustUser(t, queries, "matrix-manager@example.com", "user", "")
	outsider := mustUser(t, queries, "matrix-outsider@example.com", "user", "")
	disabled := mustUser(t, queries, "matrix-disabled@example.com", "admin", "")
	if _, err := queries.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: 1, ID: disabled}); err != nil {
		t.Fatalf("disable: %v", err)
	}

	// The admin gets the SAME seat as the viewer, deliberately. That is what
	// isolates the rule under test: two principals with identical collection
	// membership, one of whom is an instance admin, must get different answers,
	// and the difference must come from the users row rather than from a session
	// claim (round 5).
	//
	// The seat is also load-bearing for a reason worth recording: an instance
	// admin who is NOT a member of the collection cannot resolve a cross-entry
	// auth_token at all, because resolveVaultReferenceFor gates on
	// entryCurrentlyUsableBy and that deliberately has no admin branch. That is
	// pre-existing and fails CLOSED with a named error, so it is a narrower
	// behaviour than the exit rule rather than a hole in it.
	mustCollection(t, queries, "coll-matrix", victim, map[string]string{
		victim:  collRoleManager,
		admin:   collRoleViewer,
		viewer:  collRoleViewer,
		editor:  collRoleEditor,
		manager: collRoleManager,
	})
	const teamEntry = "entry-matrix-team"
	const teamSecret = "sk_live_MATRIX_TEAM_SECRET"
	mustEntry(t, h, queries, teamEntry, victim, "matrix-team", teamSecret)
	placeInCollection(t, queries, teamEntry, "coll-matrix")

	// One carrier entry per principal, owned by that principal, so the target
	// write itself is always legitimate and the ONLY question left is the exit's.
	carriers := map[string]string{}
	for i, who := range []string{admin, viewer, editor, manager, outsider, disabled, victim} {
		id := "entry-matrix-carrier-" + itoa(i)
		mustEntry(t, h, queries, id, who, "carrier-"+itoa(i), "carrier-seed")
		carriers[who] = id
	}

	cases := []struct {
		name string
		who  string
		// wantDelivered is whether the TEAM SECRET should reach the sink.
		wantDelivered bool
		why           string
	}{
		{"the entry's own creator", victim, true,
			"the owner may send their own secret wherever they like; that is what the widening right IS"},
		{"an instance admin", admin, true,
			"grantFor row 3: an admin may do anything to any entry, and the write gate says so too, " +
				"so the delivery gate must agree or round 5 recurs with the roles swapped"},
		{"an accepted VIEWER", viewer, false, "THE ROUND-6 BREAK"},
		{"an accepted EDITOR", editor, false,
			"manage is not the right to choose where a secret goes; that is round 3 stated once"},
		{"an accepted MANAGER", manager, false, "same: manage is not the widening right"},
		{"an outsider", outsider, false, "no access at all"},
		{"a DISABLED admin", disabled, false,
			"grantFor row 2: a disabled account has no rights on any path, including this one"},
	}

	delivered := 0
	refused := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := newHeaderSink(t)
			carrier := carriers[tc.who]

			target := RotationTarget{
				Type: "forgejo_secret", Label: "x",
				Instance: sink.URL, Repo: "o/r", SecretName: "S",
				AuthToken: "matrix-team", ConfiguredBy: tc.who,
			}
			// Called directly rather than through PUT /targets: a disabled
			// account cannot drive an HTTP route at all, and the property under
			// test is the DELIVERY answer, which has to be the same for a row
			// that arrived through an import, a backup or an older binary.
			err := deliverToForgejoSecret(ctx, h, target,
				h.MintedEntrySecret([]byte("carrier-rotated"), carrier, "carrier"), tc.who)

			got := sink.sawSecret(teamSecret)
			if got != tc.wantDelivered {
				auths, lines, bodies := sink.received()
				t.Fatalf("the team secret delivered=%v, want %v (%s)\n  err: %v\n  auths=%q lines=%q bodies=%q",
					got, tc.wantDelivered, tc.why, err, auths, lines, bodies)
			}
			if tc.wantDelivered {
				delivered++
				if err != nil {
					t.Fatalf("the delivery reached the sink but reported an error: %v", err)
				}
			} else {
				refused++
				if err == nil {
					t.Fatal("the delivery was refused on the wire but reported SUCCESS, which would " +
						"record a clean rotation for a key nobody received")
				}
			}
		})
	}

	// A matrix where every row answers the same way proves nothing about the
	// rule; it proves the fixture is broken.
	if delivered == 0 || refused == 0 {
		t.Fatalf("VACUOUS: %d delivered, %d refused. Both answers have to appear or this matrix is "+
			"testing a constant", delivered, refused)
	}
	t.Logf("%d principals delivered, %d refused, one rule", delivered, refused)
}

// TestTheSchedulerIsHeldToTheSameRule closes the "with nobody watching" path.
//
// Round 4's report walked it: the scheduler runs with no request, no session and
// no caller, so a gate that reads middleware.IsAdmin or a request context simply
// is not there. It has to reach the same answer from the row.
func TestTheSchedulerIsHeldToTheSameRule(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	victim := mustUser(t, queries, "sched-victim@example.com", "user", "")
	viewer := mustUser(t, queries, "sched-viewer@example.com", "vault_only", "")
	mustCollection(t, queries, "coll-sched", victim, map[string]string{
		victim: collRoleManager,
		viewer: collRoleViewer,
	})
	const teamSecret = "sk_live_SCHED_TEAM_SECRET"
	mustEntry(t, h, queries, "entry-sched-team", victim, "sched-team", teamSecret)
	placeInCollection(t, queries, "entry-sched-team", "coll-sched")
	mustEntry(t, h, queries, "entry-sched-carrier", viewer, "sched-carrier", "seed")

	sink := newHeaderSink(t)
	targets := []RotationTarget{{
		Type: "forgejo_secret", Instance: sink.URL, Repo: "o/r", SecretName: "S",
		AuthToken: "sched-team", ConfiguredBy: viewer,
	}}

	// DeliverRotatedKey is what both the manual handler and the sweep call.
	results := DeliverRotatedKey(ctx, queries, h, "entry-sched-carrier", "sched-carrier",
		h.MintedEntrySecret([]byte("old"), "entry-sched-carrier", "sched-carrier"),
		h.MintedEntrySecret([]byte("new"), "entry-sched-carrier", "sched-carrier"),
		targets, viewer)

	if sink.sawSecret(teamSecret) {
		auths, lines, bodies := sink.received()
		t.Fatalf("the scheduler delivered the team secret to a viewer's host: auths=%q lines=%q bodies=%q",
			auths, lines, bodies)
	}
	if len(results) != 1 || results[0].Success {
		t.Fatalf("the refusal must be a delivery FAILURE, not a silent skip: %+v", results)
	}
	// Loudly, so the operator sees it.
	if status, summary := summarizeDelivery(results); status != "partial" || summary == "" {
		t.Fatalf("the refusal did not surface as a partial rotation: status=%q summary=%q", status, summary)
	}
	// And it must not leak the thing it refused to send.
	if results[0].Error == teamSecret || len(results[0].Error) == 0 {
		t.Fatalf("the refusal message is %q", results[0].Error)
	}
	for _, s := range []string{teamSecret, "new", "old"} {
		if s != "new" && s != "old" && containsAny(results[0].Error, s) {
			t.Fatalf("the refusal leaked a secret: %q", results[0].Error)
		}
	}
}

func containsAny(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}

// TestOwnerWebhookStillReceivesTheRotatedPlaintext is the headline positive
// control the brief names: a guard that stops the feature working is not a fix.
//
// It drives the REAL route end to end and reads the sink.
func TestOwnerWebhookStillReceivesTheRotatedPlaintext(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)

	const password = "owner-login-password"
	owner := mustUser(t, queries, "pos-webhook@example.com", "user", password)
	mustEntry(t, h, queries, "entry-pos-webhook", owner, "prod-key", "seed-value")

	sink := newHeaderSink(t)
	body := `[{"type":"webhook","label":"ci","webhook_url":` + quote(sink.URL+"/deploy") +
		`,"webhook_secret":"hmac"}]`
	if rec := putTargets(t, h, owner, "user", "entry-pos-webhook", body); rec.Code != http.StatusOK {
		t.Fatalf("the owner could not configure their own webhook (%d: %s)", rec.Code, rec.Body.String())
	}

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/entry-pos-webhook/rotate",
		owner, "user", "entry-pos-webhook", `{"password":`+quote(password)+`}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner could not rotate their own secret (%d: %s)", rec.Code, rec.Body.String())
	}
	if !h.WaitForDelivery(30 * time.Second) {
		t.Fatal("delivery did not drain")
	}

	_, lines, bodies := sink.received()
	if len(bodies) == 0 {
		t.Fatal("THE FEATURE IS BROKEN. The owner's own webhook received nothing")
	}
	if !containsAny(bodies[0], `"event":"vault.key_rotated"`) {
		t.Fatalf("the sink received something that is not a rotation payload: %s", bodies[0])
	}
	if containsAny(bodies[0], `"new_value":""`) || !containsAny(bodies[0], `"new_value":"`) {
		t.Fatalf("the payload carries no rotated plaintext: %s", bodies[0])
	}
	if containsAny(bodies[0], "seed-value") {
		t.Fatalf("the delivered value is the PRE-rotation secret: %s", bodies[0])
	}
	t.Logf("wire, owner webhook: %v carrying a freshly rotated plaintext", lines)
}

// TestAnUnauthorisedExitReleasesNoBytes pins the shape of a refusal at the
// handlers boundary: the error and the bytes must not both arrive.
func TestAnUnauthorisedExitReleasesNoBytes(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "bytes-owner@example.com", "user", "")
	stranger := mustUser(t, queries, "bytes-stranger@example.com", "user", "")
	mustEntry(t, h, queries, "entry-bytes", owner, "bytes", "sk_live_BYTES")

	pt, err := h.EntrySecretByID(ctx, "entry-bytes")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, b, err := secretexit.Exit(ctx, pt,
		secretexit.ToHost("a host the stranger chose", secretexit.ChosenBy(stranger), "attacker.example"))
	if err == nil {
		t.Fatal("a stranger's chosen host was authorised for somebody else's secret")
	}
	if len(b) != 0 {
		t.Fatalf("%d bytes came back alongside the refusal", len(b))
	}

	// The owner's own choice still works, so the rule is not "refuse everything".
	_, b, err = secretexit.Exit(ctx, pt,
		secretexit.ToHost("a host the owner chose", secretexit.ChosenBy(owner), "consumer.example"))
	if err != nil {
		t.Fatalf("the owner could not choose a destination for their own secret: %v", err)
	}
	if string(b) != "sk_live_BYTES" {
		t.Fatalf("the authorised exit returned %q", b)
	}
}

// TestBothForgejoExitsAreAskedSeparately is the case an ablation found.
//
// deliverToForgejoSecret carries TWO secrets to one host: the rotated value of
// the entry being delivered, in the body, and another entry's token, in the
// Authorization header. The round-6 fix is about the SECOND one, so every test
// written for it drives a principal who fails on the bearer and never reaches
// the body. Misstating the chooser on the body exit therefore changed nothing
// anybody was looking at.
//
// This is the configuration that separates them: the configurer owns the entry
// the BEARER comes from and does not own the entry being ROTATED. The bearer
// exit says yes, correctly, and the body exit has to say no on its own.
func TestBothForgejoExitsAreAskedSeparately(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	alice := mustUser(t, queries, "split-alice@example.com", "user", "")
	bob := mustUser(t, queries, "split-bob@example.com", "vault_only", "")
	mustCollection(t, queries, "coll-split", alice, map[string]string{
		alice: collRoleManager,
		bob:   collRoleEditor,
	})

	// Alice's shared entry: the one being rotated, whose value goes in the BODY.
	const aliceSecret = "sk_live_ALICES_ROTATED_VALUE"
	mustEntry(t, h, queries, "entry-split-alice", alice, "alice-app", "seed")
	placeInCollection(t, queries, "entry-split-alice", "coll-split")

	// Bob's OWN personal token: the one that goes in the Authorization header.
	// He is its creator, so he genuinely may choose where it goes.
	mustEntry(t, h, queries, "entry-split-bob-pat", bob, "bobs-pat", "bob_PAT_VALUE")

	sink := newHeaderSink(t)
	target := RotationTarget{
		Type: "forgejo_secret", Instance: sink.URL, Repo: "o/r", SecretName: "S",
		AuthToken: "bobs-pat", ConfiguredBy: bob,
	}

	// Guard the setup, both halves, or the assertion below proves nothing about
	// WHICH exit refused.
	if !h.mayConfigureDelivery(ctx, bob, "entry-split-bob-pat") {
		t.Fatal("ABORT: Bob cannot choose where his OWN token goes, so the bearer exit would refuse " +
			"and this test would not reach the body exit at all")
	}
	if h.mayConfigureDelivery(ctx, bob, "entry-split-alice") {
		t.Fatal("ABORT: Bob may choose where Alice's secret goes, so there is nothing for the body " +
			"exit to refuse")
	}

	err := deliverToForgejoSecret(ctx, h, target,
		h.MintedEntrySecret([]byte(aliceSecret), "entry-split-alice", "alice-app"), alice)
	if err == nil {
		t.Fatal("the delivery succeeded. Bob owns the bearer token but not the entry being rotated, " +
			"so the BODY exit had to refuse on its own")
	}
	if sink.sawSecret(aliceSecret) {
		auths, lines, bodies := sink.received()
		t.Fatalf("Alice's rotated value reached a host Bob chose: auths=%q lines=%q bodies=%q",
			auths, lines, bodies)
	}
	// And Bob's own token must not have gone either: the request is not sent at all.
	if sink.sawSecret("bob_PAT_VALUE") {
		t.Fatal("the bearer left even though the delivery was refused")
	}

	// THE POSITIVE CONTROL, in the same shape. Alice configures the same target
	// with her OWN token, and both exits say yes.
	mustEntry(t, h, queries, "entry-split-alice-pat", alice, "alices-pat", "alice_PAT_VALUE")
	ok := RotationTarget{
		Type: "forgejo_secret", Instance: sink.URL, Repo: "o/r", SecretName: "S",
		AuthToken: "alices-pat", ConfiguredBy: alice,
	}
	if err := deliverToForgejoSecret(ctx, h, ok,
		h.MintedEntrySecret([]byte(aliceSecret), "entry-split-alice", "alice-app"), alice); err != nil {
		t.Fatalf("THE FEATURE IS BROKEN: the owner's own two-secret delivery was refused: %v", err)
	}
	if !sink.sawSecret(aliceSecret) || !sink.sawSecret("alice_PAT_VALUE") {
		auths, _, bodies := sink.received()
		t.Fatalf("the owner's delivery did not carry both secrets: auths=%q bodies=%q", auths, bodies)
	}
}

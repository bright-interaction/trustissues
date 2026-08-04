package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TWO GATES THAT MUST AGREE, AND THE ONE THAT DRIFTED.
//
// The product rule is written down in five places (the 403 body, the
// mayDirectSecretEgress doc, the UpdateTargets comment, THREAT-MODEL.md and
// DEFERRED.md) in the same words:
//
//	adding a delivery destination takes the entry's creator OR AN INSTANCE ADMIN.
//
// Round 5 implemented it twice.
//
//	write     UpdateTargets -> decideDeliveryEgress(ctx, userID,
//	          middleware.IsAdmin(ctx), ...). An admin PASSES.
//	delivery  targetStillAuthorized -> mayDirectSecretEgress(ctx,
//	          target.ConfiguredBy, false, entryID). isAdmin HARDCODED false, so
//	          the same admin FAILS.
//
// The result is the worst of the three possible behaviours: the write is
// accepted, the operator is told it worked, and every subsequent rotation
// silently does not deliver. An operator wiring up delivery on a team secret
// (which is what an instance admin is FOR) gets a rotation panel that lies.
//
// The rule that is correct is the one everybody already documented: an instance
// admin may configure delivery. So the delivery half has to be able to answer
// "is this configurer an instance admin?" too. There is no request context at
// delivery, so the only possible source is the users table, and therefore the
// WRITE half must read it from the same place: a session that still claims
// admin after a demotion would otherwise re-create the identical disagreement
// with the roles swapped.
//
// mayConfigureDelivery is that single answer. Both halves call it with the same
// two arguments, so there is no isAdmin argument left for a call site to get
// wrong.

// TestInstanceAdminDeliveryTargetIsAcceptedAndDelivered is the wire-level half.
//
// It asserts the property that "accepted then silent" violates: if the write
// gate takes the target, a real rotation must really deliver it, to a real HTTP
// server that records what it received.
func TestInstanceAdminDeliveryTargetIsAcceptedAndDelivered(t *testing.T) {
	swapProviderHTTP(t)

	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const ownerPassword = "correct-horse-battery-staple"
	owner := mustUser(t, queries, "agree-owner@example.com", "user", ownerPassword)
	// The instance admin is deliberately NOT a member of the collection. That is
	// the shape the two halves disagree about: grantFor row 3 hands an admin
	// manage on any entry, and every other row would refuse them.
	admin := mustUser(t, queries, "agree-admin@example.com", "admin", "")

	mustCollection(t, queries, "coll-agree", owner, map[string]string{owner: collRoleManager})
	const entryID = "entry-agree"
	mustEntry(t, h, queries, entryID, owner, "team-stripe", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-agree")

	consumer := newDeliverySink(t)

	// ── the write half ──────────────────────────────────────────────────────
	body := `[{"type":"webhook","label":"ops","webhook_url":"` + consumer.URL + `/deploy"}]`
	rec := putTargets(t, h, admin, "admin", entryID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: an instance admin could not configure a delivery target: HTTP %d (%s).\n"+
			"Every statement of this rule in the tree says the creator OR AN INSTANCE ADMIN may. If the "+
			"decision is that admins may NOT, this test is the place to say so, and UpdateTargets has to "+
			"refuse them at the write rather than accept and never deliver",
			rec.Code, rec.Body.String())
	}

	stored, err := queries.GetVaultEntryTargets(ctx, entryID)
	if err != nil {
		t.Fatalf("read back targets: %v", err)
	}
	targets := ParseRotationTargets(h.decryptColumnOrLog(stored.String, "[]", "rotation_targets"))
	if len(targets) != 1 || targets[0].ConfiguredBy != admin {
		t.Fatalf("stored targets = %+v, want one attributed to the admin %q", targets, admin)
	}

	// ── the delivery half, on the wire ──────────────────────────────────────
	//
	// Not "targetStillAuthorized returns nil". A rotation, through the real
	// route, and then a read of what the sink actually received.
	out := httptest.NewRecorder()
	h.Rotate(out, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/rotate", owner, "user",
		entryID, `{"password":`+quote(ownerPassword)+`}`))
	if out.Code != http.StatusOK {
		t.Fatalf("ABORT: the owner could not rotate their own secret (%d: %s)", out.Code, out.Body.String())
	}
	if !h.WaitForDelivery(30 * time.Second) {
		t.Fatal("rotation delivery did not drain; the wire assertion below would be racing it")
	}

	hosts, bodies := consumer.got()
	if len(bodies) == 0 {
		t.Fatalf("THE HALVES DISAGREE. The write gate accepted an instance admin's delivery target and "+
			"the rotation delivered NOTHING to it.\n"+
			"  write:    decideDeliveryEgress -> mayDirectSecretEgress(..., isAdmin, ...) -> allowed\n"+
			"  delivery: targetStillAuthorized -> mayDirectSecretEgress(..., false, ...) -> refused\n"+
			"An accepted configuration that never delivers is worse than a refusal: the operator is told "+
			"it worked and the consumer never gets the key. Rotation result: %s", out.Body.String())
	}
	var payload struct {
		Event     string `json:"event"`
		EntryName string `json:"entry_name"`
		NewValue  string `json:"new_value"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &payload); err != nil {
		t.Fatalf("the consumer received something that is not a delivery payload (%q): %v", bodies[0], err)
	}
	if payload.Event != "vault.key_rotated" || payload.EntryName != "team-stripe" || payload.NewValue == "" {
		t.Fatalf("the consumer received %+v, want the rotated value for team-stripe", payload)
	}
	t.Logf("wire, admin-configured target: hosts=%v event=%s entry=%s", hosts, payload.Event, payload.EntryName)

	// And the rotation must not be recorded as partial, which is what a silent
	// delivery refusal looks like to an operator reading the panel.
	if strings.Contains(out.Body.String(), "delivery target skipped") {
		t.Errorf("the rotation reported a skipped target while the sink received the value: %s", out.Body.String())
	}
}

// TestDemotedAdminStopsDeliveringAndCannotConfigure is the other direction of
// the same rule, and the reason both halves must read the users table rather
// than the request context.
//
// A session carries the role it was minted with. If the write half trusted that
// claim, a demoted admin would keep passing the write gate while the delivery
// gate, which has no session to read, correctly refused: the identical
// "accepted then silent" defect with the roles swapped.
func TestDemotedAdminStopsDeliveringAndCannotConfigure(t *testing.T) {
	swapProviderHTTP(t)

	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "demote-owner@example.com", "user", "")
	admin := mustUser(t, queries, "demote-admin@example.com", "admin", "")
	mustCollection(t, queries, "coll-demote", owner, map[string]string{owner: collRoleManager})
	const entryID = "entry-demote"
	mustEntry(t, h, queries, entryID, owner, "team-stripe", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-demote")

	sink := newDeliverySink(t)
	rec := putTargets(t, h, admin, "admin", entryID,
		`[{"type":"webhook","label":"ops","webhook_url":"`+sink.URL+`/deploy"}]`)
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the admin could not configure the target: %d %s", rec.Code, rec.Body.String())
	}
	target := RotationTarget{Type: "webhook", Label: "ops", WebhookURL: sink.URL + "/deploy", ConfiguredBy: admin}
	if err := targetStillAuthorized(ctx, h, entryID, target); err != nil {
		t.Fatalf("ABORT: the admin's own target is refused at delivery before any demotion: %v", err)
	}

	// Demote in the DATABASE, which is what an operator does, and leave the
	// session claim alone.
	if _, err := h.db.ExecContext(ctx, `UPDATE users SET role = 'user' WHERE id = ?`, admin); err != nil {
		t.Fatalf("demote: %v", err)
	}

	if err := targetStillAuthorized(ctx, h, entryID, target); err == nil {
		t.Error("a demoted admin's delivery target is still authorized; the delivery gate is reading a " +
			"stale role")
	}
	// The write half must agree, using the same source. A stale session that
	// still says "admin" must not get a target accepted that delivery will then
	// silently drop.
	rec = putTargets(t, h, admin, "admin", entryID,
		`[{"type":"webhook","label":"ops","webhook_url":"`+sink.URL+`/deploy"},`+
			`{"type":"webhook","label":"second","webhook_url":"`+sink.URL+`/second"}]`)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a demoted admin, presenting a session that still claims admin, added a delivery "+
			"destination: HTTP %d (%s). The write gate is trusting the session claim while the delivery "+
			"gate reads the users table, which is the same disagreement in the other direction",
			rec.Code, rec.Body.String())
	}
}

// TestDeliveryGateAgreesWithWriteGate is the drift guard.
//
// "Two gates that must agree" is exactly the shape that rots, so this does not
// assert what either half answers. It runs BOTH halves over the same principals
// against the same database and fails if they ever differ, whatever the answer
// is. A future change that tightens or relaxes the rule stays green as long as
// it changes both halves; a change that touches one of them reds here and names
// the principal it disagreed about.
func TestDeliveryGateAgreesWithWriteGate(t *testing.T) {
	swapProviderHTTP(t)

	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "drift-creator@example.com", "user", "")
	admin := mustUser(t, queries, "drift-admin@example.com", "admin", "")
	editor := mustUser(t, queries, "drift-editor@example.com", "vault_only", "")
	manager := mustUser(t, queries, "drift-manager@example.com", "user", "")
	viewer := mustUser(t, queries, "drift-viewer@example.com", "user", "")
	outsider := mustUser(t, queries, "drift-outsider@example.com", "user", "")
	disabledAdmin := mustUser(t, queries, "drift-disabled-admin@example.com", "admin", "")
	if _, err := h.db.ExecContext(ctx, `UPDATE users SET disabled = 1 WHERE id = ?`, disabledAdmin); err != nil {
		t.Fatalf("disable: %v", err)
	}

	mustCollection(t, queries, "coll-drift", creator, map[string]string{
		creator: collRoleManager,
		manager: collRoleManager,
		editor:  collRoleEditor,
		viewer:  collRoleViewer,
	})
	const entryID = "entry-drift"
	mustEntry(t, h, queries, entryID, creator, "team-stripe", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-drift")

	sink := newDeliverySink(t)

	cases := []struct {
		name   string
		userID string
		role   string
	}{
		{"entry creator", creator, "user"},
		{"instance admin, not a collection member", admin, "admin"},
		{"collection editor", editor, "vault_only"},
		{"collection manager who did not create the entry", manager, "user"},
		{"collection viewer", viewer, "user"},
		{"outsider", outsider, "user"},
		{"disabled instance admin", disabledAdmin, "admin"},
		{"unknown user id", "no-such-user", "admin"},
		{"empty user id", "", "user"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The WRITE half, through the real route. A target is added, so the
			// oracle is consulted; 200 means the gate said yes.
			//
			// Reset the column first so every case is judged against the same
			// stored state and one case cannot make the next one a narrowing.
			if _, err := h.db.ExecContext(ctx, `UPDATE vault_entries SET rotation_targets = NULL WHERE id = ?`,
				entryID); err != nil {
				t.Fatalf("reset targets: %v", err)
			}
			rec := putTargets(t, h, tc.userID, tc.role, entryID,
				`[{"type":"webhook","label":"x","webhook_url":"`+sink.URL+`/deploy"}]`)
			writeAllowed := rec.Code == http.StatusOK

			// The DELIVERY half, on a row attributed to the same principal.
			deliveryErr := targetStillAuthorized(ctx, h, entryID, RotationTarget{
				Type: "webhook", Label: "x", WebhookURL: sink.URL + "/deploy", ConfiguredBy: tc.userID,
			})
			deliveryAllowed := deliveryErr == nil

			if writeAllowed != deliveryAllowed {
				t.Fatalf("THE HALVES DISAGREE about %s (%q).\n"+
					"  write gate  (PUT /api/vault/{id}/targets): allowed=%v (HTTP %d: %s)\n"+
					"  delivery gate (targetStillAuthorized):     allowed=%v (%v)\n"+
					"Accepting a configuration that will never deliver is the worst of the three "+
					"options: the operator is told it worked and the consumer never gets the key. "+
					"Both halves must call VaultHandler.mayConfigureDelivery.",
					tc.name, tc.userID, writeAllowed, rec.Code, strings.TrimSpace(rec.Body.String()),
					deliveryAllowed, deliveryErr)
			}
			t.Logf("%s: write=%v delivery=%v", tc.name, writeAllowed, deliveryAllowed)
		})
	}

	// The matrix is only evidence if it contains both answers. A bug that makes
	// every principal fail, or every principal pass, would agree everywhere.
	var allowed, refused int
	for _, tc := range cases {
		if _, err := h.db.ExecContext(ctx, `UPDATE vault_entries SET rotation_targets = NULL WHERE id = ?`,
			entryID); err != nil {
			t.Fatalf("reset targets: %v", err)
		}
		if putTargets(t, h, tc.userID, tc.role, entryID,
			`[{"type":"webhook","label":"x","webhook_url":"`+sink.URL+`/deploy"}]`).Code == http.StatusOK {
			allowed++
		} else {
			refused++
		}
	}
	if allowed == 0 || refused == 0 {
		t.Fatalf("ABORT: the matrix is vacuous, %d allowed and %d refused. Two gates that both say no to "+
			"everybody agree perfectly and protect nothing", allowed, refused)
	}
	t.Logf("agreement matrix: %d principals allowed, %d refused", allowed, refused)
}

// TestNotifyTargetsStayOpenToManage pins the other half of the delivery rule so
// the fix above cannot quietly widen it. A notify target carries no value, so it
// is not a destination and an editor may still configure one.
func TestNotifyTargetsStayOpenToManage(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	owner := mustUser(t, queries, "notify-owner@example.com", "user", "")
	editor := mustUser(t, queries, "notify-editor@example.com", "vault_only", "")
	mustCollection(t, queries, "coll-notify", owner, map[string]string{
		owner: collRoleManager, editor: collRoleEditor,
	})
	const entryID = "entry-notify"
	mustEntry(t, h, queries, entryID, owner, "team-stripe", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-notify")

	if rec := putTargets(t, h, editor, "vault_only", entryID,
		`[{"type":"notify","label":"tell-me"}]`); rec.Code != http.StatusOK {
		t.Fatalf("an editor could not configure a notify target (%d: %s); notify transmits no value, so "+
			"it is not a delivery destination and must stay open to manage", rec.Code, rec.Body.String())
	}

	// The reference to db keeps this file honest about which package the fixture
	// helpers come from; without it a future refactor could silently drop them.
	if _, err := queries.GetVaultEntryTargets(context.Background(), entryID); err != nil {
		t.Fatalf("read back targets: %v", err)
	}
	var _ db.Queries
}

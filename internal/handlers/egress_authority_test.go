package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE ROUND-4 BLOCKER, REPRODUCED AND CLOSED.
//
// The verdict, verbatim: "provider_meta is an ungated second host-choosing
// column: an accepted vault_only editor sets provider / provider_meta /
// auto_rotate via the same PUT with no password, and the rotation scheduler
// delivers the operator's decrypted gateway key to attacker.grafana.net (or any
// host at all via datadog's site field)."
//
// Every assertion below is on WHAT THE FAKE UPSTREAM RECEIVED. A status code
// says what a handler decided; only the wire says where the secret went, and
// three rounds of this stream shipped a green suite while the secret was still
// leaving. The positive controls are not decoration either: a "fix" that simply
// broke rotation and validation would satisfy every refusal in this file.

// providerWire records every request that actually left, with enough of it to
// answer "did the secret travel, and where to".
type providerWire struct {
	reqs []providerWireReq
}

type providerWireReq struct {
	host    string
	method  string
	path    string
	headers string
	body    string
}

func (w *providerWire) RoundTrip(r *http.Request) (*http.Response, error) {
	var body string
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}
	var hdr strings.Builder
	for k, vs := range r.Header {
		hdr.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	w.reqs = append(w.reqs, providerWireReq{
		host: r.URL.Hostname(), method: r.Method, path: r.URL.Path,
		headers: hdr.String(), body: body,
	})
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"key":"NEW","token":"NEW","id":"1"}`)),
		Request:    r,
	}, nil
}

func (w *providerWire) reset() { w.reqs = nil }

// carried reports whether the secret appears anywhere on the wire, in a header
// or in a body. Providers inject it differently (Bearer, DD-API-KEY, apikey,
// Basic), so the assertion looks at everything rather than at one header name.
func (w *providerWire) carried(secret string) []providerWireReq {
	var out []providerWireReq
	for _, r := range w.reqs {
		if strings.Contains(r.headers, secret) || strings.Contains(r.body, secret) {
			out = append(out, r)
		}
	}
	return out
}

func (w *providerWire) hosts() []string {
	out := make([]string, 0, len(w.reqs))
	for _, r := range w.reqs {
		out = append(out, r.method+" "+r.host+r.path)
	}
	return out
}

// installProviderWire swaps the shared provider client for a recorder.
func installProviderWire(t *testing.T) *providerWire {
	t.Helper()
	wire := &providerWire{}
	prev := providerHTTP
	providerHTTP = &http.Client{Transport: wire}
	t.Cleanup(func() { providerHTTP = prev })
	return wire
}

// assertNothingLeftFor is the assertion that matters, stated once.
func assertNothingLeftFor(t *testing.T, wire *providerWire, secret, forbiddenHost string) {
	t.Helper()
	for _, r := range wire.reqs {
		if r.host == forbiddenHost {
			t.Fatalf("a request reached %s (%s %s); headers were:\n%s",
				forbiddenHost, r.method, r.path, r.headers)
		}
	}
	if leaked := wire.carried(secret); len(leaked) > 0 {
		t.Fatalf("the operator's secret went out on the wire to %v", leaked)
	}
}

// putVault drives the REAL PUT /api/vault/{id} as the given principal.
func putVault(t *testing.T, h *VaultHandler, userID, role, entryID string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+entryID, userID, role, entryID, string(raw)))
	return rec
}

// forceProviderConfig writes provider + provider_meta + auto_rotate straight
// into the database, bypassing every handler.
//
// It stands in for any writer that is NOT the PUT the write gate guards: an
// older binary, a restored backup, an import, the next second writer nobody has
// written yet. Round 3's fix held at the write and the review moved one column
// over; a fix that only guards writes moves the same way again.
func forceProviderConfig(t *testing.T, h *VaultHandler, entryID, provider, metaJSON string) {
	t.Helper()
	enc, err := h.encryptColumn(metaJSON)
	if err != nil {
		t.Fatalf("encrypt provider_meta: %v", err)
	}
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET provider = ?, provider_meta = ?, auto_rotate = 1,
		 rotation_interval_days = 1, last_rotated_at = datetime('now','-90 days'),
		 updated_at = datetime('now','-1 hour') WHERE id = ?`,
		provider, enc, entryID); err != nil {
		t.Fatalf("force provider config: %v", err)
	}
}

func storedProvider(t *testing.T, queries *db.Queries, entryID string) (string, string) {
	t.Helper()
	row, err := queries.GetVaultEntryMeta(context.Background(), entryID)
	if err != nil {
		t.Fatalf("reload entry: %v", err)
	}
	return row.Provider.String, row.ProviderMeta.String
}

const egressTestPassword = "CorrectHorseBatteryStaple1!"

// TestEditorCannotRedirectTheGatewayKeyThroughTheProviderConfiguration is the
// round-4 blocker end to end, on the exact entry the report names: the one an
// admin wired into the AI gateway.
func TestEditorCannotRedirectTheGatewayKeyThroughTheProviderConfiguration(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	wire := installProviderWire(t)

	const (
		entryID      = "entry-team-openai"
		theKey       = "sk-openai-OPERATOR-KEY"
		attackerHost = "api.attacker-controlled.example"
	)

	operator := mustUser(t, queries, "operator@example.com", "user", egressTestPassword)
	// The role RedeemInvitation hands out over the PUBLIC invite endpoint,
	// holding an accepted EDITOR seat. grantFor row 5 gives it manage.
	attacker := mustUser(t, queries, "attacker@example.com", "vault_only", egressTestPassword)
	mustCollection(t, queries, "coll-team", operator, map[string]string{
		operator: collRoleManager,
		attacker: collRoleEditor,
	})
	mustEntry(t, h, queries, entryID, operator, "team-openai", theKey)
	placeInCollection(t, queries, entryID, "coll-team")
	if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
		Provider:     toNullString("openai"),
		ProviderMeta: toNullString("{}"),
		AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
		ID:           entryID,
	}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	// PUT /api/settings/ai is AdminOnly; this is that write.
	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "ai_key_openai", Value: entryID}); err != nil {
		t.Fatalf("wire the gateway: %v", err)
	}

	t.Run("STEP 1: the reported PUT is refused and nothing is stored", func(t *testing.T) {
		// Exactly the request from the verdict: provider, provider_meta and
		// auto_rotate in one body, no password anywhere.
		rec := putVault(t, h, attacker, "vault_only", entryID, map[string]any{
			"provider":      "datadog",
			"provider_meta": `{"site":"attacker-controlled.example","app_key":"x"}`,
			"auto_rotate":   true,
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("the reported PUT returned %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "egress_widening_denied") {
			t.Errorf("the refusal should name the reason, got %s", rec.Body.String())
		}
		p, m := storedProvider(t, queries, entryID)
		if p != "openai" {
			t.Fatalf("the provider was changed anyway: %q", p)
		}
		if strings.Contains(h.decryptColumnOrLog(m, "{}", vaultFieldProviderMeta), "attacker") {
			t.Fatalf("provider_meta was written anyway: %s", h.decryptColumnOrLog(m, "{}", vaultFieldProviderMeta))
		}
	})

	t.Run("STEP 1b: the grafana variant from the verdict is refused too", func(t *testing.T) {
		rec := putVault(t, h, attacker, "vault_only", entryID, map[string]any{
			"provider":      "grafana",
			"provider_meta": `{"instance":"attacker","service_account_id":"1"}`,
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("pointing the key at attacker.grafana.net returned %d, want 403 (body: %s)",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("STEP 1c: provider_meta alone, with the provider left as it was", func(t *testing.T) {
		// The narrowest form of the attack, and the one a gate watching only
		// `provider` misses entirely.
		//
		// The rule under test is not "the column is read-only". It is "the set of
		// hosts this entry can reach must not grow". openai declares a fixed
		// host, so parking a datadog-shaped site key on it changes nothing, and
		// the assertion is on the host set rather than on the status code:
		// whatever the handler decided, the reachable set must be what it was.
		before := declaredProviderEgress("openai", map[string]string{})
		putVault(t, h, attacker, "vault_only", entryID, map[string]any{
			"provider_meta": `{"site":"attacker-controlled.example"}`,
		})
		p, m := storedProvider(t, queries, entryID)
		after := declaredProviderEgress(p, ParseProviderMeta(h.decryptColumnOrLog(m, "{}", vaultFieldProviderMeta)))
		if after.Describe() != before.Describe() {
			t.Fatalf("the reachable host set moved from %s to %s on a write by an editor",
				before.Describe(), after.Describe())
		}
	})

	t.Run("a server-owned provider_meta key cannot be planted", func(t *testing.T) {
		// performPendingRevoke issues meta[pending_revoke_url] with
		// "Authorization: Bearer <the NEW secret>". Planting one would have the
		// rotation engine post the freshly minted credential wherever it said.
		rec := putVault(t, h, operator, "user", entryID, map[string]any{
			"provider_meta": `{"pending_revoke_url":"https://` + attackerHost + `/collect","pending_revoke_method":"POST"}`,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("planting pending_revoke_url returned %d, want 400 (body: %s)", rec.Code, rec.Body.String())
		}
	})

	// Everything above depends on the write path. Now give the attacker what a
	// write gate cannot take back: the row itself, already rewritten.
	forceProviderConfig(t, h, entryID, "datadog", `{"site":"attacker-controlled.example","app_key":"x"}`)

	t.Run("the SCHEDULER refuses a row that was already rewritten", func(t *testing.T) {
		// ANTI-VACUITY FIRST. "The sweep sent nothing" is also what a sweep that
		// never looked at this entry produces, and that is the shape of a test
		// that passes for the wrong reason. Prove the due query selects it before
		// asserting on what it did.
		due, dueErr := queries.ListVaultEntriesNeedingRotation(ctx)
		if dueErr != nil {
			t.Fatalf("list due entries: %v", dueErr)
		}
		found := false
		for _, e := range due {
			if e.ID == entryID {
				found = true
			}
		}
		if !found {
			t.Fatalf("ABORT: the rewritten entry is not selected by the due query, so this case is "+
				"not exercising the scheduler at all (%d entries due)", len(due))
		}

		wire.reset()
		RotateVaultKeys(h.db, queries, h)
		if !h.WaitForDelivery(5 * 1e9) {
			t.Fatal("delivery did not drain")
		}
		assertNothingLeftFor(t, wire, theKey, attackerHost)
		if len(wire.reqs) != 0 {
			t.Fatalf("the sweep dialled %v on a pinned entry pointed at somebody else's host", wire.hosts())
		}
		// And the refusal has to be RECORDED, or an operator watching a key that
		// silently stopped rotating has nothing to look at.
		row, rErr := queries.GetVaultEntryMeta(ctx, entryID)
		if rErr != nil {
			t.Fatalf("reload entry: %v", rErr)
		}
		if row.LastRotationError.String == "" {
			t.Error("the sweep refused the rotation and recorded nothing; the entry now looks healthy " +
				"while its schedule is dead")
		}
	})

	t.Run("VALIDATE refuses it too, and that is the fastest path", func(t *testing.T) {
		// No scheduler wait and no rotation: POST /api/vault/{id}/validate
		// decrypts the key and authenticates with it upstream, needing only the
		// CALLER'S OWN password. An accepted editor has one.
		wire.reset()
		rec := httptest.NewRecorder()
		body := `{"password":` + jsonQuote(egressTestPassword) + `}`
		h.ValidateKey(rec, vaultAuthzRequest(http.MethodPost,
			"/api/vault/"+entryID+"/validate", attacker, "vault_only", entryID, body))
		assertNothingLeftFor(t, wire, theKey, attackerHost)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("validate against a rewritten row returned %d, want 403 (body: %s)",
				rec.Code, rec.Body.String())
		}
		if len(wire.reqs) != 0 {
			t.Fatalf("validate dialled %v", wire.hosts())
		}
	})

	t.Run("POSITIVE CONTROL: the real key still reaches the real provider", func(t *testing.T) {
		// Without this, a fix that broke validation outright would pass every
		// assertion above.
		if err := setProviderFixture(t, queries, vaultegress.ProviderParams{
			Provider:     toNullString("openai"),
			ProviderMeta: toNullString("{}"),
			AutoRotate:   sql.NullInt64{Int64: 0, Valid: true},
			ID:           entryID,
		}); err != nil {
			t.Fatalf("restore provider: %v", err)
		}
		wire.reset()
		rec := httptest.NewRecorder()
		body := `{"password":` + jsonQuote(egressTestPassword) + `}`
		h.ValidateKey(rec, vaultAuthzRequest(http.MethodPost,
			"/api/vault/"+entryID+"/validate", operator, "user", entryID, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("the legitimate validate returned %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
		if len(wire.reqs) != 1 || wire.reqs[0].host != "api.openai.com" {
			t.Fatalf("the legitimate validate reached %v, want one call to api.openai.com", wire.hosts())
		}
		if !strings.Contains(wire.reqs[0].headers, theKey) {
			t.Fatalf("the operator's key did NOT reach the provider; the guard has broken the "+
				"feature rather than scoped it. headers:\n%s", wire.reqs[0].headers)
		}
	})
}

// TestEditorCannotRedirectAnOrdinarySharedSecretThroughProviderMeta is the
// general rule, on a secret with no AI gateway anywhere near it.
//
// The pin only covers the entry an admin wired into the gateway. Every OTHER
// shared secret is exposed by the same shape, and it is the shape that matters:
// grafana's "instance" is a per-tenant label that anybody can register at
// Grafana Cloud, so repointing it is not a theoretical redirect.
func TestEditorCannotRedirectAnOrdinarySharedSecretThroughProviderMeta(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	wire := installProviderWire(t)

	const (
		entryID = "entry-team-grafana"
		theKey  = "glsa_OPERATOR_GRAFANA_TOKEN"
	)

	owner := mustUser(t, queries, "owner@example.com", "user", egressTestPassword)
	editor := mustUser(t, queries, "editor@example.com", "vault_only", egressTestPassword)
	admin := mustUser(t, queries, "admin@example.com", "admin", egressTestPassword)
	mustCollection(t, queries, "coll-obs", owner, map[string]string{
		owner:  collRoleManager,
		editor: collRoleEditor,
	})
	mustEntry(t, h, queries, entryID, owner, "team-grafana", theKey)
	placeInCollection(t, queries, entryID, "coll-obs")
	forceProviderConfig(t, h, entryID, "grafana", `{"instance":"acme","service_account_id":"7"}`)

	t.Run("the editor cannot move the instance", func(t *testing.T) {
		rec := putVault(t, h, editor, "vault_only", entryID, map[string]any{
			"provider_meta": `{"instance":"attacker","service_account_id":"7"}`,
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("moving the grafana instance returned %d, want 403 (body: %s)", rec.Code, rec.Body.String())
		}
		_, m := storedProvider(t, queries, entryID)
		if strings.Contains(h.decryptColumnOrLog(m, "{}", vaultFieldProviderMeta), "attacker") {
			t.Fatalf("stored anyway: %s", h.decryptColumnOrLog(m, "{}", vaultFieldProviderMeta))
		}
	})

	t.Run("and the scheduler still delivers only to the operator's instance", func(t *testing.T) {
		wire.reset()
		RotateVaultKeys(h.db, queries, h)
		if !h.WaitForDelivery(5 * 1e9) {
			t.Fatal("delivery did not drain")
		}
		for _, r := range wire.reqs {
			if r.host != "acme.grafana.net" {
				t.Fatalf("the sweep dialled %q; the only host this entry names is acme.grafana.net", r.host)
			}
		}
		// POSITIVE CONTROL in the same breath: the rotation must actually have
		// happened, carrying the real token, or the refusals above are worthless.
		if len(wire.carried(theKey)) == 0 {
			t.Fatalf("the scheduled rotation never authenticated with the stored token; it reached %v. "+
				"A guard that stops the feature working is not a fix", wire.hosts())
		}
	})

	t.Run("the owner and an instance admin still can", func(t *testing.T) {
		// The right is narrower than manage, not narrower than everything. If
		// this fails the product has lost the ability to move a self-hosted
		// instance at all.
		if rec := putVault(t, h, owner, "user", entryID, map[string]any{
			"provider_meta": `{"instance":"acme-new","service_account_id":"7"}`,
		}); rec.Code != http.StatusOK {
			t.Fatalf("the entry's creator was refused: %d %s", rec.Code, rec.Body.String())
		}
		if rec := putVault(t, h, admin, "admin", entryID, map[string]any{
			"provider_meta": `{"instance":"acme-admin","service_account_id":"7"}`,
		}); rec.Code != http.StatusOK {
			t.Fatalf("an instance admin was refused: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("an editor may still edit everything that is not a destination", func(t *testing.T) {
		// The counterweight. Narrowing this right too far takes shared editing
		// away, which is a product regression dressed as a security fix.
		if rec := putVault(t, h, editor, "vault_only", entryID, map[string]any{
			"notes":       "rotated by the on-call rota",
			"category":    "other",
			"auto_rotate": false,
		}); rec.Code != http.StatusOK {
			t.Fatalf("an editor could not save ordinary metadata: %d %s", rec.Code, rec.Body.String())
		}
		// And clearing the provider is a NARROWING (it reaches fewer hosts), so
		// it stays open to manage: an editor must be able to unhook a broken
		// integration without hunting down the creator.
		if rec := putVault(t, h, editor, "vault_only", entryID, map[string]any{
			"provider": "",
		}); rec.Code != http.StatusOK {
			t.Fatalf("an editor could not clear the provider: %d %s", rec.Code, rec.Body.String())
		}
	})
	_ = ctx
}

// TestVaultOnlyCannotMintACapabilityToken closes the item the previous round
// reported and left open.
//
// The route fix (POST /api/secrets/issue and /api/mcp behind VaultOnlyBlock) is
// pinned by TestServerRoutesKeepTheirGuards, which parses cmd/server/main.go.
// This is the handler's own refusal, and the two are not redundant: the first
// failure of this exact property was that /api/ai was blocked while the mint
// route beside it was not, which no handler test in this package could see. A
// handler that refuses on its own cannot be un-refused by moving a line in
// main.go.
func TestVaultOnlyCannotMintACapabilityToken(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	capH, err := NewCapabilityHandler(h.db, h, testEgressVaultKey)
	if err != nil {
		t.Fatalf("NewCapabilityHandler: %v", err)
	}

	const (
		entryID = "entry-team-key"
		theKey  = "sk-openai-OPERATOR-KEY"
	)
	operator := mustUser(t, queries, "op@example.com", "user", "")
	attacker := mustUser(t, queries, "vo@example.com", "vault_only", "")
	mustCollection(t, queries, "coll-x", operator, map[string]string{
		operator: collRoleManager,
		attacker: collRoleEditor,
	})
	mustEntry(t, h, queries, entryID, operator, "team-openai", theKey)
	placeInCollection(t, queries, entryID, "coll-x")
	if _, err := h.db.Exec(
		`UPDATE vault_entries SET destination_patterns = ?, injection_spec = ? WHERE id = ?`,
		`["api.openai.com/*"]`, `{"type":"bearer"}`, entryID); err != nil {
		t.Fatalf("seed ceiling: %v", err)
	}

	mint := func(userID, role string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(issueRequest{Secret: "team-openai", AgentID: "agent-1"})
		r := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", bytes.NewReader(body))
		ctx := context.WithValue(r.Context(), timw.UserIDKey, userID)
		ctx = context.WithValue(ctx, timw.UserRoleKey, role)
		rec := httptest.NewRecorder()
		capH.Issue(rec, r.WithContext(ctx))
		return rec
	}

	rec := mint(attacker, "vault_only")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a vault_only account minted a capability token: %d %s.\n"+
			"That token is spent at /proxy, which injects the operator's decrypted key upstream, so "+
			"blocking /api/ai and leaving this open is the same door twice.", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "token") && strings.Contains(rec.Body.String(), "proxy_url") {
		t.Fatalf("a token came back in the refusal body: %s", rec.Body.String())
	}

	// POSITIVE CONTROL: an ordinary user still mints, or the bridge is simply
	// broken and every assertion above is vacuous.
	if ok := mint(operator, "user"); ok.Code != http.StatusCreated {
		t.Fatalf("an ordinary user could not mint: %d %s", ok.Code, ok.Body.String())
	}
}

// TestProviderDoFailsClosed pins the two defaults nothing else can reach.
//
// Both are unreachable through any handler today, which is exactly why they need
// their own test: a default that no test exercises is a default that can be
// inverted without a single failure. The chokepoint's whole value is that
// forgetting to say where a secret may go REFUSES rather than allows.
func TestProviderDoFailsClosed(t *testing.T) {
	wire := installProviderWire(t)

	t.Run("no authority in the context is a refusal", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.openai.com/v1/models", nil)
		resp, err := providerDo(req)
		if err == nil {
			if resp != nil {
				resp.Body.Close()
			}
			t.Fatal("a request with no egress authority was forwarded. A new call site that forgets " +
				"to install one must fail loudly, not inherit a permissive default")
		}
		if len(wire.reqs) != 0 {
			t.Fatalf("it reached the wire anyway: %v", wire.hosts())
		}
	})

	t.Run("a provider with no declaration reaches nothing", func(t *testing.T) {
		// An exit that authorised an EMPTY host set never happens: Exit refuses a
		// network destination with no host. So the only way to hold a receipt for
		// an undeclared provider is not to hold one, and the request is refused.
		ctx := exitReceiptForTest(t, "a-provider-nobody-declared", declaredProviderEgress("a-provider-nobody-declared", nil))
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/x", nil)
		resp, err := providerDo(req)
		if err == nil {
			if resp != nil {
				resp.Body.Close()
			}
			t.Fatal("an undeclared provider egressed. declaredProviderEgress must return an EMPTY " +
				"allowance for a name it does not know, so adding an adapter without declaring its " +
				"hosts cannot reach the network")
		}
		if len(wire.reqs) != 0 {
			t.Fatalf("it reached the wire anyway: %v", wire.hosts())
		}
	})
}

// failingSettingReader makes providerPinFor fail the way a database error does.
type failingSettingReader struct{}

func (failingSettingReader) GetSetting(context.Context, string) (string, error) {
	return "", errFakeSettingsRead
}

var errFakeSettingsRead = &settingsReadError{}

type settingsReadError struct{}

func (*settingsReadError) Error() string { return "settings table unreadable" }

// TestProviderEgressRefusesWhenThePinCannotBeRead closes a gap an ablation
// found: nothing exercised the pin's READ-ERROR path.
//
// providerPinFor's own doc says callers deny on a read error, and the whole
// guard stands between a decrypted provider key and an attacker-named host, so
// "cannot tell" must not resolve to "allowed". Inverting that branch left every
// test in this package green, which is the definition of an unguarded property.
func TestProviderEgressRefusesWhenThePinCannotBeRead(t *testing.T) {
	_, _, err := spendProviderSecret(context.Background(), failingSettingReader{},
		secretexit.Minted([]byte("k"), secretexit.Origin{EntryID: "some-entry", Name: "x"}, allowAllExitAuthority{}),
		"some-entry", "openai", map[string]string{})
	if err == nil {
		t.Fatal("a failed settings read resolved to 'not pinned', so a transient database error " +
			"opens the gate on the instance's AI provider key")
	}
	if !strings.Contains(err.Error(), "not sent anywhere") {
		t.Errorf("the refusal should say the secret went nowhere, got %q", err)
	}
}

// TestEgressAllowanceRefusesNearMisses is the other gap an ablation found.
//
// Every behavioural test in this file asserts that something was REFUSED, so a
// loosened allowance makes them all pass harder. Nothing asserted the allowance
// says no. The suffix form is the dangerous one: it exists for exactly one
// vendor (Backblaze hands back its own storage host at runtime), and a sloppy
// suffix match is "anything ending in roughly the right letters", which is the
// same shape as the "*.supabase.co" preset this codebase already removed once.
func TestEgressAllowanceRefusesNearMisses(t *testing.T) {
	allow := egressAllowance{
		Hosts:    []string{"api.openai.com"},
		Suffixes: []string{".backblazeb2.com"},
	}
	for _, tc := range []struct {
		host string
		want bool
		why  string
	}{
		{"api.openai.com", true, "the declared host itself"},
		{"api.openai.com:443", true, "an explicit port is the same host"},
		{"API.OpenAI.COM", true, "host comparison is case insensitive"},
		{"api005.backblazeb2.com", true, "the storage host B2 returns, under the declared suffix"},

		{"api.openai.com.attacker-controlled.example", false,
			"a declared host used as a PREFIX of somebody else's domain"},
		{"attacker-controlled.example", false, "an unrelated host"},
		{"notapi.openai.com", false, "a sibling that merely ends the same way"},
		{"backblazeb2.com", false,
			"the suffix itself is not a host under it; allowing it would allow the apex"},
		{"backblazeb2.com.attacker-controlled.example", false,
			"the suffix in the middle: a substring match would allow this"},
		{"bacon.example", false, "shares only the first letters of the suffix"},
		{"", false, "an empty host is not a match for anything"},
	} {
		if got := allow.Allows(tc.host); got != tc.want {
			t.Errorf("allows(%q) = %v, want %v (%s)", tc.host, got, tc.want, tc.why)
		}
	}

	// An EMPTY allowance permits nothing. This is the load-bearing default:
	// declaredProviderEgress returns one for a provider with no declaration, and
	// secretexit.Exit refuses a network destination that resolves to one, so "we
	// never said where this may go" has to mean "nowhere".
	var empty egressAllowance
	for _, h := range []string{"api.openai.com", "attacker-controlled.example", "localhost"} {
		if empty.Allows(h) {
			t.Errorf("an empty allowance permitted %q. Empty must mean nowhere, or every provider "+
				"and every call site that was never declared egresses freely", h)
		}
	}
}

// jsonQuote quotes a string for embedding in a hand-built JSON body.
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

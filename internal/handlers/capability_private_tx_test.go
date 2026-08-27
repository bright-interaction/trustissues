package handlers

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/capability"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

func waitCapabilityResponse(t *testing.T, responses <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case <-time.After(3 * time.Second):
		t.Fatal("capability request did not finish after the competing transaction committed")
		return nil
	}
}

// TestCapabilityIssueSeesConcurrentPrivatePromotion reproduces the original
// check/use window. While a writer held an uncommitted promotion, the old Issue
// path read the standard row through several independent pool queries, minted a
// token, and only blocked when its audit INSERT needed the write lock. Once the
// promotion committed it returned that stale public token.
//
// The issue security snapshot now waits for that writer before doing its first
// lookup, then observes fully_private and exposes neither name nor token.
func TestCapabilityIssueSeesConcurrentPrivatePromotion(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	userID := mustUser(t, queries, "capability-issue-race@example.com", "user", "")
	const (
		collectionID = "capability-issue-race"
		entryID      = "capability-issue-race-entry"
	)
	mustCollection(t, queries, collectionID, userID, map[string]string{userID: collRoleManager})
	mustEntry(t, vault, queries, entryID, userID, "race issue key", "secret")
	placeInCollection(t, queries, entryID, collectionID)
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["api.example.com/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("seed destination ceiling: %v", err)
	}
	capabilityHandler := setupCapabilityHandlerWithVault(t, vault)

	blocker, err := vault.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin competing promotion: %v", err)
	}
	defer blocker.Rollback()
	if err := queries.WithTx(blocker).UpdateCollection(context.Background(), db.UpdateCollectionParams{
		Name: collectionID, Description: "",
		PrivateAccessPolicy: sql.NullString{String: string(privateaccess.PolicyFullyPrivate), Valid: true},
		ID:                  collectionID,
	}); err != nil {
		t.Fatalf("stage private promotion: %v", err)
	}

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		capabilityHandler.Issue(response, vaultAuthzRequest(http.MethodPost, "/api/secrets/issue",
			userID, "user", "", `{"secret":"race issue key","agent_id":"race-agent","destination":"api.example.com/v1","method":"POST"}`))
		responses <- response
	}()
	time.Sleep(100 * time.Millisecond)
	if err := blocker.Commit(); err != nil {
		t.Fatalf("commit private promotion: %v", err)
	}

	response := waitCapabilityResponse(t, responses)
	if response.Code != http.StatusNotFound {
		t.Fatalf("public Issue used its pre-promotion gate: HTTP %d, want 404: %s", response.Code, response.Body.String())
	}
	if body := response.Body.String(); strings.Contains(body, "token") || strings.Contains(body, "race issue key") {
		t.Fatalf("fully-private Issue response leaked a token or entry name: %s", body)
	}
	var issued int
	if err := vault.db.QueryRow(`SELECT COUNT(*) FROM capability_log WHERE event = 'issued' AND secret_id = ?`, entryID).Scan(&issued); err != nil {
		t.Fatalf("count issue audit rows: %v", err)
	}
	if issued != 0 {
		t.Fatalf("stale public Issue minted %d capability token(s) after promotion", issued)
	}
}

// TestCapabilityProxySeesConcurrentMoveIntoFullyPrivateCollection exercises the
// sibling spend race. Previously the public policy/allowlist/pin reads could all
// see the old standard collection while an entry move was uncommitted; nonce
// insertion then waited for the writer and delivered the secret after the move
// committed. One write transaction now owns the entire decision and waits
// before reading policy.
func TestCapabilityProxySeesConcurrentMoveIntoFullyPrivateCollection(t *testing.T) {
	env := newEgressEnv(t)
	owner := mustUser(t, env.queries, "capability-proxy-race@example.com", "user", "")
	const (
		standardCollection = "capability-proxy-standard"
		privateCollection  = "capability-proxy-private"
		entryID            = "capability-proxy-race-entry"
		nonce              = "capability-proxy-race-nonce"
	)
	mustCollection(t, env.queries, standardCollection, owner, map[string]string{owner: collRoleManager})
	mustCollection(t, env.queries, privateCollection, owner, map[string]string{owner: collRoleManager})
	setCollectionPrivateAccessPolicy(t, env.queries, privateCollection, string(privateaccess.PolicyFullyPrivate))
	mustEntry(t, env.vault, env.queries, entryID, owner, "race proxy key", "secret-that-must-not-egress")
	placeInCollection(t, env.queries, entryID, standardCollection)
	if err := setDestinationPatternsFixture(t, env.queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["api.example.com/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("seed destination ceiling: %v", err)
	}

	token, err := capability.Sign(capability.Token{
		Secret: "race proxy key", SecretID: entryID, Issuer: owner, Agent: "race-agent",
		Dests: []string{"api.example.com/*"}, Method: http.MethodPost, Nonce: nonce,
	}, env.cap.signingKey, time.Minute)
	if err != nil {
		t.Fatalf("sign capability: %v", err)
	}

	blocker, err := env.vault.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin competing entry move: %v", err)
	}
	defer blocker.Rollback()
	placeInCollection(t, env.queries.WithTx(blocker), entryID, privateCollection)

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/proxy/api.example.com/v1", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Capability "+token)
		env.router.ServeHTTP(response, req)
		responses <- response
	}()
	time.Sleep(100 * time.Millisecond)
	if err := blocker.Commit(); err != nil {
		t.Fatalf("commit entry move: %v", err)
	}

	response := waitCapabilityResponse(t, responses)
	if response.Code != http.StatusNotFound {
		t.Fatalf("public Proxy used its pre-move policy gate: HTTP %d, want 404: %s", response.Code, response.Body.String())
	}
	if len(env.wire.reqs) != 0 {
		t.Fatalf("proxy reached the wire after the entry became fully private: %v", env.wire.reqs)
	}
	var spent int
	if err := env.vault.db.QueryRow(`SELECT COUNT(*) FROM capability_spent_nonces WHERE nonce = ?`, nonce).Scan(&spent); err != nil {
		t.Fatalf("count spent nonce: %v", err)
	}
	if spent != 0 {
		t.Fatal("private-policy refusal spent the token nonce before denying")
	}
}

type transactionReleaseTransport struct {
	started chan struct{}
	release chan struct{}
}

func (transport *transactionReleaseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	close(transport.started)
	<-transport.release
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Request:    request,
	}, nil
}

// TestCapabilityProxyReleasesTransactionBeforeOutbound pins the other half of
// the design: the coherent snapshot must not turn a slow provider into a
// database-wide write lock. Once RoundTrip starts, an unrelated write must be
// able to commit while the network call is still blocked.
func TestCapabilityProxyReleasesTransactionBeforeOutbound(t *testing.T) {
	env := newEgressEnv(t)
	owner := mustUser(t, env.queries, "capability-outbound-tx@example.com", "user", "")
	const (
		collectionID = "capability-outbound-tx"
		entryID      = "capability-outbound-tx-entry"
	)
	mustCollection(t, env.queries, collectionID, owner, map[string]string{owner: collRoleManager})
	mustEntry(t, env.vault, env.queries, entryID, owner, "outbound tx key", "secret")
	placeInCollection(t, env.queries, entryID, collectionID)
	if err := setDestinationPatternsFixture(t, env.queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["api.example.com/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("seed destination ceiling: %v", err)
	}
	mustExec(t, env.vault.db, `UPDATE vault_entries SET injection_spec = '{"type":"bearer"}' WHERE id = ?`, entryID)

	transport := &transactionReleaseTransport{started: make(chan struct{}), release: make(chan struct{})}
	env.cap.SetHTTPClient(&http.Client{Transport: transport})
	token := signToken(t, owner, "outbound tx key", entryID, "tx-agent", "api.example.com/*", http.MethodPost)
	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/proxy/api.example.com/v1", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Capability "+token)
		env.router.ServeHTTP(response, req)
		responses <- response
	}()

	select {
	case <-transport.started:
	case response := <-responses:
		t.Fatalf("proxy returned before outbound transport: HTTP %d: %s", response.Code, response.Body.String())
	case <-time.After(3 * time.Second):
		t.Fatal("proxy never reached the in-memory transport")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := env.vault.db.Exec(`UPDATE collections SET description = 'while outbound' WHERE id = ?`, collectionID)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write after outbound began: %v", err)
		}
	case <-time.After(time.Second):
		close(transport.release)
		t.Fatal("outbound request still held the capability security transaction")
	}
	close(transport.release)
	if response := waitCapabilityResponse(t, responses); response.Code != http.StatusOK {
		t.Fatalf("proxy response = HTTP %d: %s", response.Code, response.Body.String())
	}
}

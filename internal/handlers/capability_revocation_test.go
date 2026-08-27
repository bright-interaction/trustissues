package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/capability"
)

// Clearing a secret's agent allow-list must revoke every outstanding token.
//
// Clearing it is the ONLY control the product offers for revoking an agent's access
// to one secret, and it was the exact case the proxy's current-policy re-check
// skipped: the guard read `if patterns := ...; len(patterns) > 0`, so an EMPTY list
// meant "nothing to tighten against" and the check was bypassed entirely.
//
// The inversion was the wrong way round in the most damaging possible way. Tightening
// from three hosts to one WAS enforced against an outstanding token; revoking all
// access was NOT. Every token already minted (TTL up to 600s) kept spending the
// credential.
//
// Denying on empty is exactly consistent with issuance, which already refuses:
// "this secret has no agent destination allow-list, so no capability token can be
// minted for it". A token for a pattern-less secret could never legitimately exist.
func TestClearingTheAllowListRevokesOutstandingTokens(t *testing.T) {
	tdb := newTestDB(t)
	defer tdb.Close()

	const userID, agentID, secretID = "u", "a", "s-revoke"
	capH := setupCapabilityHandler(t, tdb)
	mustExec(t, tdb, `INSERT INTO vault_entries (id, user_id, name, encrypted_value, nonce, encryption_version, destination_patterns, injection_spec)
		VALUES (?, ?, ?, ?, ?, 2, '["api.stripe.com/*"]', '{"type":"bearer"}')`,
		secretID, userID, "stripe", []byte("sk-test"), []byte("n"))

	signingKey, _ := capability.DeriveSigningKey(testCapVaultKey)
	mint := func(nonceSuffix string) string {
		tok, _ := capability.Sign(capability.Token{
			Secret: "stripe", SecretID: secretID, Issuer: userID, Agent: agentID,
			Dests:  []string{"api.stripe.com/*"},
			Method: "POST",
		}, signingKey, time.Minute)
		return tok
	}

	router := chi.NewRouter()
	router.HandleFunc("/proxy/{host}/*", capH.Proxy)

	call := func(tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/proxy/api.stripe.com/v1/charges", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Capability "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// Guard the setup: with the allow-list in place the token must NOT be refused on
	// policy grounds, or the test below proves nothing. (It may still fail further
	// on, at the real upstream dial, which is fine and not a 403.)
	before := call(mint("a"))
	if before.Code == http.StatusForbidden && strings.Contains(before.Body.String(), "destination") {
		t.Fatalf("ABORT: the token was refused on destination grounds BEFORE the allow-list was "+
			"cleared, so this test would pass vacuously: %d %s", before.Code, before.Body.String())
	}

	// The operator clears Agent access, which is the product's revoke button.
	mustExec(t, tdb, `UPDATE vault_entries SET destination_patterns = '[]' WHERE id = ?`, secretID)

	after := call(mint("b"))
	if after.Code != http.StatusForbidden {
		t.Fatalf("an outstanding token still spent the credential after the allow-list was cleared "+
			"(got %d %s).\nClearing the list is the only revocation control the product has; if it "+
			"does not bind, agent access cannot be revoked at all.", after.Code, after.Body.String())
	}
	if !strings.Contains(after.Body.String(), "destination") {
		t.Errorf("refused for the wrong reason: %s", after.Body.String())
	}
}

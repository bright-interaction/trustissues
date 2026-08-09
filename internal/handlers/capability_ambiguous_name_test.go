package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// TestIssueRefusesAmbiguousSecretName locks the fix for a silent wrong-key mint.
//
// A vault name is unique only per (user_id, name), so a user who is in a
// collection holding "stripe" AND keeps a personal "stripe" has two reachable
// entries with that name. lookupSecretByName was a QueryRow, which returns
// whatever row SQLite happens to hand back first, so use_secret(name:"stripe")
// minted for an arbitrary one: the agent asked for its sandbox key and the proxy
// could inject the company's live key against api.stripe.com. Nothing
// distinguished the two afterwards, since capability_log.secret_name is "stripe"
// either way, so the audit trail could not answer which key was spent.
//
// lookupSecretByDestination already refused its equivalent ambiguity with a 409.
// This asserts the by-name lookup now does the same, and that the refusal does
// not fire when there is only one reachable match.
func TestIssueRefusesAmbiguousSecretName(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	carol := mustUser(t, queries, "ambig-carol@example.com", "user", "")
	colleague := mustUser(t, queries, "ambig-colleague@example.com", "user", "")

	mustCollection(t, queries, "coll-finance", colleague, map[string]string{
		colleague: collRoleManager,
		carol:     collRoleEditor,
	})

	// The shared, live one: created by a colleague, lives in the collection.
	const sharedID = "entry-stripe-shared"
	mustEntry(t, h, queries, sharedID, colleague, "stripe", "sk_live_COMPANY")
	placeInCollection(t, queries, sharedID, "coll-finance")

	// Carol's own sandbox key, same name, personal.
	const personalID = "entry-stripe-personal"
	mustEntry(t, h, queries, personalID, carol, "stripe", "sk_test_SANDBOX")

	for _, id := range []string{sharedID, personalID} {
		if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
			DestinationPatterns: `["api.stripe.com/*"]`, ID: id,
		}); err != nil {
			t.Fatalf("seed ceiling on %s: %v", id, err)
		}
	}

	capH := setupCapabilityHandlerWithVault(t, h)
	issue := func(userID, secret string) (int, string) {
		body := `{"agent_id":"a","secret":"` + secret + `","destination":"api.stripe.com/v1/charges","method":"POST"}`
		r := httptest.NewRequest(http.MethodPost, "/api/secrets/issue", strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), middleware.UserIDKey, userID))
		w := httptest.NewRecorder()
		capH.Issue(w, r)
		return w.Code, w.Body.String()
	}

	// Guard the setup: both entries must really be reachable by Carol, or the
	// refusal below would be proving nothing.
	ch := &CapabilityHandler{db: h.db, vault: h}
	if _, err := ch.lookupSecretByName(ctx, colleague, "stripe"); err != nil {
		t.Fatalf("ABORT: the colleague cannot even resolve the shared entry: %v", err)
	}

	code, body := issue(carol, "stripe")
	if code != http.StatusConflict {
		t.Fatalf("an ambiguous secret name minted a token instead of refusing (%d): %s\n"+
			"the agent asked for one key and could have been handed the other, with nothing in the audit trail to tell them apart", code, body)
	}
	if !strings.Contains(body, "ambiguous_secret_name") {
		t.Errorf("refusal does not carry a machine-readable code: %s", body)
	}

	// The colleague reaches only ONE "stripe" (the shared one; Carol's personal
	// entry is not in their scope), so they must still mint normally. A guard
	// that refused for everyone would look like a pass above while breaking the
	// feature.
	if code, body := issue(colleague, "stripe"); code != http.StatusOK && code != http.StatusCreated {
		t.Errorf("a user with exactly one reachable match was refused (%d): %s", code, body)
	}
}

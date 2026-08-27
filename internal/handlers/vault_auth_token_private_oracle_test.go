package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/privateaccess"
)

// A fully-private reference must be absent from public name and ambiguity
// resolution. Otherwise adding a hidden accessible row named exactly like a
// standard token changes GET/PUT target management from 200 to 403 and reveals
// that hidden name. Private/background resolution keeps the row and therefore
// still refuses the genuinely ambiguous credential choice.
func TestFullyPrivateAuthTokenDuplicateDoesNotBecomePublicNameOracle(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	userID := mustUser(t, queries, "target-owner@example.com", "user", "")
	hiddenOwner := mustUser(t, queries, "hidden-owner@example.com", "user", "")
	mustEntry(t, h, queries, "visible-token", userID, "SAME_TOKEN_NAME", "visible-value")
	mustEntry(t, h, queries, "target-carrier", userID, "carrier", "carrier-value")

	body := `[{"type":"forgejo_secret","instance":"https://git.example.com","repo":"o/r",` +
		`"secret_name":"CI_KEY","auth_token":"SAME_TOKEN_NAME"}]`
	if rec := putTargets(t, h, userID, "user", "target-carrier", body); rec.Code != http.StatusOK {
		t.Fatalf("initial standard target save got HTTP %d: %s", rec.Code, rec.Body.String())
	}

	const collectionID = "hidden-token-collection"
	mustCollection(t, queries, collectionID, hiddenOwner, map[string]string{
		hiddenOwner: collRoleManager,
		userID:      collRoleViewer,
	})
	if _, err := h.db.ExecContext(ctx,
		`UPDATE collections SET private_access_policy = ? WHERE id = ?`,
		string(privateaccess.PolicyFullyPrivate), collectionID); err != nil {
		t.Fatalf("promote collection: %v", err)
	}
	mustEntry(t, h, queries, "hidden-token", hiddenOwner, "SAME_TOKEN_NAME", "hidden-value")
	placeInCollection(t, queries, "hidden-token", collectionID)

	get := httptest.NewRecorder()
	h.GetTargets(get, vaultAuthzRequest(http.MethodGet,
		"/api/vault/target-carrier/targets", userID, "user", "target-carrier", ""))
	if get.Code != http.StatusOK {
		t.Fatalf("hidden duplicate changed public GET response to HTTP %d: %s", get.Code, get.Body.String())
	}
	if rec := putTargets(t, h, userID, "user", "target-carrier", body); rec.Code != http.StatusOK {
		t.Fatalf("hidden duplicate changed public PUT response to HTTP %d: %s", rec.Code, rec.Body.String())
	}

	if _, err := h.resolveVaultReferenceRowFor(ctx, "SAME_TOKEN_NAME", userID); !errors.Is(err, errAmbiguousVaultReference) {
		t.Fatalf("delivery/private resolver error = %v, want ambiguity with both reachable rows", err)
	}
}

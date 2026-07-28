package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServiceKeyDiesWithItsOwner locks the FOURTH door onto the offboarding
// property.
//
// Three earlier rounds closed collection removal, rotation-target delivery and
// capability minting, and round 4 put the account-status check inside
// entryAccessFor so background callers would inherit it. This route inherits
// nothing: FetchOwnSecrets never touches entryAccessFor, and it never passes
// through the auth middleware that rejects disabled users, because it
// authenticates with a service key rather than a session.
//
// So an admin could mint a service identity scoped to their own personal
// secrets, leave, be disabled AND deleted, and their sk_ key kept returning
// those secrets in plaintext, including values rotated after they left, with
// revoked_at still NULL so nothing in the UI showed it. Password reset did not
// help either, though it deliberately revokes sessions and api_keys for exactly
// this reason.
//
// The invariant: the key stops working when the owner does, both when the
// account is disabled and when it is deleted outright.
func TestServiceKeyDiesWithItsOwner(t *testing.T) {
	h, dbConn := setupServiceHandler(t)
	seedSecret(t, dbConn, "PROD_DB", "super-secret-value")
	rawKey := seedServiceIdentity(t, dbConn, "api-prod", []string{"PROD_DB"})

	fetch := func() (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
		req.Header.Set("X-Service-Key", rawKey)
		rec := httptest.NewRecorder()
		h.FetchOwnSecrets(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Guard the setup. If the key does not work while the owner is live, every
	// assertion below would pass for the wrong reason.
	code, body := fetch()
	if code != http.StatusOK {
		t.Fatalf("ABORT: the key does not work even with a live owner (%d): %s", code, body)
	}
	var got struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil || got.Secrets["PROD_DB"] != "super-secret-value" {
		t.Fatalf("ABORT: fixture did not return the seeded secret: %s", body)
	}

	// Disable the owner. Nothing else changes: the identity is untouched and
	// revoked_at stays NULL, which is precisely the state that used to keep
	// working.
	if _, err := dbConn.Exec(`UPDATE users SET disabled = 1 WHERE id = ?`, svcTestOwnerID); err != nil {
		t.Fatalf("disable owner: %v", err)
	}
	if code, body := fetch(); code == http.StatusOK {
		t.Errorf("a DISABLED owner's service key still returned their secrets in plaintext: %s\n"+
			"disabling the account is the control an admin uses during an incident", body)
	}

	// Re-enable: disabling must be reversible, not destructive.
	if _, err := dbConn.Exec(`UPDATE users SET disabled = 0 WHERE id = ?`, svcTestOwnerID); err != nil {
		t.Fatalf("re-enable owner: %v", err)
	}
	if code, _ := fetch(); code != http.StatusOK {
		t.Errorf("re-enabling the owner did not restore the service key (%d)", code)
	}

	// Now delete the account outright. vault_entries has no FK to users, so the
	// secret row survives; the key must not.
	if _, err := dbConn.Exec(`DELETE FROM users WHERE id = ?`, svcTestOwnerID); err != nil {
		t.Fatalf("delete owner: %v", err)
	}
	if code, body := fetch(); code == http.StatusOK {
		t.Errorf("a DELETED owner's service key still returned their secrets in plaintext: %s", body)
	}
}

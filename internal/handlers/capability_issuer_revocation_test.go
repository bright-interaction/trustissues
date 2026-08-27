package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

func issueIssuerRevocationFixture(t *testing.T) (*egressEnv, string, string, string) {
	t.Helper()
	env := newEgressEnv(t)
	owner := mustUser(t, env.queries, "capability-revoke-owner@example.com", "user", "")
	issuer := mustUser(t, env.queries, "capability-revoke-issuer@example.com", "user", "")
	const (
		collectionID = "capability-revoke-collection"
		entryID      = "capability-revoke-entry"
	)
	mustCollection(t, env.queries, collectionID, owner, map[string]string{
		owner:  collRoleManager,
		issuer: collRoleEditor,
	})
	mustEntry(t, env.vault, env.queries, entryID, owner, "revocable capability key", "post-rotation-current-value")
	placeInCollection(t, env.queries, entryID, collectionID)
	env.forceDestinations(t, entryID, `["api.example.com/*"]`)
	if _, err := env.vault.db.Exec(`UPDATE vault_entries SET injection_spec = '{"type":"bearer"}' WHERE id = ?`, entryID); err != nil {
		t.Fatalf("seed injection spec: %v", err)
	}

	issued := env.issue(t, issuer, issueRequest{
		Secret: "revocable capability key", AgentID: "revocable-agent",
		Method: http.MethodPost,
	})
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue capability: HTTP %d: %s", issued.Code, issued.Body.String())
	}
	var response issueResponse
	if err := json.Unmarshal(issued.Body.Bytes(), &response); err != nil || response.Token == "" {
		t.Fatalf("decode issued token: err=%v body=%s", err, issued.Body.String())
	}
	return env, issuer, entryID, response.Token
}

func assertRevokedCapabilityDoesNotEgress(t *testing.T, env *egressEnv, token, stableCode string) {
	t.Helper()
	response := env.proxy(t, http.MethodPost, "api.example.com", "/v1/use", token)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), stableCode) {
		t.Fatalf("revoked capability got HTTP %d, want 403 %s: %s",
			response.Code, stableCode, response.Body.String())
	}
	env.assertKeyNeverLeft(t, "post-rotation-current-value")
	var spent int
	if err := env.vault.db.QueryRow(`SELECT COUNT(*) FROM capability_spent_nonces`).Scan(&spent); err != nil {
		t.Fatalf("count spent nonces: %v", err)
	}
	if spent != 0 {
		t.Fatalf("revocation refusal spent %d nonce(s) before denying", spent)
	}
}

// /proxy is bearer-only, but the bearer is not timeless authority. Its signed
// issuer is rechecked in the same transaction as policy, nonce and ciphertext,
// so offboarding, disabling, or demoting that human closes already-issued use
// paths before the current/post-rotation value can reach the network.
func TestCapabilitySpendRechecksIssuerAccountAndMembership(t *testing.T) {
	t.Run("collection membership removed", func(t *testing.T) {
		env, issuer, _, token := issueIssuerRevocationFixture(t)
		result, err := env.queries.RemoveCollectionMember(context.Background(), db.RemoveCollectionMemberParams{
			CollectionID: "capability-revoke-collection", UserID: issuer,
		})
		if err != nil {
			t.Fatalf("remove issuer membership: %v", err)
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			t.Fatalf("remove issuer membership changed %d rows", rows)
		}
		assertRevokedCapabilityDoesNotEgress(t, env, token, "capability_issuer_revoked")
	})

	t.Run("account disabled", func(t *testing.T) {
		env, issuer, _, token := issueIssuerRevocationFixture(t)
		if _, err := env.vault.db.Exec(`UPDATE users SET disabled = 1 WHERE id = ?`, issuer); err != nil {
			t.Fatalf("disable issuer: %v", err)
		}
		assertRevokedCapabilityDoesNotEgress(t, env, token, "capability_issuer_revoked")
	})

	t.Run("role demoted to vault only", func(t *testing.T) {
		env, issuer, _, token := issueIssuerRevocationFixture(t)
		if _, err := env.vault.db.Exec(`UPDATE users SET role = 'vault_only' WHERE id = ?`, issuer); err != nil {
			t.Fatalf("demote issuer: %v", err)
		}
		assertRevokedCapabilityDoesNotEgress(t, env, token, "capability_issuer_revoked")
	})
}

func TestCapabilitySpendRechecksExplicitAgentGrant(t *testing.T) {
	env, issuer, entryID, _ := issueIssuerRevocationFixture(t)
	if _, err := env.vault.db.Exec(`INSERT INTO capability_grants (agent_id, secret_id, granted_by)
		VALUES ('revocable-agent', ?, ?)`, entryID, issuer); err != nil {
		t.Fatalf("add explicit grant: %v", err)
	}
	issued := env.issue(t, issuer, issueRequest{
		Secret: "revocable capability key", AgentID: "revocable-agent", Method: http.MethodPost,
	})
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue explicitly granted capability: HTTP %d: %s", issued.Code, issued.Body.String())
	}
	var response issueResponse
	if err := json.Unmarshal(issued.Body.Bytes(), &response); err != nil || response.Token == "" {
		t.Fatalf("decode issued token: err=%v body=%s", err, issued.Body.String())
	}
	if _, err := env.vault.db.Exec(`UPDATE capability_grants SET revoked_at = CURRENT_TIMESTAMP
		WHERE agent_id = 'revocable-agent' AND secret_id = ?`, entryID); err != nil {
		t.Fatalf("revoke agent grant: %v", err)
	}
	assertRevokedCapabilityDoesNotEgress(t, env, response.Token, "capability_agent_revoked")
}

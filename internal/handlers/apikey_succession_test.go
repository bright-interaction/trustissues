package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/middleware"
)

// A minted API key must never outlive the API key that minted it.
//
// POST /api/api-keys accepts X-API-Key as authentication and mounts with neither
// AdminOnly nor VaultOnlyBlock, so an API key was sufficient to mint another API key:
// no password, no TOTP, no session. Omitting expires_in_days left expires_at NULL, and
// the auth path's `expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')`
// can never be true for NULL, so the successor was permanent.
//
// That voids the one invariant the product documents for a credential it hands out over
// a PUBLIC endpoint: RedeemInvitation's vault_only extension key is "deliberately
// time-boxed (invitationAPIKeyTTL) rather than permanent" at 90 days. Anyone who
// redeemed an invitation could convert that into permanent vault access in one request,
// revoking the original would not touch the child, and nothing in the UI shows the
// child came from a time-boxed parent.
func TestAMintedKeyCannotOutliveItsMinter(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewAPIKeyHandler(queries)
	ctx := context.Background()
	user := mustUser(t, queries, "succession@example.com", "user", "")

	parentExpiry := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)

	mint := func(t *testing.T, reqCtx context.Context, body string) apiKeyCreateResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/api-keys", strings.NewReader(body))
		req = req.WithContext(context.WithValue(reqCtx, middleware.UserIDKey, user))
		rec := httptest.NewRecorder()
		h.Create(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
		var out apiKeyCreateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	t.Run("an unbounded request is capped to the minting key's expiry", func(t *testing.T) {
		// The exact shape the frontend sends: {"name": "..."} with no expiry.
		reqCtx := context.WithValue(ctx, middleware.APIKeyExpiryKey, parentExpiry)
		out := mint(t, reqCtx, `{"name":"extension successor"}`)
		if out.ExpiresAt == nil {
			t.Fatal("a key minted BY a time-boxed API key came back with no expiry at all.\n" +
				"That converts the 90-day vault_only extension credential, handed out over a " +
				"PUBLIC endpoint, into permanent vault access in one request.")
		}
		got, err := time.Parse(time.RFC3339, *out.ExpiresAt)
		if err != nil {
			t.Fatalf("bad expiry %q: %v", *out.ExpiresAt, err)
		}
		if got.After(parentExpiry) {
			t.Errorf("successor expires %s, after its minter's %s", got, parentExpiry)
		}
	})

	t.Run("a longer requested expiry is capped too", func(t *testing.T) {
		reqCtx := context.WithValue(ctx, middleware.APIKeyExpiryKey, parentExpiry)
		out := mint(t, reqCtx, `{"name":"greedy","expires_in_days":3650}`)
		if out.ExpiresAt == nil {
			t.Fatal("no expiry on the successor")
		}
		got, _ := time.Parse(time.RFC3339, *out.ExpiresAt)
		if got.After(parentExpiry) {
			t.Errorf("a 10-year request produced %s, past the minter's %s; the cap is not applied "+
				"when the caller asks for longer, which is exactly when it matters", got, parentExpiry)
		}
	})

	t.Run("a shorter requested expiry is honoured", func(t *testing.T) {
		reqCtx := context.WithValue(ctx, middleware.APIKeyExpiryKey, parentExpiry)
		out := mint(t, reqCtx, `{"name":"short","expires_in_days":1}`)
		got, _ := time.Parse(time.RFC3339, *out.ExpiresAt)
		if !got.Before(parentExpiry) {
			t.Errorf("a 1-day request produced %s; the cap must be a ceiling, not an override", got)
		}
	})

	t.Run("a session-authenticated mint is not capped", func(t *testing.T) {
		// No APIKeyExpiryKey in context: an interactive login. The cap exists to
		// stop a time-boxed credential extending itself, not to change how a
		// logged-in operator manages their own keys.
		out := mint(t, ctx, `{"name":"from a real session"}`)
		if out.ExpiresAt != nil {
			t.Errorf("a session-authenticated key was capped to %s; the fix has changed behaviour "+
				"for the interactive path it was not aimed at", *out.ExpiresAt)
		}
	})

	_ = vh
}

// Revoking every key for a user who does not exist must not report success.
//
// RevokeAPIKeysByUser is an UPDATE with a WHERE, so an id matching nothing is not an
// error: the endpoint answered 204 and wrote "All API keys revoked for user X" into the
// activity log having touched nothing. During an incident that is the worst possible
// answer, because the admin reads it as "that person is cut off" and the audit trail
// afterwards agrees with them. A typo, a stale id from an old page, or an already
// deleted user all produce it.
func TestRevokeAllRefusesAnUnknownUser(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	h := NewAPIKeyHandler(queries)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/does-not-exist/api-keys/revoke-all", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "does-not-exist")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, middleware.UserRoleKey, "admin")
	rec := httptest.NewRecorder()
	h.AdminRevokeAll(rec, req.WithContext(ctx))

	if rec.Code == http.StatusNoContent {
		t.Fatal("revoking keys for a non-existent user reported 204 and logged a successful " +
			"revocation.\nAn admin acting on an incident is told the keys are dead when nothing " +
			"was touched, and the audit trail backs up the wrong belief.")
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404 so the admin knows the id was wrong: %s", rec.Code, rec.Body.String())
	}
}

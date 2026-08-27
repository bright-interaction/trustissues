package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/trustissues/internal/middleware"
)

// An API key must not mint a successor at all.
//
// POST /api/api-keys accepts X-API-Key as authentication and mounts with neither
// AdminOnly nor VaultOnlyBlock, so a stolen API key was sufficient to mint another
// API key: no password, no TOTP, no session.
//
// Capping the child to its parent's expiry did not make single-key revocation
// terminal: after K minted K2, deleting K left K2 live until that shared deadline.
// There was no parent linkage for a revoke to traverse. Refusing bearer-to-bearer
// minting makes the displayed key row the whole authority an operator revokes.
func TestAPIKeyCannotMintSuccessor(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewAPIKeyHandler(queries)
	user := mustUser(t, queries, "succession@example.com", "user", "")

	parentKey := "ti_" + strings.Repeat("a", 64)
	parentHash := sha256.Sum256([]byte(parentKey))
	if _, err := vh.db.Exec(`
		INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, expires_at)
		VALUES ('parent-key', ?, 'Invitation bootstrap', ?, 'aaaaaaaa', datetime('now', '+90 days'))`,
		user, hex.EncodeToString(parentHash[:]),
	); err != nil {
		t.Fatalf("seed parent API key: %v", err)
	}

	// Exercise the real authentication middleware so the denial is tied to the
	// credential presented on the wire, not a hand-built role context.
	wired := middleware.JWTOrAPIKeyAuth(strings.Repeat("j", 32), vh.db)(http.HandlerFunc(h.Create))
	req := httptest.NewRequest(http.MethodPost, "/api/api-keys",
		strings.NewReader(`{"name":"successor"}`))
	req.Header.Set("X-API-Key", parentKey)
	rec := httptest.NewRecorder()
	wired.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "interactive_session_required") {
		t.Fatalf("API-key-authenticated mint = HTTP %d %s, want interactive-session refusal", rec.Code, rec.Body.String())
	}

	var count int
	if err := vh.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = ?`, user).Scan(&count); err != nil {
		t.Fatalf("count API keys: %v", err)
	}
	if count != 1 {
		t.Fatalf("API-key-authenticated mint left %d keys, want only the parent", count)
	}

	// Missing/future principal kinds fail closed even if a caller somehow has a
	// user id; only the explicit interactive-session stamp may pass.
	unknownReq := httptest.NewRequest(http.MethodPost, "/api/api-keys", strings.NewReader(`{"name":"unknown"}`))
	unknownReq = unknownReq.WithContext(context.WithValue(unknownReq.Context(), middleware.UserIDKey, user))
	unknownRec := httptest.NewRecorder()
	h.Create(unknownRec, unknownReq)
	if unknownRec.Code != http.StatusForbidden {
		t.Fatalf("unknown principal mint = HTTP %d %s, want 403", unknownRec.Code, unknownRec.Body.String())
	}

	sessionReq := httptest.NewRequest(http.MethodPost, "/api/api-keys", strings.NewReader(`{"name":"session key"}`))
	sessionCtx := context.WithValue(sessionReq.Context(), middleware.UserIDKey, user)
	sessionCtx = context.WithValue(sessionCtx, middleware.PrincipalKindKey, middleware.PrincipalSession)
	sessionRec := httptest.NewRecorder()
	h.Create(sessionRec, sessionReq.WithContext(sessionCtx))
	if sessionRec.Code != http.StatusCreated {
		t.Fatalf("interactive-session mint = HTTP %d %s, want 201", sessionRec.Code, sessionRec.Body.String())
	}
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

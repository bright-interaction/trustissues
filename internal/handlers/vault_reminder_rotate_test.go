package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/brightinteraction/trustissues/internal/middleware"
)

// TestManualRotateRefusesReminderOnlyProviders locks the fix for a destroy-on-
// click bug.
//
// Providers split into auto-rotating (the server can mint a replacement
// upstream) and reminder-only (github, openai, stripe, aws, ...) where rotation
// has to happen in the provider's own dashboard. The manual Rotate handler
// guarded with `if ok && provider.CanAutoRotate()`, so a reminder-only entry
// fell straight through to generateToken(32): the user's real credential was
// replaced with 32 bytes of random hex that authenticates nowhere, the response
// said success, and the actual credential stayed live and unrotated at the
// provider. One click on an ordinary GitHub token entry lost the token.
//
// The invariant: a reminder-only entry is refused, and its stored value is
// byte-for-byte unchanged.
func TestManualRotateRefusesReminderOnlyProviders(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	owner := mustUser(t, queries, "o@example.com", "user", "reallylongpassword123!")

	// Pick a genuinely registered reminder-only provider rather than inventing
	// one, so this tracks the real registry.
	var reminderProvider string
	for name, p := range ProviderRegistry {
		if !p.CanAutoRotate() {
			reminderProvider = name
			break
		}
	}
	if reminderProvider == "" {
		t.Skip("no reminder-only provider registered")
	}
	t.Logf("using reminder-only provider %q", reminderProvider)

	const id = "entry-reminder"
	const realToken = "ghp_THE_USERS_REAL_LIVE_TOKEN"
	mustEntry(t, h, queries, id, owner, "GitHub token", realToken)
	if _, err := h.db.ExecContext(ctx,
		`UPDATE vault_entries SET provider = ? WHERE id = ?`, reminderProvider, id); err != nil {
		t.Fatalf("set provider: %v", err)
	}

	before, err := queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	// Guard the setup: the stored value must actually be the real token, or the
	// "unchanged" assertion below is meaningless.
	if plain, decErr := h.decrypt(before.EncryptedValue, before.Nonce); decErr != nil || string(plain) != realToken {
		t.Fatalf("ABORT: stored value is not the expected token (err %v)", decErr)
	}

	body, _ := json.Marshal(map[string]string{"password": "reallylongpassword123!"})
	req := httptest.NewRequest(http.MethodPost, "/api/vault/"+id+"/rotate", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserIDKey, owner))
	rr := httptest.NewRecorder()
	h.Rotate(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("rotate SUCCEEDED on a reminder-only provider: the user's live credential was replaced with random hex (body %s)", rr.Body.String())
	}
	if rr.Code != http.StatusConflict {
		t.Logf("note: got %d rather than 409 (body %s)", rr.Code, rr.Body.String())
	}

	// The stored secret must be untouched, byte for byte.
	after, err := queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before.EncryptedValue, after.EncryptedValue) || !bytes.Equal(before.Nonce, after.Nonce) {
		t.Fatal("the refused rotation still rewrote the stored value: the real credential is gone")
	}
	plain, decErr := h.decrypt(after.EncryptedValue, after.Nonce)
	if decErr != nil || string(plain) != realToken {
		t.Fatalf("the real token no longer decrypts after a refused rotation (err %v)", decErr)
	}
}

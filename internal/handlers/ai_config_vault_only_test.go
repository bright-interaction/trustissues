package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/middleware"
)

func TestVaultOnlyCannotReadInstanceAIConfig(t *testing.T) {
	// Deliberately no database/vault dependencies: the role refusal must happen
	// before reading whether any provider or fully-private entry exists.
	h := &AIGatewayHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/settings/ai", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserRoleKey, "vault_only"))
	rec := httptest.NewRecorder()

	h.GetConfig(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "vault-only") {
		t.Fatalf("vault_only AI config read = HTTP %d %s, want state-independent 403", rec.Code, rec.Body.String())
	}
}

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/middleware"
)

// An invitation email must never carry a blank setup code.
//
// openInviteCode returns "" when the stored code will not decrypt, and its own doc says
// the caller must render that as such rather than as a blank code. ResendInvitation did
// not: it mailed the invitee a branded email with an EMPTY setup code, answered the
// admin 200 "invitation email queued", and recorded nothing in the activity trail. The
// only evidence was one slog line.
//
// The invitation is unrecoverable from there: redemption keys off code_hash and the
// plaintext was shown once at creation, so nobody can supply the code again. Sending the
// mail is itself the harm, because it burns the invitee's trust in a link that cannot
// work.
//
// BEHAVIOURAL on purpose. The first version of this test read the source for the guard's
// presence, and an ablation setting that condition to `if false` passed it clean: the
// text was still there, doing nothing. Same "a structural check cannot verify the thing
// it points at" trap this codebase keeps producing, so the assertion is on the HTTP
// outcome instead.
func TestResendRefusesAnUnreadableInviteCode(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	uh := NewUserHandler(queries, &config.Config{VaultKey: strings.Repeat("k", 32)})
	uh.SetVault(vh)
	ctx := context.Background()

	admin := mustUser(t, queries, "resend-admin@example.com", "admin", "")

	req := httptest.NewRequest(http.MethodPost, "/api/admin/invitations",
		strings.NewReader(`{"email":"colleague@example.com","name":"Colleague","role":"user"}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserIDKey, admin))
	rec := httptest.NewRecorder()
	uh.CreateInvitation(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create invitation: %d %s", rec.Code, rec.Body.String())
	}

	var invID, storedCode string
	if err := vh.db.QueryRowContext(ctx,
		`SELECT id, code FROM invitations WHERE email = ?`, "colleague@example.com").
		Scan(&invID, &storedCode); err != nil {
		t.Fatalf("find invitation: %v", err)
	}

	// Guard the fixture: a freshly created code MUST decrypt, or the case below cannot
	// distinguish the fix from a broken environment.
	if uh.openInviteCode(storedCode) == "" {
		t.Fatal("ABORT: the freshly created code does not decrypt, so this test would pass for " +
			"the wrong reason")
	}

	// Make it undecryptable the way a key change or bit rot would: KEEP the ciphertext
	// marker so decryptColumn tries and fails. Writing cleartext instead takes the
	// pass-through path and tests nothing.
	if _, err := vh.db.ExecContext(ctx,
		`UPDATE invitations SET code = ? WHERE id = ?`,
		"enc:v1:bm90LXJlYWxseS1jaXBoZXJ0ZXh0", invID); err != nil {
		t.Fatalf("corrupt the stored code: %v", err)
	}

	rreq := httptest.NewRequest(http.MethodPost, "/api/admin/invitations/"+invID+"/resend", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", invID)
	rreq = rreq.WithContext(context.WithValue(
		context.WithValue(rreq.Context(), chi.RouteCtxKey, rctx), middleware.UserIDKey, admin))
	rrec := httptest.NewRecorder()
	uh.ResendInvitation(rrec, rreq)

	if rrec.Code == http.StatusOK {
		t.Fatalf("resend answered 200 for an unreadable code, so the invitee is mailed a BLANK "+
			"setup code and the admin is told it worked: %s", rrec.Body.String())
	}
	if rrec.Code != http.StatusConflict {
		t.Errorf("resend returned %d, want %d so the admin knows to revoke and re-invite: %s",
			rrec.Code, http.StatusConflict, rrec.Body.String())
	}
	if !strings.Contains(rrec.Body.String(), "code_unreadable") {
		t.Errorf("the error does not identify the cause, so the admin cannot act on it: %s",
			rrec.Body.String())
	}
}

// TestSenderRefusesABlankCodeFirst is the belt, kept separate because the belt and the
// call-site guard fail independently.
//
// Two call sites reach trySendInvitationEmail today and nothing stops a third, which is
// the one-property-many-doors shape that has recurred repeatedly here. The sender
// refusing is what makes a future caller safe by default. The ORDER matters too: the
// check has to precede reading SMTP settings, so "we did not send" is never reported as
// "SMTP is not configured".
func TestSenderRefusesABlankCodeFirst(t *testing.T) {
	src := mustReadSource(t, "users.go")
	i := strings.Index(src, "func (h *UserHandler) trySendInvitationEmail")
	if i < 0 {
		t.Fatal("trySendInvitationEmail not found; this guard is vacuous")
	}
	body := src[i:]
	if j := strings.Index(body, "\n}\n"); j > 0 {
		body = body[:j]
	}

	codeCheck := strings.Index(body, `strings.TrimSpace(code) == ""`)
	firstSetting := strings.Index(body, `scanSetting(`)
	if codeCheck < 0 {
		t.Error("trySendInvitationEmail no longer refuses an empty code, so every caller depends " +
			"on remembering to check; that is exactly how this shipped with two call sites")
		return
	}
	if firstSetting >= 0 && codeCheck > firstSetting {
		t.Error("the empty-code check runs AFTER SMTP configuration is read; it must come first so " +
			"the reason for not sending is never confused with 'SMTP is not set up'")
	}
}

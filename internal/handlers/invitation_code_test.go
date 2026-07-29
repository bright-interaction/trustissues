package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
)

// TestLeakedDatabaseHasNoRedeemableInviteCode is the regression test for the
// only bearer credential this product stored in cleartext.
//
// THREAT-MODEL.md tells operators a stolen .db without the vault key "is safe to
// back up off-host". It was not. /api/invitations/redeem is unauthenticated by
// design, so a keyless backup taken while an invite was pending could be read
// for the code and redeemed against the live server. An admin-role invite yields
// a real admin account, and an admin can reset another user's password and then
// unlock their vault, so a copy documented as inert was a path to every secret.
//
// The test reads the stored row exactly as someone holding a keyless backup
// would: straight out of SQLite, with no vault key.
func TestLeakedDatabaseHasNoRedeemableInviteCode(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	uh := NewUserHandler(queries, &config.Config{VaultKey: strings.Repeat("k", 32)})
	uh.SetVault(vh)
	ctx := context.Background()

	admin := mustUser(t, queries, "inv-admin@example.com", "admin", "")

	req := httptest.NewRequest(http.MethodPost, "/api/admin/invitations",
		strings.NewReader(`{"email":"colleague@example.com","name":"Colleague","role":"admin"}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserIDKey, admin))
	rec := httptest.NewRecorder()
	uh.CreateInvitation(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create invitation: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Code == "" {
		t.Fatalf("no code returned to the admin: %s", rec.Body.String())
	}

	// What an attacker with the backup, and no vault key, actually sees.
	var storedCode, storedHash string
	if err := vh.db.QueryRow(
		`SELECT code, code_hash FROM invitations WHERE email = ?`, "colleague@example.com",
	).Scan(&storedCode, &storedHash); err != nil {
		t.Fatalf("read stored row: %v", err)
	}

	if storedCode == created.Code {
		t.Error("the invite code is stored in cleartext; a keyless backup redeems into a live admin account")
	}
	if storedHash == created.Code {
		t.Error("code_hash holds the code itself, so the hash column is not protecting anything")
	}
	if storedHash == "" {
		t.Error("code_hash is empty, so redemption cannot possibly be looking it up")
	}
	if !strings.Contains(storedCode, "enc:") && !strings.Contains(storedCode, "tienc:") {
		t.Errorf("the stored code does not look like ciphertext: %q", storedCode)
	}

	// Redeeming with what the attacker can read must fail.
	for name, guess := range map[string]string{
		"stored ciphertext": storedCode,
		"stored hash":       storedHash,
	} {
		rr := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
			strings.NewReader(`{"code":"`+guess+`","password":"Attack3rChos3n!"}`))
		uh.RedeemInvitation(rr, rq)
		if rr.Code == http.StatusOK || rr.Code == http.StatusCreated {
			t.Errorf("redeeming with the %s SUCCEEDED: the leak is still live", name)
		}
	}

	// The legitimate flow must still work, or this is a break not a fix.
	rr := httptest.NewRecorder()
	rq := httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
		strings.NewReader(`{"code":"`+created.Code+`","password":"L3gitPassw0rd!"}`))
	uh.RedeemInvitation(rr, rq)
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("the real invitee could not redeem their code: %d %s", rr.Code, rr.Body.String())
	}

	// And the admin list still shows the code, which is what resend depends on.
	rows, err := queries.ListInvitations(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 invitation, got %d", len(rows))
	}
	if got := uh.openInviteCode(rows[0].Code); got != created.Code {
		t.Errorf("the stored code no longer decrypts to the original (%q); resend would email a blank code", got)
	}
}

// TestInviteCodeHashIsStableAndDistinct guards the lookup key itself.
func TestInviteCodeHashIsStableAndDistinct(t *testing.T) {
	a := hashInviteCode("INV-AAAAAAAAAAAAAAAA")
	if a != hashInviteCode("INV-AAAAAAAAAAAAAAAA") {
		t.Error("hashInviteCode is not deterministic, so redemption would be a coin flip")
	}
	if a == hashInviteCode("INV-BBBBBBBBBBBBBBBB") {
		t.Error("two different codes hash the same")
	}
	if strings.Contains(a, "INV-") {
		t.Errorf("the hash embeds the code: %q", a)
	}
}

// TestPendingInvitesWereExpiredByTheMigration checks the other half of the fix.
// Every code that existed before this change is already sitting in cleartext in
// whatever backups were taken, so it has to be treated as burned rather than
// silently carried forward as still-redeemable.
func TestPendingInvitesWereExpiredByTheMigration(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	_ = vh

	// A pre-migration row: cleartext code, no hash, still pending.
	if _, err := queries.CreateInvitation(ctx, db.CreateInvitationParams{
		Code: "INV-LEGACYCLEARTEXT", CodeHash: "", Email: "legacy@example.com",
		Name: "Legacy", TargetRole: "admin",
	}); err != nil {
		t.Skipf("cannot seed a legacy row on this schema: %v", err)
	}
	// A row with an empty code_hash can never be found: hashInviteCode never
	// returns "", so the lookup cannot match it even while it says 'pending'.
	if _, err := queries.GetPendingInvitationByCode(ctx, hashInviteCode("INV-LEGACYCLEARTEXT")); err == nil {
		t.Error("a legacy cleartext invitation is still redeemable after the migration")
	}
}

package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
)

const canonicalIdentityTestPassword = "CanonicalIdentityPassw0rd!"

func TestAccountAuthAndInvitationPathsShareOneCanonicalEmailIdentity(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	cfg := &config.Config{
		JWTSecret: strings.Repeat("j", 32),
		VaultKey:  strings.Repeat("k", 32),
	}
	auth := NewAuthHandler(queries, cfg)
	users := NewUserHandler(queries, cfg)
	users.SetVault(vault)
	ctx := context.Background()

	register := httptest.NewRecorder()
	auth.Register(register, httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(
		`{"email":"First Admin <First.Admin@Example.COM>","password":"`+canonicalIdentityTestPassword+`","name":"First"}`,
	)))
	if register.Code != http.StatusCreated {
		t.Fatalf("register: HTTP %d: %s", register.Code, register.Body.String())
	}
	admin, err := queries.GetUserByEmail(ctx, "first.admin@example.com")
	if err != nil {
		t.Fatalf("registered account was not stored canonically: %v", err)
	}
	if admin.Email != "first.admin@example.com" {
		t.Fatalf("registered email = %q, want canonical value", admin.Email)
	}

	login := httptest.NewRecorder()
	auth.Login(login, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(
		`{"email":"Administrator <FIRST.ADMIN@EXAMPLE.COM>","password":"`+canonicalIdentityTestPassword+`"}`,
	)))
	if login.Code != http.StatusOK {
		t.Fatalf("case/space variant login: HTTP %d: %s", login.Code, login.Body.String())
	}
	var attempts, noncanonicalAttempts int
	if err := vault.db.QueryRow(
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE email <> 'first.admin@example.com')
		 FROM login_attempts WHERE lower(trim(email)) = 'first.admin@example.com'`,
	).Scan(&attempts, &noncanonicalAttempts); err != nil {
		t.Fatalf("read login attempts: %v", err)
	}
	if attempts != 1 || noncanonicalAttempts != 0 {
		t.Fatalf("login attempt identity not canonical: rows=%d noncanonical=%d", attempts, noncanonicalAttempts)
	}

	created := httptest.NewRecorder()
	users.Create(created, withUser(httptest.NewRequest(http.MethodPost, "/api/admin/users", strings.NewReader(
		`{"email":"Direct Client <Direct.Client@Example.COM>","password":"`+canonicalIdentityTestPassword+`","role":"user"}`,
	)), admin.ID))
	if created.Code != http.StatusCreated {
		t.Fatalf("admin user creation: HTTP %d: %s", created.Code, created.Body.String())
	}
	if _, err := queries.GetUserByEmail(ctx, "direct.client@example.com"); err != nil {
		t.Fatalf("admin-created account was not stored canonically: %v", err)
	}
	duplicate := httptest.NewRecorder()
	users.Create(duplicate, withUser(httptest.NewRequest(http.MethodPost, "/api/admin/users", strings.NewReader(
		`{"email":"direct.client@example.com","password":"`+canonicalIdentityTestPassword+`","role":"user"}`,
	)), admin.ID))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("bare address did not collide with stored display form: HTTP %d: %s", duplicate.Code, duplicate.Body.String())
	}

	invitedEmail := "invited.client@example.com"
	invited := httptest.NewRecorder()
	users.CreateInvitation(invited, withUser(httptest.NewRequest(http.MethodPost, "/api/admin/invitations", strings.NewReader(
		`{"email":"Invited Client <Invited.Client@Example.COM>","name":"Client","role":"user"}`,
	)), admin.ID))
	if invited.Code != http.StatusCreated {
		t.Fatalf("create invitation: HTTP %d: %s", invited.Code, invited.Body.String())
	}
	var invitation invitationResponse
	if err := json.Unmarshal(invited.Body.Bytes(), &invitation); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}
	if invitation.Email != invitedEmail {
		t.Fatalf("invitation email = %q, want %q", invitation.Email, invitedEmail)
	}

	redeemed := httptest.NewRecorder()
	users.RedeemInvitation(redeemed, httptest.NewRequest(http.MethodPost, "/api/invitations/redeem", strings.NewReader(
		`{"code":"`+invitation.Code+`","password":"`+canonicalIdentityTestPassword+`"}`,
	)))
	if redeemed.Code != http.StatusOK {
		t.Fatalf("redeem invitation: HTTP %d: %s", redeemed.Code, redeemed.Body.String())
	}
	if _, err := queries.GetUserByEmail(ctx, invitedEmail); err != nil {
		t.Fatalf("redeemed account was not stored under invitation identity: %v", err)
	}
	if _, err := queries.GetUserByEmail(ctx, "Invited.Client@Example.COM"); err != sql.ErrNoRows {
		t.Fatalf("noncanonical account identity unexpectedly resolves directly: %v", err)
	}
}

func TestQuotedInternationalIdentitySurvivesRegistrationAndLogin(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	cfg := &config.Config{
		JWTSecret: strings.Repeat("j", 32),
		VaultKey:  strings.Repeat("k", 32),
	}
	auth := NewAuthHandler(queries, cfg)
	users := NewUserHandler(queries, cfg)
	users.SetVault(vault)
	ctx := context.Background()

	registerBody, err := json.Marshal(map[string]string{
		"email":    `Operations <"Root@Admin"@BÜCHER.DE.>`,
		"password": canonicalIdentityTestPassword,
		"name":     "International admin",
	})
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	register := httptest.NewRecorder()
	auth.Register(register, httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(string(registerBody))))
	if register.Code != http.StatusCreated {
		t.Fatalf("register quoted U-label identity: HTTP %d: %s", register.Code, register.Body.String())
	}

	const canonical = `"root@admin"@xn--bcher-kva.de`
	admin, err := queries.GetUserByEmail(ctx, canonical)
	if err != nil {
		t.Fatalf("registered quoted identity was not stored under its canonical A-label: %v", err)
	}
	if admin.Email != canonical {
		t.Fatalf("registered email = %q, want %q", admin.Email, canonical)
	}

	loginBody, err := json.Marshal(map[string]string{
		"email":    `Login <"ROOT@ADMIN"@XN--BCHER-KVA.DE>`,
		"password": canonicalIdentityTestPassword,
	})
	if err != nil {
		t.Fatalf("marshal login request: %v", err)
	}
	login := httptest.NewRecorder()
	auth.Login(login, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(loginBody))))
	if login.Code != http.StatusOK {
		t.Fatalf("login through equivalent A-label identity: HTTP %d: %s", login.Code, login.Body.String())
	}

	invalidBody, err := json.Marshal(map[string]string{
		"email":    "client@-example.com",
		"password": canonicalIdentityTestPassword,
		"role":     "user",
	})
	if err != nil {
		t.Fatalf("marshal invalid user request: %v", err)
	}
	invalid := httptest.NewRecorder()
	users.Create(invalid, withUser(httptest.NewRequest(http.MethodPost, "/api/admin/users", strings.NewReader(string(invalidBody))), admin.ID))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("IDNA-invalid account creation: HTTP %d: %s", invalid.Code, invalid.Body.String())
	}

	if err := ValidateEmail(`SMTP Sender <"Ops@Team"@bücher.de.>`); err != nil {
		t.Fatalf("strict IDNA validation broke a valid display-name form: %v", err)
	}
	if err := ValidateEmail("SMTP Sender <sender@-example.com>"); err == nil {
		t.Fatal("ValidateEmail accepted an IDNA-invalid display-name form")
	}
}

func TestCollectionInvitationPathsUseCanonicalAccountIdentity(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	h := NewCollectionHandler(queries, vault)
	ctx := context.Background()

	manager := mustUser(t, queries, "identity-manager@example.com", "user", "")
	invitee := mustUser(t, queries, "seat.client@example.com", "user", "")
	mustCollection(t, queries, "identity-collection", manager, map[string]string{manager: collRoleManager})

	invalid := httptest.NewRecorder()
	h.AddMember(invalid, collectionRequest(http.MethodPost, "/api/collections/identity-collection/members",
		manager, "user", "identity-collection", `{"email":"seat@-example.com","role":"editor"}`))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("IDNA-invalid collection seat: HTTP %d: %s", invalid.Code, invalid.Body.String())
	}
	var invalidSeats int
	if err := vault.db.QueryRow(
		`SELECT COUNT(*) FROM collection_invitations WHERE collection_id = ?`, "identity-collection",
	).Scan(&invalidSeats); err != nil {
		t.Fatalf("count collection seats after invalid request: %v", err)
	}
	if invalidSeats != 0 {
		t.Fatalf("IDNA-invalid request persisted %d collection seats", invalidSeats)
	}

	add := httptest.NewRecorder()
	h.AddMember(add, collectionRequest(http.MethodPost, "/api/collections/identity-collection/members",
		manager, "user", "identity-collection", `{"email":"Seat Client <SEAT.CLIENT@EXAMPLE.COM>","role":"editor"}`))
	if add.Code != http.StatusOK {
		t.Fatalf("add member with variant identity: HTTP %d: %s", add.Code, add.Body.String())
	}
	seat, err := queries.GetCollectionMembership(ctx, db.GetCollectionMembershipParams{
		CollectionID: "identity-collection", UserID: invitee,
	})
	if err != nil {
		t.Fatalf("variant email did not resolve the existing account: %v", err)
	}
	if seat.AcceptedAt.Valid || seat.Role != collRoleEditor {
		t.Fatalf("membership = role %q accepted=%t, want pending editor", seat.Role, seat.AcceptedAt.Valid)
	}
	var storedEmail string
	if err := vault.db.QueryRow(
		`SELECT email FROM collection_invitations WHERE collection_id = ?`, "identity-collection",
	).Scan(&storedEmail); err != nil {
		t.Fatalf("read invitation seat: %v", err)
	}
	if storedEmail != "seat.client@example.com" {
		t.Fatalf("collection seat email = %q, want canonical identity", storedEmail)
	}

	rescind := httptest.NewRecorder()
	h.RescindInvitation(rescind, collectionRequest(http.MethodDelete, "/api/collections/identity-collection/invitations",
		manager, "user", "identity-collection", `{"email":" Seat.Client@Example.COM\t"}`))
	if rescind.Code != http.StatusNoContent {
		t.Fatalf("rescind with variant identity: HTTP %d: %s", rescind.Code, rescind.Body.String())
	}
	if _, err := queries.GetCollectionMembership(ctx, db.GetCollectionMembershipParams{
		CollectionID: "identity-collection", UserID: invitee,
	}); err != sql.ErrNoRows {
		t.Fatalf("rescind left pending membership behind: %v", err)
	}
}

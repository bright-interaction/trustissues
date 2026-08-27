package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
)

// These tests use newCollectionAuthzEnv rather than an in-memory shortcut. It
// opens the same file-backed SQLite DSN as production, including
// _txlock=immediate. That detail is part of the security property: invitation
// consumption is a single-writer transaction, so either a revocation commits
// first and redemption sees no invitation, or redemption atomically consumes
// the invitation with every account bootstrap write.

func seedAtomicityInvitation(t *testing.T, queries *db.Queries, email, role string) (code, id string) {
	t.Helper()

	code = "INV-" + strings.ToUpper(randomHex(8))
	row, err := queries.CreateInvitation(context.Background(), db.CreateInvitationParams{
		Code:       "sealed-test-code-" + randomHex(8),
		CodeHash:   hashInviteCode(code),
		Email:      email,
		Name:       "Atomic Invitee",
		TargetRole: role,
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	return code, row.ID
}

func redeemAtomicityInvitation(h *UserHandler, code string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
		strings.NewReader(fmt.Sprintf(`{"code":%q,"password":"AtomicInvitePassw0rd!"}`, code)))
	h.RedeemInvitation(rec, req)
	return rec
}

func redeemAtomicityInvitationWithoutPassword(h *UserHandler, code string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
		strings.NewReader(fmt.Sprintf(`{"code":%q}`, code)))
	h.RedeemInvitation(rec, req)
	return rec
}

func countAtomicityRows(t *testing.T, conn *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := conn.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count rows with %q: %v", query, err)
	}
	return n
}

func assertPendingAtomicityInvitation(t *testing.T, conn *sql.DB, invitationID string) {
	t.Helper()
	var status string
	var redeemedBy sql.NullString
	var redeemedAt sql.NullTime
	if err := conn.QueryRowContext(context.Background(),
		`SELECT status, redeemed_by, redeemed_at FROM invitations WHERE id = ?`, invitationID,
	).Scan(&status, &redeemedBy, &redeemedAt); err != nil {
		t.Fatalf("read invitation after failed redemption: %v", err)
	}
	if status != "pending" || redeemedBy.Valid || redeemedAt.Valid {
		t.Fatalf("failed redemption mutated invitation: status=%q redeemed_by=%v redeemed_at=%v",
			status, redeemedBy, redeemedAt)
	}
}

func TestInvitationPendingSeatClaimFailureRollsBackAccount(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewUserHandler(queries, &config.Config{
		VaultKey: strings.Repeat("k", 32),
		BaseURL:  "https://vault.example.test",
	})
	email := "atomic-seat-failure@example.com"
	code, invitationID := seedAtomicityInvitation(t, queries, email, "vault_only")
	admin := mustUser(t, queries, "atomic-seat-admin@example.com", "admin", "AdminPassw0rd!")
	const collectionID = "atomic-seat-claim-collection"
	if err := queries.CreateCollection(context.Background(), db.CreateCollectionParams{
		ID: collectionID, Name: "Client vault", CreatedBy: toNullString(admin),
	}); err != nil {
		t.Fatalf("seed collection: %v", err)
	}
	if err := queries.UpsertCollectionInvitation(context.Background(), db.UpsertCollectionInvitationParams{
		CollectionID: collectionID, Email: email, Role: "viewer", InvitedBy: toNullString(admin),
	}); err != nil {
		t.Fatalf("seed collection seat: %v", err)
	}

	// Fail the pending-seat materialization after the account insert. Account,
	// seat claim, and invitation consume must remain one transaction: otherwise
	// this leaves a user that cannot see the invitation it was created to accept.
	if _, err := vh.db.ExecContext(context.Background(), `
		CREATE TRIGGER fail_pending_seat_claim
		BEFORE INSERT ON collection_members
		WHEN NEW.collection_id = 'atomic-seat-claim-collection'
		BEGIN
			SELECT RAISE(ABORT, 'forced pending-seat claim failure');
		END
	`); err != nil {
		t.Fatalf("install seat-claim failure trigger: %v", err)
	}

	rec := redeemAtomicityInvitation(h, code)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("seat-claim failure got HTTP %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM users WHERE email = ?`, email); got != 0 {
		t.Fatalf("seat-claim failure left %d user row(s); account bootstrap was not atomic", got)
	}
	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM collection_members WHERE collection_id = ?`, collectionID); got != 0 {
		t.Fatalf("seat-claim failure left %d membership row(s)", got)
	}
	if got := countAtomicityRows(t, vh.db,
		`SELECT COUNT(*) FROM collection_invitations WHERE collection_id = ? AND email = ?`, collectionID, email,
	); got != 1 {
		t.Fatalf("seat-claim failure lost the pending collection seat (rows=%d)", got)
	}
	assertPendingAtomicityInvitation(t, vh.db, invitationID)
}

func TestInvitationRevokedBetweenCheckAndConsumeRollsBackAccount(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewUserHandler(queries, &config.Config{
		VaultKey: strings.Repeat("k", 32),
		BaseURL:  "https://vault.example.test",
	})
	email := "atomic-revoked-midflight@example.com"
	code, invitationID := seedAtomicityInvitation(t, queries, email, "vault_only")

	// Deterministically invalidate the bearer capability at the narrowest race
	// point: after the handler's pending-invitation read but as it inserts the
	// account. The conditional invitation consume must then affect zero rows and
	// make the whole transaction roll back. Under the old multi-transaction flow,
	// this trigger deleted the invitation and committed the new user together;
	// redemption still returned success and the administrator's revocation lost.
	trigger := fmt.Sprintf(`
		CREATE TRIGGER revoke_invitation_during_account_bootstrap
		BEFORE INSERT ON users
		WHEN NEW.email = %q
		BEGIN
			DELETE FROM invitations WHERE id = %q;
		END
	`, email, invitationID)
	if _, err := vh.db.ExecContext(context.Background(), trigger); err != nil {
		t.Fatalf("install midflight revocation trigger: %v", err)
	}

	rec := redeemAtomicityInvitation(h, code)
	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Fatalf("redemption succeeded after its invitation was revoked midflight: %s", rec.Body.String())
	}
	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM users WHERE email = ?`, email); got != 0 {
		t.Fatalf("midflight revocation left %d user row(s)", got)
	}
	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM api_keys`); got != 0 {
		t.Fatalf("midflight revocation left %d API-key row(s)", got)
	}
	// The trigger's deletion was in the same transaction. A correct rollback
	// restores the pending row, allowing the administrator to explicitly revoke
	// or retry it after resolving the conflict.
	assertPendingAtomicityInvitation(t, vh.db, invitationID)
}

func TestCommittedInvitationRevocationWinsConcurrentRedemption(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewUserHandler(queries, &config.Config{
		VaultKey: strings.Repeat("k", 32),
		BaseURL:  "https://vault.example.test",
	})
	email := "atomic-revocation-wins@example.com"
	code, invitationID := seedAtomicityInvitation(t, queries, email, "vault_only")

	// BeginTx is BEGIN IMMEDIATE on this production-style DSN. Hold the writer
	// lock with an uncommitted admin revocation, then race redemption against it.
	// Redemption must wait, observe the committed deletion, and write nothing.
	revokeTx, err := vh.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin revocation transaction: %v", err)
	}
	defer revokeTx.Rollback()
	if result, err := revokeTx.ExecContext(context.Background(),
		`DELETE FROM invitations WHERE id = ? AND status = 'pending'`, invitationID); err != nil {
		t.Fatalf("stage invitation revocation: %v", err)
	} else if n, err := result.RowsAffected(); err != nil || n != 1 {
		t.Fatalf("stage invitation revocation affected %d rows (err=%v), want 1", n, err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- redeemAtomicityInvitation(h, code) }()

	select {
	case rec := <-done:
		t.Fatalf("redemption returned before the competing writer committed (HTTP %d): %s",
			rec.Code, rec.Body.String())
	case <-time.After(100 * time.Millisecond):
		// It is blocked behind the revocation writer, as required.
	}
	if err := revokeTx.Commit(); err != nil {
		t.Fatalf("commit invitation revocation: %v", err)
	}

	var rec *httptest.ResponseRecorder
	select {
	case rec = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("redemption did not finish after the competing revocation committed")
	}
	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Fatalf("redemption succeeded after revocation committed first: %s", rec.Body.String())
	}
	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM invitations WHERE id = ?`, invitationID); got != 0 {
		t.Fatalf("committed revocation did not remain effective; found %d invitation row(s)", got)
	}
	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM users WHERE email = ?`, email); got != 0 {
		t.Fatalf("revocation-first race left %d user row(s)", got)
	}
	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM api_keys`); got != 0 {
		t.Fatalf("revocation-first race left %d API-key row(s)", got)
	}
}

func TestConcurrentInvitationRedeemsCreateExactlyOneCompleteAccount(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewUserHandler(queries, &config.Config{
		VaultKey: strings.Repeat("k", 32),
		BaseURL:  "https://vault.example.test",
	})
	email := "atomic-double-redeem@example.com"
	code, invitationID := seedAtomicityInvitation(t, queries, email, "vault_only")

	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			ready.Done()
			<-start
			results <- redeemAtomicityInvitation(h, code)
		}()
	}
	ready.Wait()
	close(start)

	responses := make([]*httptest.ResponseRecorder, 0, 2)
	deadline := time.After(10 * time.Second)
	for len(responses) < 2 {
		select {
		case rec := <-results:
			responses = append(responses, rec)
		case <-deadline:
			t.Fatal("concurrent invitation redemptions did not finish")
		}
	}

	successes := 0
	for _, rec := range responses {
		if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
			successes++
			if strings.Contains(rec.Body.String(), `"api_key"`) ||
				strings.Contains(rec.Body.String(), `"api_key_expires_at"`) ||
				strings.Contains(rec.Body.String(), `"server_url"`) {
				t.Errorf("successful web-first redemption returned extension bootstrap fields: %s", rec.Body.String())
			}
			continue
		}
		if rec.Code >= 500 {
			t.Errorf("losing redemption returned HTTP %d instead of an invalid/conflict response: %s",
				rec.Code, rec.Body.String())
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent redemption successes=%d, want exactly 1 (responses: %d %s; %d %s)",
			successes, responses[0].Code, responses[0].Body.String(),
			responses[1].Code, responses[1].Body.String())
	}

	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM users WHERE email = ?`, email); got != 1 {
		t.Fatalf("double redemption produced %d user rows, want exactly 1", got)
	}
	if got := countAtomicityRows(t, vh.db,
		`SELECT COUNT(*) FROM api_keys k JOIN users u ON u.id = k.user_id WHERE u.email = ?`, email,
	); got != 0 {
		t.Fatalf("double redemption produced %d implicit API keys, want zero", got)
	}

	var status string
	var redeemedBy sql.NullString
	if err := vh.db.QueryRowContext(context.Background(),
		`SELECT status, redeemed_by FROM invitations WHERE id = ?`, invitationID,
	).Scan(&status, &redeemedBy); err != nil {
		t.Fatalf("read consumed invitation: %v", err)
	}
	if status != "redeemed" || !redeemedBy.Valid || redeemedBy.String == "" {
		t.Fatalf("invitation was not atomically consumed: status=%q redeemed_by=%v", status, redeemedBy)
	}
	if got := countAtomicityRows(t, vh.db,
		`SELECT COUNT(*) FROM users WHERE id = ? AND email = ?`, redeemedBy.String, email,
	); got != 1 {
		t.Fatalf("invitation redeemed_by does not identify the sole created account")
	}
}

func TestInvitationRedemptionRequiresPasswordForEveryRole(t *testing.T) {
	for _, role := range []string{"vault_only", "user", "admin"} {
		t.Run(role, func(t *testing.T) {
			vh, queries := newCollectionAuthzEnv(t)
			h := NewUserHandler(queries, &config.Config{
				VaultKey: strings.Repeat("k", 32),
				BaseURL:  "https://vault.example.test",
			})
			email := "password-required-" + role + "@example.com"
			code, invitationID := seedAtomicityInvitation(t, queries, email, role)

			rec := redeemAtomicityInvitationWithoutPassword(h, code)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("password-less %s redemption got HTTP %d, want 400: %s",
					role, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "password is required") {
				t.Fatalf("password-less %s redemption returned unclear error: %s", role, rec.Body.String())
			}
			if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM users WHERE email = ?`, email); got != 0 {
				t.Fatalf("password-less %s redemption left %d user row(s)", role, got)
			}
			assertPendingAtomicityInvitation(t, vh.db, invitationID)
		})
	}
}

func TestInvitationRedemptionRechecksPasswordPolicyInsideTransaction(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	h := NewUserHandler(queries, &config.Config{
		VaultKey: strings.Repeat("k", 32),
		BaseURL:  "https://vault.example.test",
	})
	email := "password-policy-race@example.com"
	code, invitationID := seedAtomicityInvitation(t, queries, email, "user")

	// Pause after the first policy check but before BEGIN IMMEDIATE. An admin
	// can now tighten the policy and commit. The authoritative check under the
	// redemption transaction must observe that newer value and reject the user.
	hasherEntered := make(chan struct{})
	releaseHasher := make(chan struct{})
	h.invitationPasswordHasher = func(string) (string, error) {
		close(hasherEntered)
		<-releaseHasher
		return "test-password-hash", nil
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/invitations/redeem",
			strings.NewReader(fmt.Sprintf(`{"code":%q,"password":"ValidOldPassword!23"}`, code)))
		h.RedeemInvitation(rec, req)
		done <- rec
	}()

	select {
	case <-hasherEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("redemption did not reach the password hashing barrier")
	}
	if err := queries.UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: "min_password_length", Value: "64",
	}); err != nil {
		t.Fatalf("tighten password policy: %v", err)
	}
	close(releaseHasher)

	var rec *httptest.ResponseRecorder
	select {
	case rec = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("redemption did not finish after releasing password hasher")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("redemption under tightened policy got HTTP %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at least 64 characters") {
		t.Fatalf("redemption did not report the committed password policy: %s", rec.Body.String())
	}
	if got := countAtomicityRows(t, vh.db, `SELECT COUNT(*) FROM users WHERE email = ?`, email); got != 0 {
		t.Fatalf("policy race left %d user row(s)", got)
	}
	assertPendingAtomicityInvitation(t, vh.db, invitationID)
}

package vaultegress

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// THE OWNERSHIP TRANSFER, DRIVEN AGAINST A REAL DATABASE.
//
// The structural guards prove there is exactly ONE post-creation writer of
// secret_owner_user_id and that it is out of reach of the handlers. That says
// nothing about whether the lock on it is a lock. These drive it.

// TestTransferSecretOwnershipRefusesAProofThatDoesNotAuthorise is the negative
// control for the write itself: the wrapper must refuse before it writes, not
// after.
func TestTransferSecretOwnershipRefusesAProofThatDoesNotAuthorise(t *testing.T) {
	q, conn := newTestQueries(t)
	ctx := context.Background()

	before := readOwner(t, conn)
	if before != "u1" {
		t.Fatalf("ABORT: the seeded entry's owner is %q, want u1; this test would prove nothing", before)
	}

	good, err := AuthorizeTransfer(TransferRequest{
		EntryID: testEntryID, Actor: "admin-1", ActorIsInstanceAdmin: true,
		To: "admin-1", Why: "the covering test",
	})
	if err != nil {
		t.Fatalf("a legitimate transfer was refused: %v", err)
	}

	cases := []struct {
		name    string
		proof   TransferProof
		entryID string
		newOwn  string
		want    string
	}{
		{"the zero proof", TransferProof{}, testEntryID, "attacker",
			"the zero TransferProof authorises nothing"},
		{"a proof for another entry", good, "some-other-entry", "admin-1",
			"is for entry"},
		{"a proof spent on a different recipient", good, testEntryID, "attacker",
			"was spent to make"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := TransferSecretOwnership(ctx, q, tc.proof,
				TransferOwnershipParams{NewOwnerUserID: tc.newOwn, ID: tc.entryID}); err == nil {
				t.Fatal("the write was performed. A wrapper that takes a proof and does not check it " +
					"is a chokepoint with no lock on it")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			if now := readOwner(t, conn); now != before {
				t.Fatalf("the owner moved to %q despite the refusal; the wrapper wrote first and "+
					"complained afterwards, which is exactly as good as not checking", now)
			}
		})
	}

	// POSITIVE CONTROL. A gate that refuses everything is not a fix: the product
	// has a genuine transfer and it has to keep working.
	if _, err := TransferSecretOwnership(ctx, q, good,
		TransferOwnershipParams{NewOwnerUserID: "admin-1", ID: testEntryID}); err != nil {
		t.Fatalf("the authorised transfer was refused: %v", err)
	}
	if now := readOwner(t, conn); now != "admin-1" {
		t.Fatalf("after an authorised transfer the owner is %q, want admin-1", now)
	}
	if custodian := readCustodian(t, conn); custodian != "admin-1" {
		t.Fatalf("the transfer moved the owner to admin-1 and left the custodian at %q. Both columns "+
			"move together or UNIQUE(user_id, name) lands in one namespace and the widening right in "+
			"another", custodian)
	}
}

// TestAuthorizeTransferIsTheOnlyWayToGetAProof pins the RULE, which is the half
// a structural guard cannot see.
func TestAuthorizeTransferIsTheOnlyWayToGetAProof(t *testing.T) {
	base := TransferRequest{
		EntryID: "e1", Actor: "admin-1", ActorIsInstanceAdmin: true, To: "admin-1", Why: "offboarding",
	}
	if _, err := AuthorizeTransfer(base); err != nil {
		t.Fatalf("the one legitimate shape was refused: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*TransferRequest)
		want string
	}{
		{"a collection manager taking ownership", func(r *TransferRequest) {
			r.Actor, r.To, r.ActorIsInstanceAdmin = "manager-1", "manager-1", false
		}, "instance admin"},
		{"an admin handing ownership to a manager", func(r *TransferRequest) {
			r.To = "manager-1"
		}, "never handed to a third party"},
		{"no entry named", func(r *TransferRequest) { r.EntryID = "  " }, "no entry was named"},
		{"no acting principal", func(r *TransferRequest) { r.Actor = "" }, "no acting principal"},
		{"no reason recorded", func(r *TransferRequest) { r.Why = "" }, "not be attributable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mut(&req)
			p, err := AuthorizeTransfer(req)
			if err == nil {
				t.Fatal("AuthorizeTransfer granted a proof it must refuse")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			if err := p.authorizes(req.EntryID, req.To); err == nil {
				t.Fatal("the refused proof still authorises the write it was refused for")
			}
		})
	}
}

func readOwner(t *testing.T, conn *sql.DB) string {
	t.Helper()
	var v string
	if err := conn.QueryRow(
		`SELECT secret_owner_user_id FROM vault_entries WHERE id = ?`, testEntryID).Scan(&v); err != nil {
		t.Fatalf("read secret_owner_user_id: %v", err)
	}
	return v
}

func readCustodian(t *testing.T, conn *sql.DB) string {
	t.Helper()
	var v string
	if err := conn.QueryRow(
		`SELECT user_id FROM vault_entries WHERE id = ?`, testEntryID).Scan(&v); err != nil {
		t.Fatalf("read user_id: %v", err)
	}
	return v
}

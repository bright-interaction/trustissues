package handlers

import (
	"context"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/db"
)

// TestTheAuditNameIsNotReadableFromTheDatabaseFile is the twin 00040 left
// behind.
//
// capability_log.secret_name records the name of every secret a capability
// token was minted for. It is written on issue, on use and on denial, so in
// cleartext it rebuilds the inventory vault_entries.name was just encrypted to
// hide, out of the same stolen file.
func TestTheAuditNameIsNotReadableFromTheDatabaseFile(t *testing.T) {
	h, _ := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const secretish = "Acme prod DB"
	sealed := h.SealAuditName(ctx, secretish)

	if strings.Contains(sealed, secretish) {
		t.Fatalf("THE AUDIT NAME IS CLEARTEXT: %q. Every capability issue, use and denial writes one "+
			"of these, so a keyless copy of the database rebuilds the inventory from the audit trail", sealed)
	}
	if sealed == "" {
		t.Fatal("a non-empty name sealed to nothing, which loses the audit record entirely")
	}
	if got := h.openAuditName(ctx, sealed); got != secretish {
		t.Errorf("the audit name did not round-trip: %q", got)
	}
	// Empty stays empty: "no name recorded" is a different fact from "a name was
	// recorded", and it must not become ciphertext that decrypts to nothing.
	if got := h.SealAuditName(ctx, ""); got != "" {
		t.Errorf("an empty name was sealed into %q", got)
	}
}

// TestTheAuditNameKeyIsNotTheMasterKey is the property the whole envelope
// exists for. If the audit columns were sealed under the master key, the rekey
// sweep would have to rewrite append-only rows it is forbidden to touch.
func TestTheAuditNameKeyIsNotTheMasterKey(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	dek, err := h.auditNameDEK(ctx)
	if err != nil {
		t.Fatalf("load dek: %v", err)
	}
	if dek == h.encryptionKey {
		t.Fatal("THE AUDIT DEK IS THE MASTER CONTENT KEY. Then the audit rows are master-key " +
			"ciphertext, a rotation must rewrite them, and the append-only triggers make that " +
			"impossible: the rows would be orphaned permanently")
	}
	if dek == h.bidxKey || dek == h.legacyKey {
		t.Fatal("the audit DEK collides with another derived key")
	}

	// It is a STORED random key, not a derivation of the master key: two
	// handlers over the same database get the same DEK, and a handler over a
	// different database gets a different one.
	stored, sErr := queries.GetSetting(ctx, auditDEKSetting)
	if sErr != nil || stored == "" {
		t.Fatalf("the wrapped DEK was not persisted: %v", sErr)
	}
	if !columncrypto.IsEncrypted(stored) {
		t.Errorf("THE DEK IS STORED IN CLEARTEXT: %q. A stolen file would carry the key to its own "+
			"audit trail", stored)
	}

	second := rekeyHandler(h.db, queries, h.keySource, "")
	again, aErr := second.auditNameDEK(ctx)
	if aErr != nil {
		t.Fatalf("second handler: %v", aErr)
	}
	if again != dek {
		t.Error("a second handler over the same store minted a DIFFERENT audit key, so everything " +
			"the first one wrote is unreadable")
	}
}

// TestTheAuditNameSurvivesAMasterKeyRotation is the whole point, end to end.
//
// The master key changes, the sweep runs, and the audit rows are NOT rewritten
// (they cannot be). They must still open, because what rotated is the wrapping
// of the DEK, not the audit data.
func TestTheAuditNameSurvivesAMasterKeyRotation(t *testing.T) {
	dbConn, queries := newRekeyDB(t)
	old := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	ctx := context.Background()

	const recorded = "Klarna prod DB"
	sealed := old.SealAuditName(ctx, recorded)
	if sealed == "" || strings.Contains(sealed, recorded) {
		t.Fatalf("ABORT: the fixture did not seal the name (%q)", sealed)
	}
	// Write it into the real append-only table, so the test is about a row that
	// genuinely cannot be rewritten.
	if _, err := dbConn.Exec(
		`INSERT INTO capability_log (id, agent_id, secret_name, event, nonce) VALUES (?, ?, ?, ?, ?)`,
		"cap-rot-1", "agent-1", sealed, "issued", "nonce-rot-1"); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	// Rotate: new key current, old key still readable, then sweep.
	fresh := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	if _, err := fresh.RekeyVault(ctx); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	// THE AUDIT ROW IS UNTOUCHED. If the sweep had tried to rewrite it, the
	// append-only trigger would have aborted the whole rotation.
	var afterRow string
	if err := dbConn.QueryRow(`SELECT secret_name FROM capability_log WHERE id = ?`, "cap-rot-1").
		Scan(&afterRow); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if afterRow != sealed {
		t.Errorf("the rotation rewrote an append-only audit row: %q -> %q", sealed, afterRow)
	}

	// AND IT STILL OPENS, under the NEW master key alone, which is the state the
	// operator is told is safe before they delete the old key.
	newOnly := rekeyHandler(dbConn, queries, rekeyNewKey, "")
	if got := newOnly.openAuditName(ctx, afterRow); got != recorded {
		t.Errorf("THE AUDIT NAME DID NOT SURVIVE THE ROTATION: got %q want %q. The DEK's wrapping is "+
			"what should have rotated; if this fails the audit trail is orphaned and cannot be "+
			"repaired, because the rows are append-only", got, recorded)
	}
}

// TestTheAuditWriteNeverFallsBackToCleartext. sealAuditName is on a path that
// deliberately never fails a request: an audit write must not take down a
// credential fetch. That makes the failure mode the thing to pin, because the
// tempting implementation logs the error and writes the name through.
func TestTheAuditWriteNeverFallsBackToCleartext(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	// Corrupt the stored DEK so it cannot be unwrapped. This is the shape of a
	// wrong master key or a damaged row.
	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: auditDEKSetting, Value: "tienc:v1:" + strings.Repeat("A", 60),
	}); err != nil {
		t.Fatalf("corrupt dek: %v", err)
	}

	got := h.SealAuditName(ctx, "Acme prod DB")
	if strings.Contains(got, "Acme prod DB") {
		t.Fatalf("THE NAME WAS WRITTEN IN CLEARTEXT when the key was unavailable: %q. A degraded "+
			"audit row is acceptable; silently storing the value this exists to protect is not", got)
	}
	if got != auditNameUnavailable {
		t.Errorf("expected the placeholder %q, got %q", auditNameUnavailable, got)
	}
	// And the placeholder is distinguishable from "no name was recorded".
	if got == "" {
		t.Error("the failure marker is the empty string, which reads as 'no name recorded' and hides " +
			"that something went wrong")
	}
}

// TestPreExistingCleartextAuditRowsStillRead. Rows written before this existed
// are cleartext and CANNOT be converted: the tables are append-only. The reader
// has to pass them through rather than treat them as corrupt.
func TestPreExistingCleartextAuditRowsStillRead(t *testing.T) {
	h, _ := newCollectionAuthzEnv(t)
	if got := h.openAuditName(context.Background(), "legacy cleartext name"); got != "legacy cleartext name" {
		t.Errorf("a pre-encryption audit row stopped reading: %q", got)
	}
}

// TestTheCapabilityLogWriterSealsTheName drives the INSERT itself, not the
// helper.
//
// The first version of this file tested SealAuditName in isolation, so ablating
// the call site (writing secretName straight into the INSERT) left every test
// green. A property that lives at a call site has to be tested at that call
// site.
func TestTheCapabilityLogWriterSealsTheName(t *testing.T) {
	h, _ := newCollectionAuthzEnv(t)
	ch := &CapabilityHandler{db: h.db, vault: h}

	const recorded = "Acme prod DB"
	ch.logCapabilityEvent(context.Background(), "agent-1", nil, recorded,
		"api.stripe.com", "POST", "issued", 0, "", "nonce-seal-1")

	var stored string
	if err := h.db.QueryRow(
		`SELECT secret_name FROM capability_log WHERE nonce = ?`, "nonce-seal-1").Scan(&stored); err != nil {
		t.Fatalf("read the audit row back: %v", err)
	}
	if stored == "" {
		t.Fatal("ABORT: no audit row was written, so this test proves nothing")
	}
	if strings.Contains(stored, recorded) {
		t.Fatalf("THE CAPABILITY LOG STORED THE SECRET NAME IN CLEARTEXT: %q", stored)
	}
	if got := h.openAuditName(context.Background(), stored); got != recorded {
		t.Errorf("the stored audit name does not open back to the original: %q", got)
	}
}

// TestTheServiceAuditWriterSealsTheNames is the same property on the other
// twin. service_secret_audit records which secrets a service pulled, so it
// reconstructs the same inventory from the other direction.
func TestTheServiceAuditWriterSealsTheNames(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	sh := NewServiceSecretsHandler(queries, h)

	sh.audit("svc-1", "billing-worker", "fetch",
		[]string{"STRIPE_KEY", "POSTGRES_PASSWORD"}, "", "10.0.0.9")

	var stored string
	// Selected by EVENT, not by occurred_at: that column is DATETIME with second
	// granularity, so two rows written in the same second tie and ORDER BY picks
	// arbitrarily between them.
	if err := h.db.QueryRow(
		`SELECT secret_names FROM service_secret_audit WHERE event = ?`, "fetch").
		Scan(&stored); err != nil {
		t.Fatalf("read the audit row back: %v", err)
	}
	for _, name := range []string{"STRIPE_KEY", "POSTGRES_PASSWORD"} {
		if strings.Contains(stored, name) {
			t.Fatalf("THE SERVICE AUDIT STORED %q IN CLEARTEXT: %s", name, stored)
		}
	}
	got := h.openAuditName(context.Background(), stored)
	for _, name := range []string{"STRIPE_KEY", "POSTGRES_PASSWORD"} {
		if !strings.Contains(got, name) {
			t.Errorf("the sealed name list did not open back to %q: %s", name, got)
		}
	}

	// An EMPTY list stays readable as "[]": "no names recorded" is a fact worth
	// keeping legible, and sealing it would only hide that nothing was recorded.
	sh.audit("svc-1", "billing-worker", "denied", nil, "no grant", "10.0.0.9")
	var empty string
	if err := h.db.QueryRow(
		`SELECT secret_names FROM service_secret_audit WHERE event = ?`, "denied").
		Scan(&empty); err != nil {
		t.Fatalf("read the empty audit row: %v", err)
	}
	if empty != "[]" {
		t.Errorf("an empty name list was stored as %q, want []", empty)
	}
}

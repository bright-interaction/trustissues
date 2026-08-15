package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// These tests run against a REAL VaultHandler over a REAL migrated database,
// unlike the rest of service_secrets_test.go, which uses stubDecrypter.
//
// That is not preference, it is the only way the properties below are askable.
// stubDecrypter's EntryNamePlain returns the stored name verbatim, so no row can
// ever open to the empty string under it, and its SealAuditName/OpenAuditName
// are passthroughs, so "is the audit column ciphertext at rest" has no meaning.
// Every bug covered here lived precisely in the gap between that stub and the
// real crypto.

// newRealVaultServiceEnv boots the migrated schema with a real VaultHandler and
// wires the service-secrets handler to it through entrySecretSource, exactly as
// main does.
func newRealVaultServiceEnv(t *testing.T) (*ServiceSecretsHandler, *VaultHandler, *db.Queries, *sql.DB) {
	t.Helper()
	vh, queries := newCollectionAuthzEnv(t)
	return NewServiceSecretsHandler(queries, vh), vh, queries, vh.db
}

// seedRealServiceIdentity inserts a service_identities row into the migrated
// schema and returns (id, plaintext key).
func seedRealServiceIdentity(t *testing.T, dbConn *sql.DB, ownerID, name string, allowed []string) (string, string) {
	t.Helper()
	allowedJSON, err := json.Marshal(allowed)
	if err != nil {
		t.Fatalf("marshal allowed_secrets: %v", err)
	}
	rawKey := ServiceKeyPrefix + randomHex(32)
	sum := sha256.Sum256([]byte(rawKey))
	id := randomHex(16)
	if _, err := dbConn.Exec(
		`INSERT INTO service_identities
		   (id, name, allowed_secrets, key_hash, key_prefix, created_by_user_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, name, string(allowedJSON), hex.EncodeToString(sum[:]), rawKey[3:11], ownerID,
	); err != nil {
		t.Fatalf("insert service identity: %v", err)
	}
	return id, rawKey
}

func fetchAsService(t *testing.T, h *ServiceSecretsHandler, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/service-identities/me/secrets", nil)
	req.Header.Set("X-Service-Key", key)
	rec := httptest.NewRecorder()
	h.FetchOwnSecrets(rec, req)
	return rec
}

// ----------------------------------------------------------------------------
// (1) An unopenable name is not a name.
// ----------------------------------------------------------------------------

// TestFetchOwnSecrets_EmptyWhitelistEntryDoesNotMatchAnUnopenableRow pins the
// zero-length hole in subtle.ConstantTimeCompare.
//
// ConstantTimeCompare returns 1 for TWO ZERO-LENGTH slices. EntryNamePlain
// returns "" for any row whose name no configured key opens. So an
// allowed_secrets entry of "" matched that unopenable row, the miss check was
// skipped because idx came back >= 0, and the handler decrypted and returned
// THAT row's value: the wrong credential, delivered under a 200 and a green
// "fetch" audit row, with the all-or-nothing 404 contract defeated.
func TestFetchOwnSecrets_EmptyWhitelistEntryDoesNotMatchAnUnopenableRow(t *testing.T) {
	h, vh, queries, dbConn := newRealVaultServiceEnv(t)
	ownerID := mustUser(t, queries, "unopenable-owner@example.com", "user", "")

	const brokenValue = "value-of-broken-row"
	ct, nonce, err := vh.EncryptValue([]byte(brokenValue))
	if err != nil {
		t.Fatalf("encrypt value: %v", err)
	}

	// A row whose NAME no configured key opens, with a VALUE that opens fine.
	// This is the shape a master-key rotation produces on every row still sealed
	// under a key older than current+previous, since decryptColumnWithKeyAge
	// tries only those two. name_bidx stays '' (its default), which is also what
	// such a row has.
	brokenName := vaultfield.ColumnPrefix +
		base64.StdEncoding.EncodeToString([]byte("sealed under a key this instance does not hold"))
	if _, err := dbConn.Exec(
		`INSERT INTO vault_entries
		   (id, user_id, secret_owner_user_id, name, encrypted_value, nonce, encryption_version)
		 VALUES (?, ?, ?, ?, ?, ?, 2)`,
		randomHex(16), ownerID, ownerID, brokenName, ct, nonce,
	); err != nil {
		t.Fatalf("insert unopenable-name entry: %v", err)
	}

	// PRECONDITION. If the fixture's name were openable, or its value were not,
	// the assertions below would pass without the bug ever being reachable.
	if got := vh.EntryNamePlain(brokenName); got != "" {
		t.Fatalf("ABORT: the fixture's name opened to %q, so this test is not about an "+
			"unopenable row at all", got)
	}

	_, key := seedRealServiceIdentity(t, dbConn, ownerID, "svc-empty-name", []string{""})
	rec := fetchAsService(t, h, key)

	if strings.Contains(rec.Body.String(), brokenValue) {
		t.Fatalf("WRONG CREDENTIAL DELIVERED: the empty whitelist entry matched a row whose name "+
			"does not open, and the handler returned that row's value: %d %s",
			rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a whitelist name that resolves to nothing must be an all-or-nothing 404, got %d: %s",
			rec.Code, rec.Body.String())
	}

	// And the trail must call it a denial, not a fetch.
	var event string
	if err := dbConn.QueryRow(
		`SELECT event FROM service_secret_audit ORDER BY occurred_at DESC, rowid DESC LIMIT 1`,
	).Scan(&event); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if event != "denied" {
		t.Errorf("audit event = %q, want denied: a fetch that delivered nothing must not be green", event)
	}
}

// TestCreateServiceIdentity_RejectsEmptyAndBlankNames closes the door upstream.
// The array-length check alone accepted [""], which wrote a contract naming
// nothing into allowed_secrets and left the fetch path to discover it.
func TestCreateServiceIdentity_RejectsEmptyAndBlankNames(t *testing.T) {
	for _, tc := range []struct{ label, body string }{
		{"empty element", `{"name":"x","allowed_secrets":[""]}`},
		{"blank element", `{"name":"x","allowed_secrets":["   "]}`},
		{"one good one empty", `{"name":"x","allowed_secrets":["REAL_NAME",""]}`},
	} {
		t.Run(tc.label, func(t *testing.T) {
			h, dbConn := setupServiceHandler(t)
			req := httptest.NewRequest(http.MethodPost, "/api/service-identities",
				strings.NewReader(tc.body)).WithContext(contextAsAdmin(t))
			rec := httptest.NewRecorder()
			h.CreateServiceIdentity(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d: %s", tc.label, rec.Code, rec.Body.String())
			}
			var n int
			if err := dbConn.QueryRow(`SELECT COUNT(*) FROM service_identities`).Scan(&n); err != nil {
				t.Fatalf("count identities: %v", err)
			}
			if n != 0 {
				t.Fatalf("an identity was minted with an unnameable secret in its whitelist")
			}
		})
	}
}

// ----------------------------------------------------------------------------
// (2) + (3) The denial names: sealed at rest, readable by the operator.
// ----------------------------------------------------------------------------

// TestServiceAuditDenialNames_SealedAtRestAndReadableByOperator is the
// round trip, and it is one test because the two halves are one channel.
//
// (2) The names were concatenated into service_secret_audit.error, which h.audit
// does not seal and 00021 gives no crypto, in a table append-only since 00039:
// a PERMANENT cleartext copy of vault entry names beside the encrypted inventory
// they describe, from the same stolen file audit_name_crypto.go exists to
// defend against. They belong in secret_names, which is already sealed and whose
// schema comment says "secrets returned (success) or requested (denied)".
//
// (3) But secret_names was unreadable: GetServiceIdentityAudit json.Unmarshal'd
// the raw enc:v1: column with the error discarded, so it shipped null on every
// row. Moving the names into a column nobody could read would have taken the
// channel away from the operator entirely, so the reader is fixed here too.
func TestServiceAuditDenialNames_SealedAtRestAndReadableByOperator(t *testing.T) {
	h, _, queries, dbConn := newRealVaultServiceEnv(t)
	ownerID := mustUser(t, queries, "audit-roundtrip-owner@example.com", "user", "")

	// A name that reads like the inventory an attacker wants, and that resolves
	// to nothing, so the fetch takes the denial path.
	const requested = "Acme prod DB"
	identityID, key := seedRealServiceIdentity(t, dbConn, ownerID, "svc-audit-roundtrip",
		[]string{requested})

	if rec := fetchAsService(t, h, key); rec.Code != http.StatusNotFound {
		t.Fatalf("expected the unresolvable name to be refused with 404, got %d: %s",
			rec.Code, rec.Body.String())
	}

	var atRestNames, atRestError, event string
	if err := dbConn.QueryRow(
		`SELECT secret_names, error, event FROM service_secret_audit
		 WHERE service_identity_id = ? ORDER BY occurred_at DESC, rowid DESC LIMIT 1`,
		identityID,
	).Scan(&atRestNames, &atRestError, &event); err != nil {
		t.Fatalf("read the at-rest audit row: %v", err)
	}
	if event != "denied" {
		t.Fatalf("ABORT: the fixture did not take the denial path (event = %q)", event)
	}

	// (2), stated directly: the unencrypted column carries no name.
	if strings.Contains(atRestError, requested) {
		t.Fatalf("THE ENTRY NAME IS CLEARTEXT IN service_secret_audit.error: %q. That column has no "+
			"crypto and the table is append-only since 00039, so this copy is permanent and a "+
			"keyless reader of the database file rebuilds the inventory 00040 encrypted",
			atRestError)
	}

	// PRECONDITION, so the assertion above cannot pass for the wrong reason (an
	// audit row that recorded no name at all would also contain no cleartext).
	if !vaultfield.IsSealedColumn(atRestNames) {
		t.Fatalf("ABORT: secret_names is not sealed at rest (%q). Either the names never reached the "+
			"sealed column or the seal is not running, and every assertion here would then be "+
			"vacuous", atRestNames)
	}
	if atRestNames == auditNameUnavailable {
		t.Fatalf("ABORT: the audit name could not be sealed in this fixture, so the round trip is " +
			"not being exercised")
	}
	if strings.Contains(atRestNames, requested) {
		t.Fatalf("secret_names carries the cleartext name despite the enc:v1: marker: %q", atRestNames)
	}

	// (3): the operator reads it back through the real endpoint.
	areq := httptest.NewRequest(http.MethodGet,
		"/api/service-identities/"+identityID+"/audit", nil).WithContext(contextAsAdmin(t))
	areq = withChiParam(areq, "id", identityID)
	arec := httptest.NewRecorder()
	h.GetServiceIdentityAudit(arec, areq)
	if arec.Code != http.StatusOK {
		t.Fatalf("audit read: expected 200, got %d: %s", arec.Code, arec.Body.String())
	}
	var entries []auditEntryResponse
	if err := json.Unmarshal(arec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode audit response: %v (%s)", err, arec.Body.String())
	}

	var denial *auditEntryResponse
	for i := range entries {
		if entries[i].Event == "denied" {
			denial = &entries[i]
			break
		}
	}
	if denial == nil {
		t.Fatalf("the denial row is missing from the audit read: %s", arec.Body.String())
	}
	found := false
	for _, n := range denial.SecretNames {
		if n == requested {
			found = true
		}
	}
	if !found {
		t.Fatalf("THE AUDIT TRAIL IS WRITE-ONLY: the operator asked which names were refused and got "+
			"%v. The name was sealed into an append-only table and nothing in the product can show "+
			"it back, which is not confidentiality, it is a table nobody can consult. Raw body: %s",
			denial.SecretNames, arec.Body.String())
	}
	// The response is the operator's view, so the name being there is correct;
	// what must never appear is the name in a column that was never sealed.
	if strings.Contains(arec.Body.String(), atRestError) && strings.Contains(atRestError, requested) {
		t.Fatalf("the error field is still carrying the name: %q", atRestError)
	}
}

// TestServiceAuditRead_UnavailableMarkerIsNotSwallowed covers the third state of
// the opened column. "[unavailable]" means a name WAS recorded and this process
// cannot show it, which is a different fact from "no name was recorded"; the
// discarded-error unmarshal turned both into an empty list.
func TestServiceAuditRead_UnavailableMarkerIsNotSwallowed(t *testing.T) {
	if got := decodeAuditSecretNames(auditNameUnavailable); len(got) != 1 || got[0] != auditNameUnavailable {
		t.Errorf("the unavailable marker was swallowed into %v", got)
	}
	if got := decodeAuditSecretNames(vaultfield.ColumnPrefix + "still-sealed"); len(got) != 1 ||
		got[0] != auditNameUnavailable {
		t.Errorf("an unparseable value must surface the marker, not an empty list; got %v", got)
	}
	if got := decodeAuditSecretNames(`["A","B"]`); len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Errorf("a plain list did not decode: %v", got)
	}
	if got := decodeAuditSecretNames("[]"); got == nil || len(got) != 0 {
		t.Errorf("an empty list must stay an empty list, not null: %v", got)
	}
}

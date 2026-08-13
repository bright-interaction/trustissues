package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// TestImportCannotBeUsedAsADecryptionOracle is the ATTACK, run end to end.
//
// The July oracle was closed in encryptColumn: user input is ALWAYS sealed, so a
// client-supplied string that already looks like ciphertext is stored as the
// attacker's own literal bytes and reads back as the same gibberish. The import
// path re-opened it by writing Name straight through with no seal at all, and
// this instance reaches further than the July one did: it lands in a column
// every read path OPENS, and the bytes it opens are the victim's secret VALUE.
//
// The two formats are byte interchangeable on purpose and cannot be told apart:
// vaultfield.Seal (entry values) stores nonce and ciphertext in separate
// columns, vaultfield.SealColumn (metadata) stores nonce||ciphertext inline
// after the enc:v1: marker. Both use h.encryptionKey and a nil AAD, so
// base64(nonce || encrypted_value) from ANY row is a well formed enc:v1: column
// value that OpenColumn will happily open.
//
// The attacker needs only raw stored bytes (a stolen DB file, a restic snapshot,
// a backup) plus any authenticated account. POST /api/vault/import/confirm sits
// in the general vault group, not behind AdminOnly, so vault_only is enough. The
// read back is a plain GET of the attacker's OWN vault, which means secretexit,
// egressgate, theExitList, owner authority and the unlock rate limiter never see
// it.
func TestImportCannotBeUsedAsADecryptionOracle(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	imp := NewVaultImportHandler(h.db, h)

	victim := mustUser(t, queries, "victim-oracle@example.com", "user", "")
	attacker := mustUser(t, queries, "attacker-oracle@example.com", "vault_only", "")

	// The victim stores a secret through the real Create handler.
	const victimSecret = "victim-prod-stripe-live-key-9f3a"
	body, _ := json.Marshal(map[string]any{"name": "Victim Stripe", "value": victimSecret})
	r := httptest.NewRequest(http.MethodPost, "/api/vault", strings.NewReader(string(body)))
	ctx := context.WithValue(r.Context(), timw.UserIDKey, victim)
	ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
	rec := httptest.NewRecorder()
	h.Create(rec, r.WithContext(ctx))
	if rec.Code != http.StatusCreated {
		t.Fatalf("victim create: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	// The attacker holds only the raw stored bytes, the way a thief holds a
	// database file. No key, no session of the victim's, no handler.
	var ct, nonce []byte
	if err := h.db.QueryRow(
		`SELECT encrypted_value, nonce FROM vault_entries WHERE user_id = ?`, victim).
		Scan(&ct, &nonce); err != nil {
		t.Fatalf("raw read of the victim row: %v", err)
	}
	if len(ct) == 0 || len(nonce) == 0 {
		t.Fatalf("ABORT: the victim row carries no ciphertext, so this test proves nothing")
	}
	packed := append(append([]byte{}, nonce...), ct...)
	payload := vaultfield.ColumnPrefix + base64.StdEncoding.EncodeToString(packed)

	// The attacker imports it as an entry NAME into their own vault.
	confirm, _ := json.Marshal(map[string]any{
		"entries": []map[string]any{{"name": payload, "value": "anything"}},
	})
	cr := httptest.NewRequest(http.MethodPost, "/api/vault/import/confirm", strings.NewReader(string(confirm)))
	cctx := context.WithValue(cr.Context(), timw.UserIDKey, attacker)
	cctx = context.WithValue(cctx, timw.UserRoleKey, "vault_only")
	crec := httptest.NewRecorder()
	imp.ImportConfirm(crec, cr.WithContext(cctx))
	if crec.Code != http.StatusOK {
		t.Fatalf("import confirm: HTTP %d: %s", crec.Code, crec.Body.String())
	}

	// And reads their own vault back. This is a plain GET of rows the attacker
	// owns, so nothing in the exit machinery is consulted.
	lr := httptest.NewRequest(http.MethodGet, "/api/vault", nil)
	lctx := context.WithValue(lr.Context(), timw.UserIDKey, attacker)
	lctx = context.WithValue(lctx, timw.UserRoleKey, "vault_only")
	lrec := httptest.NewRecorder()
	h.List(lrec, lr.WithContext(lctx))
	if lrec.Code != http.StatusOK {
		t.Fatalf("list: HTTP %d: %s", lrec.Code, lrec.Body.String())
	}

	if strings.Contains(lrec.Body.String(), victimSecret) {
		t.Fatalf("DECRYPTION ORACLE: the import path stored a client-supplied enc:v1: string "+
			"verbatim, and the vault list handed the attacker back the VICTIM'S DECRYPTED "+
			"SECRET in the name field. Every column a client can write has to go through "+
			"encryptColumn, which always seals, precisely so attacker-supplied ciphertext is "+
			"stored as the attacker's own literal bytes.\nresponse: %s", lrec.Body.String())
	}

	// The attack failing must not be because the import silently dropped the
	// row: an oracle test that passes on an empty vault proves nothing.
	var stored string
	if err := h.db.QueryRow(`SELECT name FROM vault_entries WHERE user_id = ?`, attacker).
		Scan(&stored); err != nil {
		t.Fatalf("ABORT: the attacker's row was not written at all, so this run proves "+
			"nothing about the oracle: %v", err)
	}
	if stored == payload {
		t.Errorf("the attacker's literal enc:v1: payload was stored verbatim: %q", stored)
	}
}

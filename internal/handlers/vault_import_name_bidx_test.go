package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// importOne posts a single entry through the real confirm endpoint and returns
// the recorder, so these tests exercise the path an attacker and an operator
// both actually use.
func importOne(t *testing.T, imp *VaultImportHandler, userID string, entry map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"entries": []map[string]any{entry}})
	r := httptest.NewRequest(http.MethodPost, "/api/vault/import/confirm", strings.NewReader(string(body)))
	ctx := context.WithValue(r.Context(), timw.UserIDKey, userID)
	ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
	rec := httptest.NewRecorder()
	imp.ImportConfirm(rec, r.WithContext(ctx))
	return rec
}

func createEntry(t *testing.T, h *VaultHandler, userID, name string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name, "value": "v"})
	r := httptest.NewRequest(http.MethodPost, "/api/vault", strings.NewReader(string(body)))
	ctx := context.WithValue(r.Context(), timw.UserIDKey, userID)
	ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
	rec := httptest.NewRecorder()
	h.Create(rec, r.WithContext(ctx))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %q: HTTP %d: %s", name, rec.Code, rec.Body.String())
	}
}

// TestImportedNamesGetTheSameTreatmentAsCreatedOnes.
//
// Import is the bulk-onboarding path: it carries a whole password manager in one
// request, which makes it the WORST place for the name column to be handled
// differently from Create. Three properties, all of them 00040's, and all three
// were absent on this path.
func TestImportedNamesGetTheSameTreatmentAsCreatedOnes(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	imp := NewVaultImportHandler(h.db, h)
	user := mustUser(t, queries, "importer@example.com", "user", "")

	const label = "Acme prod DB"
	if rec := importOne(t, imp, user, map[string]any{"name": label, "value": "s3cret"}); rec.Code != http.StatusOK {
		t.Fatalf("import: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	var storedName, storedBidx string
	if err := h.db.QueryRow(`SELECT name, name_bidx FROM vault_entries WHERE user_id = ?`, user).
		Scan(&storedName, &storedBidx); err != nil {
		t.Fatalf("raw read: %v", err)
	}

	// 1. Not cleartext at rest. A keyless copy of the file must not hand over
	//    the inventory, which is the whole point of migration 00040 and is worth
	//    the most on the path that carries hundreds of names at once.
	if strings.Contains(storedName, label) {
		t.Errorf("AN IMPORTED NAME IS CLEARTEXT AT REST: %q. Migration 00040 encrypted the name "+
			"column precisely so a stolen database file is not a readable inventory, and the "+
			"bulk path is where the most names arrive", storedName)
	}
	if !vaultfield.IsSealedColumn(storedName) {
		t.Errorf("the imported name is not in the column-crypto format: %q", storedName)
	}

	// 2. It still round-trips, so sealing it did not cost the operator the name.
	if got := h.EntryNamePlain(storedName); got != label {
		t.Errorf("the imported name did not survive encryption: %q, want %q", got, label)
	}

	// 3. The blind index is filled in. The unique index over it is PARTIAL and
	//    skips '', so an empty token does not fail loudly: the row is simply
	//    created outside the constraint, and per-user name uniqueness silently
	//    stops applying to everything anyone ever imported.
	if storedBidx == "" {
		t.Errorf("name_bidx is empty on an imported row, so per-user name uniqueness is not " +
			"enforced for imports at all: the unique index is partial and skips ''")
	}
	if want := h.nameBlindIndex(user, label); storedBidx != want {
		t.Errorf("name_bidx is not the custodian-keyed token Create writes: got %q want %q",
			storedBidx, want)
	}
}

// TestImportRefusesANameTheUserAlreadyHas. Uniqueness must hold ACROSS the two
// write paths, not within each. The stored name is randomized ciphertext, so the
// inline UNIQUE(user_id, name) cannot fire any more and the blind index is the
// only thing left holding this up.
func TestImportRefusesANameTheUserAlreadyHas(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	imp := NewVaultImportHandler(h.db, h)
	user := mustUser(t, queries, "dup@example.com", "user", "")

	createEntry(t, h, user, "shared-label")

	rec := importOne(t, imp, user, map[string]any{"name": "shared-label", "value": "v2"})
	if rec.Code != http.StatusOK {
		t.Fatalf("import: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Imported int `json:"imported"`
		Skipped  []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}

	var count int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM vault_entries WHERE user_id = ?`, user).
		Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("the user now holds %d entries under one name. Uniqueness is per user and it "+
			"has to survive the import path, or the bulk door is the way to defeat it", count)
	}
	if len(resp.Skipped) != 1 {
		t.Errorf("the duplicate was not REPORTED as a skip (%+v). A row that vanishes silently "+
			"is the failure this endpoint's skip reporting exists for", resp.Skipped)
	}
}

// TestOneDuplicateNameCannotWedgeTheAtRestBackfill.
//
// The backfill runs on every boot and seals whatever is still cleartext. It used
// to `return` on any UPDATE failure, so ONE row whose recomputed name_bidx
// collides with another of the same user's entries aborted the sweep for every
// row after it, on every boot, permanently. Rows written before the import path
// sealed its names are exactly that shape: cleartext name, empty name_bidx,
// sitting outside the partial unique index, free to duplicate.
//
// So this is not only a repair concern. It is a denial of at-rest encryption for
// the whole table that anyone who could reach the import could plant.
func TestOneDuplicateNameCannotWedgeTheAtRestBackfill(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	user := mustUser(t, queries, "wedge@example.com", "user", "")
	ctx := context.Background()

	createEntry(t, h, user, "Collides")

	// The legacy shape, written the way rows were written before this fix:
	// cleartext name, empty name_bidx. Inserted BEFORE the row that must still
	// be swept, so an aborting backfill never reaches the second one.
	legacy := func(id, name string) {
		t.Helper()
		if err := queries.ImportVaultEntry(ctx, db.ImportVaultEntryParams{
			ID:                id,
			UserID:            user,
			SecretOwnerUserID: user,
			Name:              name,
			EncryptedValue:    []byte("x"),
			Nonce:             []byte("n"),
		}); err != nil {
			t.Fatalf("seed legacy row %s: %v", id, err)
		}
	}
	legacy("00000000000000000000000000000001", "Collides")
	legacy("00000000000000000000000000000002", "Innocent Bystander")

	if _, err := h.BackfillMetadataAtRest(); err != nil {
		t.Fatalf("THE BACKFILL WEDGED: %v. One row whose name collides must not stop at-rest "+
			"encryption for the whole table, on every boot, forever", err)
	}

	var bystander string
	if err := h.db.QueryRow(`SELECT name FROM vault_entries WHERE id = ?`,
		"00000000000000000000000000000002").Scan(&bystander); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if !vaultfield.IsSealedColumn(bystander) {
		t.Errorf("A ROW AFTER THE COLLIDING ONE WAS NEVER SEALED: %q. The sweep stopped at the "+
			"duplicate instead of skipping it, which is the wedge", bystander)
	}
}

package handlers

import (
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/bright-interaction/trustissues/internal/config"
)

// TestMetaColumnsBackfillIsIdempotent is the regression lock for a
// data-destruction bug introduced alongside the enc:v1 decryption-oracle fix.
//
// Closing the oracle made encryptColumn ALWAYS encrypt, which is correct for
// client input. But BackfillMetadataAtRest is a storage-side caller: the values
// it passes have been read back out of the database and may already be
// ciphertext. Routing those through the always-encrypting helper wrapped them a
// second time, so on the next boot a user's saved url/username/notes decrypted
// to an inner "enc:v1:..." string instead of their data, and the recomputed URL
// blind index no longer matched, silently breaking extension autofill.
//
// The invariant: the storage-side helper must leave an already-encrypted column
// byte-identical, while still encrypting one that is still cleartext.
func TestMetaColumnsBackfillIsIdempotent(t *testing.T) {
	vh := NewVaultHandler(nil, nil, &config.Config{VaultKey: "test-vault-key"})

	const (
		url      = "https://github.com/login"
		username = "octocat"
		notes    = "my note"
	)

	// First pass: cleartext in, ciphertext out.
	encURL, encAlias, encUser, encCat, encNotes, err := vh.encryptMetaColumnsIfNeeded(url, "", username, "password", notes)
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	for name, v := range map[string]string{"url": encURL, "username": encUser, "notes": encNotes} {
		if !strings.HasPrefix(v, vaultColumnEncPrefix) {
			t.Fatalf("%s not encrypted on first pass: %q", name, v)
		}
	}

	// Second pass over the STORED values (the next boot). Must be a no-op.
	encURL2, encAlias2, encUser2, encCat2, encNotes2, err := vh.encryptMetaColumnsIfNeeded(encURL, encAlias, encUser, encCat, encNotes)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if encURL2 != encURL || encAlias2 != encAlias || encUser2 != encUser || encCat2 != encCat || encNotes2 != encNotes {
		t.Fatal("backfill re-wrapped an already-encrypted column: saved data would be destroyed on the next boot")
	}

	// And the data still decrypts to the original, not to an inner marker.
	for want, stored := range map[string]string{url: encURL2, username: encUser2, notes: encNotes2} {
		got, derr := vh.decryptColumn(stored)
		if derr != nil {
			t.Fatalf("decrypt %q: %v", want, derr)
		}
		if got != want {
			t.Fatalf("round-trip after two backfill passes: got %q want %q", got, want)
		}
		if strings.HasPrefix(got, vaultColumnEncPrefix) {
			t.Fatalf("double-wrapped: decrypt yielded another ciphertext %q", got)
		}
	}

	// A mixed-state row (one column still cleartext) must encrypt only that
	// column and leave the rest untouched. This is the exact shape that the
	// upgrade path hits and that the bug corrupted.
	mixURL, _, mixUser, mixCat, _, err := vh.encryptMetaColumnsIfNeeded(encURL, "", encUser, "password", "")
	if err != nil {
		t.Fatalf("mixed pass: %v", err)
	}
	if mixURL != encURL || mixUser != encUser {
		t.Fatal("mixed-state backfill re-wrapped already-encrypted columns")
	}
	if !strings.HasPrefix(mixCat, vaultColumnEncPrefix) {
		t.Fatalf("mixed-state backfill failed to encrypt the cleartext column: %q", mixCat)
	}
}

package handlers

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/brightinteraction/trustissues/internal/config"
)

// TestBlindIndexIsScopedAndUnlinkable locks the URL blind-index privacy fix.
//
// The index was previously a plain HMAC over the normalized host with one global
// key, so two users holding an entry for the same site produced the SAME stored
// value. Anyone with a copy of the database (a stolen backup) could therefore
// see that two people share a site, without needing the vault key. It is only
// metadata, but it is metadata the at-rest encryption is supposed to withhold.
//
// The index is now keyed per scope: personal entries by owner, collection
// entries by collection. Cross-user co-occurrence disappears, while everyone in
// one collection still derives the same value, which is what shared autofill
// needs.
func TestBlindIndexIsScopedAndUnlinkable(t *testing.T) {
	vh := NewVaultHandler(nil, nil, &config.Config{VaultKey: "test-vault-key"})

	const host = "https://github.com/login"
	personalA := vh.urlBlindIndex(bidxScope("user-a", sql.NullString{}), host)
	personalB := vh.urlBlindIndex(bidxScope("user-b", sql.NullString{}), host)

	if personalA == "" || personalB == "" {
		t.Fatal("scoped index must be non-empty for a valid host")
	}
	if personalA == personalB {
		t.Fatal("LINKABLE: two users with the same host share a blind index value")
	}

	// Same user, same host, is stable (autofill depends on it).
	if again := vh.urlBlindIndex(bidxScope("user-a", sql.NullString{}), host); again != personalA {
		t.Fatal("index is not deterministic for the same scope and host")
	}

	// Everyone in one collection derives the same value, so shared autofill works.
	coll := sql.NullString{String: "coll-1", Valid: true}
	viaOwner := vh.urlBlindIndex(bidxScope("user-a", coll), host)
	viaMember := vh.urlBlindIndex(bidxScope("user-b", coll), host)
	if viaOwner != viaMember {
		t.Fatal("collection members derive different indexes: shared autofill would break")
	}
	// And a collection scope is distinct from either member's personal scope.
	if viaOwner == personalA || viaOwner == personalB {
		t.Fatal("collection index collides with a personal index")
	}

	// A different collection is a different scope.
	other := sql.NullString{String: "coll-2", Valid: true}
	if vh.urlBlindIndex(bidxScope("user-a", other), host) == viaOwner {
		t.Fatal("two collections share an index value")
	}

	// The scope is length-prefixed, so ids that concatenate ambiguously cannot
	// collide (e.g. "ab"+"c" vs "a"+"bc").
	a := vh.urlBlindIndex(bidxScope("ab", sql.NullString{}), host)
	b := vh.urlBlindIndex(bidxScope("a", sql.NullString{String: "b", Valid: true}), host)
	if a == b {
		t.Fatal("scope encoding is ambiguous: distinct scopes collided")
	}

	// No scope means no index: an unscoped value would be globally linkable, so
	// it must never be written.
	if got := vh.urlBlindIndex("", host); got != "" {
		t.Fatalf("empty scope produced an index %q", got)
	}
	// A hostless URL still yields nothing to match on.
	if got := vh.urlBlindIndex(bidxScope("user-a", sql.NullString{}), "not a url"); got != "" {
		t.Fatalf("hostless url produced an index %q", got)
	}
	if !strings.HasPrefix(bidxScope("u1", sql.NullString{}), "u:") {
		t.Fatal("personal scope should be owner-keyed")
	}
	if !strings.HasPrefix(bidxScope("u1", coll), "c:") {
		t.Fatal("collection entry should be collection-keyed, not owner-keyed")
	}
}

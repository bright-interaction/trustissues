package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// TestReservedProviderMetaKeysAreRefusedOnBothWriteDoors defends the control
// that keeps a client from planting the rotation engine's own markers.
//
// WHY THIS TEST EXISTS AT ALL. rejectReservedProviderMetaKeys is wired at
// exactly two places -- vault.go's Create and Update -- and until this file
// NOTHING referenced it from a test. That is the shape this estate keeps
// getting burned by: the gate is real, and deleting either call site is
// invisible. It is not hypothetical here either. The comment above the Create
// call site records that the gate ONCE had a single call site, in Update,
// while Create took the identical client field straight to the column, so
// `POST /api/vault` with pending_revoke_url in the body returned 201 with the
// marker on disk. Nothing went red then; nothing would go red again.
//
// The stake rose with the pending-revoke endpoints. pending_revoke_url is
// spent as a real request, authenticated with the entry's live credential --
// and it used to be reachable only by waiting for a rotation, where now
// POST /api/vault/{id}/pending-revoke/retry spends it on demand. providerDo
// still refuses any host outside the provider's declared set, so a planted
// marker is not by itself an egress escape; this is the defence-in-depth
// layer that keeps the attempt out of the row in the first place.
//
// Both doors, every reserved key, and a positive control so the test cannot
// pass against a handler that simply refuses every provider_meta.
func TestReservedProviderMetaKeysAreRefusedOnBothWriteDoors(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "reservedmeta@example.com", "user", "")

	create := func(t *testing.T, metaJSON string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"name":          "Entry " + randomHex(6),
			"value":         "v",
			"provider":      "resend",
			"provider_meta": metaJSON,
		})
		r := httptest.NewRequest(http.MethodPost, "/api/vault", strings.NewReader(string(body)))
		ctx := context.WithValue(r.Context(), timw.UserIDKey, owner)
		ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
		rec := httptest.NewRecorder()
		h.Create(rec, r.WithContext(ctx))
		return rec
	}

	// THE SET IS PINNED HERE, NOT ONLY ITERATED BELOW.
	//
	// The loops below range over the production slice, which means a key ADDED
	// without a matching refusal cannot slip past. It also means a key REMOVED
	// takes its own subtest with it: delete pendingRevokeURL from
	// egress_authority.go and this file silently drops from 9 subtests to 7,
	// reports ok, and the write door it defends is standing open. A test whose
	// coverage is derived from the thing under test cannot see that thing
	// shrink. So the expected membership is written out by hand, once, and
	// compared -- the hand-written half catches shrinkage, the derived half
	// catches growth, and neither alone is enough.
	wantReserved := map[string]bool{
		"pending_revoke_method": true,
		"pending_revoke_url":    true,
		"pending_revoke_auth":   true,
		// Server-owned: written by deferRevokeOldProviderKey from the id the
		// provider adapter already holds, never supplied by a client.
		"pending_revoke_key_id": true,
		// Server-owned: the QUEUE of displaced marker sets that
		// dischargePendingRevokeHead promotes into the head. A client that could
		// plant one would be planting a pending_revoke_url with a delay fuse, so
		// it is refused and redacted exactly like the head markers it feeds.
		"pending_revoke_stranded": true,
		"last_revoke_error":       true,
	}
	got := map[string]bool{}
	for _, k := range reservedProviderMetaKeys {
		got[k] = true
	}
	for k := range wantReserved {
		if !got[k] {
			t.Fatalf("%q was REMOVED from reservedProviderMetaKeys. The write gate no longer refuses it, "+
				"so a client can plant it through POST /api/vault or PUT /api/vault/{id}. If this removal "+
				"is deliberate, delete it from wantReserved here and say why in the commit.", k)
		}
	}
	for k := range got {
		if !wantReserved[k] {
			t.Fatalf("%q was ADDED to reservedProviderMetaKeys. Confirm it is genuinely server-owned and "+
				"not an operator enrollment field -- adding an enrollment field here refuses legitimate "+
				"provider_meta and breaks rotation setup -- then add it to wantReserved.", k)
		}
	}

	for _, key := range reservedProviderMetaKeys {
		key := key
		t.Run("create refuses "+key, func(t *testing.T) {
			planted := `{"key_id":"k1","` + key + `":"https://attacker.example/collect"}`
			rec := create(t, planted)
			if rec.Code < 400 {
				t.Fatalf("POST /api/vault accepted a client-supplied %s (HTTP %d). The rotation "+
					"engine's own marker is now on the row, and the read path redacts it, so the "+
					"creator cannot see or clear it through the product: %s", key, rec.Code, rec.Body.String())
			}
			// And nothing was written: no entry may exist carrying the marker.
			var n int
			if err := h.db.QueryRow(`SELECT COUNT(*) FROM vault_entries WHERE user_id = ?`, owner).
				Scan(&n); err != nil {
				t.Fatalf("count: %v", err)
			}
			if n != 0 {
				t.Errorf("a refused create still left %d entr(y/ies) behind", n)
			}
		})
	}

	// ── the Update door ────────────────────────────────────────────────────
	for _, key := range reservedProviderMetaKeys {
		key := key
		t.Run("update refuses "+key, func(t *testing.T) {
			entryID := "resv-" + randomHex(6)
			mustEntry(t, h, queries, entryID, owner, "Entry "+entryID, "V")
			forceProviderConfig(t, h, entryID, "resend", `{"key_id":"k1"}`)

			meta := `{"key_id":"k1","` + key + `":"https://attacker.example/collect"}`
			rec := putVault(t, h, owner, "user", entryID, map[string]any{
				"name": "Entry " + entryID, "provider_meta": meta,
			})
			// Errorf, NOT Fatalf: the row check below is the more interesting
			// of the two and must still run when the status check fails.
			// Behind a Fatalf it was unreachable in exactly the scenario it
			// exists for, which is the shape of a vacuous assertion.
			if rec.Code < 400 {
				t.Errorf("PUT /api/vault/{id} accepted a client-supplied %s (HTTP %d): %s",
					key, rec.Code, rec.Body.String())
			}
			// NOTE ON WHAT THIS HALF IS WORTH. Update is belt-and-braces:
			// reconcileProviderMetaForStorage strips reserved keys downstream
			// independently, so removing the Update gate turns a 400 into a 200
			// and does not actually plant the marker. provider_meta_marker_
			// lockout_test.go's STEP 4 already covers this door, more strictly.
			// The load-bearing half of this file is the Create door above,
			// where the gate is the only thing between a client and a forged
			// pending_revoke on the row.
			stored := entryMetaMap(t, h, queries, entryID)
			if _, planted := stored[key]; planted {
				t.Errorf("a refused update still wrote %s to the row: %+v", key, stored)
			}
		})
	}

	// ── positive control ───────────────────────────────────────────────────
	// Without this, both loops above pass against a handler that rejects every
	// provider_meta it is ever handed.
	t.Run("positive control: a NON-reserved provider_meta key is accepted on both doors", func(t *testing.T) {
		rec := create(t, `{"key_id":"legitimate-key-id"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create refused an ordinary provider_meta (HTTP %d): %s. The refusals above "+
				"prove nothing if nothing is ever accepted.", rec.Code, rec.Body.String())
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
			t.Fatalf("could not read the new entry id: %v %s", err, rec.Body.String())
		}
		if got := entryMetaMap(t, h, queries, created.ID); got["key_id"] != "legitimate-key-id" {
			t.Errorf("the accepted provider_meta did not reach the row: %+v", got)
		}

		up := putVault(t, h, owner, "user", created.ID, map[string]any{
			"name": "Entry renamed", "provider_meta": `{"key_id":"legitimate-key-id-2"}`,
		})
		if up.Code >= 400 {
			t.Fatalf("update refused an ordinary provider_meta (HTTP %d): %s", up.Code, up.Body.String())
		}
		if got := entryMetaMap(t, h, queries, created.ID); got["key_id"] != "legitimate-key-id-2" {
			t.Errorf("the accepted provider_meta update did not reach the row: %+v", got)
		}
	})
}

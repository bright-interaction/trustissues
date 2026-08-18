package handlers

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// THE OPERATOR LOCKOUT, REPRODUCED AND CLOSED.
//
// Allowing a failed deferred revoke to keep its retry coordinates made three
// pending_revoke_* markers reachable in a stored row for the first time. The
// write-path validator that exists to stop a CLIENT planting them did not know
// that, and neither did the read path, so the product's own remediation flow
// locked the operator out of the entry:
//
//	a resend rotation's revoke returns 503 (the ordinary failure the fix exists
//	for) -> markers persist -> the operator opens the rotation panel to correct
//	the provider config that caused it -> RotationManager.parseProviderMeta
//	copies EVERY string key into form state, markers included, and they render
//	no input so nothing is on screen -> Save PUTs the whole map back ->
//
//	400 provider_meta may not contain pending_revoke_method
//
// The live-but-unrevokable upstream key stays live and the only recovery is a
// hand-crafted PUT omitting the three keys, because the write is a full column
// replace.
//
// Two properties close it and BOTH are asserted here, because either alone is a
// regression waiting to happen: the markers must not come OUT on the read path,
// and a client that sends them anyway must still be REFUSED. A fix that merely
// relaxed the validator would satisfy the lockout test and reopen the planting
// attack that validator was written for.

// listVaultAs drives the REAL GET /api/vault as the given principal and returns
// the decoded entries. This is the path RotationManager's `entry` prop comes
// from, so it is the path that must not hand over a marker.
func listVaultAs(t *testing.T, h *VaultHandler, userID, role string) []map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/vault", nil)
	ctx := context.WithValue(r.Context(), timw.UserIDKey, userID)
	ctx = context.WithValue(ctx, timw.UserRoleKey, role)
	rec := httptest.NewRecorder()
	h.List(rec, r.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/vault returned %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode vault list: %v (body: %s)", err, rec.Body.String())
	}
	return out
}

func entryFromList(t *testing.T, entries []map[string]any, id string) map[string]any {
	t.Helper()
	for _, e := range entries {
		if e["id"] == id {
			return e
		}
	}
	t.Fatalf("entry %s not in the list of %d", id, len(entries))
	return nil
}

// TestAFailedRevokeDoesNotLockTheOwnerOutOfTheirOwnRotationConfig walks the
// exact operator sequence, through the real handlers, with no attacker in it.
func TestAFailedRevokeDoesNotLockTheOwnerOutOfTheirOwnRotationConfig(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	const entryID = "entry-resend-partial"
	owner := mustUser(t, queries, "owner@example.com", "user", egressTestPassword)
	mustEntry(t, h, queries, entryID, owner, "resend-key", "re_OPERATOR_KEY")

	// The state a failed deferred revoke leaves behind, written straight to the
	// column exactly as performPendingRevoke's caller persists it: the three
	// markers plus the error that downgraded the rotation to partial, beside the
	// operator's own provider settings.
	stored := map[string]string{
		"pending_revoke_method": "DELETE",
		"pending_revoke_url":    "https://api.resend.com/api-keys/old-key-id",
		"pending_revoke_auth":   revokeAuthBearer,
		"last_revoke_error":     "revoke old key: HTTP 503",
		"pending_revoke_key_id": "old-key-id",
		"key_id":                "new-key-id",
	}
	rawStored, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	forceProviderConfig(t, h, entryID, "resend", string(rawStored))

	// The markers really are in the row. Without this the rest of the test could
	// pass against a database that never had them.
	_, encMeta := storedProvider(t, queries, entryID)
	onDisk := h.decryptColumnOrLog(encMeta, "{}", vaultFieldProviderMeta)
	for _, k := range reservedProviderMetaKeys {
		if !strings.Contains(onDisk, k) {
			t.Fatalf("fixture did not persist %s; the stored column is %s", k, onDisk)
		}
	}

	var handedToTheClient string

	t.Run("STEP 1: the read path does not hand the markers to the client", func(t *testing.T) {
		e := entryFromList(t, listVaultAs(t, h, owner, "user"), entryID)
		got, ok := e["provider_meta"].(string)
		if !ok {
			t.Fatalf("provider_meta was %T, want a string", e["provider_meta"])
		}
		handedToTheClient = got

		for _, k := range reservedProviderMetaKeys {
			if strings.Contains(got, k) {
				t.Errorf("the read path handed the client %s: %s", k, got)
			}
		}
		// The operator's OWN settings must survive. A redaction that emptied the
		// column would pass every assertion above and destroy the rotation
		// config the operator opened the panel to fix.
		if !strings.Contains(got, "key_id") || !strings.Contains(got, "new-key-id") {
			t.Fatalf("redaction removed the operator's own provider settings: %s", got)
		}
	})

	t.Run("STEP 2: saving what the client was handed is ACCEPTED", func(t *testing.T) {
		// Byte for byte what RotationManager PUTs back: it parses the string it
		// was given into form state and re-stringifies the whole map on save,
		// with no dirty-check, so an untouched Save sends exactly this.
		rec := putVault(t, h, owner, "user", entryID, map[string]any{
			"provider":      "resend",
			"provider_meta": handedToTheClient,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("the owner's untouched Save returned %d, want 200, the lockout is back (body: %s)",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("STEP 3: the server's own markers are still on the row afterwards", func(t *testing.T) {
		// The write is a full column replace, so a save that round-trips the
		// REDACTED map must not be allowed to silently drop the coordinates a
		// retry needs. This is the property that makes redaction safe to prefer
		// over "tolerate a byte-identical value".
		_, enc := storedProvider(t, queries, entryID)
		after := ParseProviderMeta(h.decryptColumnOrLog(enc, "{}", vaultFieldProviderMeta))
		if after[pendingRevokeURL] != "https://api.resend.com/api-keys/old-key-id" {
			t.Errorf("the owner's save destroyed the retry coordinates: pending_revoke_url = %q, whole map %v",
				after[pendingRevokeURL], after)
		}
		if after[pendingRevokeMethod] != "DELETE" || after[pendingRevokeAuth] != revokeAuthBearer {
			t.Errorf("the owner's save destroyed part of the retry record: %v", after)
		}
	})

	t.Run("STEP 3b: changing the provider DROPS the old provider's markers", func(t *testing.T) {
		// The coordinates name a host and a key id at ONE provider. Carrying
		// them onto a different provider is how a later rotation that did not
		// defer inherits a stale marker and fires it with a freshly minted
		// secret, so the carry-across is deliberately conditional. Asserted here
		// rather than left implicit, because "preserve the server's keys" reads
		// like an unconditional rule and is not one.
		//
		// Runs on its own entry so the sequence above is not disturbed.
		const switchedID = "entry-switching-provider"
		mustEntry(t, h, queries, switchedID, owner, "switching", "secret")
		forceProviderConfig(t, h, switchedID, "resend", string(rawStored))

		rec := putVault(t, h, owner, "user", switchedID, map[string]any{
			"provider":      "sendgrid",
			"provider_meta": `{}`,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("switching provider returned %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
		_, enc := storedProvider(t, queries, switchedID)
		after := ParseProviderMeta(h.decryptColumnOrLog(enc, "{}", vaultFieldProviderMeta))
		for _, k := range reservedProviderMetaKeys {
			if _, ok := after[k]; ok {
				t.Errorf("%s survived a provider change and can now be fired against sendgrid: %v", k, after)
			}
		}
	})

	t.Run("STEP 4: a client that PLANTS a marker is still refused", func(t *testing.T) {
		// The validator this fix works alongside, not around. If this goes green
		// by returning 200, the read-path redaction was 'fixed' by weakening the
		// write gate and the planting attack is open again.
		for _, k := range reservedProviderMetaKeys {
			planted := map[string]string{"key_id": "new-key-id", k: "https://attacker.example/x"}
			raw, mErr := json.Marshal(planted)
			if mErr != nil {
				t.Fatalf("marshal planted meta: %v", mErr)
			}
			rec := putVault(t, h, owner, "user", entryID, map[string]any{
				"provider":      "resend",
				"provider_meta": string(raw),
			})
			if rec.Code != http.StatusBadRequest {
				t.Errorf("planting %s returned %d, want 400, the write gate is open (body: %s)",
					k, rec.Code, rec.Body.String())
			}
		}
	})
}

// TestRedactReservedProviderMetaKeys covers the shapes the end-to-end test
// cannot reach cheaply, including the ones where doing nothing is correct.
func TestRedactReservedProviderMetaKeys(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty column", "", ""},
		{"empty object", "{}", "{}"},
		{"nothing reserved is returned byte-identical", `{"site":"eu"}`, `{"site":"eu"}`},
		{
			"the marker set a failed revoke leaves behind",
			`{"key_id":"k","last_revoke_error":"HTTP 503","pending_revoke_auth":"bearer","pending_revoke_method":"DELETE","pending_revoke_url":"https://x/y"}`,
			`{"key_id":"k"}`,
		},
		{"a row that is only markers becomes an empty object", `{"pending_revoke_url":"https://x/y"}`, `{}`},
		// ParseProviderMeta ignores a unmarshal failure and yields an empty map,
		// so these return unchanged. That is the SAME parse
		// rejectReservedProviderMetaKeys uses, so a key neither can see can
		// never be the cause of the 400 this redaction exists to prevent.
		{"not JSON at all", "not json", "not json"},
		{"a JSON array", `["pending_revoke_url"]`, `["pending_revoke_url"]`},
		{"the literal null a nil map marshals to", "null", "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactReservedProviderMetaKeys(tc.in); got != tc.want {
				t.Errorf("redactReservedProviderMetaKeys(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEveryClientFacingProviderMetaIsRedacted is the ENUMERATING half.
//
// The end-to-end test above covers ONE read path. There are seven places that
// fill vaultEntryMeta.ProviderMeta and the eighth is written next quarter by
// someone who has never read this file, which is exactly how the previous
// unbounded-read guard in this package covered one hand-named file while two
// copies of its bug sat in another. So this parses the package and requires the
// property of every assignment, found rather than listed.
func TestEveryClientFacingProviderMetaIsRedacted(t *testing.T) {
	fset := token.NewFileSet()

	var files []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk package: %v", err)
	}

	type site struct {
		pos  string
		expr string
	}
	var unredacted []site
	found := 0

	for _, path := range files {
		src, rErr := os.ReadFile(path)
		if rErr != nil {
			t.Fatalf("read %s: %v", path, rErr)
		}
		f, pErr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if pErr != nil {
			t.Fatalf("parse %s: %v", path, pErr)
		}
		// redacted reports whether an expression is the redaction call itself.
		redacted := func(e ast.Expr) bool {
			call, ok := e.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn, ok := call.Fun.(*ast.Ident)
			return ok && fn.Name == "redactReservedProviderMetaKeys"
		}
		record := func(at ast.Node, val ast.Expr) {
			found++
			if redacted(val) {
				return
			}
			lo := fset.Position(val.Pos()).Offset
			hi := fset.Position(val.End()).Offset
			unredacted = append(unredacted, site{
				pos:  fset.Position(at.Pos()).String(),
				expr: string(src[lo:hi]),
			})
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				// Only literals of vaultEntryMeta. A db params struct also has a
				// ProviderMeta field and that one is a WRITE, which must keep
				// the markers.
				//
				// A nil Type is an ELIDED element type, as in
				// []vaultEntryMeta{{...}}. Skipping those on the old
				// `lit.Type.(*ast.Ident)` type assertion was a hole: the elided
				// spelling leaked, and `found` merely dropped by one so the
				// ABORT below did not fire either. Elided literals are followed
				// by the outer literal's own case, so they are not missed; what
				// must not happen is treating one as "not vaultEntryMeta".
				if node.Type == nil {
					return true
				}
				name, ok := node.Type.(*ast.Ident)
				if !ok || name.Name != "vaultEntryMeta" {
					return true
				}
				for _, el := range node.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "ProviderMeta" {
						record(kv, kv.Value)
					}
				}
			case *ast.AssignStmt:
				// POST-CONSTRUCTION ASSIGNMENT, e.ProviderMeta = ...
				//
				// The guard originally saw composite literals only, and this is
				// not a hypothetical spelling in this package: vault.go builds
				// `e := vaultEntryMeta{...}` and then assigns e.RotationStatus,
				// e.CollectionID and e.UserID on the very next lines. The eighth
				// read path the doc comment above anticipates would most
				// naturally be written this way, and the guard would have said
				// nothing while the operator lockout shipped back.
				//
				// Matched on the field name rather than the receiver's type,
				// because the type is not resolvable from a single-file parse.
				// The only ProviderMeta fields in the package are this response
				// struct's and the db params structs', and a db params
				// assignment is a WRITE that legitimately keeps the markers, so
				// it must not be flagged. Writes are all built as composite
				// literals today, so requiring redaction here is correct now;
				// if a params struct ever gains a field assignment this guard
				// will fail loudly and the exclusion belongs here, spelled out.
				for i, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "ProviderMeta" {
						continue
					}
					if i >= len(node.Rhs) {
						continue // n:1 assignment from a call; nothing to inspect
					}
					record(sel, node.Rhs[i])
				}
			}
			return true
		})
	}

	// A detector that finds nothing proves nothing. If the struct is renamed or
	// the field moves, this must fail loudly rather than pass by vacuum.
	if found == 0 {
		t.Fatal("ABORT: no vaultEntryMeta.ProviderMeta assignment was found in the package at all. " +
			"The struct or field was renamed and this guard is now blind. Retarget it.")
	}
	if len(unredacted) > 0 {
		sort.Slice(unredacted, func(i, j int) bool { return unredacted[i].pos < unredacted[j].pos })
		var b strings.Builder
		for _, s := range unredacted {
			b.WriteString("\n  " + s.pos + ": " + s.expr)
		}
		t.Fatalf("%d of %d vaultEntryMeta.ProviderMeta assignments reach the client without "+
			"redactReservedProviderMetaKeys, so a stored pending_revoke_* marker is handed to a client "+
			"that PUTs the whole map back and is then refused by rejectReservedProviderMetaKeys:%s",
			len(unredacted), found, b.String())
	}
	t.Logf("all %d vaultEntryMeta.ProviderMeta assignments are redacted", found)
}

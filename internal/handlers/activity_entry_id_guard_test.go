package handlers

import (
	"context"
	"go/ast"
	"go/token"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// THE MIGRATION READS THIS LOG, AND NOBODY WAS TELLING IT WHEN THE LOG CHANGED.
//
// Migrations 00034, 00035 and 00036 decide whose authority governs a stored
// secret partly from the activity log: an entry that is personal now and that no
// vault.entry_moved or vault.entry_adopted row mentions has never been in a
// collection, so adoption was never reachable for it, so its custodian is still
// the principal who deposited the plaintext.
//
// The first cut of that predicate matched a PHRASING:
//
//	instr(al.detail, '(id: ' || vault_entries.id || ',') > 0
//
// citing 4e9bd5ec as the commit that has logged the entry id ever since. The
// citation was right and the match was wrong: 4e9bd5ec writes
//
//	"Vault entry moved to collection (id: %s)"
//
// with a closing paren and no comma. Five commits shipped that wording. So a
// database whose entry passed through a collection in that window looked to the
// backfill like one that never had, and a NON-CREATOR was stamped as owner.
//
// A LOG FORMAT IS NOT AN API. The migrations no longer read one: they ask
// whether the detail contains the entry id, which is a fixed-width opaque token
// and cannot be a substring of another id. That leaves exactly one assumption,
// and this file is where it stops being invisible:
//
//	every activity row the product writes about a SPECIFIC vault entry, for the
//	actions the backfill reads, names that entry's id somewhere in its detail.
//
// Two halves, because either alone can be satisfied by a product that lost the
// property. The census notices a NEW writer nobody thought about; the wire test
// notices an EXISTING writer whose wording dropped the id.

// entryScopedActions are the activity actions the ownership backfill reads.
//
// Each maps to what the row means, because a reader deciding whether to add a
// fourth needs to know what these three have in common: all of them are the
// record of one entry changing hands or changing scope, which is the only kind
// of row that can tell "the creator still holds this" from "somebody took it".
var entryScopedActions = map[string]string{
	"vault.entry_moved": "the entry moved in or out of a collection, which is what makes adoption " +
		"reachable for it. Migrations 00034/00035/00036 withhold an owner on any entry this names.",
	"vault.entry_adopted": "a collection manager renamed and took over an entry whose creator had " +
		"left. The direct record of the attack the ownership split exists for.",
	"vault.ownership_claimed": "an instance admin repaired a withheld owner at Settings -> Ownership. " +
		"Migrations 00035/00036 PRESERVE an owner this names, so its match is the one that stays " +
		"delimited: preserving on a false positive is the unsafe direction.",
}

// theEntryScopedActivityWriters is every production site that writes one of
// those actions, and the test that drives it.
//
// A census, not a call-shape matcher: it collects string literals equal to the
// action names, so LogActivityFromRequest, the queuedActivity literal the
// adoption path uses (it defers the write to avoid contending with its own
// transaction's lock) and any fourth spelling all land in it the same way.
var theEntryScopedActivityWriters = map[string]string{
	"internal/handlers/vault.go:vault.entry_moved": "VaultHandler.MoveToCollection, driven by " +
		"TestEveryEntryScopedActivityDetailNamesTheEntryID/moved",
	"internal/handlers/vault.go:vault.entry_adopted": "VaultHandler.Update's adoption branch, driven " +
		"by TestEveryEntryScopedActivityDetailNamesTheEntryID/adopted",
	"internal/handlers/vault_ownership_repair.go:vault.ownership_claimed": "ClaimSecretOwnership, " +
		"driven by TestEveryEntryScopedActivityDetailNamesTheEntryID/claimed",
}

// TestTheBackfillReadsNoActivityWriterNobodyDeclared is the census half.
func TestTheBackfillReadsNoActivityWriterNobodyDeclared(t *testing.T) {
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)
	if len(parsed) < 30 {
		t.Fatalf("ABORT: parsed only %d module files; this guard is not reading the source", len(parsed))
	}

	found := map[string]bool{}
	for path, f := range parsed {
		rel := moduleRelative(path)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if _, ok := entryScopedActions[v]; ok {
				found[rel+":"+v] = true
			}
			return true
		})
	}

	if len(found) == 0 {
		t.Fatal("ABORT: no writer of any entry-scoped activity action was found in the module. Either " +
			"the walk is broken or the actions were renamed, and the migrations still read the old names")
	}

	for _, site := range sortedBoolKeys(found) {
		if _, declared := theEntryScopedActivityWriters[site]; declared {
			continue
		}
		t.Errorf("AN UNDECLARED WRITER OF AN ENTRY-SCOPED ACTIVITY ACTION: %s.\n"+
			"  The ownership backfill (migrations 00034, 00035, 00036) decides who owns a stored secret\n"+
			"  partly from rows with this action, and it now matches the ENTRY ID rather than a phrasing,\n"+
			"  because the phrasing had already changed once with nobody noticing.\n"+
			"  Make sure this writer puts the entry id in its detail, add it to\n"+
			"  theEntryScopedActivityWriters, and drive it from\n"+
			"  TestEveryEntryScopedActivityDetailNamesTheEntryID. A row this backfill cannot attribute\n"+
			"  is a row that silently stops withholding.", site)
	}
	for site := range theEntryScopedActivityWriters {
		if !found[site] {
			t.Errorf("A STALE ACTIVITY-WRITER DECLARATION: %s is declared and does not exist.\n"+
				"  Either the writer moved, in which case the census below it is now blind, or the "+
				"action was removed and the migrations are reading for something nothing writes.", site)
		}
	}
	t.Logf("%d entry-scoped activity writers, all declared: %v", len(found), sortedBoolKeys(found))
}

// TestEveryEntryScopedActivityDetailNamesTheEntryID is the wire half.
//
// It drives the three real handlers and reads what actually landed in
// activity_log. A source scan cannot do this: the detail is a Sprintf and
// whether its arguments happen to include the entry id is a question about
// values, not about syntax.
func TestEveryEntryScopedActivityDetailNamesTheEntryID(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	creator := mustUser(t, queries, "aid-creator@example.com", "user", "creator-pw")
	manager := mustUser(t, queries, "aid-manager@example.com", "user", "manager-pw")
	admin := mustUser(t, queries, "aid-admin@example.com", "admin", "admin-pw")
	mustCollection(t, queries, "coll-aid", creator, map[string]string{
		creator: collRoleEditor, manager: collRoleManager,
	})

	t.Run("moved", func(t *testing.T) {
		const entryID = "entry-aid-moved"
		mustEntry(t, h, queries, entryID, creator, "aid-moved", "v")
		rec := httptest.NewRecorder()
		h.MoveToCollection(rec, vaultAuthzRequest(http.MethodPut,
			"/api/vault/"+entryID+"/collection", creator, "user", entryID,
			`{"collection_id":"coll-aid"}`))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("move: %d %s", rec.Code, rec.Body.String())
		}
		assertActivityNamesEntry(t, queries, "vault.entry_moved", entryID)
	})

	t.Run("adopted", func(t *testing.T) {
		const entryID = "entry-aid-adopted"
		mustEntry(t, h, queries, entryID, creator, "aid-adopted", "v")
		placeInCollection(t, queries, entryID, "coll-aid")
		if _, err := queries.RemoveCollectionMember(ctx, db.RemoveCollectionMemberParams{
			CollectionID: "coll-aid", UserID: creator,
		}); err != nil {
			t.Fatalf("creator leaves: %v", err)
		}
		rec := httptest.NewRecorder()
		h.Update(rec, vaultAuthzRequest(http.MethodPut, "/api/vault/"+entryID, manager, "user",
			entryID, `{"name":"aid-adopted-renamed"}`))
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("adopt: %d %s", rec.Code, rec.Body.String())
		}
		assertActivityNamesEntry(t, queries, "vault.entry_adopted", entryID)
	})

	t.Run("claimed", func(t *testing.T) {
		const entryID = "entry-aid-claimed"
		mustEntry(t, h, queries, entryID, creator, "aid-claimed", "v")
		clearSecretOwnerForTest(t, h, entryID)
		rec := httptest.NewRecorder()
		h.ClaimSecretOwnership(rec, vaultAuthzRequest(http.MethodPost,
			"/api/admin/vault/"+entryID+"/ownership/claim", admin, "admin", entryID, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("claim: %d %s", rec.Code, rec.Body.String())
		}
		assertActivityNamesEntry(t, queries, "vault.ownership_claimed", entryID)
	})
}

// assertActivityNamesEntry reads the log the way the migration does.
func assertActivityNamesEntry(t *testing.T, queries *db.Queries, action, entryID string) {
	t.Helper()
	rows, err := queries.ListActivityEntriesByAction(context.Background(),
		db.ListActivityEntriesByActionParams{Action: action, Limit: 100, Offset: 0})
	if err != nil {
		t.Fatalf("list %s activity: %v", action, err)
	}
	if len(rows) == 0 {
		t.Fatalf("ABORT: the handler produced no %s row at all, so this check is measuring nothing "+
			"(%s)", action, entryScopedActions[action])
	}
	for _, row := range rows {
		if strings.Contains(row.Detail.String, entryID) {
			t.Logf("%s names the entry: %s", action, row.Detail.String)
			return
		}
	}
	details := make([]string, 0, len(rows))
	for _, row := range rows {
		details = append(details, row.Detail.String)
	}
	t.Errorf("NO %s ROW NAMES ENTRY %s.\n"+
		"  The ownership backfill reads this action and attributes it by looking for the entry id in\n"+
		"  the detail. It used to look for one PHRASING of that detail and the phrasing had already\n"+
		"  changed underneath it, which stamped a non-creator as the owner of somebody else's secret.\n"+
		"  Put the entry id back in the detail. Rewording around it is fine; dropping it is not.\n"+
		"  %s\n  rows seen: %q", action, entryID, entryScopedActions[action], details)
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

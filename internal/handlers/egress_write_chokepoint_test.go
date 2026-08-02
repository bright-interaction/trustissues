package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// THE GUARD THAT IS SUPPOSED TO END THE SERIES.
//
// egress_field_coverage_test.go forces every vault_entries column to be
// CLASSIFIED as host-choosing or not. It is a good guard and it did not stop
// round 5, and the reason is worth stating plainly, because it is the reusable
// lesson:
//
//	rotation_targets was already classified egressChoosesHost, with a paragraph
//	of reasoning attached, sitting next to VaultHandler.UpdateTargets, which
//	never asked anybody for permission. A vault_only account holding an accepted
//	EDITOR seat on somebody else's shared entry PUT a webhook_url at a host it
//	controlled, got 200, and the next scheduled rotation POSTed the freshly
//	minted plaintext there.
//
// A classification is a CLAIM ABOUT THE CODE. Round 4's table checked that every
// field had a claim. It could not check that the claim was true, so a field
// could be marked dangerous and left unenforced, and that reads as coverage,
// which is worse than nothing.
//
// So this file checks the OTHER direction. For every column classified
// egressChoosesHost it finds, out of the GENERATED SQL, every query that writes
// it, and requires that every call to those queries goes through
// vault_egress_writes.go, whose wrappers demand an egressgate.Ticket. Nothing
// here is a hand-maintained list of routes: the columns come from the
// classification table, the queries come from internal/db, and the call sites
// come from the tree. A NEW field, or a NEW route for an old field, is covered
// on the day it is written rather than after a skeptic finds it.
//
// The ablations that validate this are in scripts/round5-ablations.json, plus
// the four-file "add a whole new host-choosing column" ablation recorded in
// AUDIT-ROUND-15.md. Both make the build succeed and this file red.

// egressChokepointFile is the one file allowed to call a query that writes a
// host-choosing column.
const egressChokepointFile = "vault_egress_writes.go"

// generatedQuery is one sqlc-generated query, as it really exists.
type generatedQuery struct {
	method  string // the Go method name on *db.Queries
	file    string
	writes  []string // vault_entries columns this statement writes
	sqlText string
}

var (
	// The shape sqlc emits: a const holding the annotated SQL.
	genQueryRe = regexp.MustCompile("(?s)const \\w+ = `-- name: (\\w+) :(\\w+)\n(.*?)\n`")
	// UPDATE vault_entries SET <assignments> [WHERE ...]
	genUpdateRe = regexp.MustCompile(`(?is)update\s+vault_entries\s+set\s+(.*?)(?:\bwhere\b|$)`)
	genAssignRe = regexp.MustCompile(`(?i)([a-z_0-9]+)\s*=`)
	// INSERT INTO vault_entries (<columns>)
	genInsertRe = regexp.MustCompile(`(?is)insert\s+into\s+vault_entries\s*\(([^)]*)\)`)
)

// generatedVaultWrites reads the REAL generated queries and reports which
// vault_entries columns each one writes.
//
// Reading the generated Go rather than the .sql sources is deliberate: the
// generated file is what the handlers actually call, so a query that exists in
// the .sql but was never regenerated cannot make this guard think a door is
// covered when the code has no such door, and vice versa.
func generatedVaultWrites(t *testing.T) []generatedQuery {
	t.Helper()
	dir := filepath.Join("..", "db")
	files, err := filepath.Glob(filepath.Join(dir, "*.sql.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("ABORT: no generated query files under %s (%v); this guard would be vacuous", dir, err)
	}
	sort.Strings(files)

	var out []generatedQuery
	total := 0
	for _, f := range files {
		src, rErr := os.ReadFile(f)
		if rErr != nil {
			t.Fatalf("read %s: %v", f, rErr)
		}
		for _, m := range genQueryRe.FindAllStringSubmatch(string(src), -1) {
			total++
			method, sqlText := m[1], m[3]
			writes := map[string]bool{}
			for _, um := range genUpdateRe.FindAllStringSubmatch(sqlText, -1) {
				for _, a := range genAssignRe.FindAllStringSubmatch(um[1], -1) {
					writes[strings.ToLower(a[1])] = true
				}
			}
			for _, im := range genInsertRe.FindAllStringSubmatch(sqlText, -1) {
				for _, c := range strings.Split(im[1], ",") {
					if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
						writes[c] = true
					}
				}
			}
			if len(writes) == 0 {
				continue
			}
			cols := make([]string, 0, len(writes))
			for c := range writes {
				cols = append(cols, c)
			}
			sort.Strings(cols)
			out = append(out, generatedQuery{method: method, file: filepath.Base(f), writes: cols, sqlText: sqlText})
		}
	}
	if total < 100 {
		t.Fatalf("ABORT: only parsed %d generated queries; the sqlc output shape has changed and this "+
			"guard is matching almost nothing", total)
	}
	return out
}

// hostChoosingColumns is the classification table, read as data. It is the ONLY
// input that says which columns matter, so reclassifying a column immediately
// changes what this guard demands.
func hostChoosingColumns(t *testing.T) []string {
	t.Helper()
	var cols []string
	for col, entry := range vaultEntryEgressClass {
		if entry.class == egressChoosesHost {
			cols = append(cols, col)
		}
	}
	sort.Strings(cols)
	if len(cols) < 4 {
		t.Fatalf("ABORT: only %d columns are classified egressChoosesHost (%v). Four are known to be "+
			"(destination_patterns, provider, provider_meta, rotation_targets), so either the "+
			"classification table shrank without an explanation or this guard is reading the wrong "+
			"thing", len(cols), cols)
	}
	return cols
}

// moduleGoFiles walks the whole module and returns every non-generated,
// non-test source file, as path -> contents.
//
// The whole module, not just this package: a second writer of these columns in
// cmd/ or in a future internal/scheduler would be exactly the "one more door"
// this series keeps finding, and a guard scoped to one package would not see it.
func moduleGoFiles(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "frontend", "docs", "scripts":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// internal/db is the generated data-access layer. It IS the queries, so
		// it cannot be held to "do not call the queries".
		if strings.Contains(filepath.ToSlash(path), "/internal/db/") {
			return nil
		}
		b, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		out[filepath.ToSlash(path)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if len(out) < 30 {
		t.Fatalf("ABORT: only found %d non-test source files under the module; the walk is not reaching "+
			"the code and this guard is checking nothing", len(out))
	}
	return out
}

// TestEveryHostChoosingWriteGoesThroughTheChokepoint is the round-5 stopper.
//
// It is the test that would have failed the day UpdateTargets was written, with
// no knowledge that webhook_url is special, and it will fail the day somebody
// adds the next column or the next route.
func TestEveryHostChoosingWriteGoesThroughTheChokepoint(t *testing.T) {
	cols := hostChoosingColumns(t)
	queries := generatedVaultWrites(t)
	files := moduleGoFiles(t)

	if _, ok := files[filepath.ToSlash(filepath.Join("..", "..", "internal", "handlers", egressChokepointFile))]; !ok {
		t.Fatalf("ABORT: the chokepoint file %s is gone. If it was renamed, rename it here too rather "+
			"than deleting this guard", egressChokepointFile)
	}

	// Which generated queries write a host-choosing column, and which column
	// made them interesting.
	guarded := map[string][]string{} // method -> columns
	for _, q := range queries {
		for _, c := range q.writes {
			for _, hc := range cols {
				if c == hc {
					guarded[q.method] = append(guarded[q.method], hc)
				}
			}
		}
	}
	for _, hc := range cols {
		found := false
		for _, got := range guarded {
			for _, c := range got {
				if c == hc {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("no generated query writes %s, yet it is classified as choosing a host. Either the "+
				"column is dead and the classification is stale, or the SQL parser above stopped "+
				"recognising the statement that writes it, in which case this guard has silently "+
				"stopped guarding that column", hc)
		}
	}
	if len(guarded) < 5 {
		t.Fatalf("ABORT: only %d generated queries were found to write a host-choosing column (%v). "+
			"Six are known to (CreateVaultEntry, UpdateVaultEntryDestinationPatterns, "+
			"UpdateVaultEntryProvider, UpdateVaultEntryProviderMeta, UpdateVaultEntryRotationTargets, "+
			"SeedVaultEntryCapabilityDefaults), so the parser is not matching", len(guarded), guarded)
	}
	t.Logf("guarding %d generated queries across %d host-choosing columns", len(guarded), len(cols))

	// Every call site of every one of them must be in the chokepoint file.
	for method, columns := range guarded {
		call := regexp.MustCompile(`\.` + regexp.QuoteMeta(method) + `\s*\(`)
		callSites := 0
		for path, src := range files {
			if !call.MatchString(src) {
				continue
			}
			callSites++
			if filepath.Base(path) == egressChokepointFile {
				continue
			}
			t.Errorf("%s calls %s directly.\n"+
				"  that query writes %v, which is classified as choosing where this secret is sent\n"+
				"  so the write has to carry an egressgate.Ticket, and the only way to get one is\n"+
				"  egressgate.Decide, which asks mayDirectSecretEgress when the write ADDS a destination.\n"+
				"Route it through the wrapper in %s.\n\n"+
				"This is the round-5 defect exactly: rotation_targets was CLASSIFIED as host-choosing and "+
				"UpdateTargets wrote it anyway, so a vault_only editor pointed a rotation webhook at a host "+
				"they controlled and the scheduler delivered the plaintext. A table that labels a field "+
				"without forcing its write path to ask is not coverage.",
				path, method, columns, egressChokepointFile)
		}
		if callSites == 0 {
			t.Errorf("nothing anywhere calls %s, which writes %v. A query with no caller is either dead "+
				"code or a rename this guard did not follow; both make it invisible to the checks above",
				method, columns)
		}
	}
}

// TestChokepointWrappersAllDemandATicket closes the obvious way to satisfy the
// test above without satisfying its point: move the call into the chokepoint
// file and do not check anything once it is there.
func TestChokepointWrappersAllDemandATicket(t *testing.T) {
	cols := hostChoosingColumns(t)
	queries := generatedVaultWrites(t)

	guardedMethods := map[string]bool{}
	for _, q := range queries {
		for _, c := range q.writes {
			for _, hc := range cols {
				if c == hc {
					guardedMethods[q.method] = true
				}
			}
		}
	}

	src := readPackageFile(t, egressChokepointFile)
	// Split into top-level functions. A wrapper is any function that calls a
	// guarded query.
	parts := strings.Split(src, "\nfunc ")
	checked := 0
	for i, body := range parts {
		if i == 0 {
			continue // the file header, before the first func
		}
		name := body
		if j := strings.IndexAny(name, "("); j > 0 {
			name = strings.TrimSpace(name[:j])
		}
		calls := ""
		for m := range guardedMethods {
			if strings.Contains(body, "."+m+"(") {
				calls = m
				break
			}
		}
		if calls == "" {
			continue
		}
		checked++
		if !strings.Contains(body, ".Authorizes(") {
			t.Errorf("%s in %s calls %s but never calls Ticket.Authorizes.\n"+
				"A wrapper that performs the write and does not check the ticket is a chokepoint with "+
				"no lock on it: every caller looks correctly routed and none of them is gated.",
				name, egressChokepointFile, calls)
		}
		if !strings.Contains(body, "egressgate.Ticket") {
			t.Errorf("%s in %s calls %s but does not take an egressgate.Ticket, so its callers are not "+
				"forced to have made a decision at all", name, egressChokepointFile, calls)
		}
	}
	if checked < 5 {
		t.Fatalf("ABORT: only %d wrappers in %s were found to call a guarded query; the file layout "+
			"changed and this guard is checking almost nothing", checked, egressChokepointFile)
	}
	t.Logf("checked %d chokepoint wrappers", checked)
}

// TestNoHandWrittenSQLWritesAHostChoosingColumn closes the third door.
//
// The two tests above are about the generated query layer. A handler holding
// *sql.DB can write the column with a string, and neither of them would see it.
func TestNoHandWrittenSQLWritesAHostChoosingColumn(t *testing.T) {
	cols := hostChoosingColumns(t)
	files := moduleGoFiles(t)
	stmt := regexp.MustCompile(`(?is)(update\s+vault_entries\s+set|insert\s+into\s+vault_entries)`)

	scanned := 0
	for path, src := range files {
		scanned++
		for _, m := range stmt.FindAllStringIndex(src, -1) {
			// Take a generous window after the statement head; a column name
			// appearing there is enough to demand a look.
			end := m[1] + 400
			if end > len(src) {
				end = len(src)
			}
			window := strings.ToLower(src[m[0]:end])
			for _, c := range cols {
				if strings.Contains(window, c) {
					t.Errorf("%s writes vault_entries.%s with hand-written SQL, going around both the "+
						"generated query layer and the egress chokepoint. Add a query to "+
						"internal/db/queries and route it through %s.",
						path, c, egressChokepointFile)
				}
			}
		}
	}
	if scanned < 30 {
		t.Fatalf("ABORT: only scanned %d files", scanned)
	}
}

// TestTheChokepointHasADeriverForEveryHostChoosingColumn is the last of the four
// and the one that keeps the gate honest rather than merely present.
//
// egressgate.Decide compares two destination sets. If the sets are computed
// wrongly, the ticket is granted for a write that does move the secret, and
// every structural check above still passes. So the derivers are named, and a
// column classified host-choosing with no deriver behind it fails here.
func TestTheChokepointHasADeriverForEveryHostChoosingColumn(t *testing.T) {
	src := readPackageFile(t, egressChokepointFile)
	// column -> the deriver that renders it as a destination set.
	derivers := map[string]string{
		"destination_patterns": "func ceilingDestinations(",
		"provider":             "func providerDestinations(",
		"provider_meta":        "func providerDestinations(",
		"rotation_targets":     "func deliveryDestinations(",
	}
	for _, col := range hostChoosingColumns(t) {
		deriver, ok := derivers[col]
		if !ok {
			t.Errorf("vault_entries.%s is classified as choosing a host but %s has no named deriver for "+
				"it.\nA wrapper cannot decide whether a write ADDS a destination without a function that "+
				"turns that column's value into the set of places the secret can reach. Write one, add it "+
				"here, and use it at the write site: without it the ticket is granted on an empty "+
				"comparison and the gate is decorative.", col, egressChokepointFile)
			continue
		}
		if !strings.Contains(src, deriver) {
			t.Errorf("the deriver %q for vault_entries.%s is gone from %s", deriver, col, egressChokepointFile)
		}
	}
}

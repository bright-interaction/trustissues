package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// tableDecl is the statement this guard looks for, assembled so the guard file
// itself never contains the literal it searches for (otherwise it matches
// itself, which is how the first version corrupted its own source).
var tableDecl = "CREATE TABLE " + "vault_entries"

// TestHandRolledFixturesMatchTheRealSchema stops a recurring failure mode
// instead of patching its fifth instance.
//
// Five test files declare their own vault_entries table rather than running the
// migrations. Every time the real schema gains a column those fixtures fall
// behind, and the resulting failure never looks like schema drift:
//
//   - missing collection_id made entryAccessFor error, so authorization tests
//     passed by failing CLOSED for a reason production never has
//   - missing users.totp_enabled made GetUserByID error, so reference
//     resolution silently denied everyone
//   - missing vault_entries.updated_at made the AI gateway answer
//     "provider key is not available", pointing at the key rather than the schema
//
// Each cost real debugging time, and one of them masked a live bug. This names
// exactly which fixture is missing what.
//
// The right long-term fix is for these fixtures to use database.RunMigrations
// like newCollectionAuthzEnv does; until then this keeps them honest.
func TestHandRolledFixturesMatchTheRealSchema(t *testing.T) {
	required := []string{
		"id", "user_id", "name", "encrypted_value", "nonce", "encryption_version",
		"collection_id", "custom_fields", "destination_patterns",
		"provider", "provider_meta", "rotation_targets", "rotation_log",
		"last_rotated_at", "last_rotation_error", "updated_at", "created_at",
	}

	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	checked := 0
	for _, f := range files {
		if f == "schema_drift_test.go" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := string(src)
		start := strings.Index(text, tableDecl)
		if start < 0 {
			continue
		}
		body, ok := balancedParens(text, start)
		if !ok {
			// Fail closed: a fixture this guard cannot parse must not be
			// silently skipped, or the guard quietly stops guarding, which is
			// the exact class of failure it exists to catch.
			t.Errorf("%s declares the table but its parentheses could not be parsed; "+
				"fix the formatting rather than letting the fixture go unchecked", f)
			continue
		}
		checked++
		var missing []string
		for _, c := range required {
			if !regexp.MustCompile(`(?m)(^|[\s,(])` + regexp.QuoteMeta(c) + `\s`).MatchString(body) {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s: fixture is missing %s.\nA fixture behind the real schema fails in ways that "+
				"look like application bugs. Add the columns, or switch to database.RunMigrations.",
				f, strings.Join(missing, ", "))
		}
	}
	if checked == 0 {
		t.Fatal("ABORT: no hand-rolled fixtures found; this guard is matching nothing and is vacuous")
	}
	t.Logf("checked %d hand-rolled fixtures", checked)
}

// balancedParens returns the contents of the parenthesised block that starts
// after from, matching nesting properly.
func balancedParens(s string, from int) (string, bool) {
	open := strings.Index(s[from:], "(")
	if open < 0 {
		return "", false
	}
	open += from
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], true
			}
		}
	}
	return "", false
}

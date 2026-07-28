package handlers

import (
	"errors"
	"os"
	"strings"
	"testing"
)

var errShortSource = errors.New("source file suspiciously short; a structural guard would pass vacuously")

func readFileBytes(name string) ([]byte, error) { return os.ReadFile(name) }

// TestImportReportsEveryDroppedRow closes a gap in an earlier fix.
//
// A previous round added the `skipped` list because a 200-entry export with 12
// duplicate titles silently became 188 entries under a plain success toast. That
// fix only covered the UNIQUE-constraint branch. Two lines above it sat
// `if entry.Skip || entry.Name == "" || entry.Value == "" { continue }`, which
// swallowed rows with no password without a slog line or a skipped entry.
//
// That is not a rare shape: Bitwarden secure notes, cards and identities, and
// LastPass secure notes, all export with an empty password. A 500-item export
// could import 380 and still report unqualified success, and a user who deletes
// their old vault afterwards loses the difference.
//
// Fixing a bug does not clean its neighbourhood: the reporting existed, the
// guard next to it still dropped silently.
func TestImportReportsEveryDroppedRow(t *testing.T) {
	src, err := readSourceFile("vault_import.go")
	if err != nil {
		t.Fatalf("ABORT: %v", err)
	}

	// entry.Skip is the ONLY legitimate silent drop: it is a user decision made
	// in the conflict step.
	if !strings.Contains(src, "if entry.Skip {") {
		t.Error("the user-requested skip is no longer its own branch; an empty-value row may be silently dropped again")
	}
	if strings.Contains(src, `if entry.Skip || entry.Name == "" || entry.Value == "" {`) {
		t.Error("the combined guard is back: rows with no password value are dropped without being reported, " +
			"so a Bitwarden or LastPass export silently loses its secure notes under a success toast")
	}
	for _, want := range []string{
		"no password value in the export row",
		"could not be encrypted",
		"could not generate an entry id",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("drop path %q is not reported in the skipped list", want)
		}
	}
	// Every `continue` in the import loop must be preceded by either a skipped
	// append or the Skip branch. Cheap structural proxy for "no silent drops".
	if n := strings.Count(src, "skipped = append(skipped, skippedEntry{"); n < 4 {
		t.Errorf("only %d reported drop paths; the loop has more ways to discard a row than it admits to", n)
	}
}

// readSourceFile is a tiny helper so this file does not depend on the one in
// vault_revoke_order_test.go changing shape.
func readSourceFile(name string) (string, error) {
	b, err := readFileBytes(name)
	if err != nil {
		return "", err
	}
	if len(b) < 1000 {
		return "", errShortSource
	}
	return string(b), nil
}

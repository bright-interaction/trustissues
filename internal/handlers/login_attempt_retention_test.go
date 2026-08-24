package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
)

// TestLoginAttemptsAreActuallySwept is the behaviour half: old rows go, rows a
// reader still needs stay.
func TestLoginAttemptsAreActuallySwept(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	// A row inside every reader's window, and one well past retention.
	if err := queries.CreateLoginAttempt(ctx, db.CreateLoginAttemptParams{
		Email: "fresh@example.com", IpAddress: "198.51.100.1", Success: 0,
		Scope: db.LoginAttemptScopePasswordLogin,
	}); err != nil {
		t.Fatalf("insert fresh: %v", err)
	}
	if _, err := vh.db.ExecContext(ctx,
		`INSERT INTO login_attempts (email, ip_address, success, created_at)
		 VALUES (?, ?, 0, datetime('now', '-30 days'))`,
		"ancient@example.com", "198.51.100.2"); err != nil {
		t.Fatalf("insert ancient: %v", err)
	}

	// Guard the setup: both rows must exist, or the sweep below proves nothing.
	var before int
	if err := vh.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_attempts`).Scan(&before); err != nil {
		t.Fatalf("count: %v", err)
	}
	if before != 2 {
		t.Fatalf("ABORT: expected 2 rows before the sweep, got %d", before)
	}

	n, err := PruneLoginAttempts(ctx, queries)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("the sweep removed %d rows, expected exactly the one past retention", n)
	}

	var survivors []string
	rows, err := vh.db.QueryContext(ctx, `SELECT email FROM login_attempts`)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatalf("scan: %v", err)
		}
		survivors = append(survivors, e)
	}
	if len(survivors) != 1 || survivors[0] != "fresh@example.com" {
		t.Fatalf("survivors = %v, expected only the fresh row; the sweep is eating rows the "+
			"lockout still needs, which would hand an attacker a reset throttle", survivors)
	}
}

// TestPruneIsIdempotentAndSafeOnAnEmptyTable pins that the janitor's first tick
// on a fresh deployment does nothing dramatic.
func TestPruneIsIdempotentAndSafeOnAnEmptyTable(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		n, err := PruneLoginAttempts(ctx, queries)
		if err != nil {
			t.Fatalf("prune %d: %v", i, err)
		}
		if n != 0 {
			t.Fatalf("prune %d removed %d rows from an empty table", i, n)
		}
	}
}

// datetimeWindow matches a SQLite relative-datetime modifier written as a
// literal, e.g. datetime('now', '-15 minutes').
var datetimeWindow = regexp.MustCompile(
	`datetime\(\s*'now'\s*,\s*'\s*-\s*(\d+)\s+(minute|minutes|hour|hours|day|days)\s*'\s*\)`)

// TestLoginAttemptRetentionOutlivesEveryReader is the completeness half, and it
// DERIVES the readers rather than listing them.
//
// A retention sweep and the queries it starves are written months apart by
// different people. If someone adds a lockout that counts back 48 hours, a
// 24-hour retention silently caps it at 24 and the control is quietly weaker
// than it reads, with no test failing. So the test parses every query block that
// touches login_attempts, extracts the window each one looks back, and fails if
// LoginAttemptRetention does not exceed the longest.
//
// Deriving beats remembering: the estate keeps hitting guards that recognised
// one spelling of the thing they guard.
func TestLoginAttemptRetentionOutlivesEveryReader(t *testing.T) {
	const queryDir = "../db/queries"
	entries, err := os.ReadDir(queryDir)
	if err != nil {
		t.Fatalf("read query dir: %v", err)
	}

	type reader struct {
		name   string
		window time.Duration
	}
	var readers []reader
	sawLoginAttemptsFile := false

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(queryDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		// Split into per-query blocks so a datetime modifier is attributed to the
		// statement it actually belongs to, not to its neighbour.
		blocks := strings.Split(string(body), "-- name: ")
		for _, b := range blocks[1:] {
			name := strings.Fields(b)[0]
			if !strings.Contains(b, "login_attempts") {
				continue
			}
			sawLoginAttemptsFile = true
			if name == "PruneLoginAttempts" {
				continue // the sweep itself, parameterised, not a reader
			}
			for _, m := range datetimeWindow.FindAllStringSubmatch(b, -1) {
				n, err := strconv.Atoi(m[1])
				if err != nil {
					t.Fatalf("%s: unparsable window %q", name, m[0])
				}
				var d time.Duration
				switch {
				case strings.HasPrefix(m[2], "minute"):
					d = time.Duration(n) * time.Minute
				case strings.HasPrefix(m[2], "hour"):
					d = time.Duration(n) * time.Hour
				case strings.HasPrefix(m[2], "day"):
					d = time.Duration(n) * 24 * time.Hour
				}
				readers = append(readers, reader{name: name, window: d})
			}
		}
	}

	// Guard the derivation itself. If the parse finds nothing, the test would
	// pass against any retention value at all, which is the failure mode this
	// whole style of test exists to avoid.
	if !sawLoginAttemptsFile {
		t.Fatal("ABORT: no query block mentioning login_attempts was found; the derivation is " +
			"looking in the wrong place and would pass against any retention window")
	}
	if len(readers) == 0 {
		t.Fatal("ABORT: found login_attempts queries but extracted zero windows; the regex no " +
			"longer matches how the windows are written, so this test proves nothing")
	}

	longest := readers[0]
	for _, r := range readers[1:] {
		if r.window > longest.window {
			longest = r
		}
	}
	if LoginAttemptRetention <= longest.window {
		var all []string
		for _, r := range readers {
			all = append(all, fmt.Sprintf("%s=%s", r.name, r.window))
		}
		t.Fatalf("LoginAttemptRetention is %s but %s looks back %s.\n"+
			"readers: %s\n"+
			"The sweep would delete rows that query still counts, so the lockout it enforces "+
			"is quietly shorter than it reads. Raise the retention constant.",
			LoginAttemptRetention, longest.name, longest.window, strings.Join(all, ", "))
	}
}

// TestNoHandWrittenSQLTouchesLoginAttempts keeps the derivation above honest.
//
// It can only see queries in the .sql files. A hand-written statement in a Go
// file would be invisible to it, and this codebase has a history of exactly that
// (a guard proving a property over one representation while the real write path
// used another). Comments naming the table are fine and there are several.
func TestNoHandWrittenSQLTouchesLoginAttempts(t *testing.T) {
	roots := []string{"..", "../../cmd"}
	offenders := map[string]int{}

	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			// The generated package is where the real statements belong.
			if strings.Contains(path, "/db/") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			for i, line := range strings.Split(string(body), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "//") {
					continue
				}
				if strings.Contains(line, "login_attempts") {
					offenders[fmt.Sprintf("%s:%d", path, i+1)]++
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if len(offenders) > 0 {
		var list []string
		for k := range offenders {
			list = append(list, k)
		}
		t.Fatalf("hand-written SQL names login_attempts outside the generated package at %s.\n"+
			"TestLoginAttemptRetentionOutlivesEveryReader derives the readers from "+
			"internal/db/queries/*.sql and cannot see these, so the retention window is no "+
			"longer known to outlive every reader.", strings.Join(list, ", "))
	}
}

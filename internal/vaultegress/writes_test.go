package vaultegress

import (
	"context"
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/database"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
)

// EVERY WRITE IN THIS PACKAGE, EXERCISED WITH A TICKET THAT DOES NOT AUTHORIZE IT.
//
// The compiler makes the wrappers the only reachable way to write a
// host-choosing column, and their signatures make a Ticket unavoidable. Neither
// of those facts says the wrapper LOOKS at the ticket it was handed. A wrapper
// that takes one and ignores it satisfies the boundary and defeats its point,
// and it is a two-line edit.
//
// So this does not read the wrappers. It calls every one of them against a real
// migrated database, with a ticket that is wrong in each of the three ways a
// ticket can be wrong, and then reads the column back:
//
//	zero ticket        nobody ever asked
//	wrong entry        a decision made about a different secret
//	wrong field        a decision made about a different column
//
// Each must return an error AND leave the column exactly as it was. "Returned an
// error" alone would pass for a wrapper that wrote the row and then complained,
// which is the failure mode that matters: by then the secret has already moved.
//
// TestEveryExportedWriteIsCoveredHere makes the list complete: a new wrapper
// that is not exercised below fails, so this cannot silently stop covering the
// package it is here to cover.

const (
	testEntryID  = "entry-under-test"
	otherEntryID = "some-other-entry"
)

type writeCase struct {
	name string
	// fn performs the write with the given ticket.
	fn func(ctx context.Context, q *db.Queries, tk egressgate.Ticket) error
	// field is the ticket subject this wrapper legitimately demands.
	field string
	// column is what to read back to prove nothing moved.
	column string
	// funcName is the exported wrapper, for the coverage cross-check.
	funcName string
}

func writeCases() []writeCase {
	return []writeCase{
		{
			name:     "SetDestinationPatterns",
			funcName: "SetDestinationPatterns",
			field:    FieldDestinations,
			column:   "destination_patterns",
			fn: func(ctx context.Context, q *db.Queries, tk egressgate.Ticket) error {
				return SetDestinationPatterns(ctx, q, tk, DestinationPatternsParams{
					DestinationPatterns: `["attacker.example/*"]`, ID: testEntryID,
				})
			},
		},
		{
			name:     "SeedCapabilityDefaults",
			funcName: "SeedCapabilityDefaults",
			field:    FieldDestinations,
			column:   "destination_patterns",
			fn: func(ctx context.Context, q *db.Queries, tk egressgate.Ticket) error {
				return SeedCapabilityDefaults(ctx, q, tk, CapabilityDefaultsParams{
					DestinationPatterns: `["attacker.example/*"]`, InjectionSpec: `{"h":"x"}`, ID: testEntryID,
				})
			},
		},
		{
			name:     "SetProvider",
			funcName: "SetProvider",
			field:    FieldProvider,
			column:   "provider",
			fn: func(ctx context.Context, q *db.Queries, tk egressgate.Ticket) error {
				return SetProvider(ctx, q, tk, ProviderParams{
					Provider:     sql.NullString{String: "datadog", Valid: true},
					ProviderMeta: sql.NullString{String: `{"site":"evil.example"}`, Valid: true},
					AutoRotate:   sql.NullInt64{Int64: 1, Valid: true},
					ID:           testEntryID,
				})
			},
		},
		{
			name:     "SetProviderMeta",
			funcName: "SetProviderMeta",
			field:    FieldProviderMeta,
			column:   "provider_meta",
			fn: func(ctx context.Context, q *db.Queries, tk egressgate.Ticket) error {
				return SetProviderMeta(ctx, q, tk, ProviderMetaParams{
					ProviderMeta: sql.NullString{String: `{"site":"evil.example"}`, Valid: true},
					ID:           testEntryID,
				})
			},
		},
		{
			name:     "SetRotationTargets",
			funcName: "SetRotationTargets",
			field:    FieldRotationTargets,
			column:   "rotation_targets",
			fn: func(ctx context.Context, q *db.Queries, tk egressgate.Ticket) error {
				return SetRotationTargets(ctx, q, tk, RotationTargetsParams{
					RotationTargets: sql.NullString{
						String: `[{"type":"webhook","webhook_url":"https://attacker.example/collect"}]`,
						Valid:  true,
					},
					ID: testEntryID,
				})
			},
		},
		{
			name:     "CreateEntry",
			funcName: "CreateEntry",
			field:    FieldProvider,
			column:   "provider",
			fn: func(ctx context.Context, q *db.Queries, tk egressgate.Ticket) error {
				return CreateEntry(ctx, q, tk, CreateEntryParams{
					ID:             testEntryID,
					UserID:         "u1",
					Name:           "planted",
					EncryptedValue: []byte("x"),
					Nonce:          []byte("n"),
					Provider:       sql.NullString{String: "datadog", Valid: true},
					ProviderMeta:   sql.NullString{String: `{"site":"evil.example"}`, Valid: true},
				})
			},
		},
	}
}

func newTestQueries(t *testing.T) (*db.Queries, *sql.DB) {
	t.Helper()
	conn, err := database.Connect(t.TempDir())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := database.RunMigrations(conn); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	// secret_owner_user_id is seeded alongside user_id because that is what every
	// row-creating statement in the product does
	// (TestEveryRowCreatingStatementNamesTheSecretOwner). A fixture that left it
	// empty would model a row the product cannot produce.
	if _, err := conn.Exec(
		`INSERT INTO vault_entries (id, user_id, secret_owner_user_id, name, encrypted_value, nonce,
		   provider, provider_meta, rotation_targets, destination_patterns, injection_spec)
		 VALUES (?, 'u1', 'u1', 'seed', x'00', x'00', 'openai', '{}', '[]', '[]', '{}')`, testEntryID); err != nil {
		t.Fatalf("seed entry: %v", err)
	}
	return db.New(conn), conn
}

func readColumn(t *testing.T, conn *sql.DB, column string) string {
	t.Helper()
	// The column name is one of a fixed set defined in this file, never input.
	var v sql.NullString
	if err := conn.QueryRow(
		`SELECT CASE ?
		   WHEN 'destination_patterns' THEN destination_patterns
		   WHEN 'provider'             THEN provider
		   WHEN 'provider_meta'        THEN provider_meta
		   WHEN 'rotation_targets'     THEN rotation_targets
		 END FROM vault_entries WHERE id = ?`, column, testEntryID).Scan(&v); err != nil {
		t.Fatalf("read %s: %v", column, err)
	}
	return v.String
}

func TestEveryWriteRefusesATicketThatDoesNotAuthorizeIt(t *testing.T) {
	ctx := context.Background()

	for _, tc := range writeCases() {
		t.Run(tc.name, func(t *testing.T) {
			tickets := map[string]egressgate.Ticket{
				"the zero ticket (nobody ever asked)": {},
				"a ticket for a different entry":      mustTicket(t, otherEntryID, tc.field),
				"a ticket for a different field":      mustTicket(t, testEntryID, "some_other_column"),
			}
			for label, tk := range tickets {
				q, conn := newTestQueries(t)
				before := readColumn(t, conn, tc.column)

				err := tc.fn(ctx, q, tk)
				if err == nil {
					t.Fatalf("%s performed the write with %s.\n"+
						"The wrapper takes a Ticket and does not look at it, which satisfies every "+
						"structural check in the tree and defeats all of them: the compiler forces the "+
						"argument, not the decision.", tc.name, label)
				}
				if after := readColumn(t, conn, tc.column); after != before {
					t.Fatalf("%s refused with %s but vault_entries.%s changed from %q to %q.\n"+
						"A wrapper that writes and then complains has already moved the secret.",
						tc.name, label, tc.column, before, after)
				}
			}
		})
	}
}

// TestTheRightTicketStillWorks is the positive control. A chokepoint that
// refuses everything is not a chokepoint, it is an outage.
func TestTheRightTicketStillWorks(t *testing.T) {
	ctx := context.Background()
	for _, tc := range writeCases() {
		t.Run(tc.name, func(t *testing.T) {
			q, conn := newTestQueries(t)
			before := ""
			if tc.funcName == "CreateEntry" {
				// The seeded row already holds testEntryID; an INSERT of the
				// same id is a primary-key conflict rather than an authority
				// question, so this one starts from no row at all.
				if _, err := conn.Exec(`DELETE FROM vault_entries WHERE id = ?`, testEntryID); err != nil {
					t.Fatalf("clear seed: %v", err)
				}
			} else {
				before = readColumn(t, conn, tc.column)
			}
			if err := tc.fn(ctx, q, mustTicket(t, testEntryID, tc.field)); err != nil {
				t.Fatalf("%s refused a ticket that names the right entry and the right field: %v",
					tc.name, err)
			}
			if after := readColumn(t, conn, tc.column); after == before {
				t.Fatalf("%s reported success and vault_entries.%s is unchanged (%q); this positive "+
					"control is not proving that the write happens", tc.name, tc.column, after)
			}
		})
	}
}

func mustTicket(t *testing.T, entryID, field string) egressgate.Ticket {
	t.Helper()
	tk, err := egressgate.Decide(egressgate.Request{
		EntryID:     entryID,
		What:        field,
		After:       []string{"a-destination"},
		MayRedirect: func() bool { return true },
	})
	if err != nil {
		t.Fatalf("mint ticket: %v", err)
	}
	return tk
}

// TestEveryExportedWriteIsCoveredHere keeps the list above complete.
//
// A new wrapper added to this package without a case here would be a write path
// nothing has ever exercised with a bad ticket, which is exactly the state
// rotation_targets was in for five rounds.
func TestEveryExportedWriteIsCoveredHere(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	pkg, ok := pkgs["vaultegress"]
	if !ok {
		t.Fatal("ABORT: package vaultegress not found; this guard is checking nothing")
	}

	var writers []string
	for path, f := range pkg.Files {
		_ = path
		for _, decl := range f.Decls {
			fn, isFn := decl.(*ast.FuncDecl)
			if !isFn || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			touchesWriter := false
			ast.Inspect(fn, func(n ast.Node) bool {
				if id, isID := n.(*ast.Ident); isID && id.Name == "writer" {
					touchesWriter = true
				}
				return true
			})
			if touchesWriter {
				writers = append(writers, fn.Name.Name)
			}
		}
	}
	sort.Strings(writers)

	var covered []string
	for _, tc := range writeCases() {
		covered = append(covered, tc.funcName)
	}
	// The writes that take a TransferProof rather than an egressgate.Ticket
	// cannot be driven by writeCases, whose fn signature is ticket-shaped. They
	// are covered by their own named tests, and the name is checked below
	// against the AST so a claim of coverage cannot outlive the test making it.
	proofWrites := map[string]string{
		"TransferSecretOwnership": "TestTransferSecretOwnershipRefusesAProofThatDoesNotAuthorise",
	}
	testFuncs := map[string]bool{}
	testPkgs, terr := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if terr != nil {
		t.Fatalf("parse tests: %v", terr)
	}
	for _, p := range testPkgs {
		for _, f := range p.Files {
			for _, decl := range f.Decls {
				if fn, isFn := decl.(*ast.FuncDecl); isFn {
					testFuncs[fn.Name.Name] = true
				}
			}
		}
	}
	for write, byTest := range proofWrites {
		if !testFuncs[byTest] {
			t.Fatalf("%s is claimed to be covered by %s, and no such test exists in this package. A "+
				"coverage claim that outlives its test reads as coverage and is not.", write, byTest)
		}
		covered = append(covered, write)
	}
	sort.Strings(covered)

	if strings.Join(writers, ",") != strings.Join(covered, ",") {
		t.Fatalf("the exported writes and the cases exercised above do not match.\n"+
			"  in the package: %v\n  covered here:   %v\n"+
			"Every function that can move a secret's destination has to be exercised with a ticket that "+
			"does not authorize it, or the compiler is forcing an argument nobody checks.",
			writers, covered)
	}
	if len(writers) < 6 {
		t.Fatalf("ABORT: only %d exported writes found (%v); the AST walk is not reading this package",
			len(writers), writers)
	}
	t.Logf("%d exported writes, all covered: %v", len(writers), writers)
	_ = filepath.Separator
}

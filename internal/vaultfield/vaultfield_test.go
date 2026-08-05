package vaultfield

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// This package had no tests at all, which is worth stating plainly: it is the
// AEAD wrapper every encrypted column in the product goes through, and its only
// coverage was the ledger-derivation guard in internal/handlers, which checks
// that columns are DECLARED, not that sealing and opening actually work.
//
// The two declarations below follow the shape columncrypto_test.go established.
// They are package-level with inline literal arguments on purpose: declscan
// derives the module's ledger FROM THE SOURCE and folds only what the compiler
// would fold, so a reason passed as a const identifier is returned Unparsed and
// aborts every guard that reads the scan. A declaration a guard cannot read is
// one it cannot check. Deliberately-invalid declarations are not tested here for
// the same reason: each Declare call site becomes a static ledger entry whether
// or not it panics at runtime, and a malformed one would be noise every
// module-wide guard has to tolerate. Declare's own refusals are already enforced
// across every production declaration by TestEveryDeclaredFieldIsARuling.

var testField = Declare(
	"vaultfield_test.roundtrip", InProcessOnly, "",
	"a declaration used only by this package's own seal and open tests. It opens no real column "+
		"and exists because every decrypt entry point refuses the zero Field.")

var otherTestField = Declare(
	"vaultfield_test.othercolumn", InProcessOnly, "",
	"a second test-only declaration, used to show that a ciphertext sealed for one column opens "+
		"under a different column's Field because the field is not AEAD additional data.")

func testKey(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey(0x11)
	plain := []byte("hunter2, but longer than a block so more than one path is exercised")

	ct, nonce, err := Seal(key, plain, rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("the ciphertext contains the plaintext verbatim")
	}
	got, err := Open(key, ct, nonce, testField)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip returned %q, want %q", got, plain)
	}
}

func TestSealIsNondeterministic(t *testing.T) {
	key := testKey(0x22)
	plain := []byte("same plaintext twice")
	a, na, err := Seal(key, plain, rand.Reader)
	if err != nil {
		t.Fatalf("seal a: %v", err)
	}
	b, nb, err := Seal(key, plain, rand.Reader)
	if err != nil {
		t.Fatalf("seal b: %v", err)
	}
	if bytes.Equal(na, nb) {
		t.Fatal("two seals reused a nonce, which destroys AES-GCM confidentiality and integrity")
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext produced identical ciphertext, so equality leaks")
	}
}

func TestWrongKeyDoesNotOpen(t *testing.T) {
	ct, nonce, err := Seal(testKey(0x33), []byte("secret"), rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(testKey(0x44), ct, nonce, testField); err == nil {
		t.Fatal("a ciphertext opened under the wrong key; this is the claim the whole backup " +
			"story rests on (THREAT-MODEL: lose the key, lose everything)")
	}
}

func TestTamperedCiphertextIsRefused(t *testing.T) {
	key := testKey(0x55)
	ct, nonce, err := Seal(key, []byte("transfer 100 to alice"), rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for i := range ct {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if _, err := Open(key, bad, nonce, testField); err == nil {
			t.Fatalf("a ciphertext with byte %d flipped still opened; GCM authentication is not "+
				"being enforced", i)
		}
	}
}

// TestTheZeroFieldNeverDecrypts pins the package's central refusal, at all four
// entry points that take a Field.
func TestTheZeroFieldNeverDecrypts(t *testing.T) {
	key := testKey(0x66)
	plain := []byte("value")

	ct, nonce, err := Seal(key, plain, rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(key, ct, nonce, Field{}); !errors.Is(err, ErrUndeclared) {
		t.Fatalf("Open with the zero Field returned %v, want ErrUndeclared", err)
	}
	if Opens(key, ct, nonce, Field{}) {
		t.Fatal("Opens reported true for the zero Field")
	}

	packed, err := SealPacked(key, plain, rand.Reader)
	if err != nil {
		t.Fatalf("seal packed: %v", err)
	}
	if _, err := OpenPacked(key, packed, Field{}); !errors.Is(err, ErrUndeclared) {
		t.Fatal("OpenPacked with the zero Field did not return ErrUndeclared")
	}
	if got, err := OpenPacked(key, packed, testField); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("packed round trip failed: %q %v", got, err)
	}

	col, err := SealColumn(key, "value")
	if err != nil {
		t.Fatalf("seal column: %v", err)
	}
	if !IsSealedColumn(col) {
		t.Fatalf("SealColumn produced %q, which IsSealedColumn does not recognise", col)
	}
	if _, err := OpenColumn(key, col, Field{}); !errors.Is(err, ErrUndeclared) {
		t.Fatal("OpenColumn with the zero Field did not return ErrUndeclared")
	}
	if got, err := OpenColumn(key, col, testField); err != nil || got != "value" {
		t.Fatalf("column round trip failed: %q %v", got, err)
	}
	if !ColumnOpens(key, col, testField) {
		t.Fatal("ColumnOpens said no to a column it had just sealed")
	}

	// And the declared field must still work, or the refusal is just breakage.
	if _, err := Open(key, ct, nonce, testField); err != nil {
		t.Fatalf("a declared Field could not open its own ciphertext: %v", err)
	}
}

// TestFieldIsADeclarationNotAADIsAKnownProperty makes an important fact
// EXECUTABLE instead of leaving it as prose that rots.
//
// vaultfield passes nil as the AEAD's additional authenticated data at every
// Seal and Open site, so the Field a caller supplies never enters the
// ciphertext. A value sealed for one column therefore opens cleanly under a
// DIFFERENT column's Field. That is the documented and accepted behaviour
// (THREAT-MODEL, "What the column encryption specifically does NOT bind"): the
// Field is a declaration the encrypted-field ledger derives coverage from, not a
// cryptographic binding. A code comment claimed the opposite until 2026-08-05.
//
// This asserts the CURRENT behaviour rather than the desirable one, on purpose.
// If someone wires the field name in as AAD, this test fails, and the failure
// message is where they are told the threat model has a paragraph to update and
// that every already-sealed column needs migrating. Silently gaining the
// property would leave the document wrong in the other direction.
func TestFieldIsADeclarationNotAADIsAKnownProperty(t *testing.T) {
	key := testKey(0x77)
	plain := []byte("a value that belongs to exactly one column")

	ct, nonce, err := Seal(key, plain, rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(key, ct, nonce, testField); err != nil {
		t.Fatalf("ABORT: the origin field could not open its own ciphertext: %v", err)
	}

	got, err := Open(key, ct, nonce, otherTestField)
	if err != nil {
		t.Fatalf("a ciphertext no longer opens under a different column's Field (%v).\n"+
			"That is an IMPROVEMENT, not a regression, but it changes a documented property:\n"+
			"  1. update THREAT-MODEL.md, the section on what the column encryption does NOT bind\n"+
			"  2. every column already sealed with nil AAD needs a re-seal sweep, or it stops opening\n"+
			"  3. delete this test and replace it with one asserting the binding\n"+
			"Do not simply relax this assertion.", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("cross-field open returned %q, want %q", got, plain)
	}
}

// TestLedgerAndLookupSeeDeclarations pins that a declaration is actually
// recorded, which is what every coverage guard in the module reads.
func TestLedgerAndLookupSeeDeclarations(t *testing.T) {
	e, ok := Lookup("vaultfield_test.roundtrip")
	if !ok {
		t.Fatal("a declared column is not in the ledger, so the coverage guards cannot see it")
	}
	if e.Class != InProcessOnly {
		t.Fatalf("ledger recorded class %v, want InProcessOnly", e.Class)
	}
	if testField.Name() != "vaultfield_test.roundtrip" || testField.IsZero() {
		t.Fatalf("Field accessors disagree with the declaration: name=%q zero=%v",
			testField.Name(), testField.IsZero())
	}
	if strings.TrimSpace(testField.Why()) == "" {
		t.Fatal("the declared reason did not survive into the Field")
	}
	if testField.Class() != InProcessOnly || testField.ExitKey() != "" {
		t.Fatalf("class/exitKey = %v/%q, want InProcessOnly and empty",
			testField.Class(), testField.ExitKey())
	}
	if !(Field{}).IsZero() {
		t.Fatal("the zero Field does not report itself as zero")
	}

	var found int
	for _, entry := range Ledger() {
		if entry.Name == "vaultfield_test.roundtrip" || entry.Name == "vaultfield_test.othercolumn" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("Ledger() lists %d of the 2 test columns Lookup finds; the two disagree", found)
	}
}

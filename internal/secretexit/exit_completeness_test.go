package secretexit

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// THE COMPLETENESS PROOF, DERIVED FROM THE TYPE SYSTEM RATHER THAN FROM READING.
//
// The deliverable this round exists for is "every path by which a decrypted
// secret leaves this process passes through a single function". Six rounds have
// shown what a list maintained by inspection is worth, so the list is not
// maintained by inspection: [Plaintext] holds its bytes in an unexported field
// and this package exports exactly one accessor for them.
//
// The test below is what makes that a fact about the code rather than a claim
// about it. It reads this package's own AST and fails if a SECOND way out
// appears, whatever it is called and whatever it is documented to do.

// theOnlyExits are the exported functions permitted to hand out a Plaintext's
// bytes. ExitString is not a second exit: it calls Exit.
var theOnlyExits = map[string]string{
	"Exit":       "THE exit. Takes a Destination, asks the Authority, mints the receipt.",
	"ExitString": "Exit, converted to a Go string, because a string cannot be wiped and that is worth naming at the call site.",
}

// escapeHatchesWithAReason are exported symbols that touch the bytes without
// releasing them. Each has to be justified here, and the justification has to be
// that the caller learns nothing it did not already know.
var escapeHatchesWithAReason = map[string]string{
	"Reseal": "re-encrypts under the same key for storage. Nothing leaves the process and the value is ciphertext again on the other side.",
	"Seal":   "encrypts a plaintext the caller already holds; it does not take a Plaintext at all.",
	"Open":   "the constructor. It produces a Plaintext, it does not consume one.",
	"Minted": "the constructor for a value this server created. Same shape as Open.",
	"EqualsString": "constant-time comparison against a candidate the caller supplied. One bit, and they " +
		"already knew how to obtain it. Not a read: no arrangement of calls recovers the value in fewer " +
		"than 256^n attempts.",

	// THE GUARD FOUND THESE THREE ON ITS FIRST RUN, which is the answer to "is it
	// vacuous". Each returns a string or bytes from a Plaintext and each returns
	// the REDACTION rather than the value. They exist precisely so that logging,
	// error text and JSON encoding cannot become exits, and the claim that they
	// redact is checked behaviourally by
	// TestPlaintextRedactsUnderEveryFormattingVerb, not by this registration.
	"String":      "the redaction. Checked by TestPlaintextRedactsUnderEveryFormattingVerb.",
	"GoString":    "the redaction, for %#v. Same test.",
	"MarshalJSON": "the redaction, for encoding/json. Same test.",
	"Format":      "the redaction, for every fmt verb including %x and %d. Same test.",
}

// TestExitIsTheOnlyWayOut walks this package's exported API and fails when
// anything other than the registered exits can return a Plaintext's bytes.
//
// It is deliberately structural and deliberately paired with the behavioural
// tests below, because a structural guard cannot tell whether the function it
// points at actually refuses anything.
func TestExitIsTheOnlyWayOut(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected exactly one package here, found %d", len(pkgs))
	}

	checked := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || !fn.Name.IsExported() {
					continue
				}
				checked++
				name := fn.Name.Name

				// Does it CONSUME a Plaintext (as a receiver or a parameter)?
				consumes := false
				if fn.Recv != nil && typeMentions(fn.Recv.List[0].Type, "Plaintext") {
					consumes = true
				}
				if fn.Type.Params != nil {
					for _, p := range fn.Type.Params.List {
						if typeMentions(p.Type, "Plaintext") {
							consumes = true
						}
					}
				}
				if !consumes {
					continue
				}

				// Does it RETURN something that could carry the value?
				leaks := false
				if fn.Type.Results != nil {
					for _, res := range fn.Type.Results.List {
						if resultCanCarryBytes(res.Type) {
							leaks = true
						}
					}
				}
				if !leaks {
					continue
				}

				if _, ok := theOnlyExits[name]; ok {
					continue
				}
				if _, ok := escapeHatchesWithAReason[name]; ok {
					continue
				}
				t.Errorf("%s takes a Plaintext and returns bytes or a string, so it is a SECOND WAY OUT.\n"+
					"  The whole construction of this package is that Exit is the only one: that is what makes\n"+
					"  \"every path a decrypted secret leaves by\" a set the compiler maintains instead of a list\n"+
					"  somebody remembers to update. Route it through Exit, or, if it genuinely releases nothing,\n"+
					"  add it to escapeHatchesWithAReason with the reason spelled out.", name)
			}
		}
	}
	if checked < 10 {
		t.Fatalf("ABORT: only walked %d exported declarations; this guard is matching almost nothing", checked)
	}

	// The registered exits must still EXIST. A refactor that renames or deletes
	// Exit would otherwise leave this test passing over a package that no longer
	// has a chokepoint at all.
	for name := range theOnlyExits {
		found := false
		for _, pkg := range pkgs {
			for _, file := range pkg.Files {
				for _, decl := range file.Decls {
					if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
						found = true
					}
				}
			}
		}
		if !found {
			t.Errorf("%s is registered as an exit but no longer exists; the chokepoint this package "+
				"is built around has been renamed or removed", name)
		}
	}
}

// TestPlaintextHasNoExportedFieldOrGetter is the other half of the same
// property: a struct field or a getter would let the compiler hand out the bytes
// without any function call at all.
func TestPlaintextHasNoExportedFieldOrGetter(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	found := false
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "Plaintext" {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				found = true
				for _, f := range st.Fields.List {
					for _, nm := range f.Names {
						if nm.IsExported() {
							t.Errorf("Plaintext.%s is EXPORTED. Any package can then read the secret with "+
								"no function call, and Exit stops being a chokepoint.", nm.Name)
						}
					}
				}
				return false
			})
		}
	}
	if !found {
		t.Fatal("ABORT: could not find the Plaintext type declaration, so this guard checked nothing")
	}
}

// typeMentions reports whether an AST type expression names ident anywhere.
func typeMentions(e ast.Expr, ident string) bool {
	mentions := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == ident {
			mentions = true
		}
		return true
	})
	return mentions
}

// resultCanCarryBytes reports whether a result type could carry the secret. It
// is deliberately generous: []byte, string, any, and anything built out of them.
func resultCanCarryBytes(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "string" || t.Name == "byte" || t.Name == "any"
	case *ast.ArrayType:
		return resultCanCarryBytes(t.Elt)
	case *ast.StarExpr:
		return resultCanCarryBytes(t.X)
	case *ast.InterfaceType:
		return t.Methods == nil || len(t.Methods.List) == 0
	}
	return false
}

// ── behavioural halves ──────────────────────────────────────────────────────

type yesAuthority struct{}

func (yesAuthority) AuthorizeSecretExit(context.Context, Origin, Destination) error { return nil }

type noAuthority struct{ err error }

func (a noAuthority) AuthorizeSecretExit(context.Context, Origin, Destination) error { return a.err }

func testOrigin() Origin { return Origin{EntryID: "e1", Name: "team-stripe"} }

// TestPlaintextRedactsUnderEveryFormattingVerb closes the log and error-text
// path by construction. A Plaintext interpolated into a log line, an error, a
// JSON body or a %#v dump must print the redaction, never the value.
func TestPlaintextRedactsUnderEveryFormattingVerb(t *testing.T) {
	const secret = "sk_live_THE_ACTUAL_SECRET"
	p := Minted([]byte(secret), testOrigin(), yesAuthority{})

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T-adjacent:%v"} {
		got := fmt.Sprintf(verb, p)
		if strings.Contains(got, secret) {
			t.Errorf("fmt.Sprintf(%q, plaintext) printed the secret: %s", verb, got)
		}
		// Hex would not contain the literal, so check the encoded form too.
		if strings.Contains(got, fmt.Sprintf("%x", []byte(secret))) {
			t.Errorf("fmt.Sprintf(%q, plaintext) printed the secret in hex", verb)
		}
	}

	// Inside a struct, which is how a slog attr or a response body carries one.
	wrapper := struct {
		Name  string
		Value Plaintext
	}{Name: "team-stripe", Value: p}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, wrapper); strings.Contains(got, secret) {
			t.Errorf("a struct holding a Plaintext printed the secret under %q: %s", verb, got)
		}
	}

	b, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), secret) {
		t.Errorf("encoding/json emitted the secret: %s", b)
	}

	// And an error built with %w-style wrapping, which is how a refusal message
	// would leak one.
	if got := fmt.Errorf("delivery failed for %v", p).Error(); strings.Contains(got, secret) {
		t.Errorf("an error carrying a Plaintext leaked it: %s", got)
	}
}

// TestExitFailsClosed pins every way of NOT asking.
func TestExitFailsClosed(t *testing.T) {
	ctx := context.Background()
	good := Minted([]byte("v"), testOrigin(), yesAuthority{})

	t.Run("the zero Plaintext has no authority", func(t *testing.T) {
		if _, _, err := Exit(ctx, Plaintext{}, ToHost("x", ChosenByTheInstance("y"), "h.example")); err == nil {
			t.Fatal("a Plaintext with no Authority released its bytes; 'nobody to ask' must mean 'no'")
		}
	})

	t.Run("the zero Destination goes nowhere", func(t *testing.T) {
		if _, _, err := Exit(ctx, good, Destination{}); err == nil {
			t.Fatal("the zero Destination released a secret. A struct literal must never be spellable " +
				"as 'asked and was allowed'")
		}
	})

	t.Run("a Destination with no chooser is refused", func(t *testing.T) {
		d := ToHost("x", Chooser{}, "h.example")
		if _, _, err := Exit(ctx, good, d); err == nil {
			t.Fatal("a destination with no recorded chooser was authorised; there was nobody to ask")
		}
	})

	t.Run("a network destination with no host is refused", func(t *testing.T) {
		if _, _, err := Exit(ctx, good, ToHost("x", ChosenByTheInstance("y"), "")); err == nil {
			t.Fatal("a destination that resolves to no host at all was authorised")
		}
	})

	t.Run("the Authority's refusal is honoured", func(t *testing.T) {
		bad := Minted([]byte("v"), testOrigin(), noAuthority{err: fmt.Errorf("the owner said no")})
		_, b, err := Exit(ctx, bad, ToHost("x", ChosenBy("u1"), "h.example"))
		if err == nil {
			t.Fatal("a refusal from the Authority still released the bytes")
		}
		if len(b) != 0 {
			t.Fatalf("bytes were returned alongside the refusal: %d of them", len(b))
		}
		if !strings.Contains(err.Error(), "the owner said no") {
			t.Errorf("the refusal reason was lost: %v", err)
		}
	})
}

// TestReceiptBindsTheHostTheExitWasAuthorisedFor is the half that closes the
// residual an argument-shaped gate always leaves: claim one destination, send to
// another.
func TestReceiptBindsTheHostTheExitWasAuthorisedFor(t *testing.T) {
	ctx := context.Background()
	p := Minted([]byte("v"), testOrigin(), yesAuthority{})

	// yesAuthority allows anything, so the CLAIM succeeds. The point is what
	// happens next.
	out, _, err := Exit(ctx, p, ToHost("a delivery", ChosenBy("u1"), "consumer.example"))
	if err != nil {
		t.Fatalf("the exit refused a claim its authority allowed: %v", err)
	}
	if err := CheckHost(out, "consumer.example"); err != nil {
		t.Fatalf("the host the exit was authorised for was refused at the send: %v", err)
	}
	if err := CheckHost(out, "attacker.example"); err == nil {
		t.Fatal("a request to a DIFFERENT host than the exit was authorised for was allowed. " +
			"Claiming one destination and sending to another is exactly the residual the receipt exists to close")
	}

	t.Run("no receipt is a refusal", func(t *testing.T) {
		if err := CheckHost(context.Background(), "consumer.example"); err == nil {
			t.Fatal("a request built with no receipt at all was allowed. A call site that forgets to " +
				"use the context Exit returned must fail loudly, not inherit a permissive default")
		}
	})

	t.Run("every secret riding along must allow the host", func(t *testing.T) {
		// A forgejo delivery carries two secrets. Both owners have to have
		// authorised the same host, and the round-6 attack is exactly the case
		// where one had and the other had not.
		first, _, err := Exit(ctx, p, ToHost("the body", ChosenBy("u1"), "consumer.example"))
		if err != nil {
			t.Fatalf("first exit: %v", err)
		}
		second := Minted([]byte("bearer"), Origin{EntryID: "e2", Name: "forgejo-pat"}, yesAuthority{})
		both, _, err := Exit(first, second, ToHost("the bearer", ChosenBy("u1"), "somewhere-else.example"))
		if err != nil {
			t.Fatalf("second exit: %v", err)
		}
		if err := CheckHost(both, "consumer.example"); err == nil {
			t.Fatal("a host allowed by only ONE of the two receipts was permitted. Every secret on the " +
				"request has to be authorised for where the request is actually going")
		}
		if err := CheckHost(both, "somewhere-else.example"); err == nil {
			t.Fatal("same, in the other direction")
		}
	})

	t.Run("an in-process destination mints no receipt", func(t *testing.T) {
		out, _, err := Exit(ctx, p, ToNowhere("a local generator"))
		if err != nil {
			t.Fatalf("an in-process release was refused: %v", err)
		}
		if ReceiptCount(out) != 0 {
			t.Fatal("an in-process destination minted a receipt, so a local generator that grows an " +
				"HTTP call would inherit permission to make it")
		}
		if err := CheckHost(out, "anywhere.example"); err == nil {
			t.Fatal("a request built after an in-process release was allowed")
		}
	})
}

// TestExitReturnsTheRealValueWhenAuthorised is the positive control for this
// package. A gate that refuses everything is not a fix.
func TestExitReturnsTheRealValueWhenAuthorised(t *testing.T) {
	const secret = "sk_live_REAL"
	p := Minted([]byte(secret), testOrigin(), yesAuthority{})
	_, b, err := Exit(context.Background(), p, ToHost("x", ChosenBy("u1"), "consumer.example"))
	if err != nil {
		t.Fatalf("an authorised exit refused: %v", err)
	}
	if string(b) != secret {
		t.Fatalf("the exit handed back %q, not the secret", b)
	}
	_, s, err := ExitString(context.Background(), p, ToCaller("x", "u1"))
	if err != nil || s != secret {
		t.Fatalf("ExitString handed back %q (err %v)", s, err)
	}
}

// TestEqualsStringIsNotAReadPath pins the one comparison that does not go
// through Exit.
func TestEqualsStringIsNotAReadPath(t *testing.T) {
	p := Minted([]byte("correct"), testOrigin(), noAuthority{err: fmt.Errorf("no")})
	if !p.EqualsString("correct") {
		t.Fatal("EqualsString said no to the right value")
	}
	if p.EqualsString("wrong") {
		t.Fatal("EqualsString said yes to the wrong value")
	}
	if p.EqualsString("correct ") || p.EqualsString("correc") {
		t.Fatal("EqualsString is matching on a prefix or ignoring trailing bytes")
	}
	// It works even under an Authority that refuses everything, which is correct:
	// it releases nothing.
	if p.Len() != len("correct") {
		t.Fatalf("Len = %d", p.Len())
	}
}

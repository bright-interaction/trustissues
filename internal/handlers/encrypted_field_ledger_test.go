package handlers

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// THE GUARD THAT STOPPED ENUMERATING DOORS.
//
// # What the previous version did, and why it was wrong
//
// Round 18's TestEveryEncryptedFieldIsClassified derived the ledger from the
// module's AST by matching FOUR CALL SHAPES: decryptColumnOrLog /
// decryptCustomFields, OpenEntrySecret, DecryptInstanceConfig, and
// columncrypto.DecryptString. Deriving beat the prose paragraph it replaced, and
// it was still the same error one level up, because a door is not a name.
//
// VaultHandler.decryptColumn was the RAW primitive and decryptColumnOrLog was
// its logging wrapper. UserHandler.openInviteCode called the raw one, on
// invitations.code, a vault-key-encrypted bearer credential that redeems into an
// account and, at target_role admin, into an account that can reset a
// colleague's password and unlock their vault. It matched none of the four
// shapes. The ledger reported coverage over a column nothing had classified, and
// the guard was green the whole time.
//
// Two further doors were in the same position and nobody had noticed either:
// vaultColumnOpens and vaultSecretOpens in vault_keycheck.go, both doing their
// own AES-GCM on stored ciphertext at boot.
//
// # What replaces it
//
// The knowledge now comes from the place plaintext is PRODUCED.
//
//   - internal/vaultfield is the only file in the module that imports crypto/aes
//     or crypto/cipher (TestAESGCMIsOpenedInExactlyOneFile). That is complete
//     rather than broad: opening AES-GCM data REQUIRES those packages, so the
//     importer set is the reader set. A wrapper-name set is open-ended; this one
//     is closed by the language.
//   - every open there demands a vaultfield.Field, whose only constructor is
//     vaultfield.Declare.
//   - Declare writes the ledger.
//
// So the tests below no longer ask "did somebody remember to classify this".
// They ask the questions that are still open once the ledger cannot have holes:
// is every declaration a real ruling, does every through-the-exit field name a
// real exit, is any declaration describing dead code, and is the classification's
// PREMISE (admin-only routes, for the instance-owned class) still true.

// ── the ablation this construction has to survive ───────────────────────────
//
// THE SIXTH DOOR. Add a new wrapper, with a new name, opening a new encrypted
// column, and touch no ledger:
//
//	func (h *UserHandler) unsealRecoveryBlob(stored string) string {
//	        packed, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, "enc:v1:"))
//	        block, _ := aes.NewCipher(h.vault.encryptionKey[:])
//	        gcm, _ := cipher.NewGCM(block)
//	        pt, _ := gcm.Open(nil, packed[:gcm.NonceSize()], packed[gcm.NonceSize():], nil)
//	        return string(pt)
//	}
//
// Under the round-18 guard that COMPILES and every test stays green: it matches
// none of the four call shapes. Under this one the build still succeeds and
// TestAESGCMIsOpenedInExactlyOneFile reddens, naming the file and the import.
//
// The other two shapes a sixth door can take are closed by construction rather
// than by a test: calling vaultfield with no Field does not compile past the
// signature, and calling it with vaultfield.Field{} is refused at the first call
// (TestTheZeroFieldDecryptsNothing).

// aesImports are the two packages you cannot open AES-GCM ciphertext without.
// crypto/aes gives the block cipher, crypto/cipher gives the AEAD. There is no
// third way to read what this product has already written to disk, which is what
// makes pinning their importers a COMPLETE statement rather than a broad one.
var aesImports = map[string]bool{
	"crypto/aes":    true,
	"crypto/cipher": true,
}

// theCryptoFiles are the files allowed to import them, each with the reason.
//
// This is an enumeration, and that is the point: it enumerates the PRIMITIVE,
// which the Go standard library closes, instead of the wrappers, which nobody
// closes. Two entries, and one of them is a different key family.
var theCryptoFiles = map[string]string{
	"internal/vaultfield/vaultfield.go": "THE door. Every vault-key-encrypted value in this product " +
		"becomes plaintext here, and every entry point demands a declared Field, which is what writes " +
		"the ledger.",
	"internal/shield/crypto.go": "a different key family entirely: the Shield PII tokenizer seals its " +
		"own session vocabulary under cfg.ShieldKey, never the vault key, and what it holds is tokenized " +
		"personal data rather than a stored credential. It is out of the vault-key ledger's scope, and " +
		"TestShieldDoesNotTouchTheVaultKey keeps that true.",
}

// TestAESGCMIsOpenedInExactlyOneFile is THE guard this round exists to add.
//
// It is what the sixth-door ablation reddens. Every previous version of this
// boundary asked "which functions look like decryption"; this one asks "which
// files can do the arithmetic at all", and the answer is fixed by the language
// rather than by a naming convention.
func TestAESGCMIsOpenedInExactlyOneFile(t *testing.T) {
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)
	if len(parsed) < 30 {
		t.Fatalf("ABORT: parsed only %d module files; this guard is not reading the source", len(parsed))
	}

	found := map[string][]string{}
	for path, f := range parsed {
		rel := moduleRelative(path)
		for _, spec := range f.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquote import %s: %v", rel, spec.Path.Value, err)
			}
			if aesImports[p] {
				found[rel] = append(found[rel], p)
			}
		}
	}

	// The positive control. If the walk stops finding the one file that is
	// SUPPOSED to do the crypto, this guard would pass over a module where
	// everything had moved, so refuse to be green about nothing.
	if _, ok := found["internal/vaultfield/vaultfield.go"]; !ok {
		t.Fatalf("ABORT: internal/vaultfield/vaultfield.go does not import crypto/aes or crypto/cipher. "+
			"That file is where every vault-key decryption is supposed to happen, so either the walk is "+
			"broken or the door moved without this guard being told. Files seen importing them: %v",
			sortedKeys(found))
	}

	for _, rel := range sortedKeys(found) {
		if _, allowed := theCryptoFiles[rel]; allowed {
			continue
		}
		sort.Strings(found[rel])
		t.Errorf("A SIXTH DECRYPTION DOOR: %s imports %s.\n"+
			"  Opening AES-GCM ciphertext requires crypto/aes and crypto/cipher, so importing them is\n"+
			"  the one thing a new decryption path cannot avoid. That is why this guard pins the\n"+
			"  IMPORTERS and not the function names: round 18 pinned four call shapes and a fifth door\n"+
			"  (UserHandler.openInviteCode, on the vault-key-encrypted invitations.code column) had\n"+
			"  already walked past it.\n"+
			"  Route the decryption through internal/vaultfield. Its entry points demand a\n"+
			"  vaultfield.Field, and declaring one is what puts the column in the ledger with a\n"+
			"  classification and a reason. If this file genuinely belongs to a different key family,\n"+
			"  add it to theCryptoFiles WITH the argument, the way internal/shield is.",
			rel, strings.Join(found[rel], " and "))
	}

	for rel := range theCryptoFiles {
		if _, ok := found[rel]; !ok {
			t.Errorf("A STALE CRYPTO EXEMPTION: theCryptoFiles allows %s to import crypto/aes or "+
				"crypto/cipher and it imports neither.\n  An exemption for code that no longer does the "+
				"thing reads as a boundary and is not one. Remove it.", rel)
		}
	}
	t.Logf("%d files import the AES primitives, all declared", len(found))
}

// TestShieldDoesNotTouchTheVaultKey holds up the one exemption above that is an
// argument rather than a definition.
//
// internal/shield is allowed its own AES because it is a different key family.
// That claim is only true while it stays away from the vault key, so it is
// checked rather than asserted.
func TestShieldDoesNotTouchTheVaultKey(t *testing.T) {
	files := moduleGoFiles(t)
	checked := 0
	for path, src := range files {
		rel := moduleRelative(path)
		if !strings.HasPrefix(rel, "internal/shield/") {
			continue
		}
		checked++
		for _, forbidden := range []string{"VaultKey", "encryptionKey", "legacyKey", "vaultfield."} {
			if strings.Contains(src, forbidden) {
				t.Errorf("%s mentions %q.\n"+
					"  internal/shield is exempt from the vault-key decryption ledger because it seals its\n"+
					"  own data under its own key. The moment it reaches for the vault key that exemption is\n"+
					"  false and its columns belong in the ledger like everything else.", rel, forbidden)
			}
		}
	}
	if checked < 3 {
		t.Fatalf("ABORT: only scanned %d files under internal/shield; this guard is checking nothing", checked)
	}
}

// TestTheZeroFieldDecryptsNothing closes the one bypass the type system leaves
// open: vaultfield.Field{} is a composite literal any package can write.
//
// It fails closed, at the first call, with a message that says what to do. A
// door written this way does not silently decrypt an unclassified column; it
// does not decrypt at all.
func TestTheZeroFieldDecryptsNothing(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	sealed, err := vaultfield.SealColumn(key, "a-real-secret-value")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Positive control: the same call with a DECLARED field works, so a failure
	// below is the Field check and not a broken fixture.
	if got, oErr := vaultfield.OpenColumn(key, sealed, vaultFieldNotes); oErr != nil || got != "a-real-secret-value" {
		t.Fatalf("positive control: OpenColumn with a declared field returned (%q, %v), want the plaintext",
			got, oErr)
	}

	if _, oErr := vaultfield.OpenColumn(key, sealed, vaultfield.Field{}); oErr == nil {
		t.Error("vaultfield.OpenColumn decrypted for the ZERO Field. That is a door with no ledger entry, " +
			"which is the whole defect this package exists to make impossible")
	}
	ct, nonce, sErr := vaultfield.Seal(key, []byte("another-secret"), zeroReader{})
	if sErr != nil {
		t.Fatalf("seal raw: %v", sErr)
	}
	if _, oErr := vaultfield.Open(key, ct, nonce, vaultfield.Field{}); oErr == nil {
		t.Error("vaultfield.Open decrypted for the ZERO Field")
	}
	if _, oErr := vaultfield.OpenPacked(key, append(nonce, ct...), vaultfield.Field{}); oErr == nil {
		t.Error("vaultfield.OpenPacked decrypted for the ZERO Field")
	}
	if vaultfield.Opens(key, ct, nonce, vaultfield.Field{}) {
		t.Error("vaultfield.Opens answered yes for the ZERO Field")
	}
	if vaultfield.ColumnOpens(key, sealed, vaultfield.Field{}) {
		t.Error("vaultfield.ColumnOpens answered yes for the ZERO Field")
	}
}

// zeroReader is a deterministic nonce source for the fixture above. It is not a
// security claim: the value it seals is thrown away one line later.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestEveryDeclaredFieldIsARuling is the ledger's own quality bar.
//
// vaultfield.Declare enforces most of it at init time (a panic on an unset
// class, a short reason, an exit claim with no key). This re-checks it from the
// outside so the bar is visible where the ledger is read, and adds the one cross
// check Declare cannot do because it does not know about theExitList.
func TestEveryDeclaredFieldIsARuling(t *testing.T) {
	entries := vaultfield.Ledger()
	// Ten was the round-18 floor and the set has grown since. A ledger that
	// suddenly holds two entries means the declarations stopped being linked
	// into this binary, and a guard over an empty set passes over anything.
	if len(entries) < 12 {
		t.Fatalf("ABORT: the ledger holds only %d fields (%v). At least twelve are known to be declared, "+
			"so the declarations are not reaching this binary and every check below is vacuous",
			len(entries), ledgerNames(entries))
	}

	throughTheExit := 0
	for _, e := range entries {
		if e.Class == vaultfield.Unclassified {
			t.Errorf("%s is declared without a classification (declared at %s)", e.Name, e.DeclaredAt)
		}
		if len(strings.TrimSpace(e.Why)) < 60 {
			t.Errorf("%s is declared without a reason worth reading. Say what the plaintext IS and why "+
				"that classification is the right one (declared at %s)", e.Name, e.DeclaredAt)
		}
		if e.Class != vaultfield.ThroughTheExit {
			if e.ExitKey != "" {
				t.Errorf("%s is not classified through-the-exit but names one (%q). One of the two is wrong",
					e.Name, e.ExitKey)
			}
			continue
		}
		throughTheExit++
		if e.ExitKey == "" {
			t.Errorf("%s is classified through-the-exit and names no exit", e.Name)
			continue
		}
		// "any" is the vault value itself: every registered exit governs it, so
		// naming one would be arbitrary.
		if e.ExitKey == "any" {
			continue
		}
		if _, ok := theExitList[e.ExitKey]; !ok {
			t.Errorf("%s says it leaves through %q and theExitList has no such entry.\n"+
				"  Either the exit was renamed and the declaration rotted, or the field is classified as "+
				"gated and is not.", e.Name, e.ExitKey)
		}
	}
	if throughTheExit < 2 {
		t.Fatalf("ABORT: only %d fields are classified through-the-exit; two are known to be "+
			"(encrypted_value and custom_fields), so this guard is checking almost nothing", throughTheExit)
	}
	t.Logf("%d declared fields, all ruled: %v", len(entries), ledgerNames(entries))
}

// TestTheLedgerIsDeclaredByProductionCode closes the way to satisfy the ledger
// without satisfying the product: declare a field from a _test.go file.
//
// A test-only declaration would let a guard read as covered while the production
// binary decrypts through a Field nobody shipped. Declaring from a test is
// allowed (internal/columncrypto does it for its own round trips), it just
// cannot appear in the ledger this package's guards read.
func TestTheLedgerIsDeclaredByProductionCode(t *testing.T) {
	for _, e := range vaultfield.Ledger() {
		site := e.DeclaredAt
		if i := strings.LastIndex(site, ":"); i >= 0 {
			site = site[:i]
		}
		if strings.HasSuffix(site, "_test.go") {
			t.Errorf("%s is declared from a TEST file (%s).\n"+
				"  A declaration in a test satisfies the ledger in the test binary and ships nothing. The\n"+
				"  field the production code decrypts with would then be unclassified in production, which\n"+
				"  is the exact hole this package removes.", e.Name, e.DeclaredAt)
		}
	}
}

// TestNoFieldIsDeclaredAndNeverOpened keeps the ledger from drifting into
// fiction in the other direction.
//
// The round-18 guard failed in BOTH directions, and that half is still worth
// keeping: a classification of something nothing decrypts reads as coverage and
// is not. The declaration set can no longer be short; this stops it being long.
func TestNoFieldIsDeclaredAndNeverOpened(t *testing.T) {
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)

	// Every identifier used anywhere in the module, by name. A field is "opened"
	// if its declaring identifier is mentioned somewhere other than its own
	// declaration, which is the same handle theExitList uses.
	uses := map[string]int{}
	declNames := map[string]string{} // identifier -> declared column name
	for path, f := range parsed {
		rel := moduleRelative(path)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					call, ok := vs.Values[i].(*ast.CallExpr)
					if !ok {
						continue
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Declare" {
						continue
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok || pkg.Name != "vaultfield" {
						continue
					}
					if len(call.Args) == 0 {
						continue
					}
					lit, ok := call.Args[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("%s declares a field with a non-literal name, so it cannot be checked. "+
							"Pass the column name literally.", rel)
						continue
					}
					column, uErr := strconv.Unquote(lit.Value)
					if uErr != nil {
						t.Fatalf("%s: unquote %s: %v", rel, lit.Value, uErr)
					}
					declNames[name.Name] = column
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				uses[id.Name]++
			}
			return true
		})
	}
	if len(declNames) < 12 {
		t.Fatalf("ABORT: found only %d vaultfield.Declare sites in the module (%v); at least twelve "+
			"exist, so this guard is reading the wrong thing", len(declNames), sortedKeys2(declNames))
	}

	for ident, column := range declNames {
		// One mention is the declaration itself.
		if uses[ident] <= 1 {
			t.Errorf("A STALE DECLARATION: %s declares %s and nothing in the module ever passes it to a "+
				"decrypt.\n  A ledger entry for a column nobody opens reads as coverage of a door that does "+
				"not exist. Remove it, or wire the door that was supposed to use it.", ident, column)
		}
	}
}

// TestTheInvitationCodeGoesThroughTheDeclaredDoor is the permanent regression for
// the FIFTH DOOR.
//
// invitations.code is vault-key-encrypted, it is a bearer credential that
// redeems into an account, and the round-18 ledger could not see it because
// UserHandler.openInviteCode called the raw decryptColumn rather than its logging
// wrapper. Three things have to stay true, and each of them is what actually
// broke:
//
//  1. the column has a ledger entry at all;
//  2. exactly one function in the module opens it;
//  3. that function is openInviteCode, in the file that argues about it.
func TestTheInvitationCodeGoesThroughTheDeclaredDoor(t *testing.T) {
	entry, ok := vaultfield.Lookup("invitations.code")
	if !ok {
		t.Fatalf("invitations.code is not in the ledger. It is a vault-key-encrypted bearer credential "+
			"that redeems into an account (an admin one, at target_role admin), and this is the exact "+
			"omission round 19 exists to close. Ledger: %v", ledgerNames(vaultfield.Ledger()))
	}
	if entry.Class != vaultfield.InstanceOwned {
		t.Errorf("invitations.code is classified %s, want instance-owned. It belongs to no vault entry, "+
			"so the exit's question (did the OWNER of this secret authorise this destination) has no "+
			"owner to ask; what carries the ruling instead is that both of its destinations are "+
			"admin-only, which TestInstanceOwnedFieldsAreOnlyReachableByAdmins checks", entry.Class)
	}

	callers := callersOf(t, "vaultFieldInvitationCode")
	const want = "invitation_code.go:UserHandler.openInviteCode"
	if len(callers) != 1 || callers[0] != want {
		t.Errorf("vaultFieldInvitationCode is used in %v, want exactly [%s].\n"+
			"  The invite code opens in ONE place so the argument about who may see it is made once. A\n"+
			"  second opener is a second answer to 'may this caller be handed a credential that redeems\n"+
			"  into an account'.", callers, want)
	}
}

// TestInstanceOwnedFieldsAreOnlyReachableByAdmins holds up the PREMISE of the
// instance-owned class.
//
// That class says: this value belongs to no vault entry, so there is no entry
// owner to ask, and the principal who chose its destination is an instance
// admin, who holds the widening right on every entry anyway. Every word of that
// rests on the routes being admin-gated. A classification whose premise is not
// checked is a claim, and the previous two rounds were both lost to claims.
//
// So the route table is re-derived from cmd/server/main.go and the invitation
// routes are required to sit inside a group that applies AdminOnly.
func TestInstanceOwnedFieldsAreOnlyReachableByAdmins(t *testing.T) {
	files := moduleGoFiles(t)
	var main string
	for path, src := range files {
		if strings.HasSuffix(moduleRelative(path), "cmd/server/main.go") {
			main = src
			break
		}
	}
	if main == "" {
		t.Fatal("ABORT: cmd/server/main.go was not found, so the route premise cannot be checked")
	}

	// The admin group is r.Route("/admin", ...) and the first thing inside it is
	// r.Use(timw.AdminOnly()). Find that block and require the invitation routes
	// to be inside it.
	const adminOpen = `r.Route("/admin", func(r chi.Router) {`
	start := strings.Index(main, adminOpen)
	if start < 0 {
		t.Fatalf("ABORT: the /admin route group was not found in cmd/server/main.go, so this guard cannot "+
			"tell whether %q is admin-gated", "/admin/invitations")
	}
	block := main[start:]
	if end := strings.Index(block, "\n\t\t\t})"); end > 0 {
		block = block[:end]
	}
	if !strings.Contains(block, "timw.AdminOnly()") {
		t.Error("the /admin route group no longer applies AdminOnly.\n" +
			"  Every instance-owned field in the ledger is classified on the premise that only an\n" +
			"  instance admin can reach it. invitations.code is returned in full by GET\n" +
			"  /api/admin/invitations, so without that gate a vault_only member could read a pending\n" +
			"  admin invite and redeem it into an admin account.")
	}
	for _, route := range []string{
		`r.Route("/invitations"`,
		`userHandler.ListInvitations`,
		`userHandler.ResendInvitation`,
	} {
		if !strings.Contains(block, route) {
			t.Errorf("%s is no longer inside the AdminOnly /admin group.\n"+
				"  invitations.code is classified instance-owned BECAUSE its destinations are admin-only.\n"+
				"  Moving the route without revisiting the classification makes the ledger a claim again.",
				route)
		}
	}
}

// TestOnlyTheCustomFieldExitDecryptsCustomFields is the half the behavioural
// tests cannot supply, and it was added because an ablation walked past them.
//
// THE ABLATION: put `h.decryptCustomFields(row.CustomFields)` back into
// vaultMetaFromGetRow, i.e. re-open the second exit on the response path it was
// found on. Every behavioural test still passed. The positive control passed
// because the owner is allowed the value either way, and the defensive control
// passed because it drives customFieldsForCaller directly, which was still
// correct and was simply no longer on the path. A guard that asserts a function
// behaves cannot notice that nothing calls it.
//
// So this pins the CALLER SET from the AST, exactly the way
// TestRawAESIsReachedFromExactlyOnePlace pins decryptWithKey's. decryptCustomFields
// is the raw door: it returns the plaintext of every field including the ones
// the operator marked secret. Exactly one production function may open it, and
// that function is the one that asks the exit.
func TestOnlyTheCustomFieldExitDecryptsCustomFields(t *testing.T) {
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)

	var callers []string
	scanned := 0
	for path, f := range parsed {
		if filepath.Base(filepath.Dir(path)) != "handlers" {
			continue
		}
		scanned++
		for _, decl := range f.Decls {
			fn, isFn := decl.(*ast.FuncDecl)
			if !isFn || fn.Body == nil {
				continue
			}
			enclosing := fn.Name.Name
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "decryptCustomFields" {
					return true
				}
				callers = append(callers, filepath.Base(path)+":"+enclosing)
				return true
			})
		}
	}
	if scanned < 20 {
		t.Fatalf("ABORT: only scanned %d files in the handlers package; this guard is checking nothing",
			scanned)
	}
	sort.Strings(callers)

	const want = "vault.go:customFieldsForCaller"
	if len(callers) != 1 || callers[0] != want {
		t.Errorf("decryptCustomFields is called from %v, want exactly [%s].\n"+
			"  It returns the plaintext of every custom field, including the ones an operator marked\n"+
			"  secret:true. Those are credentials on the same row as the entry's own value, and they\n"+
			"  leave in the same response body, so they go through secretexit.Exit. The one function\n"+
			"  entitled to the raw plaintext is the one that asks. Anything rendering custom fields\n"+
			"  into a response calls customFieldsForCaller.", callers, want)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// callersOf returns "file.go:Receiver.Func" for every function that mentions the
// identifier, across the non-test source of the whole module.
func callersOf(t *testing.T, ident string) []string {
	t.Helper()
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)
	var out []string
	for path, f := range parsed {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			enclosing := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				enclosing = receiverTypeName(fn.Recv.List[0].Type) + "." + enclosing
			}
			hit := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == ident {
					hit = true
				}
				return !hit
			})
			if hit {
				out = append(out, filepath.Base(path)+":"+enclosing)
			}
		}
	}
	sort.Strings(out)
	return out
}

// moduleRelative renders a walked path as a module-relative slash path, so the
// allowlists above read the way an operator would write them.
func moduleRelative(path string) string {
	p := filepath.ToSlash(path)
	for _, prefix := range []string{"../../", "../", "./"} {
		p = strings.TrimPrefix(p, prefix)
	}
	return p
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys2(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ledgerNames(entries []vaultfield.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}

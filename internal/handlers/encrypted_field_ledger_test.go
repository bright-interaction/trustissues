package handlers

import (
	"bytes"
	"go/ast"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/vaultfield"
	"github.com/bright-interaction/trustissues/internal/vaultfield/declscan"
)

// ── the ledger these guards read ────────────────────────────────────────────
//
// NOT vaultfield.Ledger(). That map is filled by init-time Declare calls in
// whichever packages THIS TEST BINARY LINKS, which is internal/handlers plus its
// import graph and nothing else. A guard reading it describes an import graph
// and claims to describe the module, and the difference is decided by whoever
// last edited an import somewhere unrelated. Put a Declare in cmd/server and
// every guard below used to stay green over a column it had never seen.
//
// declscan walks the module's FILES, the way the crypto-import pin and the
// key-holder pin do. The declaration set is now the module's set rather than a
// test binary's.
//
// vaultfield.Ledger() is still checked, in one place
// (TestTheStaticLedgerContainsEverythingTheBinaryLinked), as a CONTROL: a
// runtime entry missing from the source scan means the scan is blind, and a
// blind scan passes over anything.

// staticLedger is every vaultfield.Declare call in the module source.
func staticLedger(t *testing.T) []declscan.Declaration {
	t.Helper()
	decls, err := declscan.Scan(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("scan the module for vaultfield declarations: %v", err)
	}
	if len(decls) < 12 {
		t.Fatalf("ABORT: the module scan found only %d declarations (%v). At least twelve exist, so "+
			"this is not reading the source and every guard below is vacuous",
			len(decls), declaredColumns(decls))
	}
	for _, d := range decls {
		if d.Unparsed != "" {
			t.Fatalf("ABORT: %s declares a field this scan cannot read (%s). A declaration a guard "+
				"cannot parse is one it cannot check", d.At(), d.Unparsed)
		}
	}
	return decls
}

// productionLedger is the static set minus declarations made from _test.go
// files. Those satisfy a ledger inside a test binary and ship nothing.
func productionLedger(t *testing.T) []declscan.Declaration {
	t.Helper()
	var out []declscan.Declaration
	for _, d := range staticLedger(t) {
		if !d.IsTest {
			out = append(out, d)
		}
	}
	return out
}

func declaredColumns(decls []declscan.Declaration) []string {
	out := make([]string, 0, len(decls))
	for _, d := range decls {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

// lookupDeclared finds one column in the static ledger.
func lookupDeclared(decls []declscan.Declaration, column string) (declscan.Declaration, bool) {
	for _, d := range decls {
		if d.Name == column {
			return d, true
		}
	}
	return declscan.Declaration{}, false
}

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
//   - every open in internal/vaultfield demands a vaultfield.Field, whose only
//     constructor is vaultfield.Declare.
//   - Declare writes the ledger.
//   - two guards bound what can decrypt WITHOUT going through vaultfield at all.
//
// So the tests below no longer ask "did somebody remember to classify this".
// They ask the questions that are still open once the ledger cannot have holes:
// is every declaration a real ruling, does every through-the-exit field name a
// real exit, is any declaration describing dead code, and is the classification's
// PREMISE (admin-only routes, for the instance-owned class) still true.
//
// # THE CENTRAL CLAIM, RESTATED, BECAUSE THE ONE THAT SHIPPED WAS FALSE
//
// The previous version of this comment said:
//
//	opening AES-GCM data REQUIRES crypto/aes and crypto/cipher, so the importer
//	set is the reader set ... closed by the language.
//
// That sentence is not true and nothing about the language makes it true. AES
// is arithmetic. A pure-Go AES-GCM implementation imports nothing from crypto/*
// at all; so does a vendored one; and the module's own go.sum can grow a
// dependency that carries an AEAD. "Which files can do the arithmetic" is not a
// question an import graph answers. The guard built on that sentence was a
// useful NET, and it was sold as a PROOF.
//
// So: what actually has to be true for ciphertext THIS PRODUCT WROTE to be
// opened inside this module?
//
//	1. the code has to hold the KEY, and
//	2. the code has to do an AEAD open with it.
//
// Only (1) is scarce. The key enters the process once, as
// TRUSTISSUES_VAULT_KEY -> config.Config.VaultKey, and everything downstream is
// a copy of it or a KDF over it. Code that never obtains that material cannot
// open a single stored byte however it spells its crypto, and code that DOES
// obtain it can decrypt with an implementation nobody has ever seen. The key is
// the invariant; the import is a habit.
//
// Hence the two guards, in the order of what they are worth:
//
//	TestVaultKeyMaterialIsHeldOnlyByDeclaredFiles   the real pin. Every file
//	  that NAMES vault key material is declared, with a reason. A new decryption
//	  path in an undeclared file cannot obtain the key without either naming it
//	  (this reddens) or being handed it by a declared file, which is an edit
//	  inside the small set this guard makes people look at.
//
//	TestAESGCMIsOpenedInExactlyOneFile              the net. Importing the AES
//	  primitives is how a door is ACTUALLY written, so pinning the importers
//	  still catches the realistic sixth door on the day it appears. It is not a
//	  completeness claim and no longer says it is.
//
// Neither is a proof on its own, and saying so is the point: a guard that
// overstates its reach is how round 18 shipped four call shapes and read as
// coverage.

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

// aesImports are the two standard-library packages a Go AES-GCM open is
// ORDINARILY written with. crypto/aes gives the block cipher, crypto/cipher
// gives the AEAD.
//
// Not "the two packages you cannot open AES-GCM without": that is what this map
// used to claim and it is false. AES-GCM is arithmetic and can be written from
// nothing, imported from a third-party module, or lifted out of any library that
// ships an AEAD. Pinning these importers catches the door somebody actually
// writes; it does not close the set. What closes the set is the KEY, which
// theVaultKeyHolders below is about.
var aesImports = map[string]bool{
	"crypto/aes":    true,
	"crypto/cipher": true,
}

// theCryptoFiles are the files allowed to import them, each with the reason.
var theCryptoFiles = map[string]string{
	"internal/vaultfield/vaultfield.go": "THE door. Every vault-key-encrypted value in this product " +
		"becomes plaintext here, and every entry point demands a declared Field, which is what writes " +
		"the ledger.",
	"internal/shield/crypto.go": "a different key family entirely: the Shield PII tokenizer seals its " +
		"own session vocabulary under cfg.ShieldKey, never the vault key, and what it holds is tokenized " +
		"personal data rather than a stored credential. It is out of the vault-key ledger's scope, and " +
		"the exemption is CHECKED from both sides: TestShieldDoesNotTouchTheVaultKey says the package " +
		"never names vault key material, and TestNothingHandsTheVaultKeyToShield says nothing passes it " +
		"any, which is the side an argument about what a package 'seals its data under' cannot reach.",
}

// TestAESGCMIsOpenedInExactlyOneFile is the NET, not the pin.
//
// It is what the sixth-door ablation reddens: a new wrapper opening a new
// encrypted column with hand-written aes/cipher calls matches no call shape and
// no naming convention, and it still has to import these two packages to be
// written the way anybody writes it.
//
// It is not complete and the comment above says why. The completeness claim
// lives with the key, in TestVaultKeyMaterialIsHeldOnlyByDeclaredFiles.
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
			"  Importing the AES primitives is how a decryption path is ACTUALLY written, which is why\n"+
			"  this guard pins importers instead of function names: round 18 pinned four call shapes and\n"+
			"  a fifth door (UserHandler.openInviteCode, on the vault-key-encrypted invitations.code\n"+
			"  column) had already walked past it. It is a net and not a proof; the completeness claim\n"+
			"  is TestVaultKeyMaterialIsHeldOnlyByDeclaredFiles, because holding the KEY is what a reader\n"+
			"  of this product's ciphertext cannot avoid.\n"+
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

// ── THE KEY, which is the thing a reader cannot do without ──────────────────

// vaultKeyFieldNames are the names under which vault key material travels
// through this module.
//
// They are FIELD and VARIABLE names, matched on the AST, not substrings:
// RotateVaultKeys and the VerifyVaultKey comment in internal/db mention neither
// a field read nor a key, and a substring scan reported both.
//
//	VaultKey       config.Config's field. The one entry point: it is
//	               os.Getenv("TRUSTISSUES_VAULT_KEY") and nothing else writes it.
//	encryptionKey  VaultHandler's PBKDF2-derived current key.
//	legacyKey      VaultHandler's SHA-256 v1 key, still able to open v1 rows.
//	bidxKey        derived from the same source. It cannot decrypt (it is an HMAC
//	               key for the URL blind index) and it is listed anyway, because
//	               the question this guard asks is "who holds material derived
//	               from the vault key", and answering it per-purpose is how a set
//	               starts having exceptions.
//	vaultKeys      the KEYRING: the current master key followed by
//	               TRUSTISSUES_VAULT_KEY_PREVIOUS. Master-key rotation made the
//	               dual-key read the ordinary shape, so the functions that used
//	               to take a `vaultKey string` now take `vaultKeys ...string`,
//	               and a guard matching only the singular stopped seeing files
//	               that hold the key just as much as they did before. It is
//	               listed for the same reason bidxKey is: the question is who
//	               can REACH key material, not what they do with it.
var vaultKeyFieldNames = map[string]bool{
	"VaultKey": true, "encryptionKey": true, "legacyKey": true, "bidxKey": true,
	"vaultKeys": true,
}

// theVaultKeyHolders is every production file allowed to name vault key
// material, with what it needs it for.
//
// THIS IS THE COMPLETENESS CLAIM the import pin was wrongly making. Ciphertext
// this product wrote can only be opened by code holding the key that sealed it,
// whatever crypto that code is written with, so the set of files that can reach
// the key bounds the set of files that can decrypt.
//
// A file counts as a holder when it NAMES one of the key fields above, when it
// takes a [32]byte or a vaultKey parameter, or when it RETURNS a [32]byte, which
// is the shape of every KDF here. Those three cover reaching for the key,
// receiving it, and manufacturing it.
//
// THE RESIDUAL, with the two real instances named rather than left as a caveat.
// A file can also receive the configured key as an ordinarily-typed string
// parameter under some other name, and two do:
//
//	internal/handlers/capability.go   NewCapabilityHandler(..., signingKeySource string),
//	                                  called from cmd/server/main.go with cfg.VaultKey
//	internal/capability/token.go      DeriveSigningKey(source string)
//
// Neither decrypts anything (they HKDF a signing key with a fixed label, which
// is one-way), and both are reachable only because a file IN THIS SET passed the
// value. That is the shape of the whole guarantee rather than a gap in it: key
// material cannot arrive in a fresh package without an edit inside one of the
// entries below, so this list is where review concentrates. Widening the match
// to any string parameter would flag every function in the module and the list
// would stop being read, which is how a guard stops guarding.
var theVaultKeyHolders = map[string]string{
	"internal/config/config.go": "the ENTRY POINT. TRUSTISSUES_VAULT_KEY is read here and nowhere else, " +
		"and the strength checks on it live beside the read.",
	"cmd/server/main.go": "wiring. It hands cfg to the handlers that need it and holds no derived key of " +
		"its own.",
	"internal/handlers/vault.go": "the vault handler DERIVES the two content keys and the blind-index key " +
		"here (PBKDF2 for v2, SHA-256 for the v1 rows still on disk) and wipes them on shutdown.",
	"internal/handlers/vault_column_crypto.go": "the column encrypt/decrypt wrappers, which spend " +
		"encryptionKey through internal/vaultfield with a declared Field.",
	"internal/handlers/vault_keycheck.go": "the boot-time check that the configured key actually opens " +
		"what is stored, plus the re-key path, which is the one place both keys are live at once.",
	"internal/handlers/vault_rekey.go": "the master-key sweep. It is the one file that holds BOTH keys " +
		"on purpose and for the whole of a conversion: classifying a row means asking which key opens " +
		"it, and re-encrypting it means sealing under the other one. It re-derives the v1 key from the " +
		"master key string rather than reading legacyKey, because MigrateEncryption zeroes that field " +
		"after boot and a sweep triggered from the admin API later would otherwise read zeroes and " +
		"report every v1 row unreadable. Everything it opens goes through internal/vaultfield or " +
		"internal/secretexit with a declared Field; it does no crypto of its own.",
	"internal/handlers/auth.go": "TOTP secrets are a vault-key column and are opened through " +
		"columncrypto with cfg.VaultKey.",
	"internal/handlers/users.go": "the SMTP relay password is instance-owned configuration under the " +
		"same key.",
	"internal/handlers/settings.go": "the same instance-owned settings family, read and written from " +
		"the settings surface.",
	"internal/handlers/smtp_password.go": "resolves the stored SMTP relay password, which is that same " +
		"instance-owned column, and takes the configured key to do it.",
	"internal/vaultfield/vaultfield.go": "THE door. Every open here takes the derived key and a declared " +
		"Field, and Declare is what writes the ledger.",
	"internal/secretexit/secretexit.go": "opens vault_entries.encrypted_value into an opaque Plaintext, " +
		"which is the one value in this product that may not be handled as bytes.",
	"internal/columncrypto/columncrypto.go": "the string-column family (TOTP secrets, invitation codes, " +
		"instance settings). It DERIVES its own key from the configured secret and opens through " +
		"vaultfield with a declared Field like everything else.",
}

// TestVaultKeyMaterialIsHeldOnlyByDeclaredFiles is the real pin.
//
// It fails in both directions: an undeclared file that names key material is a
// new holder nobody ruled on, and a declared file that names none is an
// exemption for code that stopped doing the thing, which reads as a boundary and
// is not one.
func TestVaultKeyMaterialIsHeldOnlyByDeclaredFiles(t *testing.T) {
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)
	if len(parsed) < 30 {
		t.Fatalf("ABORT: parsed only %d module files; this guard is not reading the source", len(parsed))
	}

	holders := map[string][]string{}
	note := func(rel, name string) {
		for _, seen := range holders[rel] {
			if seen == name {
				return
			}
		}
		holders[rel] = append(holders[rel], name)
	}
	for path, f := range parsed {
		rel := moduleRelative(path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				// cfg.VaultKey, h.encryptionKey, h.vault.legacyKey.
				if vaultKeyFieldNames[v.Sel.Name] {
					note(rel, v.Sel.Name)
				}
			case *ast.Ident:
				// The struct field declarations and any local binding. VaultKey is
				// deliberately not matched here: as a bare identifier it is a
				// struct-literal key in every config fixture and says nothing about
				// who holds the value.
				if v.Name != "VaultKey" && vaultKeyFieldNames[v.Name] {
					note(rel, v.Name)
				}
			case *ast.FuncType:
				// THE OTHER HALF OF HOLDING IT: a file that never names a key field
				// but takes one as a parameter. internal/vaultfield, secretexit,
				// columncrypto and the keycheck probe are all in this shape, and
				// leaving them out would have made the declared set a list of the
				// callers rather than of the holders.
				//
				// Two spellings, both syntactic: the derived key's type, and the
				// configured key's conventional parameter name.
				if v.Params != nil {
					for _, p := range v.Params.List {
						if renderExpr(fset, p.Type) == "[32]byte" {
							note(rel, "a [32]byte key parameter")
						}
						for _, nm := range p.Names {
							if nm.Name == "vaultKey" {
								note(rel, "a vaultKey parameter")
							}
						}
					}
				}
				// And the DERIVERS. A function returning [32]byte manufactures key
				// material out of whatever it was given, which is the shape every
				// KDF in this module has (vaultV2Key, columncrypto.deriveKey) and
				// the one way a file becomes a holder without naming a key field or
				// receiving one.
				if v.Results != nil {
					for _, res := range v.Results.List {
						if renderExpr(fset, res.Type) == "[32]byte" {
							note(rel, "a function deriving a [32]byte key")
						}
					}
				}
			}
			return true
		})
	}

	// The positive control. If the walk stops finding the file that DERIVES the
	// keys, this guard would pass over a module where everything had moved.
	if _, ok := holders["internal/handlers/vault.go"]; !ok {
		t.Fatalf("ABORT: internal/handlers/vault.go names no vault key material. That is where the "+
			"content keys are derived, so either the walk is broken or the derivation moved without "+
			"this guard being told. Files seen holding key material: %v", sortedKeys(holders))
	}

	for _, rel := range sortedKeys(holders) {
		if _, allowed := theVaultKeyHolders[rel]; allowed {
			continue
		}
		sort.Strings(holders[rel])
		t.Errorf("AN UNDECLARED HOLDER OF VAULT KEY MATERIAL: %s names %s.\n"+
			"  Opening this product's ciphertext takes the KEY, not any particular crypto package, so\n"+
			"  the set of files that can reach the key is the set of files that can decrypt. That is the\n"+
			"  claim the AES-import pin used to make and could not support: AES-GCM can be written from\n"+
			"  arithmetic, and no import graph closes it.\n"+
			"  If this file genuinely needs the key, add it to theVaultKeyHolders WITH the reason. If it\n"+
			"  needs to DECRYPT, route that through internal/vaultfield, whose entry points demand a\n"+
			"  declared Field and therefore put the column in the ledger.",
			rel, strings.Join(holders[rel], ", "))
	}

	for rel := range theVaultKeyHolders {
		if _, ok := holders[rel]; !ok {
			t.Errorf("A STALE KEY-HOLDER DECLARATION: theVaultKeyHolders allows %s to hold vault key "+
				"material and it names none.\n  An exemption for code that no longer does the thing "+
				"reads as a boundary and is not one. Remove it.", rel)
		}
	}
	t.Logf("%d production files hold vault key material, all declared: %v",
		len(holders), sortedKeys(holders))
}

// TestShieldDoesNotTouchTheVaultKey is the CALLEE half of the shield exemption.
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

// TestNothingHandsTheVaultKeyToShield is the CALLER half, and it is the half
// that matters.
//
// The exemption above is a statement about what internal/shield does with a key
// it is GIVEN, and internal/shield does not choose what it is given. Its whole
// key surface is untyped bytes:
//
//	func NewSession(ctx, store, sessionID string, key []byte, ttl, hintLevel) (*Session, error)
//	func encrypt(plaintext string, key []byte) (string, error)
//
// so the package cannot tell cfg.ShieldKey from cfg.VaultKey and would seal the
// session vocabulary under either one without a word. Every file under
// internal/shield can pass TestShieldDoesNotTouchTheVaultKey unchanged while a
// single character elsewhere makes the exemption false, and the ledger would go
// on reporting shield's columns as out of scope.
//
// So the property is checked where it is DECIDED: at the call sites. Nothing
// anywhere in the module may pass an expression naming vault key material into
// internal/shield.
func TestNothingHandsTheVaultKeyToShield(t *testing.T) {
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)

	calls, keyed := 0, 0
	for path, f := range parsed {
		rel := moduleRelative(path)
		if strings.HasPrefix(rel, "internal/shield/") {
			continue // inside the package the qualifier is not written
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "shield" {
				return true
			}
			calls++
			for _, arg := range call.Args {
				rendered := renderExpr(fset, arg)
				if strings.Contains(rendered, "ShieldKey") {
					keyed++
				}
				for name := range vaultKeyFieldNames {
					if !mentionsIdent(arg, name) {
						continue
					}
					t.Errorf("%s:%d passes %s into shield.%s.\n"+
						"  internal/shield is exempt from the vault-key ledger because it seals its own data\n"+
						"  under its OWN key. That exemption is a property of what it is HANDED, and its key\n"+
						"  parameters are plain []byte, so nothing inside the package can refuse this. Pass\n"+
						"  cfg.ShieldKey. If the Shield vocabulary genuinely has to move to the vault key,\n"+
						"  its columns belong in the ledger and the exemption in theCryptoFiles has to go.",
						rel, fset.Position(arg.Pos()).Line, rendered, sel.Sel.Name)
				}
			}
			return true
		})
	}

	// ANTI-VACUITY, both halves. A guard over zero calls is green about nothing,
	// and a guard that never sees a key argument is not watching the parameter
	// the whole test is about.
	if calls == 0 {
		t.Fatal("ABORT: no calls into internal/shield were found anywhere in the module, so this guard " +
			"is checking nothing")
	}
	if keyed == 0 {
		t.Fatal("ABORT: no call into internal/shield passes anything named ShieldKey. Either the key " +
			"argument moved and this guard is now watching a parameter that no longer exists, or Shield " +
			"is being keyed from somewhere this test cannot see")
	}
	t.Logf("%d calls into internal/shield, %d of them carrying a key, none carrying the vault key",
		calls, keyed)
}

// mentionsIdent reports whether an expression names ident anywhere inside it,
// as a bare identifier or as the selected field of a selector.
//
// Rendering and substring-matching would be shorter and would also match a
// string literal or a comment. This is the same reason the holder guard walks
// the AST: the question is what the expression IS, not what it looks like.
func mentionsIdent(e ast.Expr, name string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if v.Sel.Name == name {
				found = true
			}
		case *ast.Ident:
			if v.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

// renderExpr prints an expression the way it is written, for a failure message
// that names the argument rather than describing it.
func renderExpr(fset *token.FileSet, e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, e); err != nil {
		return "<unprintable expression>"
	}
	return buf.String()
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
	entries := productionLedger(t)

	// knownClasses is the vocabulary, read textually because the ledger is now
	// derived from source. A class name that is not one of these is either a
	// typo the compiler would catch or a new class nobody told the guards about.
	knownClasses := map[string]bool{
		"ThroughTheExit": true, "InProcessOnly": true,
		"NotACredential": true, "InstanceOwned": true,
	}

	throughTheExit := 0
	for _, e := range entries {
		if e.Class == "Unclassified" || !knownClasses[e.Class] {
			t.Errorf("%s is declared with class %q, which is not a ruling (declared at %s).\n"+
				"  Unclassified is the zero value and vaultfield.Declare refuses it; anything else here "+
				"is a class the guards have never been told about.", e.Name, e.Class, e.At())
		}
		if len(strings.TrimSpace(e.Why)) < 60 {
			t.Errorf("%s is declared without a reason worth reading. Say what the plaintext IS and why "+
				"that classification is the right one (declared at %s)", e.Name, e.At())
		}
		if e.Class != "ThroughTheExit" {
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
	t.Logf("%d declared fields, all ruled: %v", len(entries), declaredColumns(entries))
}

// TestTheStaticLedgerContainsEverythingTheBinaryLinked is the CONTROL on the
// change that made this file read the source instead of the map.
//
// A source scan is only better than a runtime map if it is a SUPERSET of it. A
// scanner that silently stopped recognising Declare calls would return an empty
// set, every guard above would pass over nothing, and the failure would look
// exactly like a clean module. So the runtime ledger, which is complete for the
// packages this binary links, is required to be inside the static one.
//
// The direction it does NOT assert is the point: the static set is allowed to
// be bigger, because a declaration in a package internal/handlers does not
// import is still in the module, and being blind to it is the defect.
func TestTheStaticLedgerContainsEverythingTheBinaryLinked(t *testing.T) {
	static := staticLedger(t)
	byName := map[string]declscan.Declaration{}
	for _, d := range static {
		byName[d.Name] = d
	}

	linked := vaultfield.Ledger()
	if len(linked) < 12 {
		t.Fatalf("ABORT: the runtime ledger holds only %d fields (%v); at least twelve are linked into "+
			"this binary, so this control is comparing against nothing",
			len(linked), ledgerNames(linked))
	}
	for _, e := range linked {
		d, ok := byName[e.Name]
		if !ok {
			t.Errorf("%s is in vaultfield.Ledger() at runtime and the SOURCE SCAN did not find it.\n"+
				"  The scan is what every other guard in this file reads, so a column it cannot see is a\n"+
				"  column nothing checks. Either the declaration is spelled in a way declscan cannot fold,\n"+
				"  or it lives in a directory the walk skips.", e.Name)
			continue
		}
		if d.Class != e.Class.String() && !classMatches(d.Class, e.Class) {
			t.Errorf("%s is classified %s in the source and %s at runtime", e.Name, d.Class, e.Class)
		}
	}
	t.Logf("source scan: %d declarations; this binary links %d of them", len(static), len(linked))
}

// classMatches compares the identifier the source uses against the runtime
// Class, whose String() is the hyphenated operator-facing spelling.
func classMatches(sourceIdent string, c vaultfield.Class) bool {
	switch sourceIdent {
	case "ThroughTheExit":
		return c == vaultfield.ThroughTheExit
	case "InProcessOnly":
		return c == vaultfield.InProcessOnly
	case "NotACredential":
		return c == vaultfield.NotACredential
	case "InstanceOwned":
		return c == vaultfield.InstanceOwned
	}
	return false
}

// TestTheLedgerIsDeclaredByProductionCode closes the way to satisfy the ledger
// without satisfying the product: declare a field from a _test.go file.
//
// A test-only declaration would let a guard read as covered while the production
// binary decrypts through a Field nobody shipped. Declaring from a test is
// allowed (internal/columncrypto does it for its own round trips), it just
// cannot appear in the ledger this package's guards read.
// It is a STRICTER question than it used to be, and only because the ledger is
// static now. The runtime map could not see a test declaration from another
// package at all, so the old version of this guard was checking a set that
// excluded the thing it was worried about by construction. The source scan sees
// every declaration in the module, so the rule can be stated properly: a test
// may declare a FIXTURE column, and it may not be the only declaration of a
// column the product actually stores.
func TestTheLedgerIsDeclaredByProductionCode(t *testing.T) {
	all := staticLedger(t)
	production := productionLedger(t)

	schema, err := readMigrations()
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	if len(schema) < 5000 {
		t.Fatalf("ABORT: read only %d bytes of migrations; this guard is checking nothing", len(schema))
	}

	tests := 0
	for _, d := range all {
		if !d.IsTest {
			continue
		}
		tests++
		if _, shipped := lookupDeclared(production, d.Name); shipped {
			continue // the product declares it too; the test one is a duplicate handle at worst
		}
		table, _, ok := strings.Cut(d.Name, ".")
		if ok && strings.Contains(schema, "TABLE "+table) {
			t.Errorf("%s is declared ONLY from a TEST file (%s), and %q is a real table in the schema.\n"+
				"  A declaration in a test satisfies the ledger inside the test binary and ships nothing,\n"+
				"  so the production decrypt of that column would run through a Field nobody shipped.\n"+
				"  Move the declaration next to the door that opens it.", d.Name, d.At(), table)
		}
	}
	if len(production) < 12 {
		t.Fatalf("ABORT: only %d production declarations; at least twelve exist", len(production))
	}
	t.Logf("%d production declarations, %d test fixtures", len(production), tests)
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

	// The declaration set comes from the SOURCE SCAN, so a declaration in a
	// package this test binary never links is checked like any other. Under the
	// runtime map it was invisible, which meant a stale declaration could sit in
	// cmd/server forever and this guard would call the module clean.
	declNames := map[string]string{} // identifier -> declared column name
	for _, d := range productionLedger(t) {
		if d.Ident == "" {
			t.Errorf("%s declares %s without binding it to a package-level variable.\n"+
				"  A Field nothing holds cannot be passed to a decrypt, so the declaration is a ledger\n"+
				"  entry for a door that does not exist.", d.At(), d.Name)
			continue
		}
		declNames[d.Ident] = d.Name
	}

	// Every identifier used anywhere in the module's non-test source, by name. A
	// field is "opened" if its declaring identifier is mentioned somewhere other
	// than its own declaration, which is the same handle theExitList uses.
	uses := map[string]int{}
	for _, f := range parsed {
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
	production := productionLedger(t)
	entry, ok := lookupDeclared(production, "invitations.code")
	if !ok {
		t.Fatalf("invitations.code is not in the ledger. It is a vault-key-encrypted bearer credential "+
			"that redeems into an account (an admin one, at target_role admin), and this is the exact "+
			"omission round 19 exists to close. Ledger: %v", declaredColumns(production))
	}
	if entry.Class != "InstanceOwned" {
		t.Errorf("invitations.code is classified %s, want InstanceOwned. It belongs to no vault entry, "+
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

// TestEveryLedgerColumnExistsInTheSchema is the stale check at the DATA level.
//
// The guards above keep the ledger honest about the CODE. This one keeps it
// honest about the database: a ledger naming table.column pairs that the schema
// does not have is describing something nobody can point at, and a rename that
// leaves the declaration behind is exactly how the round-18 boundary would have
// rotted next.
//
// Two entries are deliberately not columns: the boot probes, which open whatever
// blob AnyEncryptedColumnSample happened to return. They are spelled with a
// parenthesis and are required to be in-process-only, because a ruling that
// cannot name its column must not be one that lets anything leave.
func TestEveryLedgerColumnExistsInTheSchema(t *testing.T) {
	files := moduleGoFiles(t)
	// The migrations are .sql, so read them off disk rather than through the Go
	// walk.
	schema, err := readMigrations()
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	if len(schema) < 5000 {
		t.Fatalf("ABORT: read only %d bytes of migrations; this guard is checking nothing", len(schema))
	}
	_ = files

	checked := 0
	for _, e := range productionLedger(t) {
		if strings.Contains(e.Name, "(") {
			if e.Class != "InProcessOnly" {
				t.Errorf("%s does not name a real column and is classified %s. A ruling that cannot say "+
					"WHICH column it is about must be in-process-only: it cannot argue about where a value "+
					"may go when it does not know what the value is.", e.Name, e.Class)
			}
			continue
		}
		table, column, ok := strings.Cut(e.Name, ".")
		if !ok {
			t.Errorf("%s is not spelled table.column, so it cannot be checked against the schema", e.Name)
			continue
		}
		checked++
		// settings rows are key/value, not columns: settings.smtp_password is a
		// ROW key. Check the table and the value column instead.
		if table == "settings" {
			if !strings.Contains(schema, "CREATE TABLE settings") &&
				!strings.Contains(schema, "CREATE TABLE IF NOT EXISTS settings") {
				t.Errorf("%s names the settings table and the schema has none", e.Name)
			}
			continue
		}
		if !strings.Contains(schema, table) {
			t.Errorf("%s names table %q and no migration mentions it", e.Name, table)
			continue
		}
		if !strings.Contains(schema, column) {
			t.Errorf("A LEDGER ENTRY FOR A COLUMN THAT DOES NOT EXIST: %s.\n"+
				"  No migration mentions %q. Either the column was renamed and the declaration was left\n"+
				"  behind, or the declaration was written for something that never shipped. Both read as\n"+
				"  coverage.", e.Name, column)
		}
	}
	if checked < 10 {
		t.Fatalf("ABORT: only %d ledger entries name a table.column; at least ten do", checked)
	}
}

// readMigrations concatenates the migration SQL so a guard can ask what the
// schema actually contains.
func readMigrations() (string, error) {
	dir := filepath.Join("..", "database", "migrations")
	names, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, n := range names {
		if n.IsDir() || !strings.HasSuffix(n.Name(), ".sql") {
			continue
		}
		raw, rErr := os.ReadFile(filepath.Join(dir, n.Name()))
		if rErr != nil {
			return "", rErr
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.String(), nil
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

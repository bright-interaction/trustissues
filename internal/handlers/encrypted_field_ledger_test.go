package handlers

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// THE GUARD THAT MAKES THE SCOPE BOUNDARY CHECKABLE.
//
// A comment listing what is out of scope is exactly the kind of claim that rots,
// and the round-7 one had already rotted before it shipped: it named two
// instance-owned rows and missed custom_fields, an entry column that is
// AES-encrypted at rest, can hold operator-designated secret material, and left
// in a response body with no destination and no receipt.
//
// So the boundary is derived. This walks the whole module's AST for the four
// ways a stored ciphertext becomes plaintext in this product and requires each
// to be classified in theEncryptedFieldLedger, failing in both directions:
//
//   - an encrypted field nobody classified fails on the day it is added, naming
//     the file and line;
//   - a ledger entry for something that no longer exists fails too, so the list
//     cannot become a description of deleted code.
//
// It is modelled on TestEveryExitIsRegistered, which does the same thing for the
// exits, and on TestEveryVaultEntryColumnIsClassified, which does it for the
// host-choosing columns. Three registries, one discipline: a NEW thing must be
// classified rather than forgotten.

// encryptedFieldSite is where the derivation found a field.
type encryptedFieldSite struct {
	file string
	line int
}

// deriveEncryptedFields walks the module and returns key -> first site.
//
// The four derivations, and why each is the right handle:
//
//	decryptColumnOrLog(_, _, "url")   the third argument is the FIELD NAME, a
//	                                  string literal at every call site, so the
//	                                  key is the column itself.
//	OpenEntrySecret(...)              the one door onto vault_entries.encrypted_value.
//	DecryptInstanceConfig(...)        the one door onto alert_channels.config.
//	columncrypto.DecryptString(...)   these take a blob and a key and never name
//	                                  a column, so the key is the CALL SITE. That
//	                                  is the same handle theExitList uses, for
//	                                  the same reason.
func deriveEncryptedFields(t *testing.T) map[string]encryptedFieldSite {
	t.Helper()
	fset := token.NewFileSet()
	parsed := parseModule(t, fset)
	if len(parsed) < 30 {
		t.Fatalf("ABORT: parsed only %d module files; this guard is not reading the source", len(parsed))
	}

	out := map[string]encryptedFieldSite{}
	record := func(key string, pos token.Position) {
		if _, seen := out[key]; seen {
			return
		}
		out[key] = encryptedFieldSite{file: filepath.ToSlash(pos.Filename), line: pos.Line}
	}

	for path, f := range parsed {
		base := filepath.Base(path)
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
				pos := fset.Position(call.Pos())
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					switch fun.Sel.Name {
					case "decryptColumnOrLog", "decryptCustomFields":
						// decryptCustomFields has no field argument; it is the
						// custom_fields column by construction.
						if fun.Sel.Name == "decryptCustomFields" {
							record("vault_entries.custom_fields", pos)
							return true
						}
						if len(call.Args) < 3 {
							t.Errorf("%s:%d calls decryptColumnOrLog with %d arguments; this guard "+
								"reads the field name out of the third one", base, pos.Line, len(call.Args))
							return true
						}
						lit, isLit := call.Args[2].(*ast.BasicLit)
						if !isLit || lit.Kind != token.STRING {
							t.Errorf("%s:%d names its encrypted field with something other than a "+
								"string literal, so it cannot be classified. Pass the column name "+
								"literally.", base, pos.Line)
							return true
						}
						name, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatalf("%s:%d: unquote %s: %v", base, pos.Line, lit.Value, err)
						}
						record("vault_entries."+name, pos)
					case "OpenEntrySecret":
						record("vault_entries.encrypted_value", pos)
					case "DecryptInstanceConfig":
						record("alert_channels.config", pos)
					case "DecryptString":
						pkg, isPkg := fun.X.(*ast.Ident)
						if !isPkg || pkg.Name != "columncrypto" {
							return true
						}
						record("columncrypto:"+base+":"+enclosing, pos)
					}
				}
				return true
			})
		}
	}
	return out
}

// TestEveryEncryptedFieldIsClassified is the boundary, checked.
func TestEveryEncryptedFieldIsClassified(t *testing.T) {
	found := deriveEncryptedFields(t)
	if len(found) < 10 {
		t.Fatalf("ABORT: derived only %d encrypted fields from the module (%v). At least ten are "+
			"known to exist, so the derivation is broken and would report a clean boundary over "+
			"anything", len(found), keysOf(found))
	}

	var unclassified, stale []string
	for key, site := range found {
		if _, ok := theEncryptedFieldLedger[key]; !ok {
			unclassified = append(unclassified, key+" (at "+site.file+":"+strconv.Itoa(site.line)+")")
		}
	}
	for key := range theEncryptedFieldLedger {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(unclassified)
	sort.Strings(stale)

	for _, k := range unclassified {
		t.Errorf("AN UNCLASSIFIED ENCRYPTED FIELD: %s.\n"+
			"  Every at-rest-encrypted thing in this module is classified in theEncryptedFieldLedger\n"+
			"  as one of: it goes through the exit, it is consumed in-process, it is not a credential,\n"+
			"  or it belongs to the instance. That is not bookkeeping. The round-7 boundary was prose,\n"+
			"  it missed custom_fields, and custom_fields turned out to be a second way a decrypted\n"+
			"  secret left the process. Classify it, with the reason, and if the answer is \"it goes\n"+
			"  through the exit\" then route it through secretexit.Exit and register that exit.", k)
	}
	for _, k := range stale {
		t.Errorf("A STALE CLASSIFICATION: theEncryptedFieldLedger classifies %s and nothing in the "+
			"module decrypts it.\n  A ledger that describes deleted code reads as coverage and is "+
			"not. Remove it.", k)
	}

	// The ruling has to SAY something. An empty reason is a rubber stamp.
	for key, ruling := range theEncryptedFieldLedger {
		if len(strings.TrimSpace(ruling.why)) < 60 {
			t.Errorf("%s is classified without a reason worth reading. Say what the plaintext IS and "+
				"why that classification is the right one", key)
		}
	}
	t.Logf("%d encrypted fields, all classified", len(found))
}

// TestEveryFieldThatGoesThroughTheExitHasOne closes the way to satisfy the
// ledger without satisfying its point: classify a credential as
// classThroughTheExit and never route it through one.
func TestEveryFieldThatGoesThroughTheExitHasOne(t *testing.T) {
	checked := 0
	for key, ruling := range theEncryptedFieldLedger {
		if ruling.class != classThroughTheExit {
			if ruling.exitKey != "" {
				t.Errorf("%s is not classified as going through the exit but names one (%q). One of "+
					"the two is wrong.", key, ruling.exitKey)
			}
			continue
		}
		checked++
		if ruling.exitKey == "" {
			t.Errorf("%s is classified as going through the exit and names no exit. Name the "+
				"theExitList key that governs it, or the classification is a claim with nothing "+
				"behind it.", key)
			continue
		}
		// "any" is the vault value itself: every one of the ten registered exits
		// governs it, so naming one would be arbitrary.
		if ruling.exitKey == "any" {
			continue
		}
		if _, ok := theExitList[ruling.exitKey]; !ok {
			t.Errorf("%s says it leaves through %q and theExitList has no such entry.\n"+
				"  Either the exit was renamed and the ledger rotted, or the field is classified as "+
				"gated and is not.", key, ruling.exitKey)
		}
	}
	if checked < 2 {
		t.Fatalf("ABORT: only %d fields are classified as going through the exit; two are known to be "+
			"(encrypted_value and custom_fields), so this guard is checking almost nothing", checked)
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
		if !strings.HasSuffix(filepath.ToSlash(path), "/internal/handlers/"+filepath.Base(path)) &&
			filepath.Base(filepath.Dir(path)) != "handlers" {
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

func keysOf(m map[string]encryptedFieldSite) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

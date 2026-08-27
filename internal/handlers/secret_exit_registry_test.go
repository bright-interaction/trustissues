package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// THE LIST OF EXITS, AND THE GUARD THAT MAKES A NEW ONE FAIL LOUDLY.
//
// internal/secretexit proves that Exit is the ONLY way to obtain a decrypted
// secret's bytes. That makes the set of exits something the compiler maintains,
// which is the property the six previous rounds did not have. It does not make
// the set VISIBLE, and the brief for this round is that the list is as much the
// deliverable as the code: an operator has to be able to read, in one place,
// every way a secret can leave this process.
//
// So this file is the list, and the test below derives the real one from the AST
// and fails on any difference in EITHER direction:
//
//   - a NEW exit that nobody wrote down fails on the day it is written, naming
//     the file and line, exactly the way TestNoProviderCallBypassesTheEgressGate
//     does for a direct providerHTTP.Do.
//   - a registered exit that no longer exists also fails, so the list cannot rot
//     into a description of code that was deleted. Round 6 deleted an entire
//     ablation set for exactly that reason.
//
// The registration is not a rubber stamp. Each entry has to say WHOSE secret
// leaves and WHO chose the destination, because those are the two facts the
// round-6 attack turned out to hinge on and neither is visible from the call
// site alone.

// exitSite is one registered call to secretexit.Exit / secretexit.ExitString.
type exitSite struct {
	// whose secret leaves here.
	secret string
	// who chose the destination, in the Chooser vocabulary.
	chooser string
	// why that chooser is the right one.
	why string
}

// theExitList is every place in this package where a decrypted secret leaves.
//
// Keyed by "file.go:EnclosingFunc". Ordering does not matter; completeness does.
var theExitList = map[string]exitSite{
	// ── the network, provider adapters ───────────────────────────────────
	"egress_authority.go:spendProviderSecret": {
		secret:  "the entry being validated or rotated",
		chooser: "the entry's own record",
		why: "the destination is this entry's provider + provider_meta columns, whose writes already " +
			"require the widening right. The authority re-derives what the row records NOW, so an " +
			"older binary, an import or a restored backup is refused at delivery. Covers POST " +
			"/api/vault/{id}/validate, POST /api/vault/{id}/rotate and the scheduled sweep, because " +
			"all three call this one function.",
	},
	"vault_providers.go:performPendingRevoke": {
		secret:  "the entry being rotated (its NEW value)",
		chooser: "the entry's own record",
		why: "the deferred revoke sends \"Authorization: Bearer <the new secret>\" to a method and URL " +
			"taken out of provider_meta. Same entry, same declared hosts, same question.",
	},

	// ── the network, rotation delivery ───────────────────────────────────
	"vault_targets.go:deliverToWebhook": {
		secret:  "the entry being rotated",
		chooser: "the user who configured the target",
		why: "a webhook POSTs {\"new_value\": <the plaintext>} to a URL somebody named. That somebody " +
			"has to hold the widening right on the entry whose value it is.",
	},
	"vault_targets.go:deliverToForgejoSecret": {
		secret:  "TWO: the entry being rotated (body) AND the entry named by auth_token (bearer)",
		chooser: "the user who configured the target",
		why: "THE ROUND-6 PATH. The bearer half is the break: auth_token names an entry by name, and " +
			"an accepted vault_only VIEWER of a shared collection may USE the team's secret. Both " +
			"secrets exit separately and each is asked about ITS OWN owner, so the viewer, who holds " +
			"the widening right on their carrier entry and not on the victim's, is refused on the " +
			"second one.",
	},

	// ── the network, the AI gateway ──────────────────────────────────────
	"ai_gateway.go:AIGatewayHandler.Proxy": {
		secret:  "the entry an admin wired into the AI gateway",
		chooser: "the instance",
		why: "the entry is named by an AdminOnly settings row and the host is the compile-time " +
			"aiProviders baseURL. No caller and no editor of the entry can move either.",
	},

	// ── the network, the capability bridge ───────────────────────────────
	"capability.go:CapabilityHandler.Proxy": {
		secret:  "the entry the capability token was minted for",
		chooser: "the entry's own record",
		why: "the destination is the entry's destination_patterns ceiling. Everything the bridge " +
			"checks above the exit reads columns a caller with manage can write, which is how rounds " +
			"2 and 3 got in; the exit re-derives the owner's recorded destinations instead.",
	},

	// ── back to a principal ──────────────────────────────────────────────
	"vault_export.go:VaultHandler.revealAccessibleVaultEntriesWithQueries": {
		secret:  "every entry in an unlock or native-export response",
		chooser: "the caller (a read question, not a destination question)",
		why: "both callers password-re-verify above; this shared exit asks the second half, whether " +
			"each entry's owner admits this caller. A list query that widened by accident is refused " +
			"row by row, and strict export fails before writing a partial attachment.",
	},
	"vault.go:VaultHandler.customFieldsForCaller": {
		secret:  "every secret:true custom field of the entry being rendered",
		chooser: "the caller (a read question, not a destination question)",
		why: "THE SECOND CREDENTIAL AN ENTRY CAN HOLD, and the one the round-7 SCOPE BOUNDARY missed. " +
			"custom_fields is AES-encrypted at rest exactly like the value, a field marked secret:true " +
			"is operator-designated secret material (the UI masks it for that reason), and it left in " +
			"the same response body as the entry's own value with no destination, no chooser and no " +
			"receipt. Every response path that emits custom fields goes through here: GET, POST /unlock, " +
			"the create and update echoes, and the rotate response.",
	},
	"vault.go:VaultHandler.providerMetaForCaller": {
		secret:  "every credential-bearing provider_meta value of the entry being revealed",
		chooser: "the caller (a read question, not a destination question)",
		why: "Datadog's app_key is a second live credential rather than provider configuration. Ordinary " +
			"metadata responses remove it; password-gated unlock and export reach this function, which asks " +
			"the entry-owner authority before inserting that value into the response. Provider-scoped key " +
			"declarations keep identifiers such as key_id visible while credential values remain gated.",
	},
	"vault.go:VaultHandler.Rotate": {
		secret:  "the entry being rotated (its NEW value, returned so the operator can copy it)",
		chooser: "the caller",
		why: "a refusal here withholds the value from the response body and says so; it does not " +
			"unwind a rotation that has already committed.",
	},
	"vault.go:VaultHandler.ResolveReferences": {
		secret:  "every entry named by a {{vault:NAME}} reference",
		chooser: "supplied by the caller as an argument",
		why: "this renders a secret into arbitrary text, which is the most dangerous shape here. It " +
			"has no production caller; requiring a Destination means the first one has to answer the " +
			"owner question in the same commit that adds it.",
	},
	"service_secrets.go:ServiceSecretsHandler.FetchOwnSecrets": {
		secret:  "each entry in the identity's allowed_secrets list",
		chooser: "the caller (the user the service identity was minted by)",
		why: "allowed_secrets says which NAMES this machine identity may ask for. The exit says " +
			"whether each entry's owner admits the principal behind it.",
	},
}

// TestEveryExitIsRegistered derives the real exit set from the AST and compares
// it to theExitList.
func TestEveryExitIsRegistered(t *testing.T) {
	found, filesScanned := findExitCallSites(t, ".")

	if filesScanned < 20 {
		t.Fatalf("ABORT: only scanned %d source files; this guard is matching almost nothing", filesScanned)
	}
	if len(found) == 0 {
		t.Fatal("ABORT: found no calls to secretexit.Exit anywhere in this package. Either the exit " +
			"has been routed around entirely, or this guard's detection is broken. Both are worse " +
			"than a failing assertion")
	}

	var unregistered, stale []string
	for key := range found {
		if _, ok := theExitList[key]; !ok {
			unregistered = append(unregistered, key+" (at "+found[key]+")")
		}
	}
	for key := range theExitList {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)

	for _, k := range unregistered {
		t.Errorf("A NEW EXIT: %s calls secretexit.Exit and is not in theExitList.\n"+
			"  Every place a decrypted secret leaves this process is written down there, with WHOSE\n"+
			"  secret it is and WHO chose the destination. Those are the two facts the round-6 break\n"+
			"  hinged on and neither is visible from the call site. Add the entry, or route this\n"+
			"  through an exit that already exists.", k)
	}
	for _, k := range stale {
		t.Errorf("A STALE ENTRY: theExitList registers %s but no such call site exists.\n"+
			"  A list that describes deleted code reads as coverage and is not. Remove it.", k)
	}

	// The registration has to SAY something. An entry with empty fields is a
	// rubber stamp, and a rubber stamp is how a list stops being a control.
	for key, site := range theExitList {
		if strings.TrimSpace(site.secret) == "" || strings.TrimSpace(site.chooser) == "" ||
			len(strings.TrimSpace(site.why)) < 40 {
			t.Errorf("%s is registered without saying whose secret leaves, who chose the destination, "+
				"and why that chooser is the right one", key)
		}
	}
	t.Logf("%d exits, all registered", len(found))
}

// findExitCallSites returns "file.go:EnclosingFunc" -> "file.go:line" for every
// call to secretexit.Exit or secretexit.ExitString in dir's non-test files.
func findExitCallSites(t *testing.T, dir string) (map[string]string, int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	out := map[string]string{}
	scanned := 0
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			enclosing := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				enclosing = receiverTypeName(fn.Recv.List[0].Type) + "." + enclosing
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "secretexit" {
					return true
				}
				if sel.Sel.Name != "Exit" && sel.Sel.Name != "ExitString" {
					return true
				}
				key := name + ":" + enclosing
				if _, seen := out[key]; !seen {
					pos := fset.Position(call.Pos())
					out[key] = name + ":" + itoa(pos.Line)
				}
				return true
			})
		}
	}
	return out, scanned
}

func receiverTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestVaultHandlerIsTheOnlyProductionAuthority pins the rule to one
// implementation.
//
// secretexit.Authority is an interface only because the package must not import
// the handlers. A second production implementation is a second rule, and round 5
// is what a second copy of one rule costs: the write gate and the delivery gate
// both implemented "the creator or an instance admin" and disagreed about the
// admin half, so an admin's delivery target was accepted, reported as saved, and
// then silently never delivered.
func TestVaultHandlerIsTheOnlyProductionAuthority(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	fset := token.NewFileSet()
	var implementors []string
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "AuthorizeSecretExit" || fn.Recv == nil {
				continue
			}
			implementors = append(implementors, receiverTypeName(fn.Recv.List[0].Type)+" ("+name+")")
		}
	}
	if scanned < 20 {
		t.Fatalf("ABORT: only scanned %d files", scanned)
	}
	if len(implementors) != 1 || !strings.HasPrefix(implementors[0], "VaultHandler ") {
		t.Errorf("the owner rule has %d production implementations: %v.\n"+
			"  It must have exactly one, on VaultHandler. Two copies of one rule is round 5: both "+
			"implemented \"the creator or an instance admin\", they disagreed about the admin half, "+
			"and an admin's delivery target was accepted and then silently never delivered.",
			len(implementors), implementors)
	}
}

// TestOnlyTheAlertsPathDecryptsInstanceConfig pins the SCOPE BOUNDARY.
//
// DecryptInstanceConfig is the one door in this product that still returns raw
// bytes, and it is justified by what it opens: alert_channels.config, an
// instance-owned row written only through AdminOnly routes, belonging to no vault
// entry and therefore having no owner to ask.
//
// That justification holds only while it is used for exactly that. If a handler
// ever points it at vault_entries.encrypted_value, the exit is routed around and
// the whole construction is back to being a convention.
func TestOnlyTheAlertsPathDecryptsInstanceConfig(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	fset := token.NewFileSet()
	var callers []string
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "DecryptInstanceConfig" {
				return true
			}
			callers = append(callers, name+":"+itoa(fset.Position(call.Pos()).Line))
			return true
		})
	}
	if scanned < 20 {
		t.Fatalf("ABORT: only scanned %d files", scanned)
	}
	if len(callers) != 0 {
		t.Errorf("DecryptInstanceConfig is called from %v inside the handlers package.\n"+
			"  It is the one door left that returns raw bytes, and it is justified ONLY by what it\n"+
			"  opens: instance-owned notification-channel config, which belongs to no vault entry and\n"+
			"  so has no owner to ask. A handler calling it is either opening an entry secret through\n"+
			"  the wrong door, or has found a second case that needs its own justification written down\n"+
			"  in secret_exit_authority.go. Use VaultHandler.OpenEntrySecret for anything that came out\n"+
			"  of vault_entries.", callers)
	}
}

// TestRawAESIsReachedFromExactlyOnePlace is the last hole in "one way to open an
// entry secret".
//
// decryptWithKey is raw AES-GCM returning a bare []byte. It exists because the
// instance-config door needs it, and that door is justified by what it opens.
// VaultHandler.MigrateEncryption used to call it too, for a v1 -> v2 re-key: a
// purely in-process operation that transmits nothing, and therefore a second way
// to open an entry's value sitting in the tree for the next person to copy. It
// goes through the opaque type now.
func TestRawAESIsReachedFromExactlyOnePlace(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	fset := token.NewFileSet()
	var callers []string
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			enclosing := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				enclosing = receiverTypeName(fn.Recv.List[0].Type) + "." + enclosing
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok || id.Name != "decryptWithKey" {
					return true
				}
				callers = append(callers, name+":"+enclosing)
				return true
			})
		}
	}
	if scanned < 20 {
		t.Fatalf("ABORT: only scanned %d files", scanned)
	}
	want := []string{"vault.go:VaultHandler.DecryptInstanceConfig"}
	sort.Strings(callers)
	if len(callers) != 1 || callers[0] != want[0] {
		t.Errorf("decryptWithKey is called from %v, want exactly %v.\n"+
			"  It is raw AES returning a bare []byte. The ONE place entitled to it is the\n"+
			"  instance-config door, which is justified by what it opens: a row belonging to no\n"+
			"  vault entry. Anything that opens vault_entries.encrypted_value goes through\n"+
			"  VaultHandler.OpenEntrySecret and comes back opaque.", callers, want)
	}
}

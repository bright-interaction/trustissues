// Package declscan derives the vault-key field ledger FROM THE SOURCE.
//
// # Why this package exists
//
// internal/vaultfield made the ledger a by-product of being able to decrypt at
// all: every AES-GCM open in the vault-key family lives in one file, every open
// there demands a [vaultfield.Field], and [vaultfield.Declare] is the only
// constructor of one. That construction is right and this package does not
// replace it.
//
// What it replaces is how the GUARDS read it. vaultfield.Ledger() is a runtime
// map, filled by init-time Declare calls in whichever packages THE CURRENT
// BINARY LINKS. A test binary links what its package imports and nothing else,
// so a guard reading that map is reading a smaller world than the module, and
// the size of that world is decided by an import graph nobody is thinking about
// when they add a declaration. Put a Declare in cmd/server, or in any package
// internal/handlers does not import, and every guard over the runtime ledger
// stays green about a column it has never seen. That is the same failure as
// round 18's four call shapes, one level further out: the guard's evidence was
// narrower than its claim.
//
// The crypto-import pin does not have that problem, and the reason is worth
// copying rather than admiring: it walks the module's FILES. So does this. The
// declaration set it returns describes the whole module, in the same way, and it
// is unaffected by which package a test happens to live in.
//
// # What it does not claim
//
// It reads declarations, not linkage. A declaration in a package nothing
// imports is still in the module and is still returned, which is the point: an
// unreachable declaration is a ledger entry for a door that does not exist, and
// TestNoFieldIsDeclaredAndNeverOpened is what refuses that. The two guards want
// opposite things from the same set, and both of them want the set to be the
// module's.
//
// It also folds only what the compiler would fold: string literals and their
// concatenations, plus a class named as a selector or an identifier. Anything
// else is returned as an [Unparsed] entry rather than silently dropped, because
// a declaration a guard cannot read is a declaration a guard cannot check, and
// that has to be loud.
package declscan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ImportPath is the package this scanner recognises calls to.
const ImportPath = "github.com/bright-interaction/trustissues/internal/vaultfield"

// skipDirs are directories the walk does not descend into.
//
// testdata is skipped deliberately and load-bearing: the Go tool ignores it, so
// a declaration in there is not part of the product and must not enter the
// ledger. The fixture that proves this scanner sees code nothing links lives
// exactly there, and is reached by scanning it explicitly.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "frontend": true, "docs": true,
	"scripts": true, "testdata": true,
}

// Declaration is one vaultfield.Declare call, as it is written in the source.
type Declaration struct {
	// Name is the first argument: the column, as "table.column". Empty when the
	// argument was not a constant string, in which case Unparsed says so.
	Name string
	// Class is the class identifier AS WRITTEN ("ThroughTheExit",
	// "InProcessOnly", ...), not a vaultfield.Class. Keeping it textual is what
	// lets this package stay free of any dependency on the ledger it describes.
	Class string
	// ExitKey and Why are the third and fourth arguments, folded.
	ExitKey string
	Why     string
	// Ident is the package-level variable the declaration is bound to, empty for
	// a call that is not a simple var initialiser.
	Ident string
	// File is module-relative with forward slashes; Line is 1-based.
	File string
	Line int
	// Package is the module-relative directory the file is in.
	Package string
	// IsTest reports whether the declaring file is a _test.go file. A
	// declaration from a test satisfies a ledger in the test binary and ships
	// nothing.
	IsTest bool
	// Unparsed is non-empty when an argument could not be folded to a constant.
	// Such a declaration is REPORTED rather than dropped: a guard that cannot
	// read a declaration must say so, not skip it.
	Unparsed string
}

// At renders "file:line", the way a guard failure should name a site.
func (d Declaration) At() string { return d.File + ":" + strconv.Itoa(d.Line) }

// Scan walks the module rooted at root and returns every vaultfield.Declare
// call in it, sorted by name and then by site.
//
// It parses rather than greps, so a raw string literal, an interpreted one and
// two of either joined with + are all the same thing to it, exactly as they are
// to the compiler.
func Scan(root string) ([]Declaration, error) {
	fset := token.NewFileSet()
	var out []Declaration
	files := 0

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		files++
		decls, pErr := scanFile(fset, root, path)
		if pErr != nil {
			return pErr
		}
		out = append(out, decls...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if files == 0 {
		return nil, fmt.Errorf("declscan: no .go files under %s, so the scan is reading nothing", root)
	}
	sortDeclarations(out)
	return out, nil
}

// ScanDir is Scan without the skip list, for pointing at ONE directory on
// purpose. It is how the guards read a testdata fixture: code the Go tool never
// builds, and therefore code no binary can link.
func ScanDir(root, dir string) ([]Declaration, error) {
	fset := token.NewFileSet()
	entries, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var out []Declaration
	for _, path := range entries {
		decls, pErr := scanFile(fset, root, path)
		if pErr != nil {
			return nil, pErr
		}
		out = append(out, decls...)
	}
	sortDeclarations(out)
	return out, nil
}

func sortDeclarations(out []Declaration) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].At() < out[j].At()
	})
}

func scanFile(fset *token.FileSet, root, path string) ([]Declaration, error) {
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("declscan: parse %s: %w", path, err)
	}

	// The local name for the vaultfield import, which is what a call has to be
	// spelled with. A file that does not import it cannot call Declare, with one
	// exception: vaultfield itself, where the call would be unqualified. It
	// makes none, and if it ever did, selfPkg below picks it up.
	local, imported := localName(f)
	selfPkg := f.Name.Name == "vaultfield"
	if !imported && !selfPkg {
		return nil, nil
	}

	rel := relative(root, path)
	pkgDir := filepath.ToSlash(filepath.Dir(rel))
	isTest := strings.HasSuffix(rel, "_test.go")

	var out []Declaration
	// Two passes: named var initialisers first, so a declaration can carry the
	// identifier it is bound to, then every remaining call so a Declare used as
	// a bare expression is not invisible.
	bound := map[token.Pos]string{}
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
				if call, ok := vs.Values[i].(*ast.CallExpr); ok {
					bound[call.Pos()] = name.Name
				}
			}
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isDeclareCall(call, local, imported, selfPkg) {
			return true
		}
		pos := fset.Position(call.Pos())
		d := Declaration{
			Ident:   bound[call.Pos()],
			File:    rel,
			Line:    pos.Line,
			Package: pkgDir,
			IsTest:  isTest,
		}
		if len(call.Args) != 4 {
			d.Unparsed = fmt.Sprintf("Declare takes 4 arguments and this call has %d", len(call.Args))
			out = append(out, d)
			return true
		}
		var bad []string
		if s, ok := foldString(call.Args[0]); ok {
			d.Name = s
		} else {
			bad = append(bad, "name is not a constant string")
		}
		if s, ok := foldClass(call.Args[1]); ok {
			d.Class = s
		} else {
			bad = append(bad, "class is not a named constant")
		}
		if s, ok := foldString(call.Args[2]); ok {
			d.ExitKey = s
		} else {
			bad = append(bad, "exit key is not a constant string")
		}
		if s, ok := foldString(call.Args[3]); ok {
			d.Why = s
		} else {
			bad = append(bad, "reason is not a constant string")
		}
		d.Unparsed = strings.Join(bad, "; ")
		out = append(out, d)
		return true
	})
	return out, nil
}

// isDeclareCall reports whether this call is vaultfield.Declare, under whatever
// name the file imported the package as.
func isDeclareCall(call *ast.CallExpr, local string, imported, selfPkg bool) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if fun.Sel.Name != "Declare" {
			return false
		}
		id, ok := fun.X.(*ast.Ident)
		return ok && imported && id.Name == local
	case *ast.Ident:
		return selfPkg && fun.Name == "Declare"
	}
	return false
}

// localName returns the identifier the file refers to internal/vaultfield by.
func localName(f *ast.File) (string, bool) {
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil || p != ImportPath {
			continue
		}
		if spec.Name != nil {
			if spec.Name.Name == "_" || spec.Name.Name == "." {
				// A blank or dot import cannot spell vaultfield.Declare in the
				// blank case, and in the dot case the call is unqualified. The
				// module has neither; saying so is cheaper than pretending to
				// handle it.
				return spec.Name.Name, false
			}
			return spec.Name.Name, true
		}
		return "vaultfield", true
	}
	return "", false
}

// foldString folds a compile-time-constant string expression: a literal, or
// literals joined with +. That is every spelling the declarations use, and it is
// what the compiler itself folds.
func foldString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, ok := foldString(v.X)
		if !ok {
			return "", false
		}
		r, ok := foldString(v.Y)
		if !ok {
			return "", false
		}
		return l + r, true
	case *ast.ParenExpr:
		return foldString(v.X)
	}
	return "", false
}

// foldClass reads the class as it is written: vaultfield.ThroughTheExit from
// outside the package, ThroughTheExit from inside it.
func foldClass(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name, true
	case *ast.Ident:
		return v.Name, true
	case *ast.ParenExpr:
		return foldClass(v.X)
	}
	return "", false
}

func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

package declscan_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/vaultfield"
	"github.com/bright-interaction/trustissues/internal/vaultfield/declscan"
)

// moduleRoot is three levels up from internal/vaultfield/declscan.
func moduleRoot() string { return filepath.Join("..", "..", "..") }

// TestTheScannerReadsTheModuleAndNotItsOwnLinkage is the property this package
// exists for.
//
// The old ledger was vaultfield.Ledger(), a runtime map filled by init-time
// Declare calls in whichever packages the CURRENT BINARY links. Every guard
// over it therefore described the import graph of one test binary and claimed to
// describe the module. This scan describes the module.
func TestTheScannerReadsTheModuleAndNotItsOwnLinkage(t *testing.T) {
	decls, err := declscan.Scan(moduleRoot())
	if err != nil {
		t.Fatalf("scan module: %v", err)
	}
	if len(decls) < 12 {
		t.Fatalf("ABORT: the scan found only %d declarations; at least twelve exist, so it is not "+
			"reading the source", len(decls))
	}
	for _, d := range decls {
		if d.Unparsed != "" {
			t.Errorf("%s declares a field this scan cannot read (%s).\n"+
				"  A declaration a guard cannot parse is a declaration a guard cannot check. Pass the "+
				"column, the class, the exit key and the reason as constants.", d.At(), d.Unparsed)
		}
	}

	// The scan must not pick up the testdata fixture. If it did, a column
	// nothing compiles would be in the product's ledger.
	for _, d := range decls {
		if strings.Contains(d.File, "testdata/") {
			t.Errorf("the module scan returned %s from %s. testdata is not the product, and a fixture "+
				"in the ledger is a claim about a door that cannot exist", d.Name, d.At())
		}
	}
}

// TestTheScanSeesADeclarationNoBinaryCanContain is the permanent version of the
// ablation.
//
// The fixture lives under testdata, which the Go toolchain ignores entirely, so
// it is not merely unlinked by this test binary, it is unlinkable by every
// binary. A source-derived ledger finds it. A runtime one cannot. That gap is
// the defect this package closes, stated as an assertion rather than as a
// paragraph.
func TestTheScanSeesADeclarationNoBinaryCanContain(t *testing.T) {
	const fixtureColumn = "testdata_unlinked.never_built"

	fixture := filepath.Join("testdata", "unlinked")
	decls, err := declscan.ScanDir(moduleRoot(), fixture)
	if err != nil {
		t.Fatalf("scan %s: %v", fixture, err)
	}
	var found *declscan.Declaration
	for i := range decls {
		if decls[i].Name == fixtureColumn {
			found = &decls[i]
		}
	}
	if found == nil {
		t.Fatalf("the scan of %s did not find %s. Either the fixture moved or the scanner stopped "+
			"reading code it cannot link, which is the entire difference it exists to have. Found: %v",
			fixture, fixtureColumn, names(decls))
	}
	if found.Class != "InProcessOnly" {
		t.Errorf("the fixture declaration was read with class %q, want InProcessOnly", found.Class)
	}
	if found.Ident != "UnlinkedField" {
		t.Errorf("the fixture declaration was bound to %q, want UnlinkedField", found.Ident)
	}

	// THE CONTROL. If the runtime ledger could see it too, this test would be
	// proving nothing about the difference between the two mechanisms.
	if _, ok := vaultfield.Lookup(fixtureColumn); ok {
		t.Fatalf("vaultfield.Ledger() contains %s, which lives under testdata and cannot be compiled "+
			"into any binary. Either testdata stopped being ignored or this fixture was moved into the "+
			"build, and either way the control this test rests on is gone", fixtureColumn)
	}
}

// TestTheScannerFoldsTheSpellingsTheModuleActuallyUses keeps the parser honest
// about the shapes it has to read. Every real declaration writes its reason as
// a chain of concatenated literals, so a folder that only handled a single
// literal would return an Unparsed for all of them and the guards above would
// fail for the wrong reason.
func TestTheScannerFoldsTheSpellingsTheModuleActuallyUses(t *testing.T) {
	decls, err := declscan.Scan(moduleRoot())
	if err != nil {
		t.Fatalf("scan module: %v", err)
	}
	concatenated, exits := 0, 0
	for _, d := range decls {
		if len(d.Why) > 120 {
			concatenated++
		}
		if d.Class == "ThroughTheExit" {
			exits++
			if d.ExitKey == "" {
				t.Errorf("%s is through-the-exit and the scan read no exit key", d.At())
			}
		}
	}
	if concatenated < 5 {
		t.Fatalf("ABORT: only %d declarations came back with a reason longer than 120 characters. The "+
			"module writes those as concatenated literals, so this says the folder is not folding",
			concatenated)
	}
	if exits < 2 {
		t.Fatalf("ABORT: the scan found %d through-the-exit declarations; two are known to exist", exits)
	}
}

func names(decls []declscan.Declaration) []string {
	out := make([]string, 0, len(decls))
	for _, d := range decls {
		out = append(out, d.Name)
	}
	return out
}

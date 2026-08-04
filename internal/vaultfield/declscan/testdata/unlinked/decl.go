// Package unlinked is a FIXTURE, and the whole point of it is that nothing can
// link it.
//
// It lives under testdata, which the Go tool ignores completely: it is never
// compiled, never vetted and never part of any binary. So a declaration in here
// can appear in a source-derived ledger and cannot possibly appear in a runtime
// one, which is exactly the difference the guards need to be able to prove.
//
// It exists because the previous ledger was a runtime map filled by init-time
// Declare calls in whichever packages the current binary happened to link, and
// a guard reading that map could be green about a column in a package it never
// imported. Asserting that the scanner finds THIS file is asserting the thing
// that used to be false.
package unlinked

import "github.com/bright-interaction/trustissues/internal/vaultfield"

// UnlinkedField is a declaration no binary in this module contains.
var UnlinkedField = vaultfield.Declare(
	"testdata_unlinked.never_built", vaultfield.InProcessOnly, "",
	"a fixture column that exists only under testdata, so it is visible to a scan of the module source "+
		"and invisible to vaultfield.Ledger() in every binary. Nothing decrypts it because nothing "+
		"compiles this file.")

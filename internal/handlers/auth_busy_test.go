package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCapacityErrorIsNeverAFailedLoginAttempt pins a contract that was written
// down and never checked.
//
// passwordhash/cost_test.go says, in a comment: "login must surface ErrBusy as 503
// and NOT as a failed attempt, or an attacker saturating the hash semaphore could
// drive any account to its lockout threshold without guessing anything." That is
// exactly right, and nothing verified it. An ablation that disabled the ErrBusy
// branch in auth.go, so capacity exhaustion fell through to recordFailure and a
// 401, passed the whole suite.
//
// The attack needs no credentials: saturate the semaphore, spray logins at a
// victim's address, and the account locks out on server-capacity errors. An
// availability problem converted into a denial of access.
//
// Checked positionally rather than by driving a request, and that choice is the
// point. Reaching ErrBusy through the handler means saturating an unexported
// semaphore from another package, which would mean adding exported slot-juggling
// seams to a security-sensitive package purely for one test. The property at stake
// is an ORDERING (classify capacity BEFORE counting a failure, and return), which a
// positional check states directly. Same reasoning and same technique as
// TestNothingReachesThePoolInsideATransaction.
//
// Testing the passwordhash contract alone is precisely what left this open, so the
// assertion belongs here, where the decision is made.
func TestCapacityErrorIsNeverAFailedLoginAttempt(t *testing.T) {
	// EVERY file, not just auth.go.
	//
	// Scoped to auth.go this guard found the TOTPDisable door and stopped. Three
	// more sat in vault.go: the reauth gates, whose recordReauthFailure writes the
	// same login_attempts rows that reauthLocked counts for a lockout. Five doors on
	// one property, and a guard that looks at one file can only ever find the doors
	// in that file.
	files, gErr := filepath.Glob("*.go")
	if gErr != nil {
		t.Fatalf("glob: %v", gErr)
	}

	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}

			// Only functions that both verify a password and count failures.
			var busyPos, firstFailurePos token.Pos
			var busyReturns bool
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				// if errors.Is(verifyErr, passwordhash.ErrBusy) { ... }
				// The shared helper, or a hand-rolled ErrBusy test. The helper is
				// preferred (one decision, six callers) but either satisfies the rule.
				if ifs, ok := m.(*ast.IfStmt); ok && (mentionsErrBusy(ifs.Cond) || callsCapacityHelper(ifs.Cond)) {
					if !busyPos.IsValid() {
						busyPos = ifs.Pos()
						busyReturns = blockReturns(ifs.Body)
					}
				}
				// Anything that counts an attempt toward a lockout.
				if call, ok := m.(*ast.CallExpr); ok {
					switch fn := call.Fun.(type) {
					case *ast.Ident:
						if fn.Name == "recordFailure" && !firstFailurePos.IsValid() {
							firstFailurePos = call.Pos()
						}
					case *ast.SelectorExpr:
						if fn.Sel.Name == "recordReauthFailure" && !firstFailurePos.IsValid() {
							firstFailurePos = call.Pos()
						}
					}
				}
				return true
			})

			if !firstFailurePos.IsValid() {
				return true
			}
			checked++

			if !busyPos.IsValid() {
				t.Errorf("%s: %s counts failed login attempts but never classifies passwordhash.ErrBusy.\n"+
					"A server-capacity error would be recorded as a wrong password, which lets anyone "+
					"saturating the hash semaphore lock out any account without guessing.",
					fset.Position(firstFailurePos), fn.Name.Name)
				return true
			}
			if busyPos > firstFailurePos {
				t.Errorf("%s: the ErrBusy check sits AFTER the first recordFailure at %s in %s.\n"+
					"Order is the whole contract: capacity has to be classified before anything is "+
					"counted against the account.",
					fset.Position(busyPos), fset.Position(firstFailurePos), fn.Name.Name)
			}
			if !busyReturns {
				t.Errorf("%s: the ErrBusy branch in %s does not return.\n"+
					"Falling through reaches recordFailure anyway, so the 503 is cosmetic.",
					fset.Position(busyPos), fn.Name.Name)
			}
			return true
		})
	}

	// Fail closed. If the login handler is renamed, moved, or stops counting
	// attempts, this guard silently stops asserting anything.
	if checked == 0 {
		t.Fatal("ABORT: found no function in this package that records a failed login or " +
			"re-auth attempt; this guard is vacuous (did the handlers move, or did " +
			"recordFailure / recordReauthFailure get renamed?)")
	}
	t.Logf("checked %d login path(s) that count failed attempts", checked)
}

// mentionsErrBusy reports whether an expression tests passwordhash.ErrBusy.
func mentionsErrBusy(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "ErrBusy" {
			found = true
		}
		return !found
	})
	return found
}

// blockReturns reports whether a block ends the request, by return or by panic.
func blockReturns(b *ast.BlockStmt) bool {
	if b == nil {
		return false
	}
	for _, st := range b.List {
		switch s := st.(type) {
		case *ast.ReturnStmt:
			return true
		case *ast.ExprStmt:
			if call, ok := s.X.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && strings.EqualFold(id.Name, "panic") {
					return true
				}
			}
		}
	}
	return false
}

// callsCapacityHelper reports whether a condition routes through the shared
// capacityExhausted responder.
func callsCapacityHelper(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "capacityExhausted" {
				found = true
			}
		}
		return !found
	})
	return found
}

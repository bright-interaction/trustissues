package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every auto-rotating provider must declare what happens to the key it replaces, and
// the declaration must match the code.
//
// The product's promise is "the old key is dead and the new one works". Nine adapters
// mint a successor and leave the predecessor live, and the rotation is still recorded as
// a clean success with no alert, because the orchestration layer only knows about a
// revoke that was QUEUED. An operator rotating a credential they believe is compromised
// is told it worked while the compromised key still authenticates.
//
// Whether each SHOULD revoke is a per-vendor API question this repo cannot settle, so
// the table does not guess. What it does is make the gap explicit, force a new provider
// to decide, and surface the answer through ListProviders so the UI can tell the
// operator what a rotation does and does not do. Silence was the defect; the table is
// the fix.
func TestEveryAutoRotatingProviderDeclaresPredecessorFate(t *testing.T) {
	for name, p := range ProviderRegistry {
		if !p.CanAutoRotate() {
			continue
		}
		fate, ok := predecessorFate[name]
		if !ok {
			t.Errorf("provider %q auto-rotates but does not declare what happens to the key it "+
				"replaces. Add it to predecessorFate: fateRevokes if rotation destroys the "+
				"predecessor, fateLeavesLive/fateNotApplicable/fateUnknown with a note otherwise. "+
				"An undeclared provider silently reports a clean success while both keys stay "+
				"live.", name)
			continue
		}
		if fate.Status != fateRevokes && strings.TrimSpace(fate.Note) == "" {
			t.Errorf("provider %q declares it does NOT revoke the predecessor but gives no reason. "+
				"Either it is a local secret (fateNotApplicable), a confirmed vendor behavior "+
				"(fateLeavesLive), or an open gap (fateUnknown with a TODO saying what to check).", name)
		}
	}
}

// TestPredecessorFateMatchesTheCode keeps the declaration honest.
//
// A table that drifts from the adapters is worse than no table: it would tell an
// operator a predecessor is destroyed when it is not. So the claim is checked against
// whether the provider's Rotate actually queues a revoke.
//
// codeRevokes used to also accept a bare "RevokeOldKey"/"revokeOldKey" substring,
// which is how this test kept passing while Backblaze called backblazeRevokeOldKey
// INLINE, before the caller had persisted the new value: the table said "revokes:
// true" and the substring matched, so the test never noticed that the revoke ran at
// the wrong time, only that a revoke-shaped call existed somewhere in the body. It
// checks ONLY for the deferred call now, so a provider that reverts to revoking
// inline (Backblaze or a new adapter making the same mistake) fails HERE, not just in
// TestNoProviderRevokesBeforeReturning, which asserts the same property a different
// way. A table entry of `Revokes: true` now means, specifically, "Rotate queues a
// deferred revoke", not merely "some revoke-sounding call is reachable from Rotate".
func TestPredecessorFateMatchesTheCode(t *testing.T) {
	src, err := os.ReadFile("vault_providers.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	body := string(src)

	rotateRe := regexp.MustCompile(`(?s)func \(p \*(\w+)\) Rotate\(ctx context\.Context.*?\n\}\n`)
	// A full-line comment is prose, not a call. Stripping it is what makes the
	// checks below falsifiable; see codeRevokes for the bug that proved it.
	commentLine := regexp.MustCompile(`(?m)^\s*//.*$`)
	nameRe := func(typ string) string {
		m := regexp.MustCompile(`func \(p \*` + typ + `\) Name\(\) string\s*\{?\s*return "([^"]+)"`).FindStringSubmatch(body)
		if len(m) == 2 {
			return m[1]
		}
		return ""
	}

	checked := 0
	for _, m := range rotateRe.FindAllStringSubmatch(body, -1) {
		typ, rot := m[1], m[0]
		name := nameRe(typ)
		if name == "" {
			continue
		}
		p, ok := ProviderRegistry[name]
		if !ok || !p.CanAutoRotate() {
			continue
		}
		fate, declared := predecessorFate[name]
		if !declared {
			continue // the test above already reports this
		}
		checked++

		// Two defenses, because the first version of this tightened check was vacuous
		// for the ONE provider it was written to protect. Backblaze's Rotate carries a
		// comment explaining the deferred-revoke fix, and that comment contains the
		// literal "deferRevokeOldProviderKey". A bare substring match over the raw body
		// therefore reported codeRevokes=true for Backblaze no matter what the code did:
		// replacing the real deferred call with the old INLINE backblazeRevokeOldKey left
		// this test green, and only TestNoProviderRevokesBeforeReturning and
		// TestBackblazeCASConflictLeavesThePredecessorLive caught the regression. So:
		// strip full-line comments, and require the call syntax rather than the bare name.
		code := commentLine.ReplaceAllString(rot, "")
		codeRevokes := strings.Contains(code, "deferRevokeOldProviderKey(")

		if fate.Status == fateRevokes && !codeRevokes {
			t.Errorf("%s (%s) is declared as revoking its predecessor, but its Rotate does not queue "+
				"a DEFERRED revoke (deferRevokeOldProviderKey). The table would tell an operator the "+
				"old key is dead when it is live, or (if some other revoke-shaped call is present) "+
				"live only until a CAS conflict destroys it before the new value is ever stored.",
				name, typ)
		}
		// The RevokeOldKey/revokeOldKey substrings are deliberately still checked HERE, on
		// the "declared as not revoking" side, even though codeRevokes no longer accepts
		// them: an adapter that revokes inline is both a mis-declaration AND the CAS bug,
		// and dropping the substrings here would let it pass this direction silently.
		if fate.Status != fateRevokes && (codeRevokes || strings.Contains(code, "RevokeOldKey") || strings.Contains(code, "revokeOldKey")) &&
			!strings.Contains(fate.Note, "local secret") {
			t.Errorf("%s (%s) DOES revoke its predecessor but is declared as not doing so; the UI "+
				"would understate what rotation achieves.", name, typ)
		}
	}

	// Fail closed: if the regex stops matching, this guard silently checks nothing.
	if checked < 8 {
		t.Fatalf("ABORT: only %d auto-rotating providers were cross-checked against the source; "+
			"the Rotate matcher has probably drifted and this guard is vacuous", checked)
	}
	t.Logf("cross-checked %d auto-rotating providers against their Rotate bodies", checked)
}

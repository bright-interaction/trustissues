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
				"replaces. Add it to predecessorFate: true if rotation revokes the predecessor, "+
				"false with a note saying why not. An undeclared provider silently reports a "+
				"clean success while both keys stay live.", name)
			continue
		}
		if !fate.Revokes && strings.TrimSpace(fate.Note) == "" {
			t.Errorf("provider %q declares it does NOT revoke the predecessor but gives no reason. "+
				"Either it is a local secret (say so) or it is an open gap (say TODO and what to "+
				"check).", name)
		}
	}
}

// TestPredecessorFateMatchesTheCode keeps the declaration honest.
//
// A table that drifts from the adapters is worse than no table: it would tell an
// operator a predecessor is destroyed when it is not. So the claim is checked against
// whether the provider's Rotate actually queues or performs a revoke.
func TestPredecessorFateMatchesTheCode(t *testing.T) {
	src, err := os.ReadFile("vault_providers.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	body := string(src)

	rotateRe := regexp.MustCompile(`(?s)func \(p \*(\w+)\) Rotate\(ctx context\.Context.*?\n\}\n`)
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

		codeRevokes := strings.Contains(rot, "deferRevokeOldProviderKey") ||
			strings.Contains(rot, "RevokeOldKey") ||
			strings.Contains(rot, "revokeOldKey")

		// A provider in predecessorDestroysInPlace revokes as an INSEPARABLE part
		// of its mint call (e.g. Cloudflare's rollToken replaces the token value
		// under the same id): there is no separate revoke/delete call for this
		// substring heuristic to find, by design. That claim is checked against
		// the vendor docs cited in the table's Note instead of against the source.
		if fate.Revokes && !codeRevokes && !predecessorDestroysInPlace[name] {
			t.Errorf("%s (%s) is declared as revoking its predecessor, but its Rotate neither queues "+
				"nor performs a revoke. The table would tell an operator the old key is dead when "+
				"it is live.", name, typ)
		}
		if !fate.Revokes && codeRevokes && !strings.Contains(fate.Note, "local secret") {
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

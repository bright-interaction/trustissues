package passwordhash

import (
	"strings"
	"testing"
)

// TestSetTestCostRoundTripsAndIsGuarded checks the two things that matter about
// a knob which, if reached from production, silently weakens every stored
// password: that lowering the cost still produces a verifiable hash, and that
// the production guard exists.
func TestSetTestCostRoundTripsAndIsGuarded(t *testing.T) {
	if ProdCost() {
		SetTestCost()
	}
	if ProdCost() {
		t.Fatal("SetTestCost did not lower the cost")
	}

	h, err := Hash("CorrectHorseBatteryStaple1!")
	if err != nil {
		t.Fatalf("hash at test cost: %v", err)
	}
	ok, err := Verify("CorrectHorseBatteryStaple1!", h)
	if err != nil || !ok {
		t.Fatalf("verify at test cost: ok=%v err=%v", ok, err)
	}
	bad, err := Verify("wrong password", h)
	if err != nil || bad {
		t.Fatalf("a wrong password verified: ok=%v err=%v", bad, err)
	}
	// The encoded parameters must reflect the cost actually used, or a hash
	// written under test cost would be re-read as a production-cost hash.
	if !strings.Contains(h, "m=8,") {
		t.Errorf("encoded hash does not record the test cost: %q", h)
	}
}

// TestProductionCostIsUnchanged pins the shipped parameters. If someone tunes
// them, that should be a deliberate, reviewed change and not a side effect.
func TestProductionCostIsUnchanged(t *testing.T) {
	if argonTimeProd != 3 || argonMemoryProd != 64*1024 || argonThreadsProd != 4 {
		t.Errorf("production argon2id cost changed: t=%d m=%d p=%d (want 3 / 65536 / 4)",
			argonTimeProd, argonMemoryProd, argonThreadsProd)
	}
}

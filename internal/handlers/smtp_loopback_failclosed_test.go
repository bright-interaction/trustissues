package handlers

import "testing"

// isLoopbackSMTPHost is the other net.ParseIP call site the P0-4 primitive sweep
// allowlisted as fail-CLOSED. The allowlist row in
// parseip_primitive_guard_test.go names this test.
//
// The claim: the function is permissive-on-TRUE. Returning true is the only
// thing that waives the TLS requirement, for a local mail catcher or sidecar
// relay. net.ParseIP returning nil yields false, so a zoned host is treated as
// remote and TLS stays mandatory. nil is therefore the strict answer here, which
// is the exact opposite of the capability-ceiling site where nil SKIPPED the
// rejection.

// TestIsLoopbackSMTPHostFailsClosed pins the direction of the nil result.
func TestIsLoopbackSMTPHostFailsClosed(t *testing.T) {
	// Positive control: the function must still recognise a real local relay,
	// or "always false" would pass every assertion below while breaking the
	// local mail catcher it exists for.
	for _, h := range []string{"localhost", "LocalHost", " localhost ", "127.0.0.1", "::1"} {
		if !isLoopbackSMTPHost(h) {
			t.Fatalf("control failed: %q is a local relay and must waive TLS; the function is "+
				"answering false to everything, so this test proves nothing", h)
		}
	}

	// Zoned and otherwise unparseable spellings. net.ParseIP returns nil for all
	// of these; false is the required answer, so TLS is still enforced.
	waived := []string{
		"::1%1",
		"::1%lo0",
		"[::1]",
		"::ffff:127.0.0.1%1",
		"relay.example.com",
		"169.254.169.254",
		"not-an-address",
	}
	for _, h := range waived {
		if isLoopbackSMTPHost(h) {
			t.Errorf("isLoopbackSMTPHost(%q) = true, so the TLS requirement would be WAIVED for it. "+
				"Only a host proven to be on this machine may waive TLS; anything net.ParseIP "+
				"cannot classify must stay remote.", h)
		}
	}
}

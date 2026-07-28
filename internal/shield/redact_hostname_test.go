package shield

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestIdentifiersAreNotHostnames locks the fix for a bug that made the AI
// gateway useless for its documented purpose.
//
// The hostname pattern required the final label to be 2..63 letters, which is
// also the shape of nearly every dotted code identifier. So a developer pointing
// their SDK at the gateway and asking about strings.HasPrefix shipped Anthropic
// a prompt where every identifier was an opaque [shield:hostname:tok_...].
//
// It is not self-correcting either: the model answers about nothing, writes the
// real name back in its reply, UnshieldJSON passes that through untouched, and
// the caller sees a confident but unrelated answer with no sign their prompt was
// rewritten. They are billed for the mangled prompt.
func TestIdentifiersAreNotHostnames(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)

		identifiers := []string{
			"strings.HasPrefix", "strings.EqualFold", "json.Unmarshal", "fmt.Errorf",
			"console.error", "np.array", "React.useEffect", "res.json", "u.id",
			"ctx.Done", "http.StatusOK", "time.Now", "os.Getenv", "db.Query",
			"self.value", "this.state", "err.Error", "sql.NullString",
		}
		for _, id := range identifiers {
			out, err := s.RedactString(ctx, "Use "+id+" here")
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			if !strings.Contains(out, id) {
				t.Errorf("code identifier %q was tokenized as a hostname: %q\n"+
					"the provider cannot see which symbol is being discussed and answers about nothing", id, out)
			}
		}
	})
}

// TestRealHostnamesStillTokenize is the other half. A guard that fixes the false
// positives by tokenizing nothing would "pass" the test above while silently
// turning off hostname shielding, so the negation has to be asserted too.
func TestRealHostnamesStillTokenize(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)

		hosts := []string{
			"crm.example.com", "host.internal", "trustissues.brightinteraction.com",
			"api.stripe.com", "db01.corp.local", "foo.se", "svc.cluster.lan",
			"registry.example.io", "mail.example.dev",
		}
		for _, h := range hosts {
			out, err := s.RedactString(ctx, "Connect to "+h+" now")
			if err != nil {
				t.Fatalf("%s: %v", h, err)
			}
			if strings.Contains(out, h) {
				t.Errorf("hostname %q was NOT tokenized and egressed verbatim to the LLM provider: %q", h, out)
			}
			if !strings.Contains(out, "[shield:hostname:") {
				t.Errorf("hostname %q produced no shield marker: %q", h, out)
			}
		}
	})
}

// TestFilenamesStillSkipped guards the pre-existing behaviour the new positive
// test could otherwise have replaced.
func TestFilenamesStillSkipped(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)

		for _, f := range []string{"config.json", "main.go", "docker-compose.yml", "index.tsx", "notes.md"} {
			out, err := s.RedactString(ctx, "Open "+f+" please")
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if !strings.Contains(out, f) {
				t.Errorf("filename %q was tokenized as a hostname: %q", f, out)
			}
		}
	})
}

// TestHostnameGuardDoesNotWeakenOtherKinds proves the change is scoped to the
// hostname pattern. The valuable kinds match on their own shape, and a guard
// bug that let one through would be a real leak rather than a broken prompt.
func TestHostnameGuardDoesNotWeakenOtherKinds(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)

		for _, tc := range []struct{ name, in, leak string }{
			{"email", "write to anna.andersson@example.com about it", "anna.andersson@example.com"},
			{"personnummer", "the number is 19850101-1234 ok", "19850101-1234"},
			{"ipv4", "server at 192.168.1.10 responds", "192.168.1.10"},
			// Real Stripe key shapes. sk_live_/sk_test_ were NOT matched before
			// this round: the generic sk_[A-Za-z0-9]{8,} alternative stops at the
			// underscore, so every production Stripe secret reached the provider
			// verbatim while the pattern looked like it covered the prefix.
			{"stripe secret live", "token sk_live_51HabcdefgABCDEFG leaked", "sk_live_51HabcdefgABCDEFG"},
			{"stripe secret test", "token sk_test_abcd1234efgh leaked", "sk_test_abcd1234efgh"},
			{"stripe restricted", "token rk_live_abcd1234efgh leaked", "rk_live_abcd1234efgh"},
			{"generic sk", "token sk_abcdefgh12345 leaked", "sk_abcdefgh12345"},
			{"github pat", "token ghp_a123456789012345678901 leaked", "ghp_a123456789012345678901"},
		} {
			out, err := s.RedactString(ctx, tc.in)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if strings.Contains(out, tc.leak) {
				t.Errorf("%s egressed verbatim after the hostname change: %q", tc.name, out)
			}
		}
	})
}

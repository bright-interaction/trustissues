package shield

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRedactStringPatterns(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)
		cases := []struct {
			name     string
			in       string
			mustGone []string
			mustHave []string
		}{
			{"email", "Reach me at anna@example.se for details",
				[]string{"anna@example.se"}, []string{"[shield:email:tok_"}},
			{"phone_se", "Call +46 70 123 45 67 for support",
				[]string{"+46 70 123 45 67"}, []string{"[shield:phone:tok_"}},
			{"personnummer", "PNR is 19850315-1234, take note",
				[]string{"19850315-1234"}, []string{"[shield:personnummer:tok_"}},
			{"iban", "IBAN SE3550000000054910000003",
				[]string{"SE3550000000054910000003"}, []string{"[shield:iban:tok_"}},
			{"mixed_email_and_phone",
				"Email anna@example.se or call +46701234567 today",
				[]string{"anna@example.se", "+46701234567"},
				[]string{"[shield:email:tok_", "[shield:phone:tok_"}},
			{"ipv4", "Server at 203.0.113.10 is up",
				[]string{"203.0.113.10"}, []string{"[shield:ip:tok_"}},
			{"ipv6_compressed", "agent reached fe80::1 ok",
				[]string{"fe80::1"}, []string{"[shield:ip:tok_"}},
			{"hostname", "visit crm.example.com now",
				[]string{"crm.example.com"}, []string{"[shield:hostname:tok_"}},
			{"secret_prefix", "token ak_live_8f3c2a1b9d4e was found",
				[]string{"ak_live_8f3c2a1b9d4e"}, []string{"[shield:secret:tok_"}},
			{"ssh_fingerprint", "key SHA256:" + strings.Repeat("a", 43) + " present",
				[]string{"SHA256:" + strings.Repeat("a", 43)}, []string{"[shield:sshfp:tok_"}},
			{"filename_not_hostname",
				"edit main.go and config.json and docker-compose.yml",
				[]string{}, []string{}},
			{"no_pii_passthrough",
				"The deal stage is qualified and the next action is review",
				[]string{}, []string{}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				out, err := s.RedactString(ctx, tc.in)
				if err != nil {
					t.Fatalf("RedactString: %v", err)
				}
				for _, gone := range tc.mustGone {
					if strings.Contains(out, gone) {
						t.Errorf("output still contains raw %q: %q", gone, out)
					}
				}
				for _, have := range tc.mustHave {
					if !strings.Contains(out, have) {
						t.Errorf("output missing expected marker %q: %q", have, out)
					}
				}
				if len(tc.mustHave) == 0 && out != tc.in {
					t.Errorf("expected passthrough but got transformation: in=%q out=%q", tc.in, out)
				}
			})
		}
	})
}

func TestRedactStringResolves(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)
		in := "ping anna@example.se when ready"
		redacted, err := s.RedactString(ctx, in)
		if err != nil {
			t.Fatalf("RedactString: %v", err)
		}
		out, err := s.UnshieldString(ctx, redacted)
		if err != nil {
			t.Fatalf("UnshieldString: %v", err)
		}
		if out != in {
			t.Fatalf("redact -> unshield mismatch:\nwant %q\n got %q", in, out)
		}
	})
}

func TestRedactStringResolvesInfra(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)
		in := "server 203.0.113.10 host crm.example.com fp SHA256:" + strings.Repeat("b", 43)
		redacted, err := s.RedactString(ctx, in)
		if err != nil {
			t.Fatalf("RedactString: %v", err)
		}
		if strings.Contains(redacted, "203.0.113.10") || strings.Contains(redacted, "crm.example.com") {
			t.Fatalf("infra identifiers leaked through redaction: %q", redacted)
		}
		out, err := s.UnshieldString(ctx, redacted)
		if err != nil {
			t.Fatalf("UnshieldString: %v", err)
		}
		if out != in {
			t.Fatalf("infra redact -> unshield mismatch:\nwant %q\n got %q", in, out)
		}
	})
}

func TestRedactStringIdempotent(t *testing.T) {
	runOnAllStores(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		s, _ := NewSession(ctx, store, "id", testKey(), time.Minute, HintFull)
		in := "Email anna@example.se about the deal"
		once, err := s.RedactString(ctx, in)
		if err != nil {
			t.Fatalf("first redact: %v", err)
		}
		twice, err := s.RedactString(ctx, once)
		if err != nil {
			t.Fatalf("second redact: %v", err)
		}
		if once != twice {
			t.Fatalf("redact not idempotent on already-redacted text:\n once: %q\ntwice: %q", once, twice)
		}
	})
}

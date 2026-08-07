package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// THE THIRD ORACLE, CLOSED AT THE RESPONSE, KEPT AT THE LOG.
//
// POST /api/vault/{id}/validate authenticates the DECRYPTED key against the
// provider a caller's own entry names, and used to write provider.Validate's
// raw transport error straight into the response body. Any authenticated
// caller, including the vault_only role the public invite-redeem endpoint
// hands out, can create their own entry with provider "forgejo" and
// provider_meta.instance pointed at any host, POST validate with their own
// password, and read back one of three DIFFERENT answers depending on what
// that host actually is:
//
//   - it resolves to a private address: GuardedWebhookClient's dial control
//     names the RESOLVED address ("blocked outbound to private address
//     10.0.1.42:8500")
//   - it does not resolve at all: "no such host"
//   - it resolves publicly but nothing answers: "connection refused" (or
//     times out)
//
// That is a DNS resolver and a connect scanner for the server's own network,
// with no rate limit beyond the caller's own reauth password. This test
// proves the three responses are now IDENTICAL (the oracle is closed) while
// the server's own log still says which one actually happened (an operator
// debugging a real outage loses nothing).
//
// oracleTransport swaps in for providerHTTP so the test needs no real DNS or
// TCP: it inspects the request host and manufactures exactly the transport
// failure each case is named for, deterministically and hermetically.
type oracleTransport struct{}

func (oracleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Hostname() {
	case "private.internal.example":
		// The literal shape GuardedWebhookClient's dial Control returns
		// (internal/alerts/channels.go), resolved-address and all.
		return nil, errString("blocked outbound to private address 10.0.1.42:8500")
	case "nohost.invalid.example":
		return nil, errString("dial tcp: lookup nohost.invalid.example: no such host")
	case "refused.public.example":
		return nil, errString("dial tcp 203.0.113.7:443: connect: connection refused")
	default:
		return nil, errString("oracleTransport: unexpected host " + req.URL.Hostname())
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// oracleLogRecorder collects every rendered slog line, unfiltered, so the test
// can assert on what actually reached the log rather than on a channel a
// production dispatcher happens to subscribe.
type oracleLogRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *oracleLogRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *oracleLogRecorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *oracleLogRecorder) WithGroup(string) slog.Handler            { return r }

func (r *oracleLogRecorder) Handle(_ context.Context, rec slog.Record) error {
	var sb strings.Builder
	sb.WriteString(rec.Message)
	rec.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, sb.String())
	return nil
}

func (r *oracleLogRecorder) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

func TestValidateResponseHidesTransportOracleButLogKeepsIt(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)

	const pw = "CorrectHorseBatteryStaple1!"
	owner := mustUser(t, queries, "oracle-owner@example.com", "user", pw)
	const entryID = "entry-oracle-probe"
	mustEntry(t, h, queries, entryID, owner, "oracle-secret", "sk-oracle-value")

	prevHTTP := providerHTTP
	providerHTTP = &http.Client{Transport: oracleTransport{}}
	t.Cleanup(func() { providerHTTP = prevHTTP })

	cases := []struct {
		name      string
		host      string
		logNeedle string
	}{
		{"the name resolves to a private address", "private.internal.example", "blocked outbound to private address"},
		{"the name does not resolve", "nohost.invalid.example", "no such host"},
		{"the connection is refused", "refused.public.example", "connection refused"},
	}

	var bodies []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forceProviderConfig(t, h, entryID, "forgejo", `{"instance":"https://`+tc.host+`"}`)

			rec := &oracleLogRecorder{}
			prevLog := slog.Default()
			slog.SetDefault(slog.New(rec))

			respRec := httptest.NewRecorder()
			body := `{"password":` + jsonQuote(pw) + `}`
			h.ValidateKey(respRec, vaultAuthzRequest(http.MethodPost,
				"/api/vault/"+entryID+"/validate", owner, "user", entryID, body))

			slog.SetDefault(prevLog)

			if respRec.Code != http.StatusOK {
				t.Fatalf("validate returned %d, want 200 (body: %s)", respRec.Code, respRec.Body.String())
			}
			var parsed map[string]any
			if err := json.Unmarshal(respRec.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("decode response: %v (body: %s)", err, respRec.Body.String())
			}
			errField, _ := parsed["error"].(string)
			if errField == "" {
				t.Fatalf("case %q produced no \"error\" field at all; the transport failure vanished "+
					"silently instead of being classified: %s", tc.name, respRec.Body.String())
			}
			bodies = append(bodies, errField)

			// THE OTHER HALF OF THE FIX. The response is now generic, but an
			// operator debugging a real outage must not lose the actual cause:
			// it has to still be on the log line this request produced.
			logLine := rec.all()
			if !strings.Contains(logLine, tc.logNeedle) {
				t.Errorf("case %q: the server log does not contain %q (the real failure reason); got:\n%s",
					tc.name, tc.logNeedle, logLine)
			}
		})
	}

	if len(bodies) != len(cases) {
		t.Fatalf("only %d of %d cases produced a comparable response body", len(bodies), len(cases))
	}

	// THE ASSERTION THAT MATTERS: the three DIFFERENT server-side failures must
	// produce the exact SAME caller-visible string. Any difference at all is
	// the oracle: a caller iterating provider_meta.instance across a network
	// range can tell "private and listening", "does not exist" and "public but
	// closed" apart from the HTTP response alone.
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("THE ORACLE IS STILL LIVE: case %q returned %q but case %q returned %q. "+
				"A caller probing the vault's own network can tell these apart from the response alone.",
				cases[0].name, bodies[0], cases[i].name, bodies[i])
		}
	}

	// And the shared body must not simply be a DIFFERENT raw transport string:
	// closing the oracle by choosing the private-address message as the
	// universal answer would still leak the resolved address on every call,
	// private or not.
	for i, b := range bodies {
		for _, leak := range []string{"10.0.1.42", "blocked outbound", "no such host", "connection refused", "dial tcp"} {
			if strings.Contains(b, leak) {
				t.Errorf("case %q: the response body still carries transport detail (%q): %q",
					cases[i].name, leak, b)
			}
		}
	}
}

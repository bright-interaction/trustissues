package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/shield"
)

// P1-13. The non-streaming guard and the redaction pass used to parse the same
// bytes with two different parsers, and the two disagreed about which documents
// exist. json.Unmarshal (the guard) rejects anything after the JSON value;
// a json.Decoder reading one value (Shield) does not care what follows. So
//
//	{"model":"gpt-4","stream":true,"messages":[]}x
//
// was "not streaming" to the guard, because the ignored Unmarshal error left the
// probe zeroed, and stream:true to Shield, which then dropped the trailing byte
// in its re-marshal and put a clean streaming request on the wire.
//
// No test had ever fed BOTH layers the same hostile bytes, which is exactly why
// it survived. These do. The invariant every case below asserts is the one that
// matters, and it is deliberately stated about the bytes the PROVIDER receives
// rather than about either layer's internals:
//
//	the gateway either refuses the request, or what reaches the provider is a
//	single valid JSON document that BOTH parsers agree is non-streaming.
//
// Anything else means the gate cleared one document and a different one flew.

// streamVerdictUnmarshal is how the old guard read a body: the strict parser.
//
// It decodes into any, not into a struct, on purpose. Unmarshalling a non-object
// document into a struct returns an UnmarshalTypeError, which is a statement
// about the DESTINATION and not about whether the bytes parse; folding that in
// would make the helper report a parse failure for the perfectly well formed
// `true`, and the comparison against the lenient parser would be meaningless.
func streamVerdictUnmarshal(b []byte) (streaming bool, parsed bool) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return false, false
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return false, true
	}
	for k, val := range obj {
		if strings.EqualFold(k, "stream") && notProvablyNonStreaming(val) {
			return true, true
		}
	}
	return false, true
}

// streamVerdictDecoder is how Shield read the same body: the lenient parser.
func streamVerdictDecoder(b []byte) (streaming bool, parsed bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false, false
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return false, true
	}
	for k, val := range obj {
		if strings.EqualFold(k, "stream") && notProvablyNonStreaming(val) {
			return true, true
		}
	}
	return false, true
}

func notProvablyNonStreaming(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	}
	return true
}

// gatewayProbe runs one body through the real handler and reports the caller's
// status plus the exact bytes the upstream provider was handed.
type gatewayProbe struct {
	status       int
	upstreamSaw  []byte
	upstreamHit  bool
	callerAnswer string
}

func runGatewayBody(t *testing.T, shieldOn bool, method, path, body string) gatewayProbe {
	t.Helper()
	conn := aiGatewayTestDB(t)
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: "test-vault-key",
		ShieldKey: "0123456789abcdef0123456789abcdef", ShieldHintLevel: "full"}
	vh := NewVaultHandler(conn, queries, cfg)
	seedProviderKey(t, conn, vh, "ai_key_openai", "sk-openai-KEY")

	var probe gatewayProbe
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		probe.upstreamSaw = b
		probe.upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"model":"gpt-4","usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	var store shield.Store
	if shieldOn {
		store = shield.NewSQLStore(conn)
	}
	h := NewAIGatewayHandler(queries, cfg, vh, store)
	p := h.providers["openai"]
	p.baseURL = upstream.URL
	h.providers["openai"] = p

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	gatewayRouter(h).ServeHTTP(rr, req)
	probe.status = rr.Code
	probe.callerAnswer = rr.Body.String()
	return probe
}

func TestAIGatewayStreamGateAndRedactionAgreeOnHostileBodies(t *testing.T) {
	cases := []struct {
		name string
		body string
		// wantRefused pins the decision, so a future edit cannot quietly turn a
		// refusal into a forward and still satisfy the agreement invariant.
		wantRefused bool
		why         string
	}{
		{"plain non-streaming", `{"model":"gpt-4","stream":false,"messages":[]}`, false,
			"the ordinary request; it must still work"},
		{"plain streaming", `{"model":"gpt-4","stream":true,"messages":[]}`, true,
			"the guard's original job"},
		{"stream absent", `{"model":"gpt-4","messages":[]}`, false,
			"no stream key at all is non-streaming"},

		// The finding itself, in every shape the trailing bytes can take.
		{"trailing byte after streaming", `{"model":"gpt-4","stream":true,"messages":[]}x`, true,
			"P1-13: Unmarshal errored and the guard read false, Decoder read true"},
		{"trailing byte after non-streaming", `{"model":"gpt-4","stream":false,"messages":[]}x`, true,
			"fail closed: a body neither layer can agree is well formed is refused"},
		{"trailing second json value", `{"stream":true} {"stream":false}`, true,
			"two documents in one body is two answers to the same question"},
		{"trailing NUL", "{\"stream\":true}\x00", true,
			"a NUL is invisible in a log and defeated the guard exactly like 'x'"},
		{"trailing closing brace", `{"stream":true}}`, true,
			"json.Decoder.More() returns false on a trailing '}', so a More()-based check would miss this one"},
		{"trailing newline only", "{\"model\":\"gpt-4\",\"stream\":false}\n", false,
			"trailing whitespace is legal JSON and must not be refused"},

		// Duplicate keys: Go is last-wins in both parsers, so the risk is that a
		// gate and a re-marshal pick different winners.
		{"duplicate stream true then false", `{"stream":true,"stream":false,"model":"gpt-4"}`, false,
			"last-wins: the document the provider sees says false"},
		{"duplicate stream false then true", `{"stream":false,"stream":true,"model":"gpt-4"}`, true,
			"last-wins: the document the provider sees says true"},

		// Placement and type.
		{"stream nested where the guard does not look", `{"model":"gpt-4","opts":{"stream":true}}`, false,
			"neither provider reads a nested stream, and the forwarded body has none at top level"},
		{"stream as the string true", `{"model":"gpt-4","stream":"true"}`, true,
			"fail closed on a type the gate cannot prove is non-streaming"},
		{"stream as the string false", `{"model":"gpt-4","stream":"false"}`, true,
			"also refused: the gate accepts only absent, null or boolean false"},
		{"stream as number 1", `{"model":"gpt-4","stream":1}`, true, "fail closed"},
		{"stream as number 0", `{"model":"gpt-4","stream":0}`, true,
			"fail closed; 0 is not boolean false to either provider"},
		{"stream null", `{"model":"gpt-4","stream":null}`, false,
			"null is absent for both providers"},
		{"stream key case variant", `{"model":"gpt-4","StReAm":true}`, true,
			"the old struct-tag probe folded case and refused this; not loosening a security gate"},

		// Prefixes and shapes.
		{"leading whitespace", "  \n\t{\"model\":\"gpt-4\",\"stream\":true}", true,
			"leading whitespace is legal and must not hide the stream key"},
		{"BOM prefix", "\xef\xbb\xbf{\"model\":\"gpt-4\",\"stream\":true}", true,
			"a BOM is not JSON; fail closed rather than forward a body no layer could read"},
		{"truncated", `{"model":"gpt-4","stream":true`, true, "unparseable, fail closed"},
		{"whitespace only body", `   `, true, "not a JSON value, fail closed"},
		{"array not object", `[{"stream":true}]`, false,
			"no TOP-LEVEL stream key exists; the provider will reject it on its own merits"},
		{"scalar not object", `true`, false,
			"same: nothing here is a top-level stream key"},
		{"json null body", `null`, false, "no top-level stream key"},
	}

	for _, c := range cases {
		for _, shieldOn := range []bool{false, true} {
			mode := "shield-off"
			if shieldOn {
				mode = "shield-on"
			}
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				got := runGatewayBody(t, shieldOn, http.MethodPost,
					"/api/ai/openai/v1/chat/completions", c.body)

				refused := got.status != http.StatusOK
				if refused != c.wantRefused {
					t.Fatalf("refused = %v, want %v (%s)\nstatus %d, caller body %s",
						refused, c.wantRefused, c.why, got.status, got.callerAnswer)
				}
				if refused {
					if got.upstreamHit {
						t.Fatalf("SECURITY: request was refused with %d but the provider was still called with %q",
							got.status, got.upstreamSaw)
					}
					return
				}
				if !got.upstreamHit {
					t.Fatalf("status 200 but the provider was never called")
				}

				// THE INVARIANT. Whatever reached the provider must be one
				// document that both parsers read the same way, and that way
				// must be non-streaming. This is the assertion the old code
				// fails: it forwarded a body the two layers read differently.
				strictStreaming, strictParsed := streamVerdictUnmarshal(got.upstreamSaw)
				lenientStreaming, lenientParsed := streamVerdictDecoder(got.upstreamSaw)

				if !strictParsed || !lenientParsed {
					t.Fatalf("the provider was handed bytes the two parsers disagree even PARSE: "+
						"strictParsed=%v lenientParsed=%v, bytes %q",
						strictParsed, lenientParsed, got.upstreamSaw)
				}
				if strictStreaming != lenientStreaming {
					t.Fatalf("DIFFERENTIAL PARSE: strict parser says streaming=%v, lenient says %v, for %q",
						strictStreaming, lenientStreaming, got.upstreamSaw)
				}
				if strictStreaming {
					t.Fatalf("GUARD DEFEATED: the gate cleared this request as non-streaming, "+
						"but the provider was handed a STREAMING body: %q", got.upstreamSaw)
				}
			})
		}
	}
}

// TestAIGatewayStreamGateForwardsExactlyWhatItInspected is the other half. It is
// not enough that the forwarded body is non-streaming: the gate must have judged
// the same document that flew. With Shield off the bytes must be untouched, and
// with Shield on the only permitted difference is redaction, never a silent
// repair of the caller's JSON.
func TestAIGatewayStreamGateForwardsExactlyWhatItInspected(t *testing.T) {
	const body = `{"model":"gpt-4","stream":false,"messages":[{"role":"user","content":"hi"}]}`

	off := runGatewayBody(t, false, http.MethodPost, "/api/ai/openai/v1/chat/completions", body)
	if off.status != http.StatusOK {
		t.Fatalf("shield off: status %d, want 200 (%s)", off.status, off.callerAnswer)
	}
	if string(off.upstreamSaw) != body {
		t.Errorf("shield off: the gateway rewrote the body it cleared\n got %q\nwant %q",
			off.upstreamSaw, body)
	}

	// The GET routes carry no body at all, and must keep working: fail-closed on
	// an unparseable body must not mean fail-closed on an absent one.
	empty := runGatewayBody(t, true, http.MethodGet, "/api/ai/openai/v1/models", "")
	if empty.status != http.StatusOK {
		t.Fatalf("empty body on an allowlisted GET: status %d, want 200 (%s)",
			empty.status, empty.callerAnswer)
	}
}

// TestAIGatewayTrailingByteCannotSmuggleStreamingPastTheGate is the finding's
// own repro, kept standalone and blunt so a regression names itself.
func TestAIGatewayTrailingByteCannotSmuggleStreamingPastTheGate(t *testing.T) {
	attack := `{"model":"gpt-4","stream":true,"messages":[]}x`

	got := runGatewayBody(t, true, http.MethodPost, "/api/ai/openai/v1/chat/completions", attack)
	if got.upstreamHit {
		t.Fatalf("ATTACK SUCCEEDED: one trailing byte carried stream:true past the guard; "+
			"the provider received %q", got.upstreamSaw)
	}
	if got.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got.status)
	}
}

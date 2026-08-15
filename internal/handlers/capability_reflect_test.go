package handlers

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────
// THE RETURN TRIP
//
// The bridge's promise is USE-without-SEE: the caller drives /proxy, the server
// decrypts the credential and injects it, and the caller never holds the bytes.
// THREAT-MODEL.md states it as a guarantee.
//
// Injection was only half of it. The response came back VERBATIM: headers
// copied, body io.Copy'd, no guard. So the whole promise rested on the upstream
// choosing not to echo, and echoing is an ordinary thing for an upstream to do:
//
//	POST /proxy/api.cloudflare.com/anything
//	  -> upstream: {"headers":{"authorization":"Bearer cf-OPERATOR-TOKEN-...`"}}
//	  -> 200, straight through to a caller who may not have that token
//
// It needs no attack on the bridge. httpbin-style debug endpoints, validation
// errors that quote the offending token, 401 bodies repeating what was sent and
// gateways that add an X-Echo-* header all do it by default, and the
// destination allow-list is a column a collection editor has a hand in.
//
// Every test below asserts on what the CALLER received, never on the status
// code alone: a 200 whose body carries the credential is the failure.
// ──────────────────────────────────────────────────────────────────────

const (
	reflectHost    = "api.cloudflare.com"
	reflectDest    = reflectHost + "/*"
	reflectEntryID = "entry-reflect-cf"
	// Long enough to be a real credential and to carry characters that make the
	// percent-encoded form differ from the raw one, so the encoding cases below
	// are not all secretly testing the same needle.
	theReflectedKey = "cf-OPERATOR-TOKEN-AbC/dEf+GhI-0123456789"
)

// reflectingTransport is the fake upstream. It hands back whatever the test
// asks, with {auth} substituted for the Authorization header value the proxy
// actually injected, so the reflection is of the REAL delivered credential
// rather than of a string the test typed in.
// header is an http.Header, NOT a map[string]string. The map could not express
// two values for one header name, which is exactly the shape that carried the
// Content-Encoding bug past this file: a fixture type that cannot represent the
// input is a guard that cannot fail.
type reflectingTransport struct {
	status  int
	header  http.Header
	body    func(auth string) string
	sawAuth string
}

func (rt *reflectingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	auth := r.Header.Get("Authorization")
	rt.sawAuth = auth
	h := http.Header{"Content-Type": []string{"application/json"}}
	for k, vs := range rt.header {
		for _, v := range vs {
			h.Add(k, strings.ReplaceAll(v, "{auth}", auth))
		}
	}
	body := ""
	if rt.body != nil {
		body = rt.body(auth)
	}
	st := rt.status
	if st == 0 {
		st = http.StatusOK
	}
	return &http.Response{
		StatusCode: st,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

// newReflectEnv builds the real bridge over a real migrated database with one
// ordinary (unpinned, non-LLM) entry the caller is allowed to spend, and points
// its upstream client at the supplied fake.
func newReflectEnv(t *testing.T, rt *reflectingTransport) *egressEnv {
	t.Helper()
	env := newEgressEnv(t)
	env.cap.SetHTTPClient(&http.Client{Timeout: 5 * time.Second, Transport: rt})

	owner := mustUser(t, env.queries, "reflect-owner@example.com", "user", "")
	mustEntry(t, env.vault, env.queries, reflectEntryID, owner, "cloudflare-token", theReflectedKey)
	if _, err := env.vault.db.Exec(`UPDATE vault_entries SET injection_spec = ? WHERE id = ?`,
		`{"type":"bearer"}`, reflectEntryID); err != nil {
		t.Fatalf("seed injection spec: %v", err)
	}
	if rec := env.putDestinations(t, owner, "user", reflectEntryID, []string{reflectDest}); rec.Code != http.StatusOK {
		t.Fatalf("ABORT: could not set the ceiling: %d %s", rec.Code, rec.Body.String())
	}
	return env
}

func (e *egressEnv) spendOnce(t *testing.T, agent string) *httptest.ResponseRecorder {
	t.Helper()
	tok := signToken(t, "cloudflare-token", reflectEntryID, agent, reflectDest, "*")
	return e.proxy(t, http.MethodPost, reflectHost, "/client/v4/user/tokens/verify", tok)
}

// auditRows returns every capability_log row, newest last, as "event|status|error".
func (e *egressEnv) auditRows(t *testing.T) []string {
	t.Helper()
	rows, err := e.vault.db.Query(
		`SELECT event, COALESCE(status_code, 0), error FROM capability_log ORDER BY rowid`)
	if err != nil {
		t.Fatalf("read capability_log: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var event, errMsg string
		var status int
		if err := rows.Scan(&event, &status, &errMsg); err != nil {
			t.Fatalf("scan capability_log: %v", err)
		}
		out = append(out, event+"|"+strconv.Itoa(status)+"|"+errMsg)
	}
	return out
}

// TestProxyRefusesAnUpstreamThatReflectsTheInjectedSecret is the finding,
// reproduced end to end through the real bridge and then closed.
func TestProxyRefusesAnUpstreamThatReflectsTheInjectedSecret(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		header  http.Header
		body    func(auth string) string
		wantAud string
	}{
		{
			// The httpbin / "debug echo" shape. The single most common way an
			// upstream hands back what it was sent.
			name:    "raw plaintext in the response body",
			body:    func(auth string) string { return `{"headers":{"authorization":"` + auth + `"}}` },
			wantAud: "reflected_secret_blocked: body (plaintext)",
		},
		{
			// A 401 body quoting the credential it just rejected. Note the
			// status: a guard that only looked at 2xx would wave this through.
			name:    "a 401 body repeating the rejected credential",
			status:  http.StatusUnauthorized,
			body:    func(auth string) string { return `{"error":"invalid token: ` + auth + `"}` },
			wantAud: "reflected_secret_blocked: body (plaintext)",
		},
		{
			// The encoded case. A naive bytes.Contains on the raw plaintext
			// finds nothing here, and the secret starts at offset 7 of the
			// encoded blob, so it is not even base64-aligned.
			name: "base64 of the whole Authorization header",
			body: func(auth string) string {
				return `{"received_b64":"` + base64.StdEncoding.EncodeToString([]byte(auth)) + `"}`
			},
			wantAud: "reflected_secret_blocked: body (base64)",
		},
		{
			// Headers reach the caller before a single byte of body does, so a
			// body-only guard would have shipped this one intact.
			name:    "reflected into a response header",
			header:  http.Header{"X-Echo-Authorization": {"{auth}"}},
			body:    func(string) string { return `{"ok":true}` },
			wantAud: "reflected_secret_blocked: header X-Echo-Authorization (plaintext)",
		},
		{
			name:    "reflected into Set-Cookie",
			header:  http.Header{"Set-Cookie": {"last_seen_token={auth}; Path=/"}},
			body:    func(string) string { return `{"ok":true}` },
			wantAud: "reflected_secret_blocked: header Set-Cookie (plaintext)",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt := &reflectingTransport{status: c.status, header: c.header, body: c.body}
			env := newReflectEnv(t, rt)

			rec := env.spendOnce(t, "reflect-agent")

			// THE assertion. Not the status code: what the caller received.
			if strings.Contains(rec.Body.String(), theReflectedKey) {
				t.Fatalf("USE-without-SEE broken: the caller received the plaintext credential.\nbody: %s", rec.Body.String())
			}
			for k, vs := range rec.Header() {
				for _, v := range vs {
					if strings.Contains(v, theReflectedKey) {
						t.Fatalf("USE-without-SEE broken: the credential came back in response header %s: %s", k, v)
					}
				}
			}
			// The encoded forms too, or the guard passes by not looking.
			if strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString([]byte(theReflectedKey))) {
				t.Fatalf("the credential came back base64-encoded: %s", rec.Body.String())
			}

			// Positive control: the credential really was delivered upstream, so
			// this test is not passing because nothing was injected.
			if !strings.Contains(rt.sawAuth, theReflectedKey) {
				t.Fatalf("ABORT: the proxy never injected the credential (upstream saw %q), so nothing was reflected and this test proves nothing", rt.sawAuth)
			}

			if rec.Code != http.StatusBadGateway {
				t.Errorf("blocked response should be a 502, got %d: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "upstream_reflected_secret") {
				t.Errorf("the caller should be told WHY, got %s", rec.Body.String())
			}

			// A silent block is nearly as bad as a leak for the operator who has
			// to explain a broken integration.
			rows := env.auditRows(t)
			found := false
			for _, row := range rows {
				if strings.Contains(row, c.wantAud) {
					found = true
				}
				if strings.Contains(row, theReflectedKey) {
					t.Fatalf("the audit row itself carries the credential: %s", row)
				}
			}
			if !found {
				t.Fatalf("no audit row recorded the detection.\nwant substring: %s\ngot rows: %v", c.wantAud, rows)
			}
		})
	}
}

// TestProxyStillDeliversACleanUpstreamResponse is the control that keeps the
// guard from being "refuse everything". If this ever fails, the fix has become
// an outage.
func TestProxyStillDeliversACleanUpstreamResponse(t *testing.T) {
	const clean = `{"result":{"id":"tok_1","status":"active"},"success":true}`
	rt := &reflectingTransport{
		header: http.Header{"X-Request-Id": {"req_abc123"}},
		body:   func(string) string { return clean },
	}
	env := newReflectEnv(t, rt)

	rec := env.spendOnce(t, "clean-agent")
	if rec.Code != http.StatusOK {
		t.Fatalf("a clean upstream response must pass through: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != clean {
		t.Fatalf("the body was altered.\n got: %s\nwant: %s", rec.Body.String(), clean)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "req_abc123" {
		t.Fatalf("upstream headers must still be relayed, got %q", got)
	}
	rows := env.auditRows(t)
	last := rows[len(rows)-1]
	if last != "used|200|" {
		t.Fatalf("a clean call should audit as a plain use, got %q", last)
	}
}

// gzipOf is a REAL gzip stream, not a byte string that merely looks like one.
// It matters: the assertions below decompress what the caller received and look
// for the credential in the result, which is the only way to show that refusing
// an unscannable body is protecting something rather than being fussy.
func gzipOf(t *testing.T, plain string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(plain)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.String()
}

// gunzipIfPossible returns the decompressed bytes when b is a gzip stream, and
// b unchanged otherwise, so a caller-side assertion can be written once and
// still catch the credential whichever form it arrived in.
func gunzipIfPossible(b []byte) []byte {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return b
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return b
	}
	return out
}

// TestProxyRefusesAContentEncodedResponseItCannotScan. Compressed bytes contain
// no plaintext needle, so a guard that scanned them would report clean and
// forward the leak. The refusal is the point: unscannable is not deliverable.
//
// The three cases are three ways to say the same thing in HTTP, and until this
// round only two of them were heard. The guard asked
// resp.Header.Get("Content-Encoding"), and Get returns only the FIRST value of
// a repeated header, so an upstream emitting
//
//	Content-Encoding: identity
//	Content-Encoding: gzip
//
// read as plain "identity" and walked past the refusal. net/http's transport
// tests the same first value before it transparently decompresses, so it too
// declined -- both wrong decisions off one wrong read -- and the guard was
// handed gzip bytes it believed were plaintext, scanned them for a plaintext
// needle, found nothing, and relayed the credential.
func TestProxyRefusesAContentEncodedResponseItCannotScan(t *testing.T) {
	cases := []struct {
		name    string
		header  http.Header
		wantAud string
	}{
		{
			// The plain case, and the control: this one was always refused.
			name:    "a single gzip Content-Encoding",
			header:  http.Header{"Content-Encoding": {"gzip"}},
			wantAud: "reflection_unscannable: content-encoding gzip",
		},
		{
			// Also always refused, because Get returns the whole line here and
			// the whole line is not "identity". Keep it working: it is the other
			// control, and it is the SAME statement as the case below.
			name:    "the single-line comma form",
			header:  http.Header{"Content-Encoding": {"identity, gzip"}},
			wantAud: "reflection_unscannable: content-encoding identity, gzip",
		},
		{
			// THE FINDING. Two lines, identity first. Semantically identical to
			// the comma form above; invisible to Header.Get.
			name:    "two Content-Encoding lines, identity first",
			header:  http.Header{"Content-Encoding": {"identity", "gzip"}},
			wantAud: "reflection_unscannable: content-encoding identity, gzip",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The body is a real gzip stream of a real reflection, so if the
			// refusal is skipped the caller receives bytes that decompress to
			// the operator's credential. That is the leak, not a hypothetical.
			rt := &reflectingTransport{
				header: c.header,
				body: func(auth string) string {
					return gzipOf(t, `{"headers":{"authorization":"`+auth+`"}}`)
				},
			}
			env := newReflectEnv(t, rt)

			rec := env.spendOnce(t, "gzip-agent")

			// THE assertion: what the caller received, decompressed. A guard
			// that only checked rec.Body for the raw plaintext would pass while
			// the credential sat one gunzip away.
			if got := gunzipIfPossible(rec.Body.Bytes()); bytes.Contains(got, []byte(theReflectedKey)) {
				t.Fatalf("USE-without-SEE broken: the caller received the credential under a content-encoding the guard did not refuse.\ndecoded body: %s", got)
			}

			// Positive control: the credential really was delivered upstream,
			// so a pass here is not a pass because nothing was injected.
			if !strings.Contains(rt.sawAuth, theReflectedKey) {
				t.Fatalf("ABORT: the proxy never injected the credential (upstream saw %q); this test proves nothing", rt.sawAuth)
			}

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("an unscannable response must not be delivered, got %d: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "upstream_unscannable") {
				t.Errorf("the caller should be told why, got %s", rec.Body.String())
			}
			found := false
			for _, row := range env.auditRows(t) {
				if strings.Contains(row, c.wantAud) {
					found = true
				}
				if strings.Contains(row, theReflectedKey) {
					t.Fatalf("the audit row itself carries the credential: %s", row)
				}
			}
			if !found {
				t.Fatalf("no audit row for the unscannable refusal.\nwant substring: %s\ngot rows: %v", c.wantAud, env.auditRows(t))
			}
		})
	}
}

// TestProxyStillDeliversAnIdentityEncodedResponse is the anti-over-refusal
// control for the case above. "identity" means "not encoded", including when it
// is said twice, and refusing it would turn a correct upstream into an outage.
func TestProxyStillDeliversAnIdentityEncodedResponse(t *testing.T) {
	const clean = `{"result":{"id":"tok_1"},"success":true}`
	for _, header := range []http.Header{
		{"Content-Encoding": {"identity"}},
		{"Content-Encoding": {"identity", "identity"}},
		{"Content-Encoding": {"identity, identity"}},
	} {
		t.Run(strings.Join(header["Content-Encoding"], "|"), func(t *testing.T) {
			rt := &reflectingTransport{header: header, body: func(string) string { return clean }}
			env := newReflectEnv(t, rt)

			rec := env.spendOnce(t, "identity-agent")
			if rec.Code != http.StatusOK {
				t.Fatalf("identity is not an encoding and must still be delivered: %d %s", rec.Code, rec.Body.String())
			}
			if rec.Body.String() != clean {
				t.Fatalf("the body was altered.\n got: %s\nwant: %s", rec.Body.String(), clean)
			}
		})
	}
}

// TestProxyDoesNotAskUpstreamsToCompress locks the header change that makes the
// case above rare rather than routine. Accept-Encoding used to be forwarded, so
// a caller could have ASKED for a gzip response and thereby chosen the one
// encoding the guard cannot read.
func TestProxyDoesNotAskUpstreamsToCompress(t *testing.T) {
	if _, ok := forwardableHeaders["Accept-Encoding"]; ok {
		t.Fatal("Accept-Encoding must not be forwarded: a caller could ask the upstream for a body the reflected-secret guard cannot scan")
	}
}

// TestProxyAbortsWhenTheReflectionIsPastTheHoldBack covers the streaming half.
// The guard never buffers an unbounded body, so past the hold-back the status
// line is already on the wire and a clean 502 is no longer available. What must
// still hold is that the credential does not reach the caller, and that the
// truncation is not passed off as a complete response.
func TestProxyAbortsWhenTheReflectionIsPastTheHoldBack(t *testing.T) {
	rt := &reflectingTransport{
		body: func(auth string) string {
			// Two megabytes of ordinary payload, then the echo.
			return strings.Repeat("x", 2<<20) + `{"headers":{"authorization":"` + auth + `"}}`
		},
	}
	env := newReflectEnv(t, rt)

	// Driven inline rather than through spendOnce so the recorder survives the
	// panic and can be inspected: what the caller actually received is the only
	// assertion that matters here.
	tok := signToken(t, "cloudflare-token", reflectEntryID, "streaming-agent", reflectDest, "*")
	req := httptest.NewRequest(http.MethodPost, "/proxy/"+reflectHost+"/client/v4/user/tokens/verify", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Capability "+tok)
	rec := httptest.NewRecorder()

	var panicked any
	func() {
		defer func() { panicked = recover() }()
		env.router.ServeHTTP(rec, req)
	}()

	if panicked != http.ErrAbortHandler {
		t.Fatalf("a reflection past the hold-back must abort the connection rather than terminate the body cleanly; recovered %v", panicked)
	}
	if strings.Contains(rec.Body.String(), theReflectedKey) {
		t.Fatal("the credential reached the caller")
	}
	if rec.Body.Len() == 0 {
		t.Fatal("ABORT: nothing was streamed at all, so this test never reached the post-commit path")
	}
	found := false
	for _, row := range env.auditRows(t) {
		if strings.Contains(row, "reflected_secret_blocked: body (plaintext)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a mid-stream detection must still be audited: %v", env.auditRows(t))
	}
}

package handlers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
)

// THE SIBLING DOOR.
//
// The capability bridge's /proxy relayed the upstream response verbatim, which
// broke USE-without-SEE the moment an upstream echoed the credential. The AI
// gateway is the same shape at a different door: it injects the OPERATOR's
// provider key server-side and writes the provider's answer to a caller who is
// deliberately not told even the ENTRY ID of the key (GetConfig withholds it
// from non-admins). A provider that quotes the offending key back in a 401
// hands it over.
//
// Fixing one call site and not its sibling is how this class of finding gets
// reported as closed and is not. The comments in provider_routes.go say exactly
// that about the previous round. So this is the same guard, asserted here.

const theGatewayKey = "sk-ant-OPERATOR-KEY-abcdef0123456789"

// gatewayReflectEnv wires the real gateway over an upstream the test controls.
func gatewayReflectEnv(t *testing.T, upstream http.HandlerFunc) (*sql.DB, http.Handler) {
	t.Helper()
	conn := aiGatewayTestDB(t)
	queries := db.New(conn)
	cfg := &config.Config{VaultKey: "test-vault-key"}
	vh := NewVaultHandler(conn, queries, cfg)
	seedProviderKey(t, conn, vh, "ai_key_anthropic", theGatewayKey)

	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)

	h := NewAIGatewayHandler(queries, cfg, vh, nil)
	p := h.providers["anthropic"]
	p.baseURL = srv.URL
	h.providers["anthropic"] = p
	return conn, gatewayRouter(h)
}

func gatewayWithheldRows(t *testing.T, conn *sql.DB) []string {
	t.Helper()
	rows, err := conn.Query(`SELECT action, COALESCE(detail,'') FROM activity_log ORDER BY id`)
	if err != nil {
		t.Fatalf("read activity_log: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var action, detail string
		if err := rows.Scan(&action, &detail); err != nil {
			t.Fatalf("scan activity_log: %v", err)
		}
		out = append(out, action+"|"+detail)
	}
	return out
}

func TestAIGatewayRefusesAProviderThatReflectsTheInjectedKey(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		header  http.Header
		body    func(key string) string
		wantAud string
	}{
		{
			// The realistic one. OpenAI and Anthropic both quote the rejected
			// credential in an authentication error, and the caller gets the
			// provider's own status code with it.
			name:    "a 401 quoting the rejected key",
			status:  http.StatusUnauthorized,
			body:    func(k string) string { return `{"error":{"message":"Incorrect API key provided: ` + k + `"}}` },
			wantAud: "reflected key in response body (plaintext)",
		},
		{
			name: "base64 of the key in a debug field",
			body: func(k string) string {
				return `{"model":"claude","debug":{"auth_b64":"` + base64.StdEncoding.EncodeToString([]byte(k)) + `"}}`
			},
			wantAud: "reflected key in response body (base64)",
		},
		{
			name:    "reflected into a response header",
			header:  http.Header{"X-Echo-Api-Key": {"{key}"}},
			body:    func(string) string { return `{"model":"claude"}` },
			wantAud: "reflected key in response header X-Echo-Api-Key (plaintext)",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var sawKey string
			conn, router := gatewayReflectEnv(t, func(w http.ResponseWriter, r *http.Request) {
				sawKey = r.Header.Get("x-api-key")
				io.Copy(io.Discard, r.Body)
				for k, vs := range c.header {
					for _, v := range vs {
						w.Header().Add(k, strings.ReplaceAll(v, "{key}", sawKey))
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if c.status != 0 {
					w.WriteHeader(c.status)
				}
				w.Write([]byte(c.body(sawKey)))
			})

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, aiCallerRequest(http.MethodPost, "/api/ai/anthropic/v1/messages",
				`{"model":"claude-3","messages":[]}`))

			if strings.Contains(rec.Body.String(), theGatewayKey) {
				t.Fatalf("USE-without-SEE broken at the gateway: the caller received the operator's key.\nbody: %s", rec.Body.String())
			}
			for k, vs := range rec.Header() {
				for _, v := range vs {
					if strings.Contains(v, theGatewayKey) {
						t.Fatalf("the operator's key came back in response header %s: %s", k, v)
					}
				}
			}
			if strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString([]byte(theGatewayKey))) {
				t.Fatalf("the key came back base64-encoded: %s", rec.Body.String())
			}

			// Positive control: the key really did egress, so a pass here is not
			// a pass because nothing was injected.
			if sawKey != theGatewayKey {
				t.Fatalf("ABORT: the gateway never injected the key (provider saw %q); this test proves nothing", sawKey)
			}

			if rec.Code != http.StatusBadGateway {
				t.Errorf("a withheld response should be a 502, got %d: %s", rec.Code, rec.Body.String())
			}
			found := false
			for _, row := range gatewayWithheldRows(t, conn) {
				if strings.Contains(row, "ai.gateway_response_withheld") && strings.Contains(row, c.wantAud) {
					found = true
				}
				if strings.Contains(row, theGatewayKey) {
					t.Fatalf("the activity row itself carries the key: %s", row)
				}
			}
			if !found {
				t.Fatalf("the block was silent: no ai.gateway_response_withheld row matching %q in %v",
					c.wantAud, gatewayWithheldRows(t, conn))
			}
		})
	}
}

// TestAIGatewayStillDeliversACleanProviderResponse is the control. The guard
// must not turn the gateway's only feature off.
func TestAIGatewayStillDeliversACleanProviderResponse(t *testing.T) {
	const clean = `{"model":"claude","usage":{"input_tokens":10,"output_tokens":5},"content":"hi"}`
	_, router := gatewayReflectEnv(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(clean))
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, aiCallerRequest(http.MethodPost, "/api/ai/anthropic/v1/messages",
		`{"model":"claude-3","messages":[]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("a clean provider response must pass through: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != clean {
		t.Fatalf("the body was altered.\n got: %s\nwant: %s", rec.Body.String(), clean)
	}
}

// TestAIGatewayRefusesAContentEncodedProviderResponse is the coverage this file
// simply did not have. The capability bridge had two content-encoding tests and
// this door had none, which is the asymmetry that let the twins drift: the
// refusal existed in ai_gateway.go, nothing asserted it, and when it turned out
// to be reading only the first header value there was no test here to notice.
//
// Everything below runs through a REAL httptest server and a REAL net/http
// transport, because the transport is half the bug. It decides whether to
// transparently decompress by testing resp.Header.Get("Content-Encoding") --
// the first value, same as the broken guard did -- so an upstream that says
//
//	Content-Encoding: identity
//	Content-Encoding: gzip
//
// gets no decompression AND no refusal off one wrong read, and the gateway then
// scans gzip bytes for a plaintext key, finds nothing, and relays. A fake
// RoundTripper would have hidden that interaction by handing the handler a
// header the real stack would never have produced.
func TestAIGatewayRefusesAContentEncodedProviderResponse(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		wantCE string
	}{
		{
			// Always refused: Get returns the whole line and the whole line is
			// not "identity". The control -- it must keep working.
			name:   "the single-line comma form",
			header: http.Header{"Content-Encoding": {"identity, gzip"}},
			wantCE: "identity, gzip",
		},
		{
			// THE FINDING. The same statement as above, split across two lines,
			// and invisible to Header.Get.
			name:   "two Content-Encoding lines, identity first",
			header: http.Header{"Content-Encoding": {"identity", "gzip"}},
			wantCE: "identity, gzip",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var sawKey string
			// A 401 quoting the rejected key, gzipped: the shape the verifier
			// saw in the wild. The provider rejects the operator's key and
			// repeats it back, compressed.
			conn, router := gatewayReflectEnv(t, func(w http.ResponseWriter, r *http.Request) {
				sawKey = r.Header.Get("x-api-key")
				io.Copy(io.Discard, r.Body)
				for k, vs := range c.header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(gzipOf(t, `{"error":{"message":"Incorrect API key provided: `+sawKey+`"}}`)))
			})

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, aiCallerRequest(http.MethodPost, "/api/ai/anthropic/v1/messages",
				`{"model":"claude-3","messages":[]}`))

			// THE assertion, and it decompresses first. Checking rec.Body for
			// the raw plaintext would pass happily while the operator's key sat
			// one gunzip away in the caller's hands.
			if got := gunzipIfPossible(rec.Body.Bytes()); bytes.Contains(got, []byte(theGatewayKey)) {
				t.Fatalf("USE-without-SEE broken at the gateway: a non-admin caller received the operator's key under a content-encoding the guard did not refuse.\ndecoded body: %s", got)
			}

			// Positive control: the key really did egress, so a pass here is not
			// a pass because nothing was injected.
			if sawKey != theGatewayKey {
				t.Fatalf("ABORT: the gateway never injected the key (provider saw %q); this test proves nothing", sawKey)
			}

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("an unscannable provider response must not be delivered, got %d: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "upstream_unscannable") {
				t.Errorf("the caller should be told why, got %s", rec.Body.String())
			}

			// A silent withholding is the other half of the finding: the
			// verifier saw the response audited as delivered with no withheld
			// row at all.
			want := "reason=unscannable content-encoding " + c.wantCE
			found := false
			for _, row := range gatewayWithheldRows(t, conn) {
				if strings.Contains(row, "ai.gateway_response_withheld") && strings.Contains(row, want) {
					found = true
				}
				if strings.Contains(row, theGatewayKey) {
					t.Fatalf("the activity row itself carries the key: %s", row)
				}
			}
			if !found {
				t.Fatalf("the block was silent: no ai.gateway_response_withheld row matching %q in %v",
					want, gatewayWithheldRows(t, conn))
			}
		})
	}
}

// TestAIGatewayStillDeliversAnIdentityEncodedResponse is the anti-over-refusal
// control. "identity" means "not encoded"; refusing it would break every
// provider that spells that out.
func TestAIGatewayStillDeliversAnIdentityEncodedResponse(t *testing.T) {
	const clean = `{"model":"claude","usage":{"input_tokens":10,"output_tokens":5},"content":"hi"}`
	for _, header := range []http.Header{
		{"Content-Encoding": {"identity"}},
		{"Content-Encoding": {"identity", "identity"}},
	} {
		t.Run(strings.Join(header["Content-Encoding"], "|"), func(t *testing.T) {
			_, router := gatewayReflectEnv(t, func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				for k, vs := range header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(clean))
			})

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, aiCallerRequest(http.MethodPost, "/api/ai/anthropic/v1/messages",
				`{"model":"claude-3","messages":[]}`))

			if rec.Code != http.StatusOK {
				t.Fatalf("identity is not an encoding and must still be delivered: %d %s", rec.Code, rec.Body.String())
			}
			if rec.Body.String() != clean {
				t.Fatalf("the body was altered.\n got: %s\nwant: %s", rec.Body.String(), clean)
			}
		})
	}
}

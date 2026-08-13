package handlers

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file used to test hardenedOutboundClient, a private-IP dial guard in
// internal/handlers/vault_ssrf.go with ZERO production callers. Every outbound
// call in the vault/rotation subsystem goes through alerts.GuardedWebhookClient
// instead (providerHTTP here, and the capability proxy's client). So the SSRF
// suite had been exercising the copy that never shipped, in a package where a
// test-only global could switch the guard off, while the copy that DID ship had
// no test at all. That is how an IPv6 zone id got to walk through the live guard
// unnoticed. The dead copy is deleted; these tests now aim at the real one.
//
// The zone/encoding matrix and the "no second copy may exist" structural guard
// live next to the implementation, in internal/alerts.

// loopbackServer starts an httptest server on the given loopback network and
// returns its base URL host and port. network is "tcp4" or "tcp6".
func loopbackServer(t *testing.T, network, addr string) (*httptest.Server, int) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, ln.Addr().(*net.TCPAddr).Port
}

// TestProviderHTTPBlocksLoopback proves the client the provider/validate/rotate
// paths actually use refuses a loopback destination at dial time. providerHTTP
// is the package-level client every provider call shares, so this is the
// shipping guard, not a lookalike constructed by the test.
func TestProviderHTTPBlocksLoopback(t *testing.T) {
	srv, _ := loopbackServer(t, "tcp4", "127.0.0.1:0")

	resp, err := providerHTTP.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("providerHTTP reached a loopback server; the dial guard is not in the path")
	}
	if !strings.Contains(err.Error(), "blocked outbound to") {
		t.Fatalf("unexpected error, wanted the dial guard's refusal: %v", err)
	}
}

// TestProviderHTTPBlocksZonedIPv6 is the P0 repro at the layer that ships. A
// zoned IPv6 literal needs no interface name (%251 is interface index 1
// everywhere) and it used to short-circuit the guard to ALLOW.
func TestProviderHTTPBlocksZonedIPv6(t *testing.T) {
	_, port := loopbackServer(t, "tcp6", "[::1]:0")

	for _, zone := range []string{"1", "lo0"} {
		url := fmt.Sprintf("http://[::1%%25%s]:%d/", zone, port)
		resp, err := providerHTTP.Get(url)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("providerHTTP reached %s: an IPv6 zone id bypassed the dial guard", url)
		}
		if !strings.Contains(err.Error(), "blocked outbound to") {
			t.Fatalf("%s: unexpected error, wanted the dial guard's refusal: %v", url, err)
		}
	}
}

// TestProviderHTTPRefusesRedirects proves a public URL cannot 3xx a
// secret-carrying request onto an internal host.
func TestProviderHTTPRefusesRedirects(t *testing.T) {
	if providerHTTP.CheckRedirect == nil {
		t.Fatal("providerHTTP follows redirects; a public URL could 3xx onto an internal host")
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if got := providerHTTP.CheckRedirect(req, nil); got != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", got)
	}
}

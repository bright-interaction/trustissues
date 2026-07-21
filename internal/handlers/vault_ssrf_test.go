package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIsPrivateIP locks the SSRF address classification: every non-routable
// range is private, public addresses are not.
func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.0.0.5", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "169.254.169.254", "0.0.0.1", "100.64.0.1",
		"::1", "fc00::1", "fe80::1",
	}
	for _, s := range private {
		if !isPrivateIP(net.ParseIP(s)) {
			t.Errorf("%s should be private", s)
		}
	}

	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"}
	for _, s := range public {
		if isPrivateIP(net.ParseIP(s)) {
			t.Errorf("%s should be public", s)
		}
	}
}

// TestHardenedOutboundClientBlocksPrivate proves the dial-time guard: with the
// production setting, a request to a loopback server is refused at dial time;
// with the test override it succeeds.
func TestHardenedOutboundClientBlocksPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := hardenedOutboundClient(5 * time.Second)

	// Production mode: loopback dial must be blocked.
	if _, err := client.Get(srv.URL); err == nil {
		t.Fatal("expected private-address dial to be blocked")
	} else if !strings.Contains(err.Error(), "blocked outbound to private address") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test override: reachable.
	allowPrivateOutbound = true
	t.Cleanup(func() { allowPrivateOutbound = false })
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("override dial failed: %v", err)
	}
	resp.Body.Close()
}

// TestHardenedOutboundClientNoRedirects proves the client refuses to follow a
// redirect (which could point a public URL at an internal host).
func TestHardenedOutboundClientNoRedirects(t *testing.T) {
	allowPrivateOutbound = true
	t.Cleanup(func() { allowPrivateOutbound = false })

	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	client := hardenedOutboundClient(5 * time.Second)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (unfollowed redirect), got %d", resp.StatusCode)
	}
	if redirected {
		t.Fatal("client followed the redirect")
	}
}

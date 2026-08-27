package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

func TestServerBoundaryOwnsIngressZone(t *testing.T) {
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if timw.IsPrivateIngress(r.Context()) {
			_, _ = w.Write([]byte("private"))
			return
		}
		_, _ = w.Write([]byte("public"))
	})

	tests := []struct {
		name string
		zone timw.IngressZone
		want string
	}{
		{name: "public", zone: timw.IngressPublic, want: "public"},
		{name: "private", zone: timw.IngressPrivate, want: "private"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTrustIssuesHTTPServer("test", router, tt.zone)
			req := httptest.NewRequest(http.MethodGet, "https://private.example/", nil)
			// None of these request-controlled values can select or override the
			// listener-owned classification.
			req.Header.Set("X-TrustIssues-Ingress", "private")
			req.Header.Set("X-Tailscale-User-Login", "admin@example.com")
			req.Header.Set("X-Forwarded-For", "100.64.0.1")
			req.Host = "private.example"
			res := httptest.NewRecorder()

			srv.Handler.ServeHTTP(res, req)
			if got := res.Body.String(); got != tt.want {
				t.Fatalf("ingress = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHealthReportsListenerStampedIngress(t *testing.T) {
	router := newRouter(routerDeps{cfg: &config.Config{
		BaseURL:           "https://vault.example.test",
		PrivateBaseURL:    "https://vault-internal.example.test",
		PrivateSocketPath: "/run/trustissues/private.sock",
	}})
	for _, tt := range []struct {
		name        string
		zone        timw.IngressZone
		wantIngress string
		wantBaseURL string
	}{
		{name: "public", zone: timw.IngressPublic, wantIngress: "public", wantBaseURL: "https://vault.example.test"},
		{name: "private", zone: timw.IngressPrivate, wantIngress: "private", wantBaseURL: "https://vault-internal.example.test"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTrustIssuesHTTPServer("test", router, tt.zone)
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.Header.Set("X-TrustIssues-Ingress", "private")
			res := httptest.NewRecorder()
			srv.Handler.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", res.Code, res.Body.String())
			}
			var body struct {
				Ingress               string `json:"ingress"`
				BaseURL               string `json:"base_url"`
				PrivateIngressEnabled bool   `json:"private_ingress_enabled"`
			}
			if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode health: %v (body=%s)", err, res.Body.String())
			}
			if body.Ingress != tt.wantIngress {
				t.Fatalf("health ingress = %q, want %q", body.Ingress, tt.wantIngress)
			}
			if body.BaseURL != tt.wantBaseURL {
				t.Fatalf("health base URL = %q, want %q", body.BaseURL, tt.wantBaseURL)
			}
			if !body.PrivateIngressEnabled {
				t.Fatal("health did not report configured private ingress")
			}
		})
	}
}

func TestRouterStampsDisabledPrivateIngressFromConfig(t *testing.T) {
	router := newRouter(routerDeps{cfg: &config.Config{BaseURL: "https://vault.example.test"}})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	var body struct {
		PrivateIngressEnabled bool `json:"private_ingress_enabled"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode health: %v (body=%s)", err, response.Body.String())
	}
	if body.PrivateIngressEnabled {
		t.Fatal("router stamped private ingress configured without a private socket")
	}
}

func TestShutdownWithNoEndpointsIsSafe(t *testing.T) {
	if err := shutdownHTTPEndpoints(context.Background(), nil); err != nil {
		t.Fatalf("shutdown empty endpoint set: %v", err)
	}
}

func TestAllIngressListenersBeginShutdownConcurrently(t *testing.T) {
	listeners := []*blockingCloseListener{newBlockingCloseListener(), newBlockingCloseListener()}
	endpoints := make([]httpEndpoint, 0, len(listeners))
	for i, listener := range listeners {
		endpoints = append(endpoints, httpEndpoint{
			name:     []string{"public", "private"}[i],
			server:   &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
			listener: listener,
		})
	}
	_ = serveHTTPEndpoints(endpoints)
	for _, listener := range listeners {
		select {
		case <-listener.acceptStarted:
		case <-time.After(time.Second):
			t.Fatal("server did not begin accepting")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- shutdownHTTPEndpoints(ctx, endpoints) }()

	// Neither listener may wait for the other's Close to finish. Both Close
	// methods deliberately block until we release them.
	for _, listener := range listeners {
		select {
		case <-listener.closeStarted:
		case <-time.After(time.Second):
			t.Fatal("one ingress waited for the other to drain")
		}
	}
	for _, listener := range listeners {
		close(listener.releaseClose)
	}
	if err := <-done; err != nil {
		t.Fatalf("shutdown endpoints: %v", err)
	}
}

type blockingCloseListener struct {
	acceptStarted chan struct{}
	closeStarted  chan struct{}
	releaseClose  chan struct{}
	closed        chan struct{}
	acceptOnce    sync.Once
	closeOnce     sync.Once
}

func newBlockingCloseListener() *blockingCloseListener {
	return &blockingCloseListener{
		acceptStarted: make(chan struct{}),
		closeStarted:  make(chan struct{}),
		releaseClose:  make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

func (l *blockingCloseListener) Accept() (net.Conn, error) {
	l.acceptOnce.Do(func() { close(l.acceptStarted) })
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingCloseListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeStarted)
		<-l.releaseClose
		close(l.closed)
	})
	return nil
}

func (l *blockingCloseListener) Addr() net.Addr { return testAddr("blocked") }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

var _ net.Listener = (*blockingCloseListener)(nil)

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// TestCSRFOriginCheck covers the defense-in-depth origin check that backs up
// SameSite=Strict on cookie-authenticated state-changing routes. The headline
// case is a blind cross-site POST to first-run register.
func TestCSRFOriginCheck(t *testing.T) {
	const baseURL = "https://vault.example.com"

	cases := []struct {
		name       string
		method     string
		path       string
		host       string
		headers    map[string]string
		withCookie bool
		wantBlock  bool
	}{
		{
			name: "GET is never blocked", method: http.MethodGet, path: "/api/auth/status",
			headers: map[string]string{"Origin": "https://evil.example"},
		},
		{
			name: "non-browser client sends no origin headers", method: http.MethodPost, path: "/api/auth/login",
		},
		{
			name: "same-origin SPA post", method: http.MethodPost, path: "/api/vault/",
			headers:    map[string]string{"Origin": baseURL, "Sec-Fetch-Site": "same-origin"},
			withCookie: true,
		},
		{
			name: "origin matches the request host when BaseURL is stale", method: http.MethodPost, path: "/api/vault/",
			host:       "other.internal",
			headers:    map[string]string{"Origin": "https://other.internal"},
			withCookie: true,
		},
		{
			name: "cross-site register is blocked", method: http.MethodPost, path: "/api/auth/register",
			headers:   map[string]string{"Origin": "https://evil.example"},
			wantBlock: true,
		},
		{
			name: "cross-site delete is blocked", method: http.MethodDelete, path: "/api/admin/users/1",
			headers: map[string]string{"Origin": "https://evil.example"}, withCookie: true,
			wantBlock: true,
		},
		{
			name: "null origin is blocked", method: http.MethodPost, path: "/api/auth/register",
			headers:   map[string]string{"Origin": "null"},
			wantBlock: true,
		},
		{
			name: "cross-site referer is blocked when no origin", method: http.MethodPost, path: "/api/auth/register",
			headers:   map[string]string{"Referer": "https://evil.example/attack.html"},
			wantBlock: true,
		},
		{
			name: "same-origin referer passes", method: http.MethodPost, path: "/api/vault/",
			headers:    map[string]string{"Referer": baseURL + "/vault"},
			withCookie: true,
		},
		{
			name: "cross-site sec-fetch-site is blocked", method: http.MethodPost, path: "/api/auth/register",
			headers:   map[string]string{"Sec-Fetch-Site": "cross-site"},
			wantBlock: true,
		},
		{
			name: "sibling same-site is blocked too", method: http.MethodPost, path: "/api/auth/register",
			headers:   map[string]string{"Sec-Fetch-Site": "same-site"},
			wantBlock: true,
		},
		{
			name: "user-initiated navigation passes", method: http.MethodPost, path: "/api/auth/login",
			headers: map[string]string{"Sec-Fetch-Site": "none"},
		},
		{
			// The browser extension posts from its own origin with an API key
			// and no ambient cookie. It must keep working.
			name: "api key without a cookie is exempt", method: http.MethodPost, path: "/api/vault/",
			headers: map[string]string{"X-API-Key": "tik_live_x", "Origin": "chrome-extension://abcdef", "Sec-Fetch-Site": "cross-site"},
		},
		{
			name: "service key without a cookie is exempt", method: http.MethodPost, path: "/api/service-identities/me/secrets",
			headers: map[string]string{"X-Service-Key": "svc_live_x"},
		},
		{
			// An API key must never launder a cookie-authenticated request:
			// with a session cookie present the origin check still applies.
			name: "api key plus session cookie is still checked", method: http.MethodPost, path: "/api/vault/",
			headers:    map[string]string{"X-API-Key": "tik_live_x", "Origin": "https://evil.example"},
			withCookie: true,
			wantBlock:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			h := csrfOriginCheck(baseURL)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Host = "vault.example.com"
			if tc.host != "" {
				req.Host = tc.host
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if tc.withCookie {
				req.AddCookie(&http.Cookie{Name: timw.SessionCookieName, Value: "session-jwt"})
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if tc.wantBlock {
				if reached || rec.Code != http.StatusForbidden {
					t.Fatalf("expected 403 block, got status %d reached=%v", rec.Code, reached)
				}
				return
			}
			if !reached {
				t.Fatalf("request should have passed through, got status %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHostOfURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://vault.example.com", "vault.example.com"},
		{"https://Vault.Example.com/path?q=1", "vault.example.com"},
		{"http://localhost:8080", "localhost:8080"},
		{"null", ""},
		{"", ""},
		{"not a url", ""},
	}
	for _, tc := range cases {
		if got := hostOfURL(tc.in); got != tc.want {
			t.Errorf("hostOfURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

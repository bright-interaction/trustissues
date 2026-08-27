package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const privateIngressRequiredBody = "{\"error\":\"private ingress required\",\"code\":\"private_ingress_required\"}\n"

func TestIngressZoneDefaultsPublic(t *testing.T) {
	if got := IngressZoneFromContext(nil); got != IngressPublic {
		t.Fatalf("nil context zone = %v, want public", got)
	}
	if IsPrivateIngress(nil) {
		t.Fatal("nil context must not be private")
	}

	if got := IngressZoneFromContext(context.Background()); got != IngressPublic {
		t.Fatalf("unstamped context zone = %v, want public", got)
	}
	if IsPrivateIngress(context.Background()) {
		t.Fatal("unstamped context must not be private")
	}

	ctx := context.WithValue(context.Background(), ingressZoneContextKey{}, IngressZone(255))
	if got := IngressZoneFromContext(ctx); got != IngressPublic {
		t.Fatalf("unknown context zone = %v, want fail-closed public", got)
	}
	if IsPrivateIngress(ctx) {
		t.Fatal("unknown context zone must not be private")
	}
}

func TestPrivateIngressConfiguredDefaultsFalseAndFirstStampWins(t *testing.T) {
	if IsPrivateIngressConfigured(nil) {
		t.Fatal("nil context must not report a configured private listener")
	}
	if IsPrivateIngressConfigured(context.Background()) {
		t.Fatal("unstamped context must not report a configured private listener")
	}

	for _, test := range []struct {
		name    string
		handler func(http.Handler) http.Handler
		want    bool
	}{
		{
			name: "configured stamp",
			handler: func(next http.Handler) http.Handler {
				return StampPrivateIngressConfigured(true)(next)
			},
			want: true,
		},
		{
			name: "disabled stamp",
			handler: func(next http.Handler) http.Handler {
				return StampPrivateIngressConfigured(false)(next)
			},
			want: false,
		},
		{
			name: "outer configured cannot be disabled",
			handler: func(next http.Handler) http.Handler {
				return StampPrivateIngressConfigured(true)(StampPrivateIngressConfigured(false)(next))
			},
			want: true,
		},
		{
			name: "outer disabled cannot be enabled",
			handler: func(next http.Handler) http.Handler {
				return StampPrivateIngressConfigured(false)(StampPrivateIngressConfigured(true)(next))
			},
			want: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reached := false
			handler := test.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if got := IsPrivateIngressConfigured(r.Context()); got != test.want {
					t.Errorf("configured = %v, want %v", got, test.want)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
			if !reached || recorder.Code != http.StatusNoContent {
				t.Fatalf("stamped handler was not reached: reached=%v status=%d", reached, recorder.Code)
			}
		})
	}
}

func TestSpoofedRequestMetadataCannotMakeIngressPrivate(t *testing.T) {
	reached := false
	h := RequirePrivateIngress()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodPost, "https://vault.example.test/api/vault/entry/reveal", nil)
	req.Host = "trustissues.private.example.ts.net"
	req.RemoteAddr = "100.64.0.42:12345"
	req.Header.Set("X-TrustIssues-Ingress-Zone", "private")
	req.Header.Set("X-Ingress-Zone", "private")
	req.Header.Set("X-Forwarded-For", "100.64.0.42")
	req.Header.Set("X-Forwarded-Host", "trustissues.private.example.ts.net")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Tailscale-User-Login", "owner@example.test")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if reached {
		t.Fatal("spoofed request metadata reached private-only handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Body.String(); got != privateIngressRequiredBody {
		t.Fatalf("body = %q, want %q", got, privateIngressRequiredBody)
	}
}

func TestPrivateListenerStampPassesPrivateGate(t *testing.T) {
	reached := false
	h := StampIngressZone(IngressPrivate)(
		RequirePrivateIngress()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			if got := IngressZoneFromContext(r.Context()); got != IngressPrivate {
				t.Errorf("handler zone = %v, want private", got)
			}
			w.WriteHeader(http.StatusNoContent)
		})),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://private.example.test/", nil))

	if !reached {
		t.Fatal("private-stamped request did not reach handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestOutermostIngressStampWinsAcrossNestedMiddleware(t *testing.T) {
	t.Run("public listener cannot be upgraded by nested private stamp", func(t *testing.T) {
		reached := false
		h := StampIngressZone(IngressPublic)(
			StampIngressZone(IngressPrivate)(
				RequirePrivateIngress()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					reached = true
				})),
			),
		)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if reached {
			t.Fatal("nested private stamp upgraded a public-listener request")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("private listener cannot be overwritten by nested public stamp", func(t *testing.T) {
		reached := false
		h := StampIngressZone(IngressPrivate)(
			StampIngressZone(IngressPublic)(
				RequirePrivateIngress()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached = true
					if !IsPrivateIngress(r.Context()) {
						t.Error("nested public stamp overwrote the private listener stamp")
					}
					w.WriteHeader(http.StatusNoContent)
				})),
			),
		)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatal("private listener request did not reach nested handler")
		}
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
		}
	})
}

func TestUnknownListenerStampNormalizesToPublic(t *testing.T) {
	reached := false
	h := StampIngressZone(IngressZone(255))(
		RequirePrivateIngress()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		})),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if reached {
		t.Fatal("unknown listener stamp reached private-only handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestPrivateIngressCarriesHTTPSContractWithoutTrustingHeaders(t *testing.T) {
	privateReq := httptest.NewRequest(http.MethodGet, "http://unix-socket/", nil)
	privateReq = privateReq.WithContext(context.WithValue(
		privateReq.Context(), ingressZoneContextKey{}, IngressPrivate,
	))
	if !ForwardedProtoHTTPS(privateReq) {
		t.Fatal("private listener did not preserve its configured HTTPS edge contract")
	}

	publicReq := httptest.NewRequest(http.MethodGet, "http://public/", nil)
	publicReq.Header.Set("X-Forwarded-Proto", "https")
	if ForwardedProtoHTTPS(publicReq) {
		t.Fatal("unstamped public request asserted HTTPS through an untrusted header")
	}
}

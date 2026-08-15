package middleware

import "net/http"

// SecurityHeaders adds security-related HTTP headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// CSP for the self-hosted Vite SPA. style-src keeps 'unsafe-inline'
		// because the Vite/Tailwind build injects runtime <style> tags and
		// inline style attributes that no nonce covers; script-src is strict
		// 'self' (no inline/eval). img-src is 'self' data: only (the app bundles
		// its own provider icons and loads no remote images), and connect-src is
		// 'self' (no WebSocket/wss; the SPA talks only to its own origin over
		// HTTP). Narrowing img-src/connect-src off the previous https:/wss:
		// wildcards removes a data-exfiltration channel.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		// ForwardedProtoHTTPS, not Header.Get: the header is a list, Get reads
		// only its first line, and an untrusted caller must not be able to assert
		// the answer. See forwarded.go.
		if ForwardedProtoHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// MaxBodySize returns middleware that limits the request body to the given size in bytes.
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

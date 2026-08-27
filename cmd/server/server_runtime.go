package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

type httpEndpoint struct {
	name     string
	server   *http.Server
	listener net.Listener
}

// newTrustIssuesHTTPServer keeps the public TCP and optional private Unix
// listeners on exactly the same resource limits. Only their outermost ingress
// stamp differs; both continue through the same router, authentication,
// authorization, rate limits, and audit path.
func newTrustIssuesHTTPServer(addr string, handler http.Handler, zone timw.IngressZone) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           timw.StampIngressZone(zone)(handler),
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		// Go's default is 1 MB for a SINGLE header value, and User-Agent is
		// stored verbatim in the append-only activity_log. Keep the limit
		// identical on every ingress.
		MaxHeaderBytes: 16 << 10,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
	}
}

// serveHTTPEndpoints starts every pre-bound endpoint and reports the first
// unexpected Serve failure. The channel is buffered so a simultaneous failure
// cannot strand a goroutine while the caller shuts down the remaining server.
func serveHTTPEndpoints(endpoints []httpEndpoint) <-chan error {
	errs := make(chan error, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint := endpoint
		go func() {
			err := endpoint.server.Serve(endpoint.listener)
			if errors.Is(err, http.ErrServerClosed) {
				return
			}
			if err == nil {
				err = errors.New("server stopped without an error")
			}
			errs <- fmt.Errorf("%s ingress: %w", endpoint.name, err)
		}()
	}
	return errs
}

// shutdownHTTPEndpoints drains all listeners concurrently under one deadline.
// Sequential Shutdown calls let the first slow listener consume the whole
// budget and give the second no opportunity to drain.
func shutdownHTTPEndpoints(ctx context.Context, endpoints []httpEndpoint) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint := endpoint
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := endpoint.server.Shutdown(ctx); err != nil {
				errCh <- fmt.Errorf("%s ingress: %w", endpoint.name, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

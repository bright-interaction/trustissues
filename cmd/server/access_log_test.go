package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The access log must never write a query string.
//
// chi's DefaultLogger emits r.RequestURI verbatim, which is the raw request-target
// INCLUDING the query. The autofill route GET /match takes the page URL there, and
// migration 00011_metadata_at_rest.sql exists precisely so that value is not kept in the
// clear: it replaced LIKE matching with a keyed blind index because those columns
// "previously sat in cleartext next to the encrypted secret, so a raw DB-file leak
// exposed which sites a user has logins for". THREAT-MODEL.md repeats the promise that
// the extension can ask "do we have an entry for this domain?" without the server
// storing the URL in the clear.
//
// Writing the same URL to stdout on every request rebuilds exactly the browsing history
// the blind index was built to avoid, in a place with looser access than the database
// file, and container logs get shipped off-box.
//
// Asserted on the emitted RECORD rather than on the source, because the property is
// what comes out, and a source check cannot see a formatter that reassembles the URL.
func TestAccessLogNeverWritesAQueryString(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	handler := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// The real shape: the extension asking whether a login exists for a page.
	const secretURL = "https://bank.example.com/login?account=12345"
	req := httptest.NewRequest(http.MethodGet,
		"/match?url="+secretURL+"&token=sensitive-value", nil)
	req = req.WithContext(context.Background())
	handler.ServeHTTP(httptest.NewRecorder(), req)

	logged := buf.String()
	if logged == "" {
		t.Fatal("ABORT: the access log emitted nothing, so nothing below is being checked")
	}
	if !strings.Contains(logged, `"path":"/match"`) {
		t.Errorf("the request path is missing, so this is not a usable access log: %s", logged)
	}
	for _, leaked := range []string{
		"bank.example.com", "account=12345", "sensitive-value", "url=", "?",
	} {
		if strings.Contains(logged, leaked) {
			t.Errorf("the access log wrote %q.\n"+
				"That is the vault-match URL migration 00011 and THREAT-MODEL.md promise not to "+
				"keep in the clear, rebuilt as a browsing history in the container log:\n  %s",
				leaked, logged)
		}
	}
}

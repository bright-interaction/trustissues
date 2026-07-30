package handlers

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// No provider may read an upstream response without a ceiling.
//
// All 16 read sites used io.ReadAll(resp.Body), letting the UPSTREAM decide how much
// memory this process allocates. Several providers (grafana, zitadel, forgejo, datadog,
// supabase) talk to an operator-supplied instance URL, so the host is not always a
// vendor, and this is a single-process secrets manager: an OOM kill landing AFTER a
// successful mint leaves the credential created upstream with nothing stored and nothing
// recorded. That is the same stranded-secret state the rotation work keeps closing,
// reached by exhaustion rather than by logic.
//
// Checked in source because the property is "no site does X", which no single request
// can demonstrate. The behavioural half is below.
func TestNoProviderReadsAnUnboundedResponse(t *testing.T) {
	src := mustReadSource(t, "vault_providers.go")

	// Strip comments so the explanation of the fix does not trip its own guard.
	noComments := regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(src, "")

	if strings.Contains(noComments, "io.ReadAll(resp.Body)") {
		lines := []string{}
		for i, l := range strings.Split(noComments, "\n") {
			if strings.Contains(l, "io.ReadAll(resp.Body)") {
				lines = append(lines, string(rune('0'+i%10)))
			}
		}
		t.Errorf("%d provider read site(s) still use io.ReadAll(resp.Body). Use readProviderBody, "+
			"which caps the read: an upstream must never choose how much memory this process "+
			"allocates.", len(lines))
	}

	// Fail closed: if the reads were renamed wholesale, this guard is asserting nothing.
	if n := strings.Count(noComments, "readProviderBody(resp)"); n < 10 {
		t.Fatalf("ABORT: only %d bounded read sites found; the helper has probably been renamed "+
			"and this guard no longer checks anything", n)
	}
}

// TestProviderBodyIsActuallyTruncated is the behavioural half.
//
// A source guard proves the call sites use the helper; only this proves the helper
// bounds anything.
func TestProviderBodyIsActuallyTruncated(t *testing.T) {
	huge := strings.Repeat("A", maxProviderBody*2)
	withFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pad":"` + huge + `"}`))
	})

	// Any provider will do; Validate is the cheapest path that reads a body.
	p := &TwilioProvider{}
	_, _ = p.Validate(context.Background(), "k", map[string]string{"account_sid": "AC"})

	// The assertion is on the helper itself, since Validate discards the body.
	resp, err := providerHTTP.Get("http://example.invalid/x")
	if err != nil {
		t.Fatalf("fake upstream: %v", err)
	}
	defer resp.Body.Close()
	body, err := readProviderBody(resp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(body) > maxProviderBody {
		t.Errorf("readProviderBody returned %d bytes, ceiling is %d; the upstream is still "+
			"choosing the allocation", len(body), maxProviderBody)
	}
	if len(body) == 0 {
		t.Error("readProviderBody returned nothing; a truncating reader that returns empty would " +
			"break every provider rather than bound it")
	}
}

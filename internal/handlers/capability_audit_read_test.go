package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// THE TRAIL HAS TO BE READABLE AND THE COLUMN HAS TO STAY SEALED.
//
// Those two are one property, not two, and getting either alone is a failure
// with a different shape. Sealed and unreadable is what shipped: three passes
// hardened capability_log and nothing could show it. Readable and unsealed would
// undo the seal and put the inventory back in the file.

// TestTheCredentialTrailOpensTheNameItSealed drives the real reader over a row
// the real writer produced.
func TestTheCredentialTrailOpensTheNameItSealed(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	_ = queries
	capH := setupCapabilityHandlerWithVault(t, vault)
	ctx := context.Background()

	const secretName = "Zzyzx prod signing key"
	// Written the way production writes it: through the handler's own logger, so
	// the seal under test is the one the bridge actually applies.
	capH.logCapabilityEvent(ctx, "agent-alpha", nil, secretName,
		"https://api.stripe.com/v1/charges", "POST", "used", 200, "", "nonce-1")

	// A thief with the file sees no name.
	var stored string
	if err := vault.db.QueryRow(
		`SELECT secret_name FROM capability_log WHERE agent_id = 'agent-alpha'`).Scan(&stored); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if strings.Contains(stored, secretName) {
		t.Fatalf("THE SECRET NAME IS CLEARTEXT IN capability_log: %q. This column is written on every "+
			"issue, use and denial, so in cleartext it rebuilds the inventory 00040 encrypted, out of "+
			"the same stolen file", stored)
	}
	if !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("the stored name is neither cleartext nor sealed: %q", stored)
	}

	// The operator sees the name.
	rec := httptest.NewRecorder()
	capH.ListCapabilityLog(rec, httptest.NewRequest(http.MethodGet, "/api/capability-log", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var got capabilityLogResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if got.Total != 1 || len(got.Entries) != 1 {
		t.Fatalf("expected exactly one row, got total=%d entries=%d", got.Total, len(got.Entries))
	}
	e := got.Entries[0]
	if e.SecretName != secretName {
		t.Errorf("the reader did not open the sealed name.\n  want: %q\n  got:  %q", secretName, e.SecretName)
	}
	if e.AgentID != "agent-alpha" || e.Event != "used" {
		t.Errorf("the row lost its identity: agent=%q event=%q", e.AgentID, e.Event)
	}
	if e.Destination != "https://api.stripe.com/v1/charges" || e.Method != "POST" {
		t.Errorf("the row lost where the credential went: %q %q", e.Method, e.Destination)
	}
	if e.StatusCode == nil || *e.StatusCode != 200 {
		t.Errorf("the row lost its outcome: %v", e.StatusCode)
	}
	// The agent list is what makes the filter selectable rather than typed.
	if len(got.Agents) != 1 || got.Agents[0] != "agent-alpha" {
		t.Errorf("the agent filter options are wrong: %v", got.Agents)
	}
}

// TestTheCredentialTrailFiltersCompose pins that the filters AND together.
//
// ListActivityEntriesFiltered's comment records what the alternative cost on the
// sibling surface: a switch whose first arm won, so choosing a user silently
// discarded the action filter and the table disagreed with its own export. On an
// audit surface, a filter that quietly means something other than what it says
// is worse than no filter.
func TestTheCredentialTrailFiltersCompose(t *testing.T) {
	vault, _ := newCollectionAuthzEnv(t)
	capH := setupCapabilityHandlerWithVault(t, vault)
	ctx := context.Background()

	capH.logCapabilityEvent(ctx, "agent-alpha", nil, "alpha used", "https://a.example", "GET", "used", 200, "", "n1")
	capH.logCapabilityEvent(ctx, "agent-alpha", nil, "alpha denied", "https://a.example", "GET", "denied", 0, "agent_not_granted", "n2")
	capH.logCapabilityEvent(ctx, "agent-beta", nil, "beta denied", "https://b.example", "GET", "denied", 0, "agent_not_granted", "n3")

	list := func(q string) capabilityLogResponse {
		t.Helper()
		rec := httptest.NewRecorder()
		capH.ListCapabilityLog(rec, httptest.NewRequest(http.MethodGet, "/api/capability-log?"+q, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("list %q: HTTP %d: %s", q, rec.Code, rec.Body.String())
		}
		var out capabilityLogResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	if got := list(""); got.Total != 3 {
		t.Errorf("unfiltered total = %d, want 3", got.Total)
	}
	if got := list("agent_id=agent-alpha"); got.Total != 2 {
		t.Errorf("agent filter total = %d, want 2", got.Total)
	}
	if got := list("event=denied"); got.Total != 2 {
		t.Errorf("event filter total = %d, want 2", got.Total)
	}
	// The one that catches a switch: BOTH must apply.
	both := list("agent_id=agent-alpha&event=denied")
	if both.Total != 1 {
		t.Fatalf("agent AND event total = %d, want 1. One of the filters is being discarded, so the "+
			"page answers a different question than the one the operator asked", both.Total)
	}
	if len(both.Entries) != 1 || both.Entries[0].SecretName != "alpha denied" {
		t.Errorf("the composed filter returned the wrong row: %+v", both.Entries)
	}
	if both.Entries[0].Error != "agent_not_granted" {
		t.Errorf("a denial that does not say WHY is not an audit row: %q", both.Entries[0].Error)
	}
}

// TestTheCredentialTrailPagerAgreesWithItsTable pins the count twin against the
// list. A total the table cannot reach sends an operator hunting for rows that
// are not there, on the surface they consult when they already suspect something.
func TestTheCredentialTrailPagerAgreesWithItsTable(t *testing.T) {
	vault, _ := newCollectionAuthzEnv(t)
	capH := setupCapabilityHandlerWithVault(t, vault)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		capH.logCapabilityEvent(ctx, "agent-alpha", nil, "secret", "https://a.example", "GET",
			"used", 200, "", "nonce-"+string(rune('a'+i)))
	}

	rec := httptest.NewRecorder()
	capH.ListCapabilityLog(rec, httptest.NewRequest(http.MethodGet, "/api/capability-log?limit=2&offset=0", nil))
	var page capabilityLogResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Total != 5 {
		t.Errorf("total = %d, want 5 (the total must count the whole filtered set, not the page)", page.Total)
	}
	if len(page.Entries) != 2 {
		t.Errorf("page size honoured? got %d rows, want 2", len(page.Entries))
	}

	// And the last page is reachable rather than one row short.
	rec = httptest.NewRecorder()
	capH.ListCapabilityLog(rec, httptest.NewRequest(http.MethodGet, "/api/capability-log?limit=2&offset=4", nil))
	var last capabilityLogResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &last); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(last.Entries) != 1 {
		t.Errorf("the tail of the trail is unreachable: offset 4 of 5 returned %d rows", len(last.Entries))
	}
}

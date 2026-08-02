package egressgate

import (
	"errors"
	"strings"
	"testing"
)

// TestZeroTicketAuthorizesNothing is the property the whole package rests on.
//
// Package handlers can write egressgate.Ticket{} and hand it to a wrapper. If
// that worked, the chokepoint would be a naming convention rather than a gate.
func TestZeroTicketAuthorizesNothing(t *testing.T) {
	var zero Ticket
	if err := zero.Authorizes("entry-1", "rotation_targets"); err == nil {
		t.Fatal("the zero Ticket authorized a write. Every wrapper in the handlers package takes a " +
			"Ticket by value, so a caller who forgot to call Decide holds one of these, and it must " +
			"be indistinguishable from a refusal")
	}
}

func TestDecide(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }

	cases := []struct {
		name        string
		req         Request
		wantGranted bool
		wantAdded   []string
		wantAsked   bool
		wantErrKind string // "denied", "subject", or ""
	}{
		{
			name: "adding a destination without the right is denied and names it",
			req: Request{EntryID: "e1", What: "rotation_targets",
				Before: []string{"webhook|https://ci.example/deploy"},
				After: []string{"webhook|https://ci.example/deploy",
					"webhook|https://attacker-controlled.example/collect"},
				MayRedirect: no},
			wantAdded: []string{"webhook|https://attacker-controlled.example/collect"}, wantAsked: true,
			wantErrKind: "denied",
		},
		{
			name: "adding a destination WITH the right is granted",
			req: Request{EntryID: "e1", What: "rotation_targets",
				After:       []string{"webhook|https://ci.example/deploy"},
				MayRedirect: yes},
			wantGranted: true, wantAdded: []string{"webhook|https://ci.example/deploy"}, wantAsked: true,
		},
		{
			name: "removing everything never consults the oracle",
			req: Request{EntryID: "e1", What: "rotation_targets",
				Before:      []string{"webhook|https://ci.example/deploy"},
				After:       nil,
				MayRedirect: no},
			wantGranted: true,
		},
		{
			name: "re-saving the same set never consults the oracle",
			req: Request{EntryID: "e1", What: "rotation_targets",
				Before:      []string{"webhook|https://ci.example/deploy"},
				After:       []string{"webhook|https://ci.example/deploy"},
				MayRedirect: no},
			wantGranted: true,
		},
		{
			name: "reordering is not a widening",
			req: Request{EntryID: "e1", What: "rotation_targets",
				Before:      []string{"a", "b"},
				After:       []string{"b", "a"},
				MayRedirect: no},
			wantGranted: true,
		},
		{
			name: "case differs only, still not a widening",
			req: Request{EntryID: "e1", What: "provider+provider_meta",
				Before:      []string{"api.openai.com"},
				After:       []string{"API.OpenAI.com"},
				MayRedirect: no},
			wantGranted: true,
		},
		{
			name: "a nil oracle denies any addition, it does not wave it through",
			req: Request{EntryID: "e1", What: "provider_meta",
				Before: []string{"api.datadoghq.com"},
				After:  []string{"api.datadoghq.com", "api.evil.example"}},
			wantAdded: []string{"api.evil.example"}, wantErrKind: "denied",
		},
		{
			name: "a Covers relation can make a narrowing look like one",
			req: Request{EntryID: "e1", What: "destination_patterns",
				Before: []string{"api.openai.com/*"},
				After:  []string{"api.openai.com/v1/chat"},
				Covers: func(have, want string) bool {
					return strings.HasSuffix(have, "/*") &&
						strings.HasPrefix(want, strings.TrimSuffix(have, "/*"))
				},
				MayRedirect: no},
			wantGranted: true,
		},
		{
			name:        "no entry named",
			req:         Request{What: "rotation_targets", After: []string{"x"}, MayRedirect: yes},
			wantErrKind: "subject",
		},
		{
			name:        "no field named",
			req:         Request{EntryID: "e1", After: []string{"x"}, MayRedirect: yes},
			wantErrKind: "subject",
		},
		{
			name: "blank entries in After are ignored rather than counted as additions",
			req: Request{EntryID: "e1", What: "rotation_targets",
				After:       []string{"", "   "},
				MayRedirect: no},
			wantGranted: true,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			asked := false
			if c.req.MayRedirect != nil {
				inner := c.req.MayRedirect
				c.req.MayRedirect = func() bool { asked = true; return inner() }
			}
			tk, err := Decide(c.req)

			switch c.wantErrKind {
			case "denied":
				var denied *DeniedError
				if !errors.As(err, &denied) {
					t.Fatalf("want a DeniedError, got %v", err)
				}
				if strings.Join(denied.Added, ",") != strings.Join(c.wantAdded, ",") {
					t.Errorf("denied.Added = %v, want %v", denied.Added, c.wantAdded)
				}
				for _, a := range c.wantAdded {
					if !strings.Contains(denied.Error(), a) {
						t.Errorf("the refusal does not name %q: %s", a, denied.Error())
					}
				}
			case "subject":
				var ns *ErrNoSubject
				if !errors.As(err, &ns) {
					t.Fatalf("want an ErrNoSubject, got %v", err)
				}
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if got := tk.Authorizes(c.req.EntryID, c.req.What) == nil; got != c.wantGranted {
				t.Errorf("ticket authorizes = %v, want %v", got, c.wantGranted)
			}
			if c.wantGranted && strings.Join(tk.Added(), ",") != strings.Join(c.wantAdded, ",") {
				t.Errorf("ticket.Added = %v, want %v", tk.Added(), c.wantAdded)
			}
			if asked != c.wantAsked {
				t.Errorf("oracle consulted = %v, want %v.\nThis matters in both directions: asking on a "+
					"pure narrowing would put revocation behind the widening right, and not asking on an "+
					"addition is the round-5 defect", asked, c.wantAsked)
			}
		})
	}
}

// TestATicketCannotBeSpentSomewhereElse is what stops one legitimate decision
// from becoming a skeleton key. A handler that has permission to narrow one
// entry's ceiling must not be able to hand that ticket to the rotation-target
// wrapper, or to the same wrapper for a different entry.
func TestATicketCannotBeSpentSomewhereElse(t *testing.T) {
	tk, err := Decide(Request{EntryID: "e1", What: "destination_patterns",
		After: []string{"api.openai.com/*"}, MayRedirect: func() bool { return true }})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if err := tk.Authorizes("e1", "destination_patterns"); err != nil {
		t.Fatalf("ABORT: the ticket does not authorize what it was issued for: %v", err)
	}
	if err := tk.Authorizes("e2", "destination_patterns"); err == nil {
		t.Error("a decision made about entry e1 was spent on entry e2")
	}
	if err := tk.Authorizes("e1", "rotation_targets"); err == nil {
		t.Error("a decision made about the capability ceiling was spent on the delivery targets")
	}
}

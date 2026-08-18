package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDeferredRevokeTargetRefusesATraversingPath defends the fix for the
// path-traversal reachable through provider_meta.
//
// THE DEFECT. Every non-b2 adapter builds the revoke URL by concatenating a
// fixed provider base with meta["key_id"] (or api_key_id / key_sid). Those are
// ORDINARY provider_meta keys: they are deliberately NOT in
// reservedProviderMetaKeys (they are operator enrollment fields, and adding
// them there breaks rotation setup), and nothing validates provider_meta
// VALUES. So any principal with canWrite supplies that string through
// PUT /api/vault/{id}. net/http does not clean dot segments, and providerDo
// constrains only the HOST -- it reads req.URL.Hostname() and never looks at
// the path. The result was a fully authenticated DELETE, signed with the
// entry's live credential, against a path the caller chose.
//
// THE FIX IS ABOUT TRAVERSAL, NOT CHARSET, and the Twilio rows below are why.
// The first version of the fix tested the final path segment against
// conservativeKeyIDPattern. Twilio's revoke URL ends "/Keys/<sid>.json", so the
// segment carries a dot, and that version refused Twilio's revoke outright --
// converting a working revoke into a permanent orphan, which is strictly worse
// than the traversal it was closing. Those rows are a regression guard: if they
// go red, someone has tightened this into a charset check again.
func TestDeferredRevokeTargetRefusesATraversingPath(t *testing.T) {
	cases := []struct {
		name   string
		rawURL string
		scheme string
		want   bool
	}{
		// The attack, in the shapes the four bearer/basic adapters produce.
		{"resend, dot-dot climbs out of the collection", "https://api.resend.com/api-keys/../domains/dom_victim", revokeAuthBearer, false},
		{"sendgrid, dot-dot", "https://api.sendgrid.com/v3/api_keys/../../admin", revokeAuthBearer, false},
		{"a bare dot-dot segment", "https://api.resend.com/api-keys/..", revokeAuthBearer, false},
		{"percent-encoded dot-dot decodes before we see it", "https://api.resend.com/api-keys/%2e%2e/domains/x", revokeAuthBearer, false},
		{"a query would travel with the request", "https://api.resend.com/api-keys/k1?force=true", revokeAuthBearer, false},
		{"a fragment", "https://api.resend.com/api-keys/k1#frag", revokeAuthBearer, false},
		{"userinfo changes who it authenticates as", "https://evil:pw@api.resend.com/api-keys/k1", revokeAuthBearer, false},
		{"a trailing slash means the id was empty", "https://api.resend.com/api-keys/", revokeAuthBearer, false},
		{"no path at all", "https://api.resend.com", revokeAuthBearer, false},
		{"not a URL", "::::not a url::::", revokeAuthBearer, false},
		{"empty", "", revokeAuthBearer, false},

		// The legitimate shapes. These MUST stay accepted.
		{"resend, ordinary key id", "https://api.resend.com/api-keys/key_old_1", revokeAuthBearer, true},
		{"neon, numeric id", "https://console.neon.tech/api/v2/api_keys/12345", revokeAuthBearer, true},
		{"REGRESSION GUARD: twilio's id legitimately carries a dot", "https://api.twilio.com/2010-04-01/Accounts/AC123/Keys/SK456.json", revokeAuthBasic, true},

		// b2 carries a BARE key id, not a URL: no path exists to traverse, so
		// the only requirement is that it reads as one opaque token.
		{"b2 bare key id", "0021abcDEF_-", revokeAuthB2, true},
		{"b2 id with a slash is not a bare id", "0021abc/def", revokeAuthB2, false},
		{"b2 id with whitespace", "0021 abc", revokeAuthB2, false},
		{"b2 empty", "", revokeAuthB2, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := revokeTargetIsNameable(c.rawURL, c.scheme); got != c.want {
				t.Errorf("revokeTargetIsNameable(%q, %q) = %t, want %t", c.rawURL, c.scheme, got, c.want)
			}
		})
	}
}

// TestDeferRevokeRecordsAnErrorRatherThanQueueingATraversingRevoke pins the
// BEHAVIOUR at the refusal, not just the predicate.
//
// Refusing must not silently drop the marker. A dropped marker is the
// 2026-08-17 shape: the predecessor stays live at the provider with nothing on
// the row recording that it exists. So the refusal takes the channel a provider
// that returns no usable id already uses (see Neon), recording last_revoke_error
// so the rotation downgrades to partial and the operator is told.
func TestDeferRevokeRecordsAnErrorRatherThanQueueingATraversingRevoke(t *testing.T) {
	t.Run("a traversing target queues nothing and says so", func(t *testing.T) {
		meta := map[string]string{"key_id": "../domains/dom_victim"}
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/../domains/dom_victim", revokeAuthBearer, "../domains/dom_victim")

		if got, ok := meta[pendingRevokeURL]; ok {
			t.Errorf("a traversing revoke was queued: %q. It would be issued with the entry's live "+
				"credential against a path the caller chose.", got)
		}
		if meta[pendingRevokeMethod] != "" || meta[pendingRevokeAuth] != "" {
			t.Errorf("partial coordinates were queued: %+v", meta)
		}
		if !strings.Contains(meta["last_revoke_error"], "not a usable key id") {
			t.Errorf("the refusal was SILENT (last_revoke_error = %q). A predecessor left live with no "+
				"record of it is the failure this whole feature exists to prevent.", meta["last_revoke_error"])
		}
	})

	t.Run("positive control: an ordinary target is still queued in full", func(t *testing.T) {
		meta := map[string]string{"key_id": "key_old_1"}
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/key_old_1", revokeAuthBearer, "key_old_1")

		if meta[pendingRevokeURL] != "https://api.resend.com/api-keys/key_old_1" {
			t.Fatalf("a legitimate revoke was not queued: %+v. The refusals above prove nothing if "+
				"nothing is ever queued.", meta)
		}
		if meta[pendingRevokeMethod] != "DELETE" || meta[pendingRevokeAuth] != revokeAuthBearer {
			t.Errorf("coordinates incomplete: %+v", meta)
		}
		if meta["last_revoke_error"] != "" {
			t.Errorf("a legitimate defer recorded an error: %q", meta["last_revoke_error"])
		}
	})
}

// TestPredecessorKeyIDIsRecordedNotReDerived pins the fix for the Twilio
// acknowledgement break.
//
// pendingRevokeStatusFrom used to reverse-engineer the predecessor id out of
// the marker URL with path.Base. That is guesswork about a string this package
// built itself, and it was wrong for the one registered provider whose revoke
// URL does not end in a bare id: Twilio's is ".../Keys/<sid>.json", so the
// operator was shown "SK....json", ResolvePendingRevoke demanded they type
// that back, and the SID copied from Twilio's own console was refused with a
// 400. The producer knows the id exactly, so it records it.
func TestPredecessorKeyIDIsRecordedNotReDerived(t *testing.T) {
	const twilioSID = "SK_EXAMPLE_NOT_A_REAL_SID"

	t.Run("twilio: the operator sees the real SID, not <sid>.json", func(t *testing.T) {
		meta := map[string]string{}
		deferRevokeOldProviderKey(meta, "DELETE",
			"https://api.twilio.com/2010-04-01/Accounts/AC123/Keys/"+twilioSID+".json",
			revokeAuthBasic, twilioSID)

		raw, err := json.Marshal(meta)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := pendingRevokeStatusFrom(string(raw))
		if got == nil || !got.Outstanding {
			t.Fatalf("no status derived: %+v", got)
		}
		if got.PredecessorKeyID != twilioSID {
			t.Errorf("PredecessorKeyID = %q, want %q. The operator is asked to type this exact "+
				"string back to acknowledge the stranded key, and the value in Twilio's console "+
				"is the bare SID.", got.PredecessorKeyID, twilioSID)
		}
	})

	t.Run("legacy rows with no recorded id still derive from the URL", func(t *testing.T) {
		// Rows written before this change carry no pending_revoke_key_id. They
		// must keep working, or every already-stranded key becomes unresolvable.
		raw := `{"pending_revoke_url":"https://api.resend.com/api-keys/key_old_1"}`
		got := pendingRevokeStatusFrom(raw)
		if got == nil || got.PredecessorKeyID != "key_old_1" {
			t.Errorf("legacy fallback broke: %+v", got)
		}
	})

	t.Run("a confirmed revoke clears the recorded id too", func(t *testing.T) {
		// A marker set that empties partially is worse than one that does not
		// empty at all: a leftover pending_revoke_key_id with no URL would read
		// as a stranded key nothing can revoke.
		meta := map[string]string{"key_id": "keep-me"}
		deferRevokeOldProviderKey(meta, "DELETE",
			"https://api.resend.com/api-keys/key_old_1", revokeAuthBearer, "key_old_1")
		if meta[pendingRevokeKeyID] != "key_old_1" {
			t.Fatalf("ABORT: the id was not recorded: %+v", meta)
		}
		deletePendingRevokeMarkers(meta)
		for _, k := range pendingRevokeMarkerKeys {
			if _, left := meta[k]; left {
				t.Errorf("%s survived the marker deletion: %+v", k, meta)
			}
		}
		if meta["key_id"] != "keep-me" {
			t.Errorf("deletion clobbered an unrelated key: %+v", meta)
		}
	})
}

// TestARedeferNeverLeavesAStaleRecordedKeyID pins the one marker that is
// written conditionally.
//
// deferRevokeOldProviderKey is routinely handed a map that ALREADY carries a
// full marker set: a failed revoke leaves all four in place and the next
// rotation defers over them. pending_revoke_key_id is recorded only when the id
// is charset-clean, so merely skipping the write on a dirty id advances
// url/method/auth to the new predecessor while the recorded id still names the
// previous one. Every reader trusts the recorded id first, so the chip and the
// resolve dialog would name K1 while Retry fires a DELETE at K2, and an
// operator typing K1 to acknowledge would discard K2's only coordinates and log
// the wrong key.
func TestARedeferNeverLeavesAStaleRecordedKeyID(t *testing.T) {
	// Rotation N: a clean id, revoke fails, so the whole set survives.
	meta := map[string]string{"key_id": "key.2"}
	deferRevokeOldProviderKey(meta, "DELETE",
		"https://api.resend.com/api-keys/K1", revokeAuthBearer, "K1")
	if meta[pendingRevokeKeyID] != "K1" {
		t.Fatalf("ABORT: the clean id was not recorded: %+v", meta)
	}

	// Rotation N+1 defers over the survivors with an id the charset refuses
	// (a dot: legal in the URL by design, for Twilio, but not recordable).
	deferRevokeOldProviderKey(meta, "DELETE",
		"https://api.resend.com/api-keys/key.2", revokeAuthBearer, "key.2")

	if got := meta[pendingRevokeKeyID]; got == "K1" {
		t.Errorf("the recorded predecessor id is STALE (%q) while the coordinates advanced to %q. "+
			"The operator is shown %q, Retry fires at the other key, and acknowledging %q discards "+
			"the live key's only coordinates.", got, meta[pendingRevokeURL], got, got)
	} else if got != "" {
		t.Errorf("pending_revoke_key_id = %q, want it absent so the reader falls back to the URL", got)
	}

	// The fallback must then name the CURRENT predecessor, not the old one.
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	st := pendingRevokeStatusFrom(string(raw))
	if st == nil || !st.Outstanding {
		t.Fatalf("no status derived after the re-defer: %+v", st)
	}
	if st.PredecessorKeyID == "K1" {
		t.Errorf("the derived status still names the PREVIOUS predecessor %q", st.PredecessorKeyID)
	}

	t.Run("positive control: a clean re-defer still records the new id", func(t *testing.T) {
		m := map[string]string{}
		deferRevokeOldProviderKey(m, "DELETE", "https://api.resend.com/api-keys/K1", revokeAuthBearer, "K1")
		deferRevokeOldProviderKey(m, "DELETE", "https://api.resend.com/api-keys/K2", revokeAuthBearer, "K2")
		if m[pendingRevokeKeyID] != "K2" {
			t.Errorf("a clean re-defer did not advance the recorded id: %+v", m)
		}
	})
}

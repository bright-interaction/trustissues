package handlers

import (
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
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/../domains/dom_victim", revokeAuthBearer)

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
		deferRevokeOldProviderKey(meta, "DELETE", "https://api.resend.com/api-keys/key_old_1", revokeAuthBearer)

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

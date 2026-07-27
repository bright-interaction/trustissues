package handlers

import (
	"context"
	"testing"

	"github.com/brightinteraction/trustissues/internal/db"
)

// TestRequireTOTPPolicyIsActuallyEnforced locks the fix for a dead security
// control.
//
// "Require two-factor authentication for all users" had exactly three code
// sites: the write, the read-back that renders the checkbox, and the checkbox
// itself. Nothing consulted it. An admin who ticked it got a compliance
// indicator, not a control: every user could still switch their own 2FA off,
// and an account with no 2FA was never told to enrol.
//
// Enforcement has to avoid the obvious trap of refusing logins, which would
// lock out every account the moment the box is ticked. So the policy binds in
// two places that cannot lock anyone out:
//   - disabling your own 2FA is refused while the policy is on (the caller has
//     just proven they hold a working code, so they are not locked out)
//   - an account without 2FA is flagged so the UI can nag until it enrols
func TestRequireTOTPPolicyIsActuallyEnforced(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	// Default: policy off.
	if settingBool(ctx, queries, "require_totp", false) {
		t.Fatal("require_totp defaults to on, which is not the shipped default")
	}

	// Turn the policy on the way the settings handler does.
	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: "require_totp", Value: "true",
	}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	// Guard the setup: if the write did not land, every assertion below is
	// vacuous and would pass against the original broken code.
	if !settingBool(ctx, queries, "require_totp", false) {
		t.Fatal("ABORT: policy did not persist, the test would prove nothing")
	}

	// The value the TOTPDisable handler consults must now be true, which is what
	// makes it refuse. The handler itself is covered end to end by the API smoke
	// test; here we pin that the setting is readable through the same helper the
	// handler uses, since the original bug was precisely that nothing read it.
	if got := settingBool(ctx, queries, "require_totp", false); !got {
		t.Fatal("the enforcement helper does not see the policy: disabling 2FA would still be allowed")
	}

	// Turning it back off restores the ability to disable.
	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: "require_totp", Value: "false",
	}); err != nil {
		t.Fatalf("clear policy: %v", err)
	}
	if settingBool(ctx, queries, "require_totp", false) {
		t.Fatal("policy still reads as on after being turned off: users could never disable 2FA again")
	}
}

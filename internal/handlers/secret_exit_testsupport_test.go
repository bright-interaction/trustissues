package handlers

import (
	"context"
	"testing"

	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// TEST-ONLY SCAFFOLDING FOR THE EXIT, AND WHY IT IS NOT A BACK DOOR.
//
// A receipt cannot be forged. secretexit keeps its receipt type and its context
// key unexported and mints one only inside Exit, so a test that needs a request
// to be forwardable has to actually call Exit, with a Destination, and get a yes
// from an Authority. That is the same path production takes.
//
// What a test MAY substitute is the Authority, and allowAllExitAuthority does.
// It exists for the contract tests that drive all 34 provider adapters against a
// fake upstream with no database behind them: there is no vault entry to own the
// secret, so there is nobody to ask. It says yes to everything, which is safe
// precisely because it says yes: it can only make a test pass that production
// would refuse, never the reverse, and the tests that assert a REFUSAL all run
// against a real VaultHandler.
//
// TestVaultHandlerIsTheOnlyProductionAuthority fails if a non-test file ever
// implements secretexit.Authority, so this cannot escape the suite.

// allowAllExitAuthority authorises every destination. Tests only.
type allowAllExitAuthority struct{}

func (allowAllExitAuthority) AuthorizeSecretExit(context.Context, secretexit.Origin,
	secretexit.Destination) error {
	return nil
}

// testExitCtx returns a context carrying a real exit receipt for hosts, minted
// the only way a receipt can be minted: by calling secretexit.Exit.
//
// It is what production's spendProviderSecret does with the pin and the owner
// rule stripped out, so a contract test exercises the same chokepoint without
// needing a database.
func testExitCtx(ctx context.Context, what string, hosts secretexit.HostSet) context.Context {
	pt := secretexit.Minted([]byte("THE-OPERATORS-DECRYPTED-SECRET"),
		secretexit.Origin{EntryID: "test-entry", Name: what}, allowAllExitAuthority{})
	out, _, err := secretexit.Exit(ctx, pt,
		secretexit.ToHosts(what, secretexit.ChosenByTheEntrysOwnRecord(), hosts))
	if err != nil {
		// Deliberately returns the ORIGINAL context, which carries no receipt, so
		// the caller fails closed exactly as production would.
		return ctx
	}
	return out
}

// exitReceiptForTest is testExitCtx on a background context, named for the
// call sites that read better that way.
func exitReceiptForTest(t *testing.T, what string, hosts secretexit.HostSet) context.Context {
	t.Helper()
	return testExitCtx(context.Background(), what, hosts)
}

// providerExitCtx is the context production hands a provider adapter: a receipt
// for the hosts DECLARED for that provider, resolved against the same meta the
// adapter is about to read.
func providerExitCtx(providerName string, meta map[string]string) context.Context {
	return testExitCtx(context.Background(), "provider "+providerName,
		declaredProviderEgress(providerName, meta))
}

// openForTest opens a stored value the production way. What comes back is
// opaque, so an assertion on it is either EqualsString or a length, never a
// read: the tests are held to the same rule the code is.
func (h *VaultHandler) openForTest(ciphertext, nonce []byte) (secretexit.Plaintext, error) {
	return h.openVersionForTest(ciphertext, nonce, 2)
}

// openVersionForTest is openForTest for a row at a stated encryption_version.
//
// The rotation tests need it: they seed v1 rows on purpose, and "does the
// RETIRED key still open this" is only a meaningful question when the version is
// pinned rather than assumed. It replaced their calls to VaultHandler.DecryptValue,
// which was the rotation branch's raw-bytes reader and is gone. The assertions
// those tests make are unchanged; what changed is that the value now comes back
// opaque, so they compare it with EqualsString instead of reading it, which is
// the same rule the production code is held to.
func (h *VaultHandler) openVersionForTest(ciphertext, nonce []byte, encVersion int) (
	secretexit.Plaintext, error) {

	return h.OpenEntrySecret(ciphertext, nonce, encVersion,
		secretexit.Origin{EntryID: "test", Name: "test"})
}

// testPlaintext wraps a literal as a Plaintext under allowAllExitAuthority, for
// the unit tests of a delivery function that have no vault behind them.
func testPlaintext(v string) secretexit.Plaintext {
	return secretexit.Minted([]byte(v),
		secretexit.Origin{EntryID: "test-entry", Name: "test-entry"}, allowAllExitAuthority{})
}

// deliveryStillAuthorized is the DELIVERY-half probe the drift and revocation
// matrices use.
//
// It used to be targetStillAuthorized. Round 7 moved the egress question out of
// that function and into the exit, so a probe that still called it would be
// asking the account-status half only, and every matrix built on it would agree
// with the write gate by accident rather than by construction.
//
// This asks the question the delivery path now actually asks: would
// secretexit.Exit release THIS entry's secret to a destination chosen by this
// principal? Same rule, same call, one place.
func deliveryStillAuthorized(ctx context.Context, h *VaultHandler, entryID string,
	target RotationTarget) error {

	if err := targetStillAuthorized(ctx, h, entryID, target); err != nil {
		return err
	}
	host := hostFromRawURL(target.WebhookURL)
	if target.Type == "forgejo_secret" {
		host = hostFromRawURL(target.Instance)
	}
	_, _, err := secretexit.ExitString(ctx,
		h.MintedEntrySecret([]byte("probe"), entryID, "probe"),
		secretexit.ToHost("a delivery target", secretexit.ChosenBy(target.ConfiguredBy), host))
	return err
}

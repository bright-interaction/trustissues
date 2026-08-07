package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE ALLOWLIST-INVERSION GATE.
//
// redactUpstreamError used to be a BLOCKLIST: it rewrote *url.Error and
// returned everything else verbatim (`return err.Error()`). A 2026-07-27 fix
// covered the non-2xx HTTP-body case with upstreamHTTPError, but every OTHER
// error type still egressed unredacted into last_rotation_error, the
// 50-entry rotation_log ring, and off-box into whatever webhook (n8n,
// Zapier, Slack) an admin configured. This file reconstructs the ACTUAL
// payloads for the four leaks that were found, using the real production
// functions (DeliverRotatedKey, deliverToWebhook, deliverToForgejoSecret,
// secretexit.Exit, summarizeDelivery), not fabricated error strings.

// TestDeliveryFailureSummaryNeverLeaksConfigurerEmail reconstructs
// summarizeDelivery's actual output -- the string that becomes
// last_rotation_error AND the notification-channel payload -- for a target
// whose configurer has been disabled.
//
// Before the fix: vault_targets.go:157 assigned authErr.Error() directly,
// skipping the redactor entirely, and targetStillAuthorized's message at
// :233 named the disabled user's EMAIL ADDRESS.
func TestDeliveryFailureSummaryNeverLeaksConfigurerEmail(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const leakedEmail = "disabled-teammate@example.com"
	configurer := mustUser(t, queries, leakedEmail, "user", "")
	owner := mustUser(t, queries, "owner@example.com", "user", "")
	const entryID = "entry-disabled-configurer"
	mustEntry(t, h, queries, entryID, owner, "Rotated Secret", "sk_live_old")

	// Disable the configurer AFTER the target references them, the way an
	// offboarding actually happens.
	if _, err := queries.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: 1, ID: configurer}); err != nil {
		t.Fatalf("disable configurer: %v", err)
	}

	targets := []RotationTarget{
		{Type: "webhook", Label: "prod-webhook", WebhookURL: "https://consumer.example/hook", ConfiguredBy: configurer},
	}

	results := DeliverRotatedKey(ctx, queries, h, entryID, "Rotated Secret",
		h.MintedEntrySecret([]byte("old"), entryID, "Rotated Secret"),
		h.MintedEntrySecret([]byte("new"), entryID, "Rotated Secret"),
		targets, owner)

	if len(results) != 1 || results[0].Success {
		t.Fatalf("expected one failed delivery result, got %+v", results)
	}

	// This is the ACTUAL string that reaches last_rotation_error and the
	// notification dispatcher: summarizeDelivery is what recordRotationFailure
	// (auto path) and the manual rotation handler both persist and dispatch.
	status, summary := summarizeDelivery(results)
	if status != "partial" {
		t.Fatalf("expected partial status, got %q", status)
	}

	if strings.Contains(summary, leakedEmail) {
		t.Fatalf("LEAK: the reconstructed rotation-failure payload contains the configurer's email: %q", summary)
	}
	if strings.Contains(results[0].Error, leakedEmail) {
		t.Fatalf("LEAK: DeliveryResult.Error contains the configurer's email: %q", results[0].Error)
	}
	// Gate 2: this must not degenerate into "everything says failed". The
	// operator still needs to know THIS class of failure (an offboarded
	// configurer), just not the identity.
	if !strings.Contains(summary, "configured it is disabled") {
		t.Errorf("the summary lost the useful failure class, got %q", summary)
	}
}

// TestSecretExitRefusalNeverLeaksEntryIdentityOrDestinationSet reconstructs
// a real AuthorizeSecretExit refusal end to end -- a live VaultHandler, a
// real entry, a real destination_patterns row -- and proves the redacted
// form used by delivery carries none of what the raw refusal names.
//
// Before the fix: secret_exit_authority.go:143-146 (a chooser with no
// widening right) names another entry's name AND UUID, the choosing user's
// id, and the destination host. secret_exit_authority.go:119-120 (a host
// outside the entry's own recorded set) names the owner's WHOLE authorised
// destination set. Both flowed through secretexit.go:561's plain
// fmt.Errorf wrap, then through vault_targets.go's `return err` at
// deliverToWebhook/deliverToForgejoSecret, straight into
// redactUpstreamError's old `return err.Error()` fallback.
func TestSecretExitRefusalNeverLeaksEntryIdentityOrDestinationSet(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "owner2@example.com", "user", "")
	stranger := mustUser(t, queries, "stranger@example.com", "user", "")
	const entryID = "entry-secret-exit-refusal"
	const entryName = "Team Database Password"
	mustEntry(t, h, queries, entryID, owner, entryName, "sk_live_teamdb")

	// The owner recorded ONE destination. Its host, and only its host, must
	// ever appear in an unredacted refusal.
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["consumer.example/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("seed destination patterns: %v", err)
	}

	pt, err := h.EntrySecretByID(ctx, entryID)
	if err != nil {
		t.Fatalf("open entry secret: %v", err)
	}

	// SCENARIO 1: a chooser with no widening right on this entry (the
	// round-6 shape). secret_exit_authority.go's chooser branch.
	_, _, err = secretexit.Exit(ctx, pt,
		secretexit.ToHost("this webhook delivery target", secretexit.ChosenBy(stranger), "attacker.example"))
	assertRefusalIsRedactedClean(t, err, entryID, entryName, stranger, "attacker.example", "consumer.example")

	// SCENARIO 2: a host outside the entry's own recorded destination set.
	// secret_exit_authority.go's ChosenByEntryRecord branch, the one whose
	// refusal message names `recorded.Describe()` -- the owner's WHOLE
	// authorised destination set.
	_, _, err = secretexit.Exit(ctx, pt,
		secretexit.ToHost("this capability token", secretexit.ChosenByTheEntrysOwnRecord(), "not-recorded.example"))
	assertRefusalIsRedactedClean(t, err, entryID, entryName, stranger, "not-recorded.example", "consumer.example")

	// Positive control: the SAME entry, delivered through DeliverRotatedKey
	// with a stranger-configured webhook, reconstructing what an operator's
	// notification channel would actually have received.
	results := DeliverRotatedKey(ctx, queries, h, entryID, entryName,
		h.MintedEntrySecret([]byte("old"), entryID, entryName),
		h.MintedEntrySecret([]byte("new"), entryID, entryName),
		[]RotationTarget{{Type: "webhook", Label: "attacker-webhook", WebhookURL: "https://attacker.example/hook", ConfiguredBy: stranger}},
		owner)
	if len(results) != 1 || results[0].Success {
		t.Fatalf("expected the stranger-configured webhook to be refused, got %+v", results)
	}
	_, summary := summarizeDelivery(results)
	assertRefusalIsRedactedClean(t, errors.New(summary), entryID, entryName, stranger, "attacker.example", "consumer.example")
}

// assertRefusalIsRedactedClean runs err through redactUpstreamError (the
// same call every delivery-failure path makes) and fails the test if any of
// the forbidden substrings survive.
func assertRefusalIsRedactedClean(t *testing.T, err error, entryID, entryName, chooserUserID, chosenHost, recordedHost string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	raw := err.Error()
	redacted := redactUpstreamError(err)
	for _, leaked := range []string{entryID, entryName, chooserUserID, chosenHost, recordedHost} {
		if strings.Contains(redacted, leaked) {
			t.Fatalf("LEAK: redacted refusal contains %q: %q (raw was %q)", leaked, redacted, raw)
		}
	}
}

// TestForgejoAuthTokenResolveFailureNeverLeaksReferencedEntryName
// reconstructs deliverToForgejoSecret's real auth_token resolve failure.
//
// Before the fix: vault_targets.go:353 wraps the resolve error with
// `fmt.Errorf("resolve Forgejo auth token %q from the configuring user's
// vault: %w", authToken, err)`, where authToken IS the referenced vault
// entry's NAME (see RotationTarget.AuthToken's doc comment). That fmt.Errorf
// is not a *url.Error and (pre-fix) was not an upstreamHTTPError either, so
// it fell straight through the old redactor.
func TestForgejoAuthTokenResolveFailureNeverLeaksReferencedEntryName(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "owner3@example.com", "user", "")
	const entryID = "entry-forgejo-source"
	mustEntry(t, h, queries, entryID, owner, "Forgejo Delivery Source", "sk_live_x")

	const leakedReferencedEntryName = "team-datadog-api-key-do-not-share"
	target := RotationTarget{
		Type:       "forgejo_secret",
		Instance:   "https://git.example.com",
		Repo:       "org/repo",
		SecretName: "MY_SECRET",
		// Names an entry that does not exist / this user cannot reach, so
		// resolveVaultReferenceFor fails with sql.ErrNoRows and
		// deliverToForgejoSecret wraps it with the name still attached.
		AuthToken:    leakedReferencedEntryName,
		ConfiguredBy: owner,
	}

	err := deliverToForgejoSecret(ctx, h, target,
		h.MintedEntrySecret([]byte("new"), entryID, "Forgejo Delivery Source"), owner)
	if err == nil {
		t.Fatal("expected the unresolvable auth_token to be refused")
	}
	if !strings.Contains(err.Error(), leakedReferencedEntryName) {
		t.Fatalf("ABORT: precondition failed, the raw error no longer names the referenced entry: %q", err.Error())
	}

	redacted := redactUpstreamError(err)
	if strings.Contains(redacted, leakedReferencedEntryName) {
		t.Fatalf("LEAK: redacted forgejo auth_token failure names the referenced entry: %q", redacted)
	}
}

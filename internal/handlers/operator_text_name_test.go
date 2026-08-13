package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"database/sql"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// Migration 00040 encrypted vault_entries.name, and every place that shows that
// name to a HUMAN has to open it first. The rotation sweep does, with a comment
// saying why. Three sites did not, and they were exactly the three the audit
// rounds had never read: the expiry reminder worker and the two offboarding
// target purges.
//
// The failure is quiet and total. Nothing errors, no test that checks a return
// value or a database row notices, and the operator gets "enc:v1:WEjZHuaOU..."
// where the secret's name should be. For the expiry alert that is the whole
// message, because the payload carries no entry id: the webhook says something
// expires on Tuesday and cannot say what.
//
// These guards assert on the string that reaches the human, which is the only
// place the defect is visible.

// recordingDispatcher captures what an alert actually put on the wire.
type recordingDispatcher struct {
	events  []string
	sources []string
	data    []map[string]string
}

func (r *recordingDispatcher) Dispatch(event, source, _ string, data map[string]string) {
	r.events = append(r.events, event)
	r.sources = append(r.sources, source)
	r.data = append(r.data, data)
}

// TestExpiryReminderNamesTheSecretInPlaintext fails if checkExpiringSecrets
// dispatches the stored column instead of the opened name.
//
// Ablation: drop the names.EntryNamePlain call in checkExpiringSecrets and the
// dispatched source becomes enc:v1: ciphertext, which this catches.
func TestExpiryReminderNamesTheSecretInPlaintext(t *testing.T) {
	ctx := context.Background()
	h, queries, ownerID, entryID := newTestVaultEnv(t)

	const secretName = "Stripe production key"
	encName, err := h.encryptColumn(secretName)
	if err != nil {
		t.Fatalf("encrypt name: %v", err)
	}
	if err := queries.UpdateVaultEntryName(ctx, db.UpdateVaultEntryNameParams{
		Name:     encName,
		NameBidx: h.nameBlindIndex(ownerID, secretName),
		ID:       entryID,
	}); err != nil {
		t.Fatalf("store encrypted name: %v", err)
	}
	// Inside the default reminder window.
	if err := queries.UpdateVaultEntryExpiresAt(ctx, db.UpdateVaultEntryExpiresAtParams{
		ExpiresAt: sql.NullTime{Time: time.Now().UTC().Add(72 * time.Hour), Valid: true},
		ID:        entryID,
	}); err != nil {
		t.Fatalf("set expires_at: %v", err)
	}

	rec := &recordingDispatcher{}
	checkExpiringSecrets(ctx, queries, h, rec)

	if len(rec.sources) != 1 {
		t.Fatalf("want exactly one expiry alert, got %d (%v)", len(rec.sources), rec.sources)
	}
	got := rec.sources[0]
	if strings.Contains(got, "enc:v1:") {
		t.Fatalf("the expiry alert shipped the STORED column to the operator's webhook: %q\n"+
			"vault_entries.name has been ciphertext since 00040; open it with EntryNamePlain "+
			"before it reaches a human sink", got)
	}
	if got != secretName {
		t.Fatalf("expiry alert source = %q, want the entry's name %q", got, secretName)
	}
}

// TestAccountTargetPurgeSummaryNamesEntriesInPlaintext covers the account-level
// offboarding purge, whose summary is written verbatim into the
// admin.user_targets_purged activity row and rendered by the Activity page.
//
// Ablation: revert vault_target_purge.go to append row.Name and the summary
// carries enc:v1: blobs, which this catches.
func TestAccountTargetPurgeSummaryNamesEntriesInPlaintext(t *testing.T) {
	ctx := context.Background()
	h, queries, ownerID, entryID := newTestVaultEnv(t)

	const secretName = "Backblaze bucket key"
	seedNamedEntryWithTarget(t, h, queries, entryID, ownerID, secretName)

	summary := h.PurgeTargetsConfiguredByUser(ctx, ownerID)
	if summary == "" {
		t.Fatal("purge reported nothing; the fixture target was not removed, so this " +
			"guard would pass without exercising the name path")
	}
	assertOperatorTextNamesTheSecret(t, "account offboarding purge summary", summary, secretName)
}

// TestCollectionTargetPurgeSummaryNamesEntriesInPlaintext is the twin. It exists
// separately on purpose: a fix landing on one of two twins is this codebase's
// recurring defect, and these two purges are copies of each other.
//
// Ablation: revert collection_target_purge.go to append row.Name and only this
// test fails, which is what proves the two are independently guarded.
func TestCollectionTargetPurgeSummaryNamesEntriesInPlaintext(t *testing.T) {
	ctx := context.Background()
	h, queries, ownerID, entryID := newTestVaultEnv(t)

	const collectionID = "collection-under-test"
	if err := queries.CreateCollection(ctx, db.CreateCollectionParams{
		ID:          collectionID,
		Name:        "Shared",
		CreatedBy:   toNullString(ownerID),
		Description: "",
	}); err != nil {
		t.Fatalf("create collection: %v", err)
	}
	if err := queries.SetVaultEntryCollection(ctx, db.SetVaultEntryCollectionParams{
		CollectionID: toNullString(collectionID),
		ID:           entryID,
	}); err != nil {
		t.Fatalf("move entry into collection: %v", err)
	}

	const secretName = "Forgejo deploy token"
	seedNamedEntryWithTarget(t, h, queries, entryID, ownerID, secretName)

	ch := &CollectionHandler{queries: queries, vault: h}
	summary := ch.purgeTargetsConfiguredBy(ctx, collectionID, ownerID)
	if summary == "" {
		t.Fatal("purge reported nothing; the fixture target was not removed, so this " +
			"guard would pass without exercising the name path")
	}
	assertOperatorTextNamesTheSecret(t, "collection offboarding purge summary", summary, secretName)
}

// seedNamedEntryWithTarget stores the entry's name the way production stores it
// (encrypted, blind index beside it) and gives it one delivery target attributed
// to configuredBy, so a purge has something to drop.
func seedNamedEntryWithTarget(t *testing.T, h *VaultHandler, queries *db.Queries, entryID, configuredBy, name string) {
	t.Helper()
	ctx := context.Background()

	encName, err := h.encryptColumn(name)
	if err != nil {
		t.Fatalf("encrypt name: %v", err)
	}
	if err := queries.UpdateVaultEntryName(ctx, db.UpdateVaultEntryNameParams{
		Name:     encName,
		NameBidx: h.nameBlindIndex(configuredBy, name),
		ID:       entryID,
	}); err != nil {
		t.Fatalf("store encrypted name: %v", err)
	}

	targets, err := json.Marshal([]RotationTarget{{
		Type:         "webhook",
		WebhookURL:   "https://consumer.example.com/hook",
		Label:        "consumer",
		ConfiguredBy: configuredBy,
	}})
	if err != nil {
		t.Fatalf("marshal targets: %v", err)
	}
	enc, err := h.encryptColumn(string(targets))
	if err != nil {
		t.Fatalf("encrypt targets: %v", err)
	}
	if err := setRotationTargetsFixture(t, queries, vaultegress.RotationTargetsParams{
		RotationTargets: toNullString(enc),
		ID:              entryID,
	}); err != nil {
		t.Fatalf("seed rotation targets: %v", err)
	}
}

func assertOperatorTextNamesTheSecret(t *testing.T, what, text, name string) {
	t.Helper()
	if strings.Contains(text, "enc:v1:") {
		t.Fatalf("%s shows the operator ciphertext: %q\n"+
			"this string lands in an activity row that the Activity page renders verbatim; "+
			"open the stored name with EntryNamePlain first", what, text)
	}
	if !strings.Contains(text, name) {
		t.Fatalf("%s does not name the affected secret %q: %q", what, name, text)
	}
}

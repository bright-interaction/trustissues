package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/database"
	"github.com/bright-interaction/trustissues/internal/db"
)

// Master-key rotation tests.
//
// The keys are full-length and distinct because config.Validate rejects short
// and weak ones, and because a test that rotates between two keys sharing a
// prefix would not notice a derivation that ignored part of the input.
const (
	rekeyOldKey   = "old-vault-key-3f1c9a77b2e45d80aa6c1e93"
	rekeyNewKey   = "new-vault-key-8b40e2c15da97f36c0d81b4e"
	rekeyThirdKey = "lost-vault-key-11ee77aa3390cc55bb220d6f"
)

// newRekeyDB returns a real migrated SQLite database. Fixtures are not
// hand-rolled here on purpose: the sweep reads sixteen columns across four
// tables, and a fixture missing one of them would make the coverage assertions
// pass for the wrong reason.
func newRekeyDB(t *testing.T) (*sql.DB, *db.Queries) {
	t.Helper()
	dbConn, err := database.Connect(t.TempDir())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { dbConn.Close() })
	if err := database.RunMigrations(dbConn); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return dbConn, db.New(dbConn)
}

func rekeyHandler(dbConn *sql.DB, queries *db.Queries, current, previous string) *VaultHandler {
	return NewVaultHandler(dbConn, queries, &config.Config{
		VaultKey:         current,
		VaultKeyPrevious: previous,
		JWTSecret:        strings.Repeat("j", 32),
	})
}

// seededStore is the plaintext every assertion compares against.
type seededStore struct {
	userID    string
	entryID   string
	inviteID  string
	channelID string
}

const (
	seedValue    = "super-secret-api-token"
	seedURL      = "https://api.example.com/v1/tokens"
	seedAlias    = "https://alias.example.net/login"
	seedUsername = "svc-account"
	seedCategory = "infrastructure"
	seedNotes    = "recovery code 4821-9930"
	seedMeta     = `{"account_id":"acct_123","key_id":"key_456"}`
	seedTargets  = `[{"type":"webhook","url":"https://hooks.example.com/x","secret":"hmac-secret"}]`
	seedFields   = `[{"label":"pin","value":"9137","secret":true}]`
	seedTOTP     = "JBSWY3DPEHPK3PXP"
	seedSMTP     = "smtp-relay-password"
	seedInvite   = "INVITE-CODE-ABCDEF"
	seedChannel  = `{"webhook_url":"https://hooks.slack.example/T000/B000/xxxx"}`
)

// seedUnderKey writes one of every keyed surface using the handler's CURRENT
// key, i.e. exactly what a normally-running instance would have produced.
func seedUnderKey(t *testing.T, h *VaultHandler, queries *db.Queries) seededStore {
	t.Helper()
	ctx := context.Background()

	user, err := queries.CreateUser(ctx, db.CreateUserParams{
		Email:        "admin@example.com",
		PasswordHash: "not-a-real-hash",
		Name:         toNullString("Admin"),
		Role:         "admin",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	ct, nonce, err := h.EncryptValue([]byte(seedValue))
	if err != nil {
		t.Fatalf("encrypt value: %v", err)
	}
	enc := func(v string) string {
		out, encErr := h.encryptColumn(v)
		if encErr != nil {
			t.Fatalf("encrypt column: %v", encErr)
		}
		return out
	}
	scope := bidxScope(user.ID, sql.NullString{})
	const entryID = "entry-rekey-1"
	if err := queries.CreateVaultEntry(ctx, db.CreateVaultEntryParams{
		ID:             entryID,
		UserID:         user.ID,
		Name:           "prod api token",
		EncryptedValue: ct,
		Nonce:          nonce,
		Url:            toNullString(enc(seedURL)),
		AliasUrl:       toNullString(enc(seedAlias)),
		Username:       toNullString(enc(seedUsername)),
		Category:       toNullString(enc(seedCategory)),
		Notes:          toNullString(enc(seedNotes)),
		ProviderMeta:   toNullString(enc(seedMeta)),
		UrlBidx:        h.urlBlindIndex(scope, seedURL),
		AliasUrlBidx:   h.urlBlindIndex(scope, seedAlias),
	}); err != nil {
		t.Fatalf("create vault entry: %v", err)
	}
	// rotation_targets and custom_fields are not columns on CreateVaultEntry, so
	// they get their own writes. They are in the sweep's registry and a rotation
	// that skipped them would orphan webhook HMAC secrets and user-flagged secret
	// fields, which is precisely the "miss one column" failure this covers.
	if err := queries.UpdateVaultEntryRotationTargets(ctx, db.UpdateVaultEntryRotationTargetsParams{
		RotationTargets: toNullString(enc(seedTargets)), ID: entryID,
	}); err != nil {
		t.Fatalf("set rotation targets: %v", err)
	}
	if err := queries.UpdateVaultEntryCustomFields(ctx, db.UpdateVaultEntryCustomFieldsParams{
		CustomFields: enc(seedFields), ID: entryID,
	}); err != nil {
		t.Fatalf("set custom fields: %v", err)
	}

	inv, err := queries.CreateInvitation(ctx, db.CreateInvitationParams{
		Code:       enc(seedInvite),
		CodeHash:   "hash-of-invite-code",
		Email:      "invitee@example.com",
		Name:       "Invitee",
		TargetRole: "user",
		CreatedBy:  toNullString(user.ID),
		ExpiresAt:  time.Now().Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	totpEnc, err := columncrypto.EncryptString(seedTOTP, h.keySource)
	if err != nil {
		t.Fatalf("encrypt totp: %v", err)
	}
	if err := queries.StoreTOTPSecret(ctx, db.StoreTOTPSecretParams{
		TotpSecret: sql.NullString{String: totpEnc, Valid: true}, ID: user.ID,
	}); err != nil {
		t.Fatalf("store totp: %v", err)
	}

	smtpEnc, err := columncrypto.EncryptString(seedSMTP, h.keySource)
	if err != nil {
		t.Fatalf("encrypt smtp: %v", err)
	}
	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: "smtp_password", Value: smtpEnc}); err != nil {
		t.Fatalf("store smtp password: %v", err)
	}

	chCT, chNonce, err := h.EncryptValue([]byte(seedChannel))
	if err != nil {
		t.Fatalf("encrypt channel config: %v", err)
	}
	chID, err := queries.CreateNotificationChannel(ctx, db.CreateNotificationChannelParams{
		Name:              "ops-slack",
		Type:              "webhook",
		Enabled:           sql.NullInt64{Int64: 1, Valid: true},
		Config:            string(chCT),
		ConfigNonce:       chNonce,
		EncryptionVersion: sql.NullInt64{Int64: 2, Valid: true},
		Events:            `["vault.rotated"]`,
	})
	if err != nil {
		t.Fatalf("create notification channel: %v", err)
	}

	// The boot sentinel, written the way a real first boot writes it.
	if err := VerifyVaultKey(ctx, queries, h.keySource); err != nil {
		t.Fatalf("seal sentinel: %v", err)
	}

	return seededStore{userID: user.ID, entryID: entryID, inviteID: inv.ID, channelID: chID}
}

// assertEverythingReadable proves each keyed surface round-trips back to the
// plaintext it was seeded with, using ONLY the keys the handler holds.
func assertEverythingReadable(t *testing.T, h *VaultHandler, queries *db.Queries, s seededStore, stage string) {
	t.Helper()
	ctx := context.Background()

	rows, err := queries.ListVaultEntriesForRekey(ctx)
	if err != nil {
		t.Fatalf("%s: list entries: %v", stage, err)
	}
	var row db.ListVaultEntriesForRekeyRow
	found := false
	for _, r := range rows {
		if r.ID == s.entryID {
			row, found = r, true
			break
		}
	}
	if !found {
		t.Fatalf("%s: seeded entry %s is gone", stage, s.entryID)
	}

	encVersion := 2
	if row.EncryptionVersion.Valid {
		encVersion = int(row.EncryptionVersion.Int64)
	}
	plain, err := h.DecryptValue(row.EncryptedValue, row.Nonce, encVersion)
	if err != nil {
		t.Fatalf("%s: secret value did not decrypt: %v", stage, err)
	}
	if string(plain) != seedValue {
		t.Fatalf("%s: secret value = %q, want %q", stage, plain, seedValue)
	}

	for _, c := range []struct {
		name   string
		stored string
		want   string
	}{
		{"url", nullStringToString(row.Url), seedURL},
		{"alias_url", nullStringToString(row.AliasUrl), seedAlias},
		{"username", nullStringToString(row.Username), seedUsername},
		{"category", nullStringToString(row.Category), seedCategory},
		{"notes", nullStringToString(row.Notes), seedNotes},
		{"provider_meta", nullStringToString(row.ProviderMeta), seedMeta},
		{"rotation_targets", nullStringToString(row.RotationTargets), seedTargets},
		{"custom_fields", row.CustomFields, seedFields},
	} {
		got, dErr := h.decryptColumn(c.stored)
		if dErr != nil {
			t.Fatalf("%s: vault_entries.%s did not decrypt: %v", stage, c.name, dErr)
		}
		if got != c.want {
			t.Fatalf("%s: vault_entries.%s = %q, want %q", stage, c.name, got, c.want)
		}
	}

	// The blind index is the surface with no error path: a stale one matches
	// nothing and reports success. Asserting through the real autofill query is
	// the only way to catch it, and the loop mirrors what Match does (one lookup
	// per candidate index, which is two only while a rotation is configured).
	matchCount := 0
	for _, bidx := range h.urlBlindIndexCandidates(bidxScope(s.userID, sql.NullString{}), seedURL) {
		matches, mErr := queries.MatchVaultEntriesByURL(ctx, db.MatchVaultEntriesByURLParams{
			UserID: s.userID, UrlBidx: bidx, AliasUrlBidx: bidx,
		})
		if mErr != nil {
			t.Fatalf("%s: autofill match query: %v", stage, mErr)
		}
		matchCount += len(matches)
	}
	if matchCount != 1 {
		t.Fatalf("%s: autofill blind-index match returned %d entries, want 1. "+
			"url_bidx is an HMAC keyed by the vault key, so it does not fail to decrypt, it just "+
			"stops matching: a rotation that neither recomputes it nor looks it up under both keys "+
			"empties autofill with no error anywhere", stage, matchCount)
	}

	invites, err := queries.ListInvitationCodesForRekey(ctx)
	if err != nil {
		t.Fatalf("%s: list invitations: %v", stage, err)
	}
	if len(invites) != 1 {
		t.Fatalf("%s: expected 1 invitation, got %d", stage, len(invites))
	}
	code, err := h.decryptColumn(invites[0].Code)
	if err != nil || code != seedInvite {
		t.Fatalf("%s: invitation code = %q (err %v), want %q", stage, code, err, seedInvite)
	}

	seeds, err := queries.ListUsersWithTOTPSecret(ctx)
	if err != nil {
		t.Fatalf("%s: list totp: %v", stage, err)
	}
	if len(seeds) != 1 {
		t.Fatalf("%s: expected 1 totp secret, got %d", stage, len(seeds))
	}
	gotSeed := decryptTOTPSecret(nullStringToString(seeds[0].TotpSecret), h.keySource, previousSourceOf(h))
	if gotSeed != seedTOTP {
		t.Fatalf("%s: totp seed = %q, want %q", stage, gotSeed, seedTOTP)
	}

	storedSMTP, err := queries.GetSetting(ctx, "smtp_password")
	if err != nil {
		t.Fatalf("%s: read smtp password: %v", stage, err)
	}
	gotSMTP, err := resolveSMTPPassword(storedSMTP, h.keySource, previousSourceOf(h))
	if err != nil || gotSMTP != seedSMTP {
		t.Fatalf("%s: smtp password = %q (err %v), want %q", stage, gotSMTP, err, seedSMTP)
	}

	channels, err := queries.ListNotificationChannelConfigsForRekey(ctx)
	if err != nil {
		t.Fatalf("%s: list channels: %v", stage, err)
	}
	if len(channels) != 1 {
		t.Fatalf("%s: expected 1 channel, got %d", stage, len(channels))
	}
	chVersion := 0
	if channels[0].EncryptionVersion.Valid {
		chVersion = int(channels[0].EncryptionVersion.Int64)
	}
	chPlain, err := h.DecryptValue([]byte(channels[0].Config), channels[0].ConfigNonce, chVersion)
	if err != nil || string(chPlain) != seedChannel {
		t.Fatalf("%s: channel config = %q (err %v), want %q", stage, chPlain, err, seedChannel)
	}

	if err := VerifyVaultKey(ctx, queries, h.keySource, previousSourceOf(h)); err != nil {
		t.Fatalf("%s: boot key gate refused: %v", stage, err)
	}
}

func previousSourceOf(h *VaultHandler) string {
	if h.previous == nil {
		return ""
	}
	return h.previous.source
}

// TestRekeyRoundTripFromOldKeyToNewKey is the headline case: everything written
// under the OLD key is readable under the NEW key alone once the sweep has run.
//
// "Under the NEW key alone" is the load-bearing part. A dual-key read makes a
// rotated instance look healthy while the retired key is still the only thing
// holding the data together, so the final assertions use a handler constructed
// with NO previous key. That is the state the operator ends up in after removing
// TRUSTISSUES_VAULT_KEY_PREVIOUS, and it is where an incomplete sweep shows up.
func TestRekeyRoundTripFromOldKeyToNewKey(t *testing.T) {
	dbConn, queries := newRekeyDB(t)

	oldHandler := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	seeded := seedUnderKey(t, oldHandler, queries)
	assertEverythingReadable(t, oldHandler, queries, seeded, "before rotation, on the old key")

	// The operator swaps the key and sets the previous one.
	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)

	// Dual-key read: the store serves correctly BEFORE any sweep has run. This is
	// what turns "changing the key orphans everything" into "changing the key is
	// survivable".
	assertEverythingReadable(t, rotating, queries, seeded, "mid-rotation, unswept")

	rep, err := rotating.RekeyVault(context.Background())
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if rep.Status != "converted" {
		t.Fatalf("status = %q, want converted (report: %+v)", rep.Status, rep)
	}
	if rep.ValuesOnPrevious == 0 {
		t.Fatal("the sweep reported nothing on the previous key, so it converted nothing; " +
			"the fixture or the scan is not seeing the seeded data")
	}
	if rep.ValuesUnreadable != 0 {
		t.Fatalf("sweep reported %d unreadable values: %+v", rep.ValuesUnreadable, rep.Blockers)
	}

	// The whole point: the old key is gone from the process.
	final := rekeyHandler(dbConn, queries, rekeyNewKey, "")
	assertEverythingReadable(t, final, queries, seeded, "after rotation, new key only")

	// And the retired key must no longer open the secret value.
	retired := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	rows, err := queries.ListVaultEntriesForRekey(context.Background())
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	if _, err := retired.DecryptValue(rows[0].EncryptedValue, rows[0].Nonce, 2); err == nil {
		t.Fatal("the OLD key still opens the secret value after a rotation; the sweep did not re-encrypt it")
	}
}

// TestRekeyIsIdempotent locks the property that makes a crashed sweep safe to
// retry: running it again finds everything already current and writes nothing.
func TestRekeyIsIdempotent(t *testing.T) {
	dbConn, queries := newRekeyDB(t)
	seeded := seedUnderKey(t, rekeyHandler(dbConn, queries, rekeyOldKey, ""), queries)

	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	if _, err := rotating.RekeyVault(context.Background()); err != nil {
		t.Fatalf("first rekey: %v", err)
	}

	second, err := rotating.RekeyVault(context.Background())
	if err != nil {
		t.Fatalf("second rekey: %v", err)
	}
	if second.RowsConverted != 0 {
		t.Fatalf("second sweep converted %d rows; a re-run must be a no-op or a crashed sweep "+
			"cannot safely be retried", second.RowsConverted)
	}
	if second.Status != "already_current" {
		t.Fatalf("second sweep status = %q, want already_current", second.Status)
	}
	if second.ValuesOnPrevious != 0 {
		t.Fatalf("second sweep still sees %d values on the previous key", second.ValuesOnPrevious)
	}
	assertEverythingReadable(t, rekeyHandler(dbConn, queries, rekeyNewKey, ""), queries, seeded, "after two sweeps")
}

// TestPartiallySweptStoreStillReads covers the state a crash mid-rotation leaves
// behind, and the state an ordinary edit produces: some rows on the new key,
// some still on the old one, in the same tables at the same time.
//
// It is built by rotating, sweeping, and then planting a value back under the
// OLD key, which is exactly what restoring one table from a pre-sweep backup
// would produce.
func TestPartiallySweptStoreStillReads(t *testing.T) {
	ctx := context.Background()
	dbConn, queries := newRekeyDB(t)
	seeded := seedUnderKey(t, rekeyHandler(dbConn, queries, rekeyOldKey, ""), queries)

	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	if _, err := rotating.RekeyVault(ctx); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	// Plant an old-key value back into a swept store: notes sealed under the old
	// key, sitting next to a value and a url that are already on the new one.
	oldHandler := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	staleNotes, err := oldHandler.encryptColumn(seedNotes)
	if err != nil {
		t.Fatalf("encrypt under old key: %v", err)
	}
	if err := queries.UpdateVaultEntryNotes(ctx, db.UpdateVaultEntryNotesParams{
		Notes: toNullString(staleNotes), ID: seeded.entryID,
	}); err != nil {
		t.Fatalf("plant stale notes: %v", err)
	}

	// Everything reads, mixed keys and all.
	assertEverythingReadable(t, rotating, queries, seeded, "half-swept")

	// The scan reports the mixture honestly rather than calling it done.
	status, err := rotating.RekeyStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Status != "needs_rekey" {
		t.Fatalf("status = %q, want needs_rekey on a half-swept store", status.Status)
	}
	if status.ValuesOnPrevious != 1 {
		t.Fatalf("status reports %d values on the previous key, want exactly the 1 planted", status.ValuesOnPrevious)
	}
	if status.ValuesOnCurrent == 0 {
		t.Fatal("status reports nothing on the current key, so the scan is not seeing the swept rows")
	}

	// And a second sweep finishes the job.
	if _, err := rotating.RekeyVault(ctx); err != nil {
		t.Fatalf("second rekey: %v", err)
	}
	assertEverythingReadable(t, rekeyHandler(dbConn, queries, rekeyNewKey, ""), queries, seeded, "after finishing the sweep")
}

// TestRekeyRefusesAndWritesNothingWhenAValueOpensUnderNoKey is the loud-refusal
// half of "handle all three crypto families or refuse loudly".
//
// The dangerous outcome is not a failed sweep, it is a sweep that reports
// success having skipped what it could not read: the operator then deletes the
// retired key while some rows are still sealed under it. So the assertion is
// twofold: the sweep errors, AND the store is byte-for-byte untouched.
func TestRekeyRefusesAndWritesNothingWhenAValueOpensUnderNoKey(t *testing.T) {
	ctx := context.Background()
	dbConn, queries := newRekeyDB(t)
	seeded := seedUnderKey(t, rekeyHandler(dbConn, queries, rekeyOldKey, ""), queries)

	// A SECOND entry whose notes are sealed under a key nobody has: a row
	// restored from an older backup, or an earlier rotation that was never
	// finished. It sits next to healthy rows on purpose, because the failure this
	// guards against is a sweep that converts the healthy ones and quietly leaves
	// this one behind.
	lost := rekeyHandler(dbConn, queries, rekeyThirdKey, "")
	orphan, err := lost.encryptColumn("unrecoverable")
	if err != nil {
		t.Fatalf("encrypt under third key: %v", err)
	}
	orphanCT, orphanNonce, err := rekeyHandler(dbConn, queries, rekeyOldKey, "").EncryptValue([]byte("other"))
	if err != nil {
		t.Fatalf("encrypt orphan row value: %v", err)
	}
	const orphanID = "entry-orphan-1"
	if err := queries.CreateVaultEntry(ctx, db.CreateVaultEntryParams{
		ID: orphanID, UserID: seeded.userID, Name: "restored from an old backup",
		EncryptedValue: orphanCT, Nonce: orphanNonce,
		Notes: toNullString(orphan),
	}); err != nil {
		t.Fatalf("plant orphan row: %v", err)
	}

	before, err := queries.ListVaultEntriesForRekey(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	rep, err := rotating.RekeyVault(ctx)
	if !errors.Is(err, ErrRekeyBlocked) {
		t.Fatalf("sweep err = %v, want ErrRekeyBlocked", err)
	}
	if rep == nil || rep.Status != "blocked" {
		t.Fatalf("report status = %+v, want blocked", rep)
	}
	if rep.BlockersTotal != 1 {
		t.Fatalf("BlockersTotal = %d, want 1", rep.BlockersTotal)
	}
	if len(rep.Blockers) != 1 || rep.Blockers[0].Column != "notes" || rep.Blockers[0].RowID != orphanID {
		t.Fatalf("blocker = %+v, want vault_entries.notes on %s", rep.Blockers, orphanID)
	}
	// A blocker must never carry the value it could not read: this is rendered in
	// the admin UI and written to the log.
	if strings.Contains(rep.Blockers[0].Reason, orphan) {
		t.Fatal("the blocker leaked the ciphertext it could not open")
	}

	after, err := queries.ListVaultEntriesForRekey(ctx)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("row count changed from %d to %d", len(before), len(after))
	}
	for i := range before {
		if string(after[i].EncryptedValue) != string(before[i].EncryptedValue) ||
			nullStringToString(after[i].Url) != nullStringToString(before[i].Url) ||
			nullStringToString(after[i].Notes) != nullStringToString(before[i].Notes) ||
			after[i].UrlBidx != before[i].UrlBidx {
			t.Fatalf("a blocked sweep wrote to vault_entries row %s; it must abort before writing "+
				"anything, otherwise the store ends up partly rotated and the operator cannot tell "+
				"which rows moved", before[i].ID)
		}
	}
	// The sentinel must not have moved either. If it had, the next boot would
	// accept the new key for a store that is still on the old one.
	if onPrev, sErr := SentinelOnPreviousKey(ctx, queries, rekeyNewKey, rekeyOldKey); sErr != nil || !onPrev {
		t.Fatalf("after a refused sweep the key sentinel should still be on the OLD key (onPrevious=%v, err=%v)", onPrev, sErr)
	}

	// The store is still fully readable on the pre-rotation key ring, i.e. the
	// refusal preserved every recovery option.
	assertEverythingReadable(t, rekeyHandler(dbConn, queries, rekeyOldKey, ""), queries, seeded, "after a refused sweep")
}

// TestRekeyUpgradesLegacyV1SecretsSealedUnderTheOldKey covers the derivation the
// probe bugs kept forgetting: encryption_version 1, sealed under sha256(key +
// ":secrets-vault") rather than PBKDF2.
//
// This is the shape MigrateEncryption cannot fix on its own during a rotation:
// it reads with the CURRENT key's legacy derivation, and on the first boot after
// a key change the row is sealed under the OLD one.
func TestRekeyUpgradesLegacyV1SecretsSealedUnderTheOldKey(t *testing.T) {
	ctx := context.Background()
	dbConn, queries := newRekeyDB(t)
	oldHandler := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	seeded := seedUnderKey(t, oldHandler, queries)

	// Re-seal the secret under the OLD key's v1 derivation.
	legacy := oldHandler.legacyKeyFor(rekeyOldKey)
	v1CT, v1Nonce := sealWithKeyForTest(t, legacy, []byte(seedValue))
	if _, err := dbConn.ExecContext(ctx,
		`UPDATE vault_entries SET encrypted_value = ?, nonce = ?, encryption_version = 1 WHERE id = ?`,
		v1CT, v1Nonce, seeded.entryID); err != nil {
		t.Fatalf("plant v1 row: %v", err)
	}

	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	if _, err := rotating.RekeyVault(ctx); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	rows, err := queries.ListVaultEntriesForRekey(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !rows[0].EncryptionVersion.Valid || rows[0].EncryptionVersion.Int64 != 2 {
		t.Fatalf("encryption_version = %v, want 2 after the sweep", rows[0].EncryptionVersion)
	}
	final := rekeyHandler(dbConn, queries, rekeyNewKey, "")
	plain, err := final.DecryptValue(rows[0].EncryptedValue, rows[0].Nonce, 2)
	if err != nil || string(plain) != seedValue {
		t.Fatalf("v1 secret after sweep = %q (err %v), want %q", plain, err, seedValue)
	}
}

// TestRekeyStatusFlagsAnUnreadableStoreWithNoPreviousKey is the discoverability
// case. An operator who changed TRUSTISSUES_VAULT_KEY in place, with no previous
// key configured, must be TOLD, not left to find out when a teammate opens an
// entry and sees blanks.
func TestRekeyStatusFlagsAnUnreadableStoreWithNoPreviousKey(t *testing.T) {
	dbConn, queries := newRekeyDB(t)
	seedUnderKey(t, rekeyHandler(dbConn, queries, rekeyOldKey, ""), queries)

	naive := rekeyHandler(dbConn, queries, rekeyNewKey, "")
	rep, err := naive.RekeyStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if rep.Status != "blocked" {
		t.Fatalf("status = %q, want blocked when nothing opens under the configured key", rep.Status)
	}
	if rep.ValuesUnreadable == 0 {
		t.Fatal("status reports zero unreadable values on a store sealed under a key that is not loaded")
	}
	if rep.PreviousKeyConfigured {
		t.Fatal("PreviousKeyConfigured is true with no previous key set")
	}
	if rep.CurrentKeyFingerprint == "" {
		t.Fatal("no current key fingerprint; the operator cannot tell which key is loaded")
	}
	// The fingerprint must not be the key.
	if strings.Contains(rep.CurrentKeyFingerprint, rekeyNewKey) {
		t.Fatal("the key fingerprint contains the key")
	}
}

// TestRekeyEncryptedValueIsNeverLeftHalfConverted asserts the per-row invariant:
// one entry's value, metadata columns and blind indexes all move together.
//
// It works by counting: after a sweep, no single vault_entries row may have a
// column that still opens under the old key while another opens under the new
// one. The scan already computes exactly that, so a post-sweep scan reporting
// any previous-key value at all is the failure.
func TestRekeyEncryptedValueIsNeverLeftHalfConverted(t *testing.T) {
	ctx := context.Background()
	dbConn, queries := newRekeyDB(t)
	seedUnderKey(t, rekeyHandler(dbConn, queries, rekeyOldKey, ""), queries)

	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)
	if _, err := rotating.RekeyVault(ctx); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	after, err := rotating.RekeyStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, s := range after.Surfaces {
		if s.OnPrevious != 0 {
			t.Errorf("%s.%s still has %d value(s) on the previous key after a successful sweep",
				s.Table, s.Column, s.OnPrevious)
		}
		if s.Unreadable != 0 {
			t.Errorf("%s.%s has %d unreadable value(s) after a successful sweep", s.Table, s.Column, s.Unreadable)
		}
	}
	// Every registered surface must have been LOOKED at. A surface that scanned
	// nothing means either the fixture does not exercise it (a test gap) or the
	// scanner never reaches it (a rotation gap), and both need to be visible.
	for _, s := range after.Surfaces {
		if s.Scanned == 0 {
			t.Errorf("surface %s.%s%s was never scanned; the sweep cannot have converted it",
				s.Table, s.Column, settingSuffix(s.SettingKey))
		}
	}
}

func settingSuffix(k string) string {
	if k == "" {
		return ""
	}
	return "[" + k + "]"
}

// sealWithKeyForTest is AES-256-GCM Seal with an explicit derived key, used to
// plant rows in derivations the production writers no longer produce (v1).
func sealWithKeyForTest(t *testing.T, key [32]byte, plaintext []byte) (ciphertext, nonce []byte) {
	t.Helper()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce
}

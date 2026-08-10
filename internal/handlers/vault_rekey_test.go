package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/database"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
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

	// The channel config points at a PRIVATE address on purpose.
	//
	// It is the one surface whose real reader lives in another package
	// (internal/alerts) behind an unexported decrypt, so the only way to read it
	// back through production code is to make production try to send. The send
	// path is SSRF-guarded at dial time, so a private literal turns "the config
	// decrypted to exactly this URL" into a deterministic, network-free
	// assertion: the guard's refusal quotes the address it refused, and that
	// address can only have come out of the ciphertext. AES-GCM authenticates
	// the whole blob, so an open that yields the right URL proves the secret
	// alongside it is intact too.
	seedChannelHost = "10.1.2.3"
	seedChannel     = `{"url":"https://10.1.2.3/hook","secret":"webhook-hmac-secret"}`
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
	// Through the egress fixtures, not off *db.Queries. The statements that write
	// the host-choosing columns are generated into a package this one cannot
	// import, and the only exported way in demands an egressgate.Ticket. See
	// egress_fixture_test.go: the fixture cannot skip the ticket, it can only be
	// honest about acting as a principal who may redirect the secret.
	if err := createVaultEntryFixture(t, queries, vaultegress.CreateEntryParams{
		ID:     entryID,
		UserID: user.ID,
		// Encrypted, with its index, exactly as the create path writes it. Seeding
		// cleartext here would leave the rekey scanner nothing to convert, and the
		// coverage guard would report the name surface as unreachable.
		Name:           enc("prod api token"),
		NameBidx:       h.nameBlindIndex(user.ID, "prod api token"),
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
	if err := setRotationTargetsFixture(t, queries, vaultegress.RotationTargetsParams{
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

	// The wrapped audit-name DEK, minted the way a real first audit write mints
	// it. Seeded through the production path rather than hand-rolled, so the
	// sweep is converting the same shape production writes.
	if _, dekErr := h.auditNameDEK(ctx); dekErr != nil {
		t.Fatalf("mint audit name key: %v", dekErr)
	}

	chID := seedNotificationChannelThroughTheRealWriter(t, h, queries)

	// The boot sentinel, written the way a real first boot writes it.
	if err := VerifyVaultKey(ctx, queries, h.keySource); err != nil {
		t.Fatalf("seal sentinel: %v", err)
	}

	return seededStore{userID: user.ID, entryID: entryID, inviteID: inv.ID, channelID: chID}
}

// seedNotificationChannelThroughTheRealWriter creates a channel the way the
// product creates one: through POST /api/admin/notification-channels.
//
// Hand-rolling this row is what hid a data-corruption bug for a whole review
// cycle. The old fixture wrote Config: string(ciphertext), which NO production
// writer ever produces (notifications.go base64-encodes into a TEXT column), so
// the fixture agreed with the sweep's mistaken assumption and both disagreed
// with the product. Every rekey test inherited the blind spot, and on a real
// store the sweep refused every instance that had ever created a channel.
//
// A fixture for an at-rest format must come from the writer that actually
// produces it. That is the rule this function exists to enforce.
func seedNotificationChannelThroughTheRealWriter(t *testing.T, h *VaultHandler, queries *db.Queries) string {
	t.Helper()
	nh := NewNotificationChannelsHandler(queries, h,
		alerts.NewChannelDispatcher(context.Background(), queries, h))

	body := `{"name":"ops-webhook","type":"webhook","config":` + seedChannel +
		`,"events":["` + alerts.EventRotationFailed + `"]}`
	rec := httptest.NewRecorder()
	nh.Create(rec, httptest.NewRequest(http.MethodPost, "/api/admin/notification-channels", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create notification channel: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.ID == "" {
		t.Fatalf("create notification channel: could not read the id back: %v (%s)", err, rec.Body.String())
	}
	return out.ID
}

// assertChannelConfigThroughTheRealReader reads a channel config back through
// internal/alerts, the code that actually serves it, rather than through the
// sweep's own helpers.
//
// Reading it back with h.DecryptValue proves nothing: that is the same call the
// sweep makes, so a sweep whose wire format disagrees with the product agrees
// with itself perfectly. The real reader base64-decodes BEFORE decrypting, and
// that one step is where the corruption lived.
//
// The send is expected to FAIL, at the SSRF dial guard, quoting the address from
// the decrypted config. See seedChannelHost for why that is the assertion.
func assertChannelConfigThroughTheRealReader(t *testing.T, h *VaultHandler, queries *db.Queries, channelID, stage string) {
	t.Helper()
	row, err := queries.GetNotificationChannel(context.Background(), channelID)
	if err != nil {
		t.Fatalf("%s: read notification channel: %v", stage, err)
	}

	// The stored form must be what the production READER expects to parse, which
	// is base64 text. Checked separately from the decrypt so a failure says which
	// half broke.
	if _, decErr := base64.StdEncoding.DecodeString(row.Config); decErr != nil {
		t.Fatalf("%s: notification_channels.config is not valid base64 (%v). "+
			"internal/alerts.decryptConfig base64-decodes before decrypting, so whatever wrote this "+
			"has made every webhook URL and bot token in the store unreadable by the product.",
			stage, decErr)
	}

	sendErr := alerts.NewChannelDispatcher(context.Background(), queries, h).DispatchTest(row)
	if sendErr == nil {
		t.Fatalf("%s: the test send to %s succeeded; it must be refused by the SSRF dial guard, "+
			"so this assertion is no longer proving anything about the config", stage, seedChannelHost)
	}
	msg := sendErr.Error()
	if strings.Contains(msg, "decrypting config") || strings.Contains(msg, "decoding config") {
		t.Fatalf("%s: the REAL reader (internal/alerts) could not open the channel config: %v", stage, sendErr)
	}
	if !strings.Contains(msg, seedChannelHost) {
		t.Fatalf("%s: the send failed with %q, which does not name %s. The webhook URL that came out of "+
			"the ciphertext is not the one that was stored.", stage, msg, seedChannelHost)
	}
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
	plain, err := h.openVersionForTest(row.EncryptedValue, row.Nonce, encVersion)
	if err != nil {
		t.Fatalf("%s: secret value did not decrypt: %v", stage, err)
	}
	if !plain.EqualsString(seedValue) {
		t.Fatalf("%s: secret value is not %q (len %d)", stage, seedValue, plain.Len())
	}
	plain.Wipe()

	for _, c := range []struct {
		name   string
		stored string
		want   string
		field  vaultfield.Field
	}{
		{"url", nullStringToString(row.Url), seedURL, vaultFieldURL},
		{"alias_url", nullStringToString(row.AliasUrl), seedAlias, vaultFieldAliasURL},
		{"username", nullStringToString(row.Username), seedUsername, vaultFieldUsername},
		{"category", nullStringToString(row.Category), seedCategory, vaultFieldCategory},
		{"notes", nullStringToString(row.Notes), seedNotes, vaultFieldNotes},
		{"provider_meta", nullStringToString(row.ProviderMeta), seedMeta, vaultFieldProviderMeta},
		{"rotation_targets", nullStringToString(row.RotationTargets), seedTargets, vaultFieldRotationTargets},
		{"custom_fields", row.CustomFields, seedFields, vaultFieldCustomFields},
	} {
		got, dErr := h.decryptColumn(c.stored, c.field)
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
	code, err := h.decryptColumn(invites[0].Code, vaultFieldInvitationCode)
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
	assertChannelConfigThroughTheRealReader(t, h, queries, s.channelID, stage)

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
	if _, err := retired.openVersionForTest(rows[0].EncryptedValue, rows[0].Nonce, 2); err == nil {
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
	if err := createVaultEntryFixture(t, queries, vaultegress.CreateEntryParams{
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
	plain, err := final.openVersionForTest(rows[0].EncryptedValue, rows[0].Nonce, 2)
	if err != nil || !plain.EqualsString(seedValue) {
		t.Fatalf("v1 secret after sweep is not %q (err %v)", seedValue, err)
	}
	plain.Wipe()
}

// TestSweepRepairsAStaleBlindIndexWithNoPreviousKeyConfigured.
//
// A stale blind index is NOT "encrypted with the previous key", and conflating
// the two produced a dead end with a false diagnosis.
//
// The reachable state: no rotation configured, and an index that does not match
// what the current key computes. BackfillMetadataAtRest runs on a two-minute
// budget and `continue`s past any row whose url will not decrypt, so a boot that
// times out or trips one bad row leaves exactly this. The old classification
// reported it as keyAgePrevious, so the operator was told "N value(s) are still
// encrypted with the previous key ... only because the old key is still loaded"
// when no old key existed, the sweep button was disabled on
// !previous_key_configured, and POST /rekey answered 400 "no previous key".
//
// The sweep can fix it with no old key at all, because an index is RECOMPUTED
// from cleartext rather than decrypted. So it must.
func TestSweepRepairsAStaleBlindIndexWithNoPreviousKeyConfigured(t *testing.T) {
	ctx := context.Background()
	dbConn, queries := newRekeyDB(t)
	h := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	seeded := seedUnderKey(t, h, queries)

	// A backfill that never finished: the index does not match the host.
	if _, err := dbConn.ExecContext(ctx,
		`UPDATE vault_entries SET url_bidx = ? WHERE id = ?`,
		strings.Repeat("ab", 32), seeded.entryID); err != nil {
		t.Fatalf("plant a stale index: %v", err)
	}

	// The damage is real and silent: autofill returns nothing, no error.
	before := httptest.NewRecorder()
	h.Match(before, withUser(httptest.NewRequest(http.MethodGet, "/api/vault/match?url="+seedURL, nil), seeded.userID))
	var beforeEntries []vaultEntryMeta
	if err := json.Unmarshal(before.Body.Bytes(), &beforeEntries); err != nil {
		t.Fatalf("decode match: %v", err)
	}
	if len(beforeEntries) != 0 {
		t.Fatalf("the planted index still matches (%d entries); this test is not reproducing the state "+
			"it exists to cover", len(beforeEntries))
	}

	status, err := h.RekeyStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Status != "needs_rekey" {
		t.Fatalf("status = %q, want needs_rekey; a stale lookup index is work the sweep must do", status.Status)
	}
	if status.ValuesStale != 1 {
		t.Fatalf("ValuesStale = %d, want 1", status.ValuesStale)
	}
	if status.ValuesOnPrevious != 0 {
		t.Fatalf(`ValuesOnPrevious = %d with NO previous key configured.

Classifying a stale index as "on the previous key" is a diagnosis the keyring
contradicts. It tells the operator to go and find a key they never lost, and the
UI then disables the only button that would have fixed it.`, status.ValuesOnPrevious)
	}

	// And the sweep must run, with no previous key, and repair it.
	rep, err := h.RekeyVault(ctx)
	if errors.Is(err, ErrRekeyNoPreviousKey) {
		t.Fatal("the sweep refused for want of a previous key, but a blind index is recomputed from " +
			"cleartext: there is nothing to convert FROM, so no old key is needed")
	}
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if rep.RowsConverted != 1 {
		t.Fatalf("RowsConverted = %d, want 1", rep.RowsConverted)
	}

	after := httptest.NewRecorder()
	h.Match(after, withUser(httptest.NewRequest(http.MethodGet, "/api/vault/match?url="+seedURL, nil), seeded.userID))
	var afterEntries []vaultEntryMeta
	if err := json.Unmarshal(after.Body.Bytes(), &afterEntries); err != nil {
		t.Fatalf("decode match: %v", err)
	}
	if len(afterEntries) != 1 {
		t.Fatalf("autofill returned %d entries after the repair, want 1", len(afterEntries))
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

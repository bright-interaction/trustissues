package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/brightinteraction/trustissues/internal/config"
	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
	"github.com/brightinteraction/trustissues/internal/passwordhash"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/pbkdf2"
)

// VaultHandler handles secrets vault operations with AES-256-GCM encryption.
type VaultHandler struct {
	db            *sql.DB
	queries       *db.Queries
	encryptionKey [32]byte // PBKDF2-derived key (current, version 2)
	legacyKey     [32]byte // SHA-256 key (version 1, only used during migration)
	bidxKey       [32]byte // PBKDF2-derived key for the URL blind index (HMAC)
	// delivery tracks the detached rotation-delivery goroutines so shutdown can
	// wait for them. srv.Shutdown only drains in-flight HTTP requests; a manual
	// rotate returns as soon as the value is stored and finishes delivery in the
	// background, so a restart in that window killed the goroutine mid-flight.
	// The value was already committed and the old key already revoked upstream,
	// but rotation_log and last_rotation_error were never finalised, so the
	// rotation was recorded as a clean success while the consumer never received
	// the new key.
	delivery sync.WaitGroup
}

// WaitForDelivery blocks until every in-flight rotation delivery has finished,
// or until the budget expires. It reports whether everything drained.
//
// The budget is essential: a delivery goroutine runs on a 15-minute context, and
// an unbounded wait would hold the process open far past any container stop
// grace period. Docker SIGKILLs 10 seconds after SIGTERM by default, so an
// unbounded wait does not protect the delivery at all, it just guarantees the
// process is killed hard instead of exiting cleanly. Bounded, plus a
// stop_grace_period in the compose file that exceeds it, means the common case
// (delivery finishes in a second or two) completes and the pathological case
// still exits in a predictable time.
func (h *VaultHandler) WaitForDelivery(budget time.Duration) bool {
	done := make(chan struct{})
	go func() {
		h.delivery.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(budget):
		return false
	}
}

// NewVaultHandler creates a new VaultHandler keyed off cfg.VaultKey. The
// encryption key is derived using PBKDF2-SHA256 with 600,000 iterations
// (OWASP 2024 recommendation). A legacy SHA-256 key is also derived to
// support transparent migration of version-1 entries (a fresh Trustissues
// database only ever writes version 2, but the v1 path keeps DecryptValue's
// encVersion contract honest for imported data).
func NewVaultHandler(dbConn *sql.DB, queries *db.Queries, cfg *config.Config) *VaultHandler {
	keySource := cfg.VaultKey

	// Version 2: PBKDF2-SHA256, 600k iterations, 32-byte output
	salt := []byte("trustissues:vault:v2")
	derived := pbkdf2.Key([]byte(keySource), salt, 600_000, 32, sha256.New)
	var newKey [32]byte
	copy(newKey[:], derived)
	// Zero the intermediate slice
	for i := range derived {
		derived[i] = 0
	}

	// Version 1 (legacy): single SHA-256 pass
	legacyKey := sha256.Sum256([]byte(keySource + ":secrets-vault"))

	// Blind-index key: a SEPARATE PBKDF2 derivation (distinct salt) from the same
	// vault key, used to HMAC normalized URLs so autofill can match on an
	// encrypted url column without ever storing the host in cleartext. It must
	// not equal the value-encryption key: reusing an encryption key as a MAC key
	// is a well-known cross-primitive footgun.
	bidxSalt := []byte("trustissues:vault:bidx:v1")
	bidxDerived := pbkdf2.Key([]byte(keySource), bidxSalt, 600_000, 32, sha256.New)
	var bidxKey [32]byte
	copy(bidxKey[:], bidxDerived)
	for i := range bidxDerived {
		bidxDerived[i] = 0
	}

	return &VaultHandler{db: dbConn, queries: queries, encryptionKey: newKey, legacyKey: legacyKey, bidxKey: bidxKey}
}

// normalizeVaultHost reduces a raw URL to the deterministic form used for the
// blind index: the lowercased hostname, with scheme, port, path, and query
// discarded (matching dockyard's host-based autofill matcher). A bare host with
// no scheme is accepted. It returns "" when no host can be extracted, so such
// entries never populate a blind index and never match.
func normalizeVaultHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// urlBlindIndex computes the deterministic HMAC-SHA256 lookup token for a URL's
// normalized host. Empty/unparseable inputs yield "" (stored as an empty index
// that the match query skips). The token is keyed by bidxKey, so it is stable
// for equality lookups yet reveals nothing about the host to a DB reader.
// bidxScope returns the blind-index scope an entry belongs to: its collection
// when it lives in one, otherwise its owner. Keying the index per scope is what
// keeps it unlinkable: two users with an entry on the same host produce
// different index values, so a stolen database no longer reveals that they share
// a site. Entries inside one collection still share a scope, which is exactly
// what shared autofill needs.
func bidxScope(userID string, collectionID sql.NullString) string {
	if collectionID.Valid && collectionID.String != "" {
		return "c:" + collectionID.String
	}
	return "u:" + userID
}

// urlBlindIndex derives the keyed lookup value for a URL within one scope.
// The scope is mixed into the HMAC input (length-prefixed so a crafted user or
// collection id cannot collide with another scope by shifting the separator).
// An empty scope yields an empty index: an unscoped index would be linkable
// across users, so it is never written.
func (h *VaultHandler) urlBlindIndex(scope, raw string) string {
	host := normalizeVaultHost(raw)
	if host == "" || scope == "" {
		return ""
	}
	mac := hmac.New(sha256.New, h.bidxKey[:])
	fmt.Fprintf(mac, "%d:%s|%s", len(scope), scope, host)
	return hex.EncodeToString(mac.Sum(nil))
}

// encryptMetaColumns encrypts the free-text metadata columns of a vault entry
// for at-rest storage using the enc:v1: column scheme. Empty values pass through
// unchanged (encryptColumn skips them), and already-encrypted values are not
// double-wrapped, so callers may pass either cleartext or stored ciphertext.
// maxCustomFields caps how many custom fields an entry may carry.
const maxCustomFields = 50

// validateCustomFields enforces sane limits before storage.
func validateCustomFields(fields []CustomField) error {
	if len(fields) > maxCustomFields {
		return fmt.Errorf("too many custom fields (max %d)", maxCustomFields)
	}
	for _, f := range fields {
		if len(f.Label) > 255 {
			return fmt.Errorf("custom field label too long (max 255)")
		}
		if len(f.Value) > 10000 {
			return fmt.Errorf("custom field value too long (max 10000)")
		}
	}
	return nil
}

// encryptCustomFields marshals the fields to JSON and encrypts the blob at rest.
// An empty set stores as a plaintext "[]" so a never-touched entry is cheap.
func (h *VaultHandler) encryptCustomFields(fields []CustomField) (string, error) {
	if len(fields) == 0 {
		return "[]", nil
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return h.encryptColumn(string(raw))
}

// decryptCustomFields decrypts and parses the stored blob, returning an empty
// slice on any error (a corrupt field must never break loading an entry).
func (h *VaultHandler) decryptCustomFields(stored string) []CustomField {
	dec := h.decryptColumnOrLog(stored, "[]", "custom_fields")
	if dec == "" {
		return nil
	}
	var fields []CustomField
	if err := json.Unmarshal([]byte(dec), &fields); err != nil {
		return nil
	}
	return fields
}

// encryptMetaColumnsIfNeeded is the STORAGE-side variant of encryptMetaColumns:
// each column may already be ciphertext (it was read out of the database), so it
// routes through encryptColumnIfNeeded and leaves already-encrypted values
// untouched. Use this from backfills and other paths that carry stored values
// forward. Never use it on client input: deciding by content whether to encrypt
// is what created the decryption oracle (see vaultColumnEncPrefix).
func (h *VaultHandler) encryptMetaColumnsIfNeeded(rawURL, aliasURL, username, category, notes string) (encURL, encAlias, encUser, encCat, encNotes string, err error) {
	if encURL, err = h.encryptColumnIfNeeded(rawURL); err != nil {
		return
	}
	if encAlias, err = h.encryptColumnIfNeeded(aliasURL); err != nil {
		return
	}
	if encUser, err = h.encryptColumnIfNeeded(username); err != nil {
		return
	}
	if encCat, err = h.encryptColumnIfNeeded(category); err != nil {
		return
	}
	encNotes, err = h.encryptColumnIfNeeded(notes)
	return
}

func (h *VaultHandler) encryptMetaColumns(rawURL, aliasURL, username, category, notes string) (encURL, encAlias, encUser, encCat, encNotes string, err error) {
	if encURL, err = h.encryptColumn(rawURL); err != nil {
		return
	}
	if encAlias, err = h.encryptColumn(aliasURL); err != nil {
		return
	}
	if encUser, err = h.encryptColumn(username); err != nil {
		return
	}
	if encCat, err = h.encryptColumn(category); err != nil {
		return
	}
	encNotes, err = h.encryptColumn(notes)
	return
}

// MigrateEncryption re-encrypts all vault entries that were encrypted with the
// legacy SHA-256 key (encryption_version=1) using the new PBKDF2-derived key
// (encryption_version=2). This runs once at startup inside a transaction.
func (h *VaultHandler) MigrateEncryption() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Check if there are any v1 entries to migrate
	count, err := h.queries.CountVaultEntriesV1(ctx)
	if err != nil {
		return fmt.Errorf("checking v1 entry count: %w", err)
	}
	if count == 0 {
		return nil
	}

	slog.Info("migrating vault encryption from SHA-256 to PBKDF2", "entries", count)

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning migration transaction: %w", err)
	}
	defer tx.Rollback()

	qtx := h.queries.WithTx(tx)

	entries, err := qtx.ListVaultEntriesV1(ctx)
	if err != nil {
		return fmt.Errorf("querying v1 entries: %w", err)
	}

	migrated := 0
	for _, e := range entries {
		// Decrypt with legacy SHA-256 key
		plaintext, err := decryptWithKey(h.legacyKey, e.EncryptedValue, e.Nonce)
		if err != nil {
			return fmt.Errorf("decrypting entry %s with legacy key: %w", e.ID, err)
		}

		// Re-encrypt with PBKDF2 key
		newCiphertext, newNonce, err := h.encrypt(plaintext)
		// Zero plaintext immediately
		for i := range plaintext {
			plaintext[i] = 0
		}
		if err != nil {
			return fmt.Errorf("re-encrypting entry %s: %w", e.ID, err)
		}

		if err := qtx.MigrateVaultEntryEncryption(ctx, db.MigrateVaultEntryEncryptionParams{
			EncryptedValue: newCiphertext,
			Nonce:          newNonce,
			ID:             e.ID,
		}); err != nil {
			return fmt.Errorf("updating entry %s: %w", e.ID, err)
		}
		migrated++
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing migration: %w", err)
	}

	slog.Info("vault encryption migration complete", "migrated", migrated)

	// Zero the legacy key, no longer needed
	for i := range h.legacyKey {
		h.legacyKey[i] = 0
	}

	return nil
}

// BackfillMetadataAtRest encrypts any free-text metadata columns (url,
// alias_url, username, category, notes) still stored in cleartext and populates
// the url_bidx / alias_url_bidx blind indexes for rows written before at-rest
// metadata encryption landed. Idempotent: enc:v1:-prefixed columns pass through
// unchanged and the blind index is recomputed deterministically, so it is safe
// to run on every boot. Mirrors the MigrateEncryption / BackfillMetadataEncryption
// precedent. Returns the number of rows updated.
func (h *VaultHandler) BackfillMetadataAtRest() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rows, err := h.queries.ListVaultEntriesForMetaAtRestBackfill(ctx)
	if err != nil {
		return 0, fmt.Errorf("listing vault entries for metadata backfill: %w", err)
	}

	updated := 0
	for _, row := range rows {
		// A row needs a rewrite if any text column still holds cleartext, or if
		// a blind index is stale/missing relative to its (decrypted) URL.
		needsMeta := metaColumnNeedsEncrypt(row.Url.String) ||
			metaColumnNeedsEncrypt(row.AliasUrl.String) ||
			metaColumnNeedsEncrypt(row.Username.String) ||
			metaColumnNeedsEncrypt(row.Category.String) ||
			metaColumnNeedsEncrypt(row.Notes.String)

		// Recover the cleartext host to (re)compute the blind index. decryptColumn
		// is idempotent on cleartext, so this works whether the column is still
		// plaintext or already encrypted.
		urlPlain, derr := h.decryptColumn(row.Url.String)
		if derr != nil {
			slog.Error("vault: metadata backfill url decrypt failed", "id", row.ID, "error", derr)
			continue
		}
		aliasPlain, derr := h.decryptColumn(row.AliasUrl.String)
		if derr != nil {
			slog.Error("vault: metadata backfill alias_url decrypt failed", "id", row.ID, "error", derr)
			continue
		}
		scope := bidxScope(row.UserID, row.CollectionID)
		wantURLBidx := h.urlBlindIndex(scope, urlPlain)
		wantAliasBidx := h.urlBlindIndex(scope, aliasPlain)
		needsBidx := wantURLBidx != row.UrlBidx || wantAliasBidx != row.AliasUrlBidx

		if !needsMeta && !needsBidx {
			continue
		}

		// Storage-side caller: these values come out of the database and may
		// ALREADY be ciphertext, so this must use the idempotent variant.
		// encryptMetaColumns routes to encryptColumn, which always encrypts
		// (that is what closes the decryption oracle) and would therefore
		// double-wrap an already-encrypted column, permanently corrupting the
		// user's saved url/username/notes on the next boot.
		encURL, encAlias, encUser, encCat, encNotes, encErr := h.encryptMetaColumnsIfNeeded(
			row.Url.String, row.AliasUrl.String, row.Username.String, row.Category.String, row.Notes.String)
		if encErr != nil {
			return updated, fmt.Errorf("encrypt metadata for %s: %w", row.ID, encErr)
		}
		if err := h.queries.UpdateVaultEntryMetaAtRest(ctx, db.UpdateVaultEntryMetaAtRestParams{
			Url:          toNullString(encURL),
			AliasUrl:     toNullString(encAlias),
			Username:     toNullString(encUser),
			Category:     toNullString(encCat),
			Notes:        toNullString(encNotes),
			UrlBidx:      wantURLBidx,
			AliasUrlBidx: wantAliasBidx,
			ID:           row.ID,
		}); err != nil {
			return updated, fmt.Errorf("persist metadata for %s: %w", row.ID, err)
		}
		updated++
	}
	if updated > 0 {
		slog.Info("vault: backfilled metadata-at-rest encryption", "rows_updated", updated)
	}
	return updated, nil
}

// decryptWithKey decrypts data using a specific AES-256-GCM key.
func decryptWithKey(key [32]byte, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Guard the nonce length ourselves: gcm.Open PANICS on a wrong-length
	// (e.g. nil/empty) nonce rather than returning an error, which would
	// otherwise surface as a bare HTTP 500 via chi's Recoverer. A malformed
	// stored nonce must degrade to a handled decrypt error, never a panic.
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("decrypt: invalid nonce length %d (want %d)", len(nonce), gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// vaultEntryMeta is the JSON response for vault entries (metadata only, no secret value).
type vaultEntryMeta struct {
	ID                   string        `json:"id"`
	UserID               string        `json:"user_id,omitempty"`
	CollectionID         *string       `json:"collection_id"`
	Name                 string        `json:"name"`
	URL                  string        `json:"url"`
	AliasURL             string        `json:"alias_url"`
	Username             string        `json:"username"`
	Category             string        `json:"category"`
	Notes                string        `json:"notes"`
	AutoLogin            bool          `json:"auto_login"`
	RotationIntervalDays *int          `json:"rotation_interval_days"`
	ExpiresAt            *string       `json:"expires_at"`
	LastRotatedAt        *string       `json:"last_rotated_at"`
	RotationStatus       string        `json:"rotation_status"`
	Provider             string        `json:"provider"`
	ProviderMeta         string        `json:"provider_meta"`
	AutoRotate           bool          `json:"auto_rotate"`
	LastRotationError    string        `json:"last_rotation_error"`
	CustomFields         []CustomField `json:"custom_fields,omitempty"`
	// The capability ceiling, returned so the edit form can show what is set.
	// Not a secret: it is a list of hosts, and the operator needs to see it to
	// narrow it. An empty list means no agent token can be minted at all.
	DestinationPatterns []string `json:"destination_patterns"`
	CreatedAt           *string  `json:"created_at"`
	UpdatedAt           *string  `json:"updated_at"`
}

// CustomField is an arbitrary user-defined field on an entry (Bitwarden-style):
// a label, a value, and a secret flag that tells the UI to mask the value by
// default. The whole set is encrypted at rest, so a secret field is protected
// the same way regardless of the flag; the flag is only a display hint.
type CustomField struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Secret bool   `json:"secret"`
}

// vaultEntryFull includes the decrypted secret value (only returned on explicit unlock).
type vaultEntryFull struct {
	vaultEntryMeta
	Value string `json:"value"`
}

// vaultMetaFromGetRow converts a db.GetVaultEntryMetaRow to a vaultEntryMeta.
// Method (not free func) so it can decrypt the at-rest-encrypted provider_meta
// column before it is emitted to a client.
func (h *VaultHandler) vaultMetaFromGetRow(row db.GetVaultEntryMetaRow) vaultEntryMeta {
	e := vaultEntryMeta{
		ID:                   row.ID,
		Name:                 row.Name,
		URL:                  h.decryptColumnOrLog(row.Url.String, "", "url"),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", "alias_url"),
		Username:             h.decryptColumnOrLog(row.Username.String, "", "username"),
		Category:             h.decryptColumnOrLog(row.Category.String, "", "category"),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", "notes"),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         h.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"),
		AutoRotate:           row.AutoRotate.Int64 != 0,
		LastRotationError:    row.LastRotationError.String,
		CustomFields:         h.decryptCustomFields(row.CustomFields),
		DestinationPatterns:  parseDestinationPatterns(row.DestinationPatterns),
		CreatedAt:            nullTimePtr(row.CreatedAt),
		UpdatedAt:            nullTimePtr(row.UpdatedAt),
	}
	e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt, e.CreatedAt, &e.LastRotationError)
	return e
}

// vaultMetaFromListAllRow converts a db.ListAllVaultEntriesRow to a vaultEntryMeta.
func (h *VaultHandler) vaultMetaFromListAllRow(row db.ListAllVaultEntriesRow) vaultEntryMeta {
	return vaultEntryMeta{
		ID:                   row.ID,
		UserID:               row.UserID,
		Name:                 row.Name,
		URL:                  h.decryptColumnOrLog(row.Url.String, "", "url"),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", "alias_url"),
		Username:             h.decryptColumnOrLog(row.Username.String, "", "username"),
		Category:             h.decryptColumnOrLog(row.Category.String, "", "category"),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", "notes"),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         h.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"),
		AutoRotate:           row.AutoRotate.Int64 != 0,
		LastRotationError:    row.LastRotationError.String,
		CreatedAt:            nullTimePtr(row.CreatedAt),
		UpdatedAt:            nullTimePtr(row.UpdatedAt),
	}
}

// vaultMetaFromListByUserRow converts a db.ListVaultEntriesByUserRow to a vaultEntryMeta.
func (h *VaultHandler) vaultMetaFromListByUserRow(row db.ListVaultEntriesByUserRow) vaultEntryMeta {
	return vaultEntryMeta{
		ID:                   row.ID,
		UserID:               row.UserID,
		Name:                 row.Name,
		URL:                  h.decryptColumnOrLog(row.Url.String, "", "url"),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", "alias_url"),
		Username:             h.decryptColumnOrLog(row.Username.String, "", "username"),
		Category:             h.decryptColumnOrLog(row.Category.String, "", "category"),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", "notes"),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         h.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"),
		AutoRotate:           row.AutoRotate.Int64 != 0,
		LastRotationError:    row.LastRotationError.String,
		CreatedAt:            nullTimePtr(row.CreatedAt),
		UpdatedAt:            nullTimePtr(row.UpdatedAt),
	}
}

// vaultMetaFromMatchRow converts a db.MatchVaultEntriesByURLRow to a vaultEntryMeta.
func (h *VaultHandler) vaultMetaFromMatchRow(row db.MatchVaultEntriesByURLRow) vaultEntryMeta {
	return vaultEntryMeta{
		ID:                   row.ID,
		Name:                 row.Name,
		URL:                  h.decryptColumnOrLog(row.Url.String, "", "url"),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", "alias_url"),
		Username:             h.decryptColumnOrLog(row.Username.String, "", "username"),
		Category:             h.decryptColumnOrLog(row.Category.String, "", "category"),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", "notes"),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         h.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"),
		AutoRotate:           row.AutoRotate.Int64 != 0,
		LastRotationError:    row.LastRotationError.String,
		CreatedAt:            nullTimePtr(row.CreatedAt),
		UpdatedAt:            nullTimePtr(row.UpdatedAt),
	}
}

// vaultMetaFromAccessibleRow converts a db.ListAccessibleVaultEntriesRow (the
// collection-aware listing that returns personal + collection entries) to a
// vaultEntryMeta, including which collection the entry belongs to.
func (h *VaultHandler) vaultMetaFromAccessibleRow(row db.ListAccessibleVaultEntriesRow) vaultEntryMeta {
	return vaultEntryMeta{
		ID:                   row.ID,
		UserID:               row.UserID,
		CollectionID:         nullStringPtr(row.CollectionID),
		Name:                 row.Name,
		URL:                  h.decryptColumnOrLog(row.Url.String, "", "url"),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", "alias_url"),
		Username:             h.decryptColumnOrLog(row.Username.String, "", "username"),
		Category:             h.decryptColumnOrLog(row.Category.String, "", "category"),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", "notes"),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         h.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"),
		AutoRotate:           row.AutoRotate.Int64 != 0,
		LastRotationError:    row.LastRotationError.String,
		CreatedAt:            nullTimePtr(row.CreatedAt),
		UpdatedAt:            nullTimePtr(row.UpdatedAt),
	}
}

// vaultMetaFromMatchPersonalRow converts a personal-scope autofill match row.
func (h *VaultHandler) vaultMetaFromMatchPersonalRow(row db.MatchPersonalVaultEntriesByURLRow) vaultEntryMeta {
	return h.vaultMetaFromMatchAccessibleRow(db.MatchAccessibleVaultEntriesByURLRow(row))
}

// vaultMetaFromMatchCollectionRow converts a collection-scope autofill match row.
func (h *VaultHandler) vaultMetaFromMatchCollectionRow(row db.MatchCollectionVaultEntriesByURLRow) vaultEntryMeta {
	return h.vaultMetaFromMatchAccessibleRow(db.MatchAccessibleVaultEntriesByURLRow(row))
}

// vaultMetaFromMatchAccessibleRow converts a collection-aware autofill match row
// to a vaultEntryMeta.
func (h *VaultHandler) vaultMetaFromMatchAccessibleRow(row db.MatchAccessibleVaultEntriesByURLRow) vaultEntryMeta {
	return vaultEntryMeta{
		ID:                   row.ID,
		CollectionID:         nullStringPtr(row.CollectionID),
		Name:                 row.Name,
		URL:                  h.decryptColumnOrLog(row.Url.String, "", "url"),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", "alias_url"),
		Username:             h.decryptColumnOrLog(row.Username.String, "", "username"),
		Category:             h.decryptColumnOrLog(row.Category.String, "", "category"),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", "notes"),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         h.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"),
		AutoRotate:           row.AutoRotate.Int64 != 0,
		LastRotationError:    row.LastRotationError.String,
		CreatedAt:            nullTimePtr(row.CreatedAt),
		UpdatedAt:            nullTimePtr(row.UpdatedAt),
	}
}

// encrypt encrypts data using AES-256-GCM.
func (h *VaultHandler) encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(h.encryptionKey[:])
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// decrypt decrypts data using AES-256-GCM.
func (h *VaultHandler) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(h.encryptionKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Guard the nonce length ourselves: gcm.Open PANICS on a wrong-length
	// (e.g. nil/empty) nonce rather than returning an error, which would
	// otherwise surface as a bare HTTP 500 via chi's Recoverer. A malformed
	// stored nonce must degrade to a handled decrypt error, never a panic.
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("decrypt: invalid nonce length %d (want %d)", len(nonce), gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DecryptedValueByID returns the decrypted secret value of an entry by id. It
// exists for server-side consumers that inject a stored credential into an
// outbound request without exposing it (the AI gateway). It does NOT do access
// control: the caller must have already authorized (the AI gateway resolves the
// provider-key entry from an admin-set setting, not from user input).
func (h *VaultHandler) DecryptedValueByID(ctx context.Context, id string) (string, error) {
	row, err := h.queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		return "", err
	}
	pt, err := h.decrypt(row.EncryptedValue, row.Nonce)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// EncryptValue encrypts a plaintext value using the current PBKDF2 key.
// Used by other handlers that need vault-compatible encryption.
func (h *VaultHandler) EncryptValue(plaintext []byte) (ciphertext, nonce []byte, err error) {
	return h.encrypt(plaintext)
}

// DecryptValue decrypts a vault-encrypted value. It handles both v1 (legacy SHA-256)
// and v2 (PBKDF2) encryption versions. This method satisfies the
// alerts.ConfigDecrypter interface so the vault handler can be passed to
// alerts.NewChannelDispatcher at integration.
func (h *VaultHandler) DecryptValue(ciphertext, nonce []byte, encVersion int) ([]byte, error) {
	if encVersion == 1 {
		return decryptWithKey(h.legacyKey, ciphertext, nonce)
	}
	return h.decrypt(ciphertext, nonce)
}

// computeRotationStatus determines the rotation status of a vault entry based
// on its rotation interval, expiration date, and last rotation time.
// computeRotationStatus derives the badge shown for a vault entry.
//
// lastRotationError is NOT cosmetic: an entry whose auto-rotation is failing
// must never report "fresh". It did until 2026-07-27, when the Cloudflare entry
// logged 50 consecutive hourly failures ("identify token: token verification
// failed") while the UI and MCP both reported `fresh`. Age alone cannot tell you
// rotation works. Worse, UpdateVaultEntryValue stamps last_rotated_at, so saving
// a value manually looks identical to a successful rotation and buys another
// full interval of silence. Keep this in sync with the dockyard twin.
func computeRotationStatus(rotationDays *int, expiresAt *string, lastRotatedAt *string, createdAt *string, lastRotationError *string) string {
	// If expires_at is set and past, return "expired"
	if expiresAt != nil && *expiresAt != "" {
		exp, err := time.Parse("2006-01-02 15:04:05", *expiresAt)
		if err == nil && time.Now().After(exp) {
			return "expired"
		}
		// Also try RFC3339
		exp, err = time.Parse(time.RFC3339, *expiresAt)
		if err == nil && time.Now().After(exp) {
			return "expired"
		}
	}

	// A recorded rotation failure outranks any age-based status. Checked after
	// "expired" only because an already-expired credential is the worse fact.
	if lastRotationError != nil && strings.TrimSpace(*lastRotationError) != "" {
		return "error"
	}

	// If no rotation interval, it's fresh
	if rotationDays == nil || *rotationDays <= 0 {
		return "fresh"
	}

	// A never-rotated entry ages from when it was enrolled, not "forever fresh".
	// The scheduler uses the same COALESCE(last_rotated_at, created_at) fallback,
	// and the two must agree: this used to return "fresh" unconditionally while
	// the sweep treated the same NULL as "due now", so the UI told an operator
	// their key was fresh in the same hour the scheduler rotated it away.
	anchor := lastRotatedAt
	if anchor == nil || *anchor == "" {
		anchor = createdAt
	}
	if anchor == nil || *anchor == "" {
		return "fresh"
	}

	// Calculate age
	lastRotated, err := time.Parse("2006-01-02 15:04:05", *anchor)
	if err != nil {
		// Must be *anchor, not *lastRotatedAt: when the entry has never rotated,
		// anchor is createdAt and lastRotatedAt is nil, so this dereferenced nil
		// and panicked for any createdAt the first layout could not parse.
		lastRotated, err = time.Parse(time.RFC3339, *anchor)
		if err != nil {
			return "fresh"
		}
	}

	ageDays := time.Since(lastRotated).Hours() / 24
	interval := float64(*rotationDays)

	if ageDays > interval {
		return "overdue"
	}
	if ageDays >= interval*0.8 {
		return "due_soon"
	}
	return "fresh"
}

// Collection membership roles (per-collection, distinct from the account-level
// admin/user/vault_only roles).
const (
	collRoleViewer  = "viewer"
	collRoleEditor  = "editor"
	collRoleManager = "manager"
)

// entryAccess resolves whether the authenticated user may read and/or write a
// vault entry. Personal entries (no collection) are owner-only, with instance
// admins seeing everything. Collection entries are governed by the caller's
// membership role OR'd with the creating owner's residual right: viewer can
// read, editor and manager can also write, and the user recorded in user_id
// keeps read+write on an entry they created even after it is placed in a
// collection; a non-member non-owner gets nothing. Returns (false, false) for a
// missing entry so callers 404 uniformly. This is the single authorization point
// for every single-entry operation; do not bypass it with a raw owner check.
func (h *VaultHandler) entryAccess(r *http.Request, entryID string) (canRead, canWrite bool) {
	return h.entryAccessFor(r.Context(), middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context()), entryID)
}

// entryCurrentlyUsableBy reports whether userID may USE this entry's secret
// value right now: they are the personal owner, or an accepted member of the
// collection it lives in.
//
// This is deliberately NARROWER than entryAccessFor's canRead. entryAccessFor
// grants a removed creator a residual READ so they can recover a secret they own
// when somebody moves it into a collection they are not a member of. That right
// is for recovering their own value through the UI; it must never let them spend
// the credential, because a removed creator is otherwise indistinguishable from
// a current one (the entry keeps their user_id forever).
//
// Gating value-resolution on canRead is exactly the mistake that made the
// forgejo auth_token path an exfiltration channel. Same distinction the
// capability bridge draws: reading a secret and delegating it are different
// questions, and delegation is the narrow one.
func (h *VaultHandler) entryCurrentlyUsableBy(ctx context.Context, userID, entryID string) bool {
	// isAdmin false on purpose: this asks whether THIS user may spend the
	// credential, not whether the process is privileged. Callers that want an
	// admin bypass add it explicitly at the call site (see ValidateKey).
	return h.grantFor(ctx, userID, false, entryID).use
}

// entryAccessFor is entryAccess without an *http.Request, so background work
// (rotation delivery) can ask the same question about a user who is not the
// caller. entryAccess is the request-scoped wrapper; both share this body so
// the two can never drift into different answers.
func (h *VaultHandler) entryAccessFor(ctx context.Context, userID string, isAdmin bool, entryID string) (canRead, canWrite bool) {
	g := h.grantFor(ctx, userID, isAdmin, entryID)
	return g.read, g.manage
}

// canMoveEntryOutOfCollection reports whether the caller may move an entry that
// currently lives in collectionID somewhere else. Moving it out revokes access
// for everyone who reached it through that collection, including the manager who
// can no longer get it back, so the editor role is deliberately NOT enough here:
// only the entry's creating owner, an instance admin, or a manager of the source
// collection.
func (h *VaultHandler) canMoveEntryOutOfCollection(r *http.Request, ownerID, collectionID string) bool {
	if middleware.IsAdmin(r.Context()) {
		return true
	}
	userID := middleware.GetUserID(r.Context())
	if userID != "" && userID == ownerID {
		return true
	}
	role, err := h.queries.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
		CollectionID: collectionID,
		UserID:       userID,
	})
	if err != nil {
		return false
	}
	return role == collRoleManager
}

// canWriteCollection reports whether the caller may add or modify entries in a
// collection: an instance admin, or a member with the editor or manager role.
func (h *VaultHandler) canWriteCollection(r *http.Request, collectionID string) bool {
	if middleware.IsAdmin(r.Context()) {
		return true
	}
	role, err := h.queries.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
		CollectionID: collectionID,
		UserID:       middleware.GetUserID(r.Context()),
	})
	if err != nil {
		return false
	}
	return role == collRoleEditor || role == collRoleManager
}

// List handles GET /api/vault and returns vault entries (metadata only, no secret values).
// Non-admin users see only their own entries.
// Admin can use ?all=true to see all entries or ?user_id=X to scope to a specific user.
func (h *VaultHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	isAdmin := middleware.IsAdmin(r.Context())
	ctx := r.Context()

	entries := []vaultEntryMeta{}

	if isAdmin && r.URL.Query().Get("all") == "true" {
		rows, err := h.queries.ListAllVaultEntries(ctx)
		if err != nil {
			logError(r, "vault.list: query failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		for _, row := range rows {
			e := h.vaultMetaFromListAllRow(row)
			e.CollectionID = nullStringPtr(row.CollectionID)
			e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt, e.CreatedAt, &e.LastRotationError)
			entries = append(entries, e)
		}
	} else if isAdmin && r.URL.Query().Get("user_id") != "" {
		rows, err := h.queries.ListVaultEntriesByUser(ctx, r.URL.Query().Get("user_id"))
		if err != nil {
			logError(r, "vault.list: query failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		for _, row := range rows {
			e := h.vaultMetaFromListByUserRow(row)
			e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt, e.CreatedAt, &e.LastRotationError)
			entries = append(entries, e)
		}
	} else {
		// Non-admin: personal entries plus entries in collections the user
		// belongs to. Access is enforced in the query itself.
		rows, err := h.queries.ListAccessibleVaultEntries(ctx, db.ListAccessibleVaultEntriesParams{
			ID:       userID,
			UserID:   userID,
			UserID_2: userID,
		})
		if err != nil {
			logError(r, "vault.list: query failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		for _, row := range rows {
			e := h.vaultMetaFromAccessibleRow(row)
			e.UserID = "" // omitempty will exclude it
			e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt, e.CreatedAt, &e.LastRotationError)
			entries = append(entries, e)
		}
	}

	writeJSON(w, http.StatusOK, entries)
}

// Create handles POST /api/vault and creates a new vault entry with an encrypted value.
func (h *VaultHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	ctx := r.Context()

	var req struct {
		Name                 string        `json:"name"`
		Value                string        `json:"value"`
		URL                  string        `json:"url"`
		AliasURL             string        `json:"alias_url"`
		Username             string        `json:"username"`
		Category             string        `json:"category"`
		Notes                string        `json:"notes"`
		AutoLogin            bool          `json:"auto_login"`
		RotationIntervalDays *int          `json:"rotation_interval_days"`
		ExpiresAt            *string       `json:"expires_at"`
		Provider             string        `json:"provider"`
		ProviderMeta         string        `json:"provider_meta"`
		AutoRotate           bool          `json:"auto_rotate"`
		CollectionID         *string       `json:"collection_id"`
		CustomFields         []CustomField `json:"custom_fields"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	if err := validateCustomFields(req.CustomFields); err != nil {
		writeBadRequest(w, r, err.Error())
		return
	}

	// If the entry is being created inside a shared collection, the caller must
	// be an editor or manager of it (or an instance admin). Authorize before we
	// do any work so a non-member cannot even probe collection ids.
	var collectionID sql.NullString
	if req.CollectionID != nil && *req.CollectionID != "" {
		if !h.canWriteCollection(r, *req.CollectionID) {
			writeForbidden(w, r, "you do not have write access to that collection")
			return
		}
		collectionID = sql.NullString{String: *req.CollectionID, Valid: true}
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeBadRequest(w, r, "name is required")
		return
	}
	if len(req.Name) > 255 {
		writeBadRequest(w, r, "name must be 255 characters or less")
		return
	}
	if req.Value == "" {
		writeBadRequest(w, r, "value is required")
		return
	}
	if len(req.Value) > 65536 {
		writeBadRequest(w, r, "value must be 64KB or less")
		return
	}
	if len(req.URL) > 2048 {
		writeBadRequest(w, r, "url must be 2048 characters or less")
		return
	}
	if len(req.AliasURL) > 2048 {
		writeBadRequest(w, r, "alias url must be 2048 characters or less")
		return
	}
	if len(req.Username) > 255 {
		writeBadRequest(w, r, "username must be 255 characters or less")
		return
	}
	if len(req.Notes) > 10000 {
		writeBadRequest(w, r, "notes must be 10000 characters or less")
		return
	}
	validCategories := map[string]bool{
		"": true, "login": true, "password": true, "api_key": true, "database": true,
		"certificate": true, "credit_card": true, "ssh_key": true, "server": true,
		"identity": true, "bank_account": true, "email": true, "other": true,
	}
	if !validCategories[req.Category] {
		writeBadRequest(w, r, "invalid category")
		return
	}

	// Encrypt the secret value
	encrypted, nonce, err := h.encrypt([]byte(req.Value))
	if err != nil {
		logError(r, "vault.create: encryption failed", "error", err)
		writeInternalError(w, r, "failed to encrypt secret")
		return
	}

	// Generate a random ID (the per-user unique-name schema has no usable
	// DEFAULT flow through sqlc's INSERT + SELECT pattern)
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		logError(r, "vault.create: failed to generate ID", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	entryID := fmt.Sprintf("%x", idBytes)

	// Default provider_meta to empty JSON object if not set, then encrypt it at
	// rest (it can carry account ids / key ids next to the encrypted secret).
	providerMeta := req.ProviderMeta
	if providerMeta == "" {
		providerMeta = "{}"
	}
	if enc, encErr := h.encryptColumn(providerMeta); encErr == nil {
		providerMeta = enc
	} else {
		logError(r, "vault.create: provider_meta encrypt failed", "error", encErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Encrypt the free-text metadata columns at rest and derive the URL blind
	// indexes. The display url/alias_url are stored encrypted, so autofill
	// matching goes through url_bidx/alias_url_bidx (computed from the cleartext
	// host before encryption), not the ciphertext.
	encURL, encAlias, encUser, encCat, encNotes, err := h.encryptMetaColumns(req.URL, req.AliasURL, req.Username, req.Category, req.Notes)
	if err != nil {
		logError(r, "vault.create: metadata encrypt failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	entryScope := bidxScope(userID, collectionID)
	urlBidx := h.urlBlindIndex(entryScope, req.URL)
	aliasBidx := h.urlBlindIndex(entryScope, req.AliasURL)

	// Use separate INSERT + SELECT instead of RETURNING (mattn/go-sqlite3 has bugs with RETURNING)
	createExpiresAt, expErr := stringPtrToNullTime(req.ExpiresAt)
	if expErr != nil {
		writeValidationError(w, r, expErr.Error())
		return
	}
	err = h.queries.CreateVaultEntry(ctx, db.CreateVaultEntryParams{
		ID:                   entryID,
		UserID:               userID,
		Name:                 req.Name,
		EncryptedValue:       encrypted,
		Nonce:                nonce,
		Url:                  toNullString(encURL),
		AliasUrl:             toNullString(encAlias),
		Username:             toNullString(encUser),
		Category:             toNullString(encCat),
		Notes:                toNullString(encNotes),
		AutoLogin:            boolToInt64(req.AutoLogin),
		RotationIntervalDays: intPtrToNullInt64(req.RotationIntervalDays),
		ExpiresAt:            createExpiresAt,
		Provider:             toNullString(req.Provider),
		ProviderMeta:         toNullString(providerMeta),
		AutoRotate:           sql.NullInt64{Int64: boolToInt64(req.AutoRotate), Valid: true},
		UrlBidx:              urlBidx,
		AliasUrlBidx:         aliasBidx,
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeConflict(w, r, "a vault entry with that name already exists")
			return
		}
		logError(r, "vault.create: insert failed", "error", err)
		writeInternalError(w, r, "failed to store secret")
		return
	}

	// Place the entry in its collection (CreateVaultEntry always inserts a
	// personal row; a shared entry is moved into its collection here, after the
	// caller was authorized above).
	if collectionID.Valid {
		if err := h.queries.SetVaultEntryCollection(ctx, db.SetVaultEntryCollectionParams{
			CollectionID: collectionID,
			ID:           entryID,
		}); err != nil {
			logError(r, "vault.create: set collection failed", "error", err)
			writeInternalError(w, r, "failed to store secret")
			return
		}
	}

	// Persist custom fields (encrypted at rest) when present.
	if len(req.CustomFields) > 0 {
		enc, cfErr := h.encryptCustomFields(req.CustomFields)
		if cfErr != nil {
			logError(r, "vault.create: custom fields encrypt failed", "error", cfErr)
			writeInternalError(w, r, "failed to store secret")
			return
		}
		if cfErr := h.queries.UpdateVaultEntryCustomFields(ctx, db.UpdateVaultEntryCustomFieldsParams{
			CustomFields: enc, ID: entryID,
		}); cfErr != nil {
			logError(r, "vault.create: custom fields save failed", "error", cfErr)
			writeInternalError(w, r, "failed to store secret")
			return
		}
	}

	row, err := h.queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		logError(r, "vault.create: select after insert failed", "error", err)
		writeInternalError(w, r, "failed to store secret")
		return
	}

	entry := h.vaultMetaFromGetRow(row)
	entry.CollectionID = nullStringPtr(collectionID)

	// Seed the capability-bridge columns from the provider's defaults so the
	// secret is immediately usable through /secrets/issue + /proxy (dockyard
	// did this in its vault-enroll path). Only untouched rows are filled.
	h.seedCapabilityDefaults(ctx, h.queries, r, entryID, req.Provider)

	LogActivityFromRequest(h.queries, r, "vault.entry_created", fmt.Sprintf("Vault secret created: %s (user: %s)", req.Name, userID))

	writeJSON(w, http.StatusCreated, entry)
}

// MoveToCollection handles PUT /api/vault/{id}/collection and moves an entry
// into a shared collection, or back to personal with a null/empty id.
//
// Two separate authorizations apply. Taking an entry OUT of the collection it
// currently sits in is a dispossessing operation (everyone else who reached it
// through that collection loses it, permanently, and only the new holder can
// give it back), so it needs the entry owner, an instance admin, or a manager of
// the SOURCE collection: write access alone, which every editor has, is not
// enough. Putting it INTO a destination collection separately needs
// editor/manager there.
func (h *VaultHandler) MoveToCollection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()
	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	info, err := h.queries.GetVaultEntryAccess(ctx, id)
	if err != nil {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	var req struct {
		CollectionID *string `json:"collection_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}

	source := ""
	if info.CollectionID.Valid {
		source = info.CollectionID.String
	}
	if source != "" && !h.canMoveEntryOutOfCollection(r, info.UserID, source) {
		writeForbidden(w, r, "only the entry owner, a manager of the current collection, or an admin can move this entry out of it")
		return
	}

	var target sql.NullString
	destination := ""
	if req.CollectionID != nil && *req.CollectionID != "" {
		if !h.canWriteCollection(r, *req.CollectionID) {
			writeForbidden(w, r, "you do not have write access to that collection")
			return
		}
		destination = *req.CollectionID
		target = sql.NullString{String: destination, Valid: true}
	}
	if err := h.queries.SetVaultEntryCollection(ctx, db.SetVaultEntryCollectionParams{
		CollectionID: target,
		ID:           id,
	}); err != nil {
		logError(r, "vault.move: set collection failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// The blind index is keyed to the entry's scope, so a move invalidates it.
	// Recompute both indexes under the new scope, otherwise the entry keeps an
	// index nobody will ever compute again and autofill silently stops offering
	// it. Recovering the cleartext host requires decrypting the stored url.
	if meta, mErr := h.queries.GetVaultEntryMeta(ctx, id); mErr != nil {
		logError(r, "vault.move: reindex lookup failed", "error", mErr)
	} else {
		newScope := bidxScope(info.UserID, target)
		urlPlain := h.decryptColumnOrLog(meta.Url.String, "", "url")
		aliasPlain := h.decryptColumnOrLog(meta.AliasUrl.String, "", "alias_url")
		if err := h.queries.UpdateVaultEntryMetaAtRest(ctx, db.UpdateVaultEntryMetaAtRestParams{
			Url:          meta.Url,
			AliasUrl:     meta.AliasUrl,
			Username:     meta.Username,
			Category:     meta.Category,
			Notes:        meta.Notes,
			UrlBidx:      h.urlBlindIndex(newScope, urlPlain),
			AliasUrlBidx: h.urlBlindIndex(newScope, aliasPlain),
			ID:           id,
		}); err != nil {
			logError(r, "vault.move: reindex failed", "error", err)
		}
	}

	name, nameErr := h.queries.GetVaultEntryName(ctx, id)
	if nameErr != nil {
		name = "(unknown)"
	}
	LogActivityFromRequest(h.queries, r, "vault.entry_moved", fmt.Sprintf(
		"Vault entry moved: %s (id: %s, from: %s, to: %s)",
		name, id, collectionLabel(source), collectionLabel(destination)))
	w.WriteHeader(http.StatusNoContent)
}

// collectionLabel renders a collection id for the activity log, naming the
// personal vault explicitly so a move out of a collection is unambiguous.
func collectionLabel(collectionID string) string {
	if collectionID == "" {
		return "personal"
	}
	return collectionID
}

// seedCapabilityDefaults fills destination_patterns + injection_spec from the
// provider's CapabilityDefaults when the entry still carries the untouched
// '[]' / '{}' defaults. Best-effort: a failure only means auto-routing stays
// off until patterns are set explicitly.
// seedCapabilityDefaults writes the provider's capability preset onto an entry.
//
// q is the querier to use. Callers inside an open write transaction MUST pass
// their qtx: this helper both reads and writes, and running it on the pool while
// the caller holds the SQLite write lock made the two contend on separate
// connections. Measured from Update: the whole _busy_timeout burned (about 5.3s
// of DB-wide write stall), a stale provider_meta read, and the seed then
// silently discarded while the request returned 200 with no way to enrol the
// secret afterwards.
//
// Same shape as the activity-log write that used to sit inside this handler's
// transaction. Any helper called between BeginTx and Commit has to take the
// transaction, not reach for h.queries.
func (h *VaultHandler) seedCapabilityDefaults(ctx context.Context, q *db.Queries, r *http.Request, entryID, provider string) {
	if provider == "" {
		return
	}
	// Tenant-scoped presets (Supabase, Auth0, Grafana) need the entry's own
	// project/tenant/instance id to expand into a concrete host. Read it back
	// from the row that was just written; if it is absent the preset resolves to
	// no destinations, and the bridge refuses to mint until the owner sets one.
	// That is deliberate: the old "*.supabase.co/*" preset read like a ceiling
	// while granting reach over a domain space anyone can register into.
	var meta map[string]string
	if row, err := q.GetVaultEntryMeta(ctx, entryID); err == nil {
		meta = ParseProviderMeta(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"))
	}
	dests, inj := MarshalCapabilityDefaults(provider, meta)
	if dests == "" && inj == "" {
		return
	}
	if dests == "" {
		dests = "[]"
	}
	if inj == "" {
		inj = "{}"
	}
	if err := q.SeedVaultEntryCapabilityDefaults(ctx, db.SeedVaultEntryCapabilityDefaultsParams{
		DestinationPatterns: dests,
		InjectionSpec:       inj,
		ID:                  entryID,
	}); err != nil {
		logError(r, "vault: capability defaults seed failed", "entry_id", entryID, "error", err)
	}
}

// Update handles PUT /api/vault/{id} and updates a vault entry. If a new value
// is provided, it is re-encrypted and last_rotated_at is reset.
// Users can only update their own entries. Admins can update any entry.
func (h *VaultHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())
	ctx := r.Context()

	// Authorize: personal owner/admin, or editor/manager in the entry's collection.
	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	var req struct {
		Name      *string `json:"name"`
		Value     *string `json:"value"`
		URL       *string `json:"url"`
		AliasURL  *string `json:"alias_url"`
		Username  *string `json:"username"`
		Category  *string `json:"category"`
		Notes     *string `json:"notes"`
		AutoLogin *bool   `json:"auto_login"`
		// nullableField, not a bare pointer: the edit form sends an explicit
		// null to CLEAR these, and a pointer cannot tell that apart from the key
		// being absent, so clearing was silently dropped.
		RotationIntervalDays nullableField[int]    `json:"rotation_interval_days"`
		ExpiresAt            nullableField[string] `json:"expires_at"`
		Provider             *string               `json:"provider"`
		ProviderMeta         *string               `json:"provider_meta"`
		AutoRotate           *bool                 `json:"auto_rotate"`
		CustomFields         *[]CustomField        `json:"custom_fields"`
		// The capability ceiling: which hosts an agent token minted for this
		// secret may ever reach. Until this existed the column had exactly one
		// writer (the provider preset seed), so any secret created without a
		// recognised provider could never mint a token and the whole MCP
		// "use a secret without seeing it" feature was unreachable for it.
		// nil means unchanged; an empty array clears the ceiling, which disables
		// minting rather than widening it.
		DestinationPatterns *[]string `json:"destination_patterns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}

	// Refuse the whole request if any encrypted column on this entry cannot be
	// opened, BEFORE writing anything.
	//
	// Placement is the whole fix. This guard first shipped below the
	// custom_fields, destination_patterns and value writes, which made it worse
	// than useless: for custom_fields it re-read the row AFTER that column had
	// already been replaced, so it inspected its own fresh write, never fired,
	// and returned 200 while the still-recoverable ciphertext was gone. When a
	// different column was the damaged one it returned 409 "nothing was changed"
	// having already wiped custom_fields and the agent destination ceiling. A
	// guard that reports protection while destroying data is the worst shape
	// available.
	//
	// The edit form always resubmits every metadata field, and an undecryptable
	// column reads back as "" or [], so an ordinary save on a damaged entry
	// would replace recoverable ciphertext with NULL. custom_fields can hold
	// secret:true values (the importer parks TOTP seeds and recovery PINs
	// there), so this is not merely metadata.
	//
	// Refusing the WHOLE request rather than skipping the damaged column is
	// deliberate: a partial save on a damaged entry gives the operator no signal
	// that anything was withheld.
	if req.Name != nil || req.URL != nil || req.AliasURL != nil || req.Username != nil ||
		req.Category != nil || req.Notes != nil || req.CustomFields != nil ||
		req.DestinationPatterns != nil || req.Value != nil {
		damaged, metaErr := h.queries.GetVaultEntryMeta(ctx, id)
		if metaErr != nil {
			// Fail closed. Skipping the check on a read error is how a guard
			// quietly stops guarding.
			logError(r, "vault.update: could not read the entry to check it is intact", "entry", id, "error", metaErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if field, broken := h.anyMetaColumnUndecryptable(map[string]string{
			"url":           damaged.Url.String,
			"alias_url":     damaged.AliasUrl.String,
			"username":      damaged.Username.String,
			"category":      damaged.Category.String,
			"notes":         damaged.Notes.String,
			"custom_fields": damaged.CustomFields,
		}); broken {
			logError(r, "vault.update: refusing to overwrite an undecryptable column", "entry", id, "field", field)
			writeError(w, r, http.StatusConflict, "decrypt_failed",
				"part of this entry ("+field+") could not be decrypted, so nothing was changed; saving would have overwritten data that is still recoverable with the correct key")
			return
		}
	}

	// Everything from here down runs in ONE transaction.
	//
	// Update writes each column with its own statement and validates as it goes,
	// so a refusal partway through left the earlier writes committed. Concretely:
	// a rename colliding on UNIQUE(user_id, name) returned 409 "a vault entry
	// with that name already exists" AFTER custom_fields had been replaced
	// (destroying imported TOTP seeds and recovery PINs), the secret value had
	// been rewritten and last_rotated_at restamped. The user is told the save was
	// rejected and the still-open editor shows the old data, so nothing suggests
	// anything changed.
	//
	// Reordering the name check would fix only the name case. Every one of the
	// 20-odd early returns below has the same shape, and the next validation
	// added late would reintroduce it. A transaction plus a deferred Rollback
	// makes every return path leave the row exactly as it was.
	// Activity rows are queued and written AFTER commit: see the note at the
	// first append for why writing them inside the transaction is a 5s stall.
	var deferredActivity []queuedActivity

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		logError(r, "vault.update: begin transaction failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit has succeeded
	qtx := h.queries.WithTx(tx)

	// Custom fields: nil means "unchanged"; a present (even empty) array replaces
	// the set. Encrypted at rest.
	if req.CustomFields != nil {
		if err := validateCustomFields(*req.CustomFields); err != nil {
			writeBadRequest(w, r, err.Error())
			return
		}
		if enc, cfErr := h.encryptCustomFields(*req.CustomFields); cfErr != nil {
			logError(r, "vault.update: custom fields encrypt failed", "error", cfErr)
			writeInternalError(w, r, "internal server error")
			return
		} else if err := qtx.UpdateVaultEntryCustomFields(ctx, db.UpdateVaultEntryCustomFieldsParams{CustomFields: enc, ID: id}); err != nil {
			logError(r, "vault.update: update custom fields failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}

	// Capability ceiling. Validation is strict on purpose: this list is the only
	// thing standing between a minted token and an arbitrary destination, so a
	// pattern that looks like a restriction but is not (a host wildcard, a
	// private address, a pasted URL) is rejected rather than stored.
	if req.DestinationPatterns != nil {
		patterns := NormalizeDestinationPatterns(*req.DestinationPatterns)
		if err := ValidateDestinationPatterns(patterns); err != nil {
			writeValidationError(w, r, err.Error())
			return
		}
		encoded, mErr := json.Marshal(patterns)
		if mErr != nil {
			logError(r, "vault.update: encode destination patterns failed", "error", mErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if err := qtx.UpdateVaultEntryDestinationPatterns(ctx, db.UpdateVaultEntryDestinationPatternsParams{
			DestinationPatterns: string(encoded),
			ID:                  id,
		}); err != nil {
			logError(r, "vault.update: update destination patterns failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		// Queued, NOT written here. LogActivityFromRequest runs on its own
		// background context and therefore its own connection, so writing it
		// inside the transaction made it contend with the write lock this
		// handler holds: measured a 5.1s stall (the full _busy_timeout) and the
		// row was then LOST to SQLITE_BUSY. Emitting after commit also means the
		// audit trail never claims a change that later rolled back.
		deferredActivity = append(deferredActivity, queuedActivity{
			action: "vault.destinations_updated",
			detail: fmt.Sprintf("Agent destination allow-list set on entry %s: %v", id, patterns),
		})
	}

	// If value is provided and non-empty, re-encrypt and update last_rotated_at
	if req.Value != nil && *req.Value != "" {
		// Two guards before touching the stored secret, both learned the hard way.
		//
		// 1. Never overwrite something we could not read. The unlock response
		//    renders an undecryptable entry as the literal "[decryption error]",
		//    and the edit form submits whatever it was showing, so a single save
		//    would persist that sentinel as the new secret and return 200,
		//    destroying a value that was still recoverable. Mirror the Rotate
		//    handler: refuse with 409 and leave the row alone.
		//
		// 2. Re-storing the SAME value is not a rotation. Writing the value
		//    stamps last_rotated_at = now, so a client that echoes the current
		//    secret back (the edit form used to pre-fill it) silently reset the
		//    rotation clock and de-scheduled an overdue auto-rotation. If the
		//    plaintext is unchanged, skip the write entirely.
		current, curErr := qtx.GetVaultEntryForRotation(ctx, id)
		if curErr != nil {
			logError(r, "vault.update: load current value failed", "entry", id, "error", curErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		currentPlain, decErr := h.decrypt(current.EncryptedValue, current.Nonce)
		if decErr != nil {
			logError(r, "vault.update: refusing to overwrite an undecryptable secret", "entry", id, "error", decErr)
			writeError(w, r, http.StatusConflict, "decrypt_failed",
				"this secret could not be decrypted, so it was not changed; saving would have overwritten a value that is still recoverable")
			return
		}
		unchanged := string(currentPlain) == *req.Value
		for i := range currentPlain {
			currentPlain[i] = 0
		}

		if !unchanged {
			encrypted, nonce, err := h.encrypt([]byte(*req.Value))
			if err != nil {
				logError(r, "vault.update: encryption failed", "error", err)
				writeInternalError(w, r, "failed to encrypt secret")
				return
			}
			if err := qtx.UpdateVaultEntryValue(ctx, db.UpdateVaultEntryValueParams{
				EncryptedValue: encrypted,
				Nonce:          nonce,
				ID:             id,
			}); err != nil {
				logError(r, "vault.update: update value failed", "error", err)
				writeInternalError(w, r, "failed to update secret value")
				return
			}
		}
	}

	// Update metadata fields.
	//
	// The name is validated and its write error is SURFACED, matching Create.
	// It used to be logged and stepped over: a rename onto a name the user
	// already had hit UNIQUE(user_id, name), the handler continued, applied
	// every other field in the request and returned 200, and the UI closed the
	// editor and toasted "Secret updated". So the request was half-applied and
	// reported as fully successful, on the field that is the lookup key for
	// service-identity allowed_secrets and for MCP list_secrets/use_secret.
	// A blank name was accepted the same way, leaving an entry nothing can
	// resolve by name at all.
	//
	// Done FIRST so a refused rename leaves the rest of the entry untouched.
	if req.Name != nil {
		newName := strings.TrimSpace(*req.Name)
		if newName == "" {
			writeBadRequest(w, r, "name is required")
			return
		}
		if len(newName) > 255 {
			writeBadRequest(w, r, "name must be 255 characters or less")
			return
		}
		if err := qtx.UpdateVaultEntryName(ctx, db.UpdateVaultEntryNameParams{Name: newName, ID: id}); err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				writeConflict(w, r, "a vault entry with that name already exists")
				return
			}
			logError(r, "vault.update: update name failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if req.Category != nil {
		if enc, encErr := h.encryptColumn(*req.Category); encErr != nil {
			logError(r, "vault.update: category encrypt failed", "error", encErr)
			writeInternalError(w, r, "internal server error")
			return
		} else if err := qtx.UpdateVaultEntryCategory(ctx, db.UpdateVaultEntryCategoryParams{Category: toNullString(enc), ID: id}); err != nil {
			logError(r, "vault.update: update category failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if req.Notes != nil {
		if enc, encErr := h.encryptColumn(*req.Notes); encErr != nil {
			logError(r, "vault.update: notes encrypt failed", "error", encErr)
			writeInternalError(w, r, "internal server error")
			return
		} else if err := qtx.UpdateVaultEntryNotes(ctx, db.UpdateVaultEntryNotesParams{Notes: toNullString(enc), ID: id}); err != nil {
			logError(r, "vault.update: update notes failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if req.RotationIntervalDays.Set {
		interval := sql.NullInt64{}
		if req.RotationIntervalDays.Value != nil {
			interval = sql.NullInt64{Int64: int64(*req.RotationIntervalDays.Value), Valid: true}
		}
		if err := qtx.UpdateVaultEntryRotationInterval(ctx, db.UpdateVaultEntryRotationIntervalParams{RotationIntervalDays: interval, ID: id}); err != nil {
			logError(r, "vault.update: update rotation_interval_days failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if req.ExpiresAt.Set {
		expires, expErr := stringPtrToNullTime(req.ExpiresAt.Value)
		if expErr != nil {
			writeValidationError(w, r, expErr.Error())
			return
		}
		if err := qtx.UpdateVaultEntryExpiresAt(ctx, db.UpdateVaultEntryExpiresAtParams{ExpiresAt: expires, ID: id}); err != nil {
			logError(r, "vault.update: update expires_at failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if req.URL != nil || req.AliasURL != nil {
		// The blind index is scoped, so recomputing one needs the entry's CURRENT
		// scope (its collection, or its owner when personal).
		access, accErr := qtx.GetVaultEntryAccess(ctx, id)
		if accErr != nil {
			logError(r, "vault.update: scope lookup failed", "error", accErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		scope := bidxScope(access.UserID, access.CollectionID)
		if req.URL != nil {
			if enc, encErr := h.encryptColumn(*req.URL); encErr != nil {
				logError(r, "vault.update: url encrypt failed", "error", encErr)
				writeInternalError(w, r, "internal server error")
				return
			} else if err := qtx.UpdateVaultEntryURL(ctx, db.UpdateVaultEntryURLParams{Url: toNullString(enc), UrlBidx: h.urlBlindIndex(scope, *req.URL), ID: id}); err != nil {
				logError(r, "vault.update: update url failed", "error", err)
				writeInternalError(w, r, "internal server error")
				return
			}
		}
		if req.AliasURL != nil {
			if enc, encErr := h.encryptColumn(*req.AliasURL); encErr != nil {
				logError(r, "vault.update: alias_url encrypt failed", "error", encErr)
				writeInternalError(w, r, "internal server error")
				return
			} else if err := qtx.UpdateVaultEntryAliasURL(ctx, db.UpdateVaultEntryAliasURLParams{AliasUrl: toNullString(enc), AliasUrlBidx: h.urlBlindIndex(scope, *req.AliasURL), ID: id}); err != nil {
				logError(r, "vault.update: update alias_url failed", "error", err)
				writeInternalError(w, r, "internal server error")
				return
			}
		}
	}
	if req.Username != nil {
		if enc, encErr := h.encryptColumn(*req.Username); encErr != nil {
			logError(r, "vault.update: username encrypt failed", "error", encErr)
			writeInternalError(w, r, "internal server error")
			return
		} else if err := qtx.UpdateVaultEntryUsername(ctx, db.UpdateVaultEntryUsernameParams{Username: toNullString(enc), ID: id}); err != nil {
			logError(r, "vault.update: update username failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if req.AutoLogin != nil {
		if err := qtx.UpdateVaultEntryAutoLogin(ctx, db.UpdateVaultEntryAutoLoginParams{AutoLogin: boolToInt64(*req.AutoLogin), ID: id}); err != nil {
			logError(r, "vault.update: update auto_login failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if req.Provider != nil || req.ProviderMeta != nil || req.AutoRotate != nil {
		// Fetch current values for fields not being updated
		current, fetchErr := qtx.GetVaultEntryMeta(ctx, id)
		if fetchErr == nil {
			provider := current.Provider.String
			providerMeta := current.ProviderMeta.String
			autoRotate := current.AutoRotate.Int64
			if req.Provider != nil {
				provider = *req.Provider
			}
			if req.AutoRotate != nil {
				autoRotate = boolToInt64(*req.AutoRotate)
			}
			// provider_meta at rest. The two cases are kept explicitly apart:
			// client-supplied meta is ALWAYS encrypted, while an untouched column
			// is carried forward exactly as stored. Never decide by content
			// (a passthrough of client input that already looks encrypted is a
			// decryption oracle; see vaultColumnEncPrefix).
			encMeta := providerMeta // untouched: already-stored value, verbatim
			if req.ProviderMeta != nil {
				enc, encErr := h.encryptColumn(*req.ProviderMeta)
				if encErr != nil {
					logError(r, "vault.update: provider_meta encrypt failed", "error", encErr)
					writeInternalError(w, r, "internal server error")
					return
				}
				encMeta = enc
			}
			if err := qtx.UpdateVaultEntryProvider(ctx, db.UpdateVaultEntryProviderParams{
				Provider:     toNullString(provider),
				ProviderMeta: toNullString(encMeta),
				AutoRotate:   sql.NullInt64{Int64: autoRotate, Valid: true},
				ID:           id,
			}); err != nil {
				logError(r, "vault.update: update provider failed", "error", err)
				writeInternalError(w, r, "internal server error")
				return
			}
			// A newly set provider seeds the capability-bridge columns
			// (untouched rows only, same as Create).
			if req.Provider != nil {
				h.seedCapabilityDefaults(ctx, qtx, r, id, provider)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		logError(r, "vault.update: commit failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	for _, a := range deferredActivity {
		LogActivityFromRequest(h.queries, r, a.action, a.detail)
	}

	// Fetch updated entry (post-commit, so it reflects what was actually stored)
	row, err := h.queries.GetVaultEntryMeta(ctx, id)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	if err != nil {
		logError(r, "vault.update: fetch failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	entry := h.vaultMetaFromGetRow(row)

	LogActivityFromRequest(h.queries, r, "vault.entry_updated", fmt.Sprintf("Vault secret updated: %s (user: %s)", entry.Name, userID))

	writeJSON(w, http.StatusOK, entry)
}

// Delete handles DELETE /api/vault/{id} and removes a vault entry.
// Users can only delete their own entries. Admins can delete any entry.
func (h *VaultHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())
	ctx := r.Context()

	// Authorize: personal owner/admin, or editor/manager in the entry's collection.
	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	// Get the entry name for logging
	name, err := h.queries.GetVaultEntryName(ctx, id)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	result, err := h.queries.DeleteVaultEntry(ctx, id)
	if err != nil {
		logError(r, "vault.delete: delete failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	LogActivityFromRequest(h.queries, r, "vault.entry_deleted", fmt.Sprintf("Vault secret deleted: %s (user: %s)", name, userID))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Unlock handles POST /api/vault/unlock and decrypts and returns the user's
// vault entries. Requires password re-entry for security. Each user only sees
// their own entries. Auto-lock is enforced client-side against the
// vault_auto_lock_max_minutes policy served by GET /api/settings/vault-policy
// (unlock itself is stateless server-side).
// reauthLocked reports whether the user has too many recent failed re-auth
// attempts. It shares the login lockout budget (5 failures in 15 minutes) so a
// stolen session cannot brute-force the account password on the re-auth
// endpoints (unlock, rotate, validate). Correct re-auths never record a
// failure, so the frontend's per-mutation re-lock is unaffected. It returns the
// user's email so a subsequent failure can be recorded. On lookup error it fails
// open (not locked) rather than bricking re-auth on a transient DB hiccup.
func (h *VaultHandler) reauthLocked(ctx context.Context, r *http.Request, userID string) (email string, locked bool) {
	email, err := h.queries.GetUserEmailByID(ctx, userID)
	if err != nil {
		logError(r, "vault.reauth: email lookup failed", "error", err)
		return "", false
	}
	count, err := h.queries.CountRecentFailedLoginAttemptsByEmail(ctx, email)
	if err != nil {
		logError(r, "vault.reauth: attempt count failed", "error", err)
		return email, false
	}
	return email, count >= 5
}

// recordReauthFailure logs a failed password re-auth so repeated wrong-password
// attempts trip the same 5/15m lockout as login.
func (h *VaultHandler) recordReauthFailure(ctx context.Context, r *http.Request, email string) {
	if email == "" {
		return
	}
	if err := h.queries.CreateLoginAttempt(ctx, db.CreateLoginAttemptParams{
		Email: email, IpAddress: middleware.ClientIP(r), Success: 0,
	}); err != nil {
		logError(r, "vault.reauth: failed to record attempt", "error", err)
	}
}

func (h *VaultHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeBadRequest(w, r, "password is required to unlock the vault")
		return
	}

	// Verify password against current user
	userID := middleware.GetUserID(r.Context())
	ctx := r.Context()

	email, locked := h.reauthLocked(ctx, r, userID)
	if locked {
		writeRateLimited(w, r, "too many attempts, try again in 15 minutes")
		return
	}

	passwordHash, err := h.queries.GetUserPasswordHash(ctx, userID)
	if err != nil {
		writeUnauthorized(w, r, "user not found")
		return
	}
	if ok, verifyErr := passwordhash.Verify(req.Password, passwordHash); verifyErr != nil || !ok {
		h.recordReauthFailure(ctx, r, email)
		writeForbidden(w, r, "incorrect password")
		return
	}

	// Reveal spans personal entries plus entries in the user's collections.
	rows, err := h.queries.ListAccessibleVaultEntriesWithSecrets(ctx, db.ListAccessibleVaultEntriesWithSecretsParams{
		ID:       userID,
		UserID:   userID,
		UserID_2: userID,
	})
	if err != nil {
		logError(r, "vault.unlock: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	entries := []vaultEntryFull{}
	for _, row := range rows {
		e := vaultEntryFull{
			vaultEntryMeta: vaultEntryMeta{
				ID:                   row.ID,
				CollectionID:         nullStringPtr(row.CollectionID),
				Name:                 row.Name,
				URL:                  h.decryptColumnOrLog(row.Url.String, "", "url"),
				AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", "alias_url"),
				Username:             h.decryptColumnOrLog(row.Username.String, "", "username"),
				Category:             h.decryptColumnOrLog(row.Category.String, "", "category"),
				Notes:                h.decryptColumnOrLog(row.Notes.String, "", "notes"),
				AutoLogin:            row.AutoLogin != 0,
				RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
				ExpiresAt:            nullTimePtr(row.ExpiresAt),
				LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
				Provider:             row.Provider.String,
				ProviderMeta:         h.decryptColumnOrLog(row.ProviderMeta.String, "{}", "provider_meta"),
				AutoRotate:           row.AutoRotate.Int64 != 0,
				LastRotationError:    row.LastRotationError.String,
				CustomFields:         h.decryptCustomFields(row.CustomFields),
				DestinationPatterns:  parseDestinationPatterns(row.DestinationPatterns),
				CreatedAt:            nullTimePtr(row.CreatedAt),
				UpdatedAt:            nullTimePtr(row.UpdatedAt),
			},
		}

		decrypted, err := h.decrypt(row.EncryptedValue, row.Nonce)
		if err != nil {
			logError(r, "vault.unlock: decrypt failed", "name", e.Name, "error", err)
			e.Value = "[decryption error]"
		} else {
			e.Value = string(decrypted)
			// Zero out decrypted bytes after copying to string
			for i := range decrypted {
				decrypted[i] = 0
			}
		}

		e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt, e.CreatedAt, &e.LastRotationError)
		entries = append(entries, e)
	}

	LogActivityFromRequest(h.queries, r, "vault.unlocked", fmt.Sprintf("Vault unlocked (user: %s)", userID))

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, entries)
}

// Rotate handles POST /api/vault/{id}/rotate and generates a new secret value.
// If the entry has a provider configured with auto-rotation, calls the provider API.
// Otherwise generates a random 32-byte hex value.
// Returns the new plaintext value so the user can copy it.
func (h *VaultHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeBadRequest(w, r, "password is required to rotate a secret")
		return
	}

	// Verify password against current user
	userID := middleware.GetUserID(r.Context())

	email, locked := h.reauthLocked(ctx, r, userID)
	if locked {
		writeRateLimited(w, r, "too many attempts, try again in 15 minutes")
		return
	}

	passwordHash, err := h.queries.GetUserPasswordHash(ctx, userID)
	if err != nil {
		writeUnauthorized(w, r, "user not found")
		return
	}
	if ok, verifyErr := passwordhash.Verify(req.Password, passwordHash); verifyErr != nil || !ok {
		h.recordReauthFailure(ctx, r, email)
		writeForbidden(w, r, "incorrect password")
		return
	}

	// Authorize: personal owner/admin, or editor/manager in the entry's collection.
	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	// Check if this entry has a provider that supports auto-rotation
	meta, err := h.queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	var newValue string
	var oldValue string // current plaintext, needed by provider.Rotate()
	// Deferred until after the CAS: writing either of these before it would move
	// updated_at and make the compare-and-swap reject the handler's own write.
	var pendingRevokeWarn string
	rotationMethod := "manual"
	providerName := meta.Provider.String
	// Resolved once. Every branch below asks providerRole rather than re-deriving
	// the state from (name, found, CanAutoRotate), which is the shape that let an
	// unregistered provider reach the local generator.
	providerRoleFor, resolvedProvider := classifyProvider(providerName)

	// Decrypt the current value once. provider.Rotate() needs it to
	// authenticate against the provider API when minting the successor key.
	// Do NOT ignore this error: on an empty row (the pre-fix auto_rotate=1
	// filter returned sql.ErrNoRows for on-demand entries) the zero-value
	// nonce would reach h.decrypt. Ownership + meta were already verified
	// above, so a failure here is a genuine load error, not a missing entry.
	entryRow, err := h.queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		logError(r, "vault.rotate: load entry for rotation failed", "entry", id, "error", err)
		writeInternalError(w, r, "failed to load secret for rotation")
		return
	}
	// Never rotate a value we could not read. This used to have no else branch:
	// oldValue simply stayed empty and the handler carried on. For a provider
	// entry that called Rotate with an empty current key; for a non-provider
	// entry it generated a fresh random value, OVERWROTE the undecryptable
	// ciphertext and returned 200, destroying a secret that was still
	// recoverable (a row an older migration missed, bit rot, a partial write).
	// Refuse instead, and leave the stored value untouched so it can be
	// recovered once the underlying cause is fixed.
	currentValue, decErr := h.decrypt(entryRow.EncryptedValue, entryRow.Nonce)
	if decErr != nil {
		logError(r, "vault.rotate: decrypt failed, refusing to rotate", "entry", id, "error", decErr)
		recordRotationFailure(ctx, h.queries, h, id, meta.Name, providerName,
			entryRow.RotationLog.String, rotFailDecrypt, rotationMethod, &userID)
		writeError(w, r, http.StatusConflict, "decrypt_failed",
			"this secret could not be decrypted, so it was not rotated; rotating would have overwritten a value that is still recoverable")
		return
	}
	oldValue = string(currentValue)
	// Best-effort zero of the plaintext slice. oldValue copy outlives this.
	for i := range currentValue {
		currentValue[i] = 0
	}

	// Declared out here so the deferred revoke after the value is persisted can
	// still reach it; the revoke must not run until the new value is stored.
	var providerMeta map[string]string
	{
		if providerRoleFor == providerAuto {
			provider := resolvedProvider
			providerMeta = ParseProviderMeta(h.decryptColumnOrLog(entryRow.ProviderMeta.String, "{}", "provider_meta"))
			rotatedValue, rotErr := provider.Rotate(ctx, oldValue, providerMeta)
			if rotErr != nil {
				// Do NOT fall through to a locally generated value. The upstream
				// credential is untouched, so storing a random string here would
				// destroy the live credential from the user's point of view while
				// reporting success. Mirror the scheduled sweep instead: leave the
				// stored value alone, record the failure, and fail the request.
				// The persisted message is static because a provider Rotate error
				// can embed the raw upstream response body (tokens, internal
				// topology) and last_rotation_error is API-visible; the detail is
				// in the log line.
				logError(r, "vault.rotate: provider rotation failed", "provider", providerName, "entry", id, "error", rotErr)
				const rotateFailed = "provider rotation failed (details in server logs)"
				_ = h.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
					LastRotationError: toNullString(rotateFailed),
					ID:                id,
				})
				updatedLog := AppendRotationLog(entryRow.RotationLog.String, RotationLogEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Status:    "error",
					Provider:  providerName,
					Error:     rotateFailed,
					Method:    rotationMethod,
				})
				_ = h.queries.UpdateVaultEntryRotationLog(ctx, db.UpdateVaultEntryRotationLogParams{
					RotationLog: toNullString(updatedLog),
					ID:          id,
				})
				writeError(w, r, http.StatusBadGateway, "upstream_error",
					"the provider rejected the rotation; the stored secret was left unchanged")
				return
			}
			newValue = rotatedValue
			rotationMethod = "auto"
			// Rotate mutated providerMeta with the NEW provider-side key id;
			// persist it (encrypted) so the NEXT rotation revokes THIS key
			// instead of a stale predecessor id. Strip the transient revoke
			// flag first (never persisted); a failed old-key revoke is
			// surfaced as a rotation error.
			// Held in memory until AFTER the CAS, deliberately.
			//
			// Writing provider_meta here bumps updated_at, which is the exact
			// column the compare-and-swap below reads from a snapshot taken
			// before this point. So the handler invalidated its own CAS and
			// every provider-backed rotate 409'd, after the provider had already
			// minted a replacement key. The sweep does CAS-then-meta and works;
			// this path did meta-then-CAS. Nothing may touch the row between the
			// snapshot and the CAS.
			pendingRevokeWarn = providerMeta["last_revoke_error"]
			delete(providerMeta, "last_revoke_error")
		}
	}

	// A REMINDER-ONLY provider must never reach the generator. Generating a
	// random value locally does not rotate anything at GitHub, OpenAI, Stripe or
	// AWS: it throws away the user's real credential, stores 32 bytes of hex that
	// authenticates nowhere, reports "success", and leaves the actual credential
	// live and unrotated at the provider. That is destruction dressed as
	// rotation, and it is one button click away on an ordinary entry.
	//
	// The correct flow for these providers is the one the scheduled sweep
	// already uses: tell the operator to rotate upstream, then paste the new
	// value in via Edit. Only an entry with NO provider is a local secret this
	// server is entitled to generate.
	// This guard used to read `if p, ok := Registry[name]; ok && !p.CanAutoRotate()`,
	// so it caught providerReminder and let providerUnknown walk straight past it
	// into the generator below. The sweep refused the same entry. Ask the role.
	if newValue == "" {
		switch providerRoleFor {
		case providerReminder:
			updatedLog := AppendRotationLog(entryRow.RotationLog.String, RotationLogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Status:    "reminder",
				Provider:  providerName,
				Method:    rotationMethod,
			})
			_ = h.queries.UpdateVaultEntryRotationLog(ctx, db.UpdateVaultEntryRotationLogParams{
				RotationLog: toNullString(updatedLog),
				ID:          id,
			})
			LogActivityFromRequest(h.queries, r, "vault.rotation_reminder",
				fmt.Sprintf("Rotation reminder for vault secret: %s (provider: %s cannot rotate automatically)", meta.Name, providerName))
			writeError(w, r, http.StatusConflict, "manual_rotation_required",
				"this provider cannot be rotated automatically; rotate the credential in the provider's own dashboard, then edit this entry and paste the new value. Nothing was changed.")
			return

		case providerUnknown:
			// The stored secret is a real credential for a system this build has
			// no code to talk to, so there is nothing this server can do EXCEPT
			// leave it alone. Generating locally would discard a live credential
			// for a value that authenticates nowhere.
			//
			// Recorded as a failure, matching the sweep, so the entry shows up as
			// broken rather than silently never rotating.
			logError(r, "vault.rotate: provider is not in this build's registry, refusing to rotate",
				"entry", id, "provider", providerName)
			recordRotationFailure(ctx, h.queries, h, id, meta.Name, providerName,
				entryRow.RotationLog.String, rotFailUnknownProvider, rotationMethod, &userID)
			writeError(w, r, http.StatusConflict, "unknown_provider",
				"this entry is configured for a provider this server does not support, so it was not rotated; "+
					"rotate the credential at the provider, then edit this entry and paste the new value. Nothing was changed.")
			return
		}
	}

	// Fallback: generate a random value when no provider produced one. This is
	// the local-secret path (no provider configured), where this server owns the
	// value and generating a fresh one IS the rotation. A FAILED auto-rotating
	// provider never reaches here, it returned 502 above, and a reminder-only
	// provider was refused just above.
	if newValue == "" {
		// Belt, to the switch above's braces. Every role except providerNone has
		// already returned by now, so arriving here as anything else means a new
		// role was added and this chain was not updated. Refuse rather than
		// generate: guessing wrong here destroys a live credential, so doing
		// nothing is the only safe default.
		if !providerRoleFor.mayGenerateLocally() {
			logError(r, "vault.rotate: refusing to generate a local value for a provider-backed entry",
				"entry", id, "provider", providerName, "role", int(providerRoleFor))
			writeError(w, r, http.StatusConflict, "manual_rotation_required",
				"this secret cannot be rotated automatically; rotate it at the provider, then edit this entry "+
					"and paste the new value. Nothing was changed.")
			return
		}
		newValue, err = generateToken(32)
		if err != nil {
			logError(r, "vault.rotate: failed to generate token", "error", err)
			writeInternalError(w, r, "failed to generate new secret")
			return
		}
	}

	// Encrypt the new value
	encrypted, nonce, err := h.encrypt([]byte(newValue))
	if err != nil {
		logError(r, "vault.rotate: encryption failed", "error", err)
		writeInternalError(w, r, "failed to encrypt new secret")
		return
	}

	// Update the entry. UpdatedAtText feeds the compare-and-swap; omitting it
	// binds "", which never matches, so this write silently affected zero rows
	// and the handler answered 404 for an entry the user was looking at. The
	// sweep passed it and this path did not, so the CAS made manual rotation
	// 100% dead while the test suite stayed green.
	applied, err := persistRotatedValue(ctx, h.queries,
		snapshotFromRotationRow(id, entryRow.UpdatedAtText), encrypted, nonce)
	if err != nil {
		// Same hazard as the CAS-miss branch just below, and it recorded nothing.
		// A provider-backed rotation has ALREADY minted the successor upstream by
		// this point, and providerMeta (which holds its key id) is discarded
		// on return, so nobody holds the new key and nothing in the product says so.
		// The sweep records rotFailPersist here; this path returned 500 and left the
		// entry looking untouched.
		logError(r, "vault.rotate: update failed", "error", err)
		recordRotationFailure(ctx, h.queries, h, id, meta.Name, providerName,
			entryRow.RotationLog.String, rotFailPersist, rotationMethod, &userID)
		writeInternalError(w, r, "failed to update secret")
		return
	}

	if !applied {
		// A CAS miss is a CONFLICT, not a missing entry, and saying "not found"
		// about a row the caller is looking at sends them hunting for the wrong
		// problem. It also matters that a provider has usually ALREADY minted the
		// replacement key by this point, so record the orphan rather than
		// dropping it silently: the old key is still live and the new one is
		// stranded upstream with nobody holding it.
		logError(r, "vault.rotate: entry changed during rotation, value not stored", "entry", id)
		if providerName != "" {
			recordRotationFailure(ctx, h.queries, h, id, meta.Name, providerName,
				entryRow.RotationLog.String, rotFailConflict, "manual", nil)
		}
		writeError(w, r, http.StatusConflict, "rotation_conflict",
			"this secret changed while it was being rotated, so the new value was not stored; reload and try again")
		return
	}

	// PAST THIS LINE THE ROTATION HAS COMMITTED, so the caller's context must no
	// longer be able to stop the work.
	//
	// Everything after the CAS ran on r.Context(): the upstream revoke of the old
	// key, the provider_meta write carrying the successor's key id, the response
	// fetch, and both outcome writes. A browser tab closed, a client timeout, or a
	// proxy hang-up cancels that context, and sqlc's generated ExecContext fails
	// immediately on a done context. So the value was durably rotated while the
	// revoke never fired, the successor's key id was never stored, and NOTHING was
	// recorded: no last_rotation_error, no rotation_log entry, no alert. The entry
	// then looks freshly rotated and clean, with both keys live upstream and the
	// next revoke aimed at a stale id.
	//
	// The pre-CAS work deliberately keeps r.Context(), so an abandoned request
	// still stops before anything is minted. The seam is exactly here, which is
	// also where the shared core will take over.
	//
	// The sweep has done this since round 8 (vault_rotation.go:115) for the same
	// reason: an entry must be able to write its own outcome even when the caller
	// that triggered it is gone.
	postCtx, cancelPost := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
	defer cancelPost()
	ctx = postCtx

	// One fact, collected from both places a revoke can fail, folded into the
	// final status exactly once at the end.
	//
	// It used to be written to last_rotation_error here, and again below, and both
	// writes were then unconditionally overwritten by the outcome block: "" and
	// status "success" without targets, a delivery-only summary with them. So the
	// only durable record said the rotation was clean while the predecessor key
	// was still live. See foldRevokeOutcome.
	revokeWarn := pendingRevokeWarn
	if revokeWarn != "" {
		logError(r, "vault.rotate: old key revoke failed (predecessor still live)", "entry", id, "detail", revokeWarn)
	}

	// Shared with the sweep from here. See vault_rotation_core.go.
	deps := rotationDeps{queries: h.queries, vault: h}
	if warn := revokeOldKeyAndPersistMeta(ctx, deps, id, meta.Name, providerMeta, newValue); warn != "" {
		revokeWarn = warn
	}

	// Fetch updated entry for response
	row, err := h.queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		logError(r, "vault.rotate: fetch failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	entry := vaultEntryFull{
		vaultEntryMeta: h.vaultMetaFromGetRow(row),
	}
	entry.Value = newValue

	// Record the rotation outcome. The TRUE status depends on whether each
	// configured target applied + verified the new key, so with targets we
	// finalise the rotation_log in the delivery goroutine below (the HTTP
	// response stays immediate). Without targets the rotation is complete now.
	rawTargets := h.decryptColumnOrLog(entryRow.RotationTargets.String, "[]", "rotation_targets")
	targets := ParseRotationTargets(rawTargets)

	rec := rotationRecord{
		EntryID:     id,
		EntryName:   entry.Name,
		Provider:    providerName,
		Method:      rotationMethod,
		UserID:      userID,
		RotationLog: entryRow.RotationLog.String,
		Targets:     targets,
		OldValue:    oldValue,
		NewValue:    newValue,
		RevokeWarn:  revokeWarn,
	}

	if len(targets) == 0 {
		// Nothing to deliver, so the outcome is already final.
		recordRotationOutcome(ctx, deps, rec)
	} else {
		// Delivery can take minutes and the user needs the new value now, so the
		// SAME core runs in a detached goroutine. This is the one genuine difference
		// between the paths and the only reason the core is split in two.
		//
		// The log column is re-read inside the goroutine: the value-commit and the
		// meta write have both landed by now, and reading a stale copy here would
		// drop whatever they appended.
		h.delivery.Add(1)
		go func(rec rotationRecord) {
			defer h.delivery.Done()
			deliveryCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			if fresh, err := h.queries.GetVaultEntryForRotation(deliveryCtx, rec.EntryID); err == nil {
				rec.RotationLog = fresh.RotationLog.String
			}
			recordRotationOutcome(deliveryCtx, deps, rec)
		}(rec)
	}

	LogActivityFromRequest(h.queries, r, "vault.rotated", fmt.Sprintf("Vault secret rotated (%s/%s): %s (user: %s, targets: %d)", rotationMethod, providerName, entry.Name, userID, len(targets)))

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, entry)
}

// Providers handles GET /api/vault/providers and returns available key providers.
func (h *VaultHandler) Providers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ListProviders())
}

// ValidateKey handles POST /api/vault/{id}/validate and checks if a key is still valid.
func (h *VaultHandler) ValidateKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeBadRequest(w, r, "password is required")
		return
	}

	userID := middleware.GetUserID(r.Context())

	email, locked := h.reauthLocked(ctx, r, userID)
	if locked {
		writeRateLimited(w, r, "too many attempts, try again in 15 minutes")
		return
	}

	passwordHash, err := h.queries.GetUserPasswordHash(ctx, userID)
	if err != nil {
		writeUnauthorized(w, r, "user not found")
		return
	}
	if ok, verifyErr := passwordhash.Verify(req.Password, passwordHash); verifyErr != nil || !ok {
		h.recordReauthFailure(ctx, r, email)
		writeForbidden(w, r, "incorrect password")
		return
	}

	// The SPEND right, not the read right. This handler decrypts the stored
	// value and authenticates with it against the provider, so it is a live use
	// of the credential, not a look at metadata.
	//
	// It was the last entryAccess site still gated on canRead, and entryAccessFor
	// deliberately grants a removed creator a residual READ so they can recover a
	// secret they own. That left them an oracle: after being removed from the
	// collection they could still ask "is the team's key valid?" and have the
	// server spend it upstream on their behalf, learning every rotation, with no
	// activity_log row to show for it.
	//
	// Ninth distinct door onto "removing someone ends their access". Same
	// read-versus-use distinction as the reference resolver.
	// Admins keep their branch. entryCurrentlyUsableBy deliberately has no admin
	// bypass (it answers "may THIS user spend it", which is what closed the
	// removed-member oracle), but an instance admin can already rotate this entry
	// for plaintext, so refusing them a validity check protects nothing and just
	// breaks the operator flow. Round 10 tightened this without restoring the
	// bypass that entryAccess had.
	if !middleware.IsAdmin(ctx) && !h.entryCurrentlyUsableBy(ctx, userID, id) {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	meta, err := h.queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	if meta.Provider.String == "" {
		writeBadRequest(w, r, "no provider configured for this entry")
		return
	}

	provider, ok := ProviderRegistry[meta.Provider.String]
	if !ok {
		writeBadRequest(w, r, "unknown provider: "+meta.Provider.String)
		return
	}

	// Decrypt the value
	entryRow, err := h.queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		writeNotFound(w, r, "entry not found")
		return
	}

	plaintext, err := h.decrypt(entryRow.EncryptedValue, entryRow.Nonce)
	if err != nil {
		writeInternalError(w, r, "failed to decrypt secret")
		return
	}

	providerMeta := ParseProviderMeta(h.decryptColumnOrLog(meta.ProviderMeta.String, "{}", "provider_meta"))
	valid, validErr := provider.Validate(ctx, string(plaintext), providerMeta)

	// Zero plaintext
	for i := range plaintext {
		plaintext[i] = 0
	}

	result := map[string]any{
		"valid":    valid,
		"provider": meta.Provider.String,
	}
	if validErr != nil {
		result["error"] = validErr.Error()
	}

	writeJSON(w, http.StatusOK, result)
}

// GetTargets handles GET /api/vault/{id}/targets - returns rotation targets for an entry.
func (h *VaultHandler) GetTargets(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// WRITE access, not read. Rotation targets are a management surface and
	// they carry OTHER people's credentials: webhook HMAC signing secrets and
	// forgejo auth_token references, configured by other members.
	//
	// Gating on read leaked them twice over. entryAccessFor deliberately grants
	// a removed creator a residual READ so they can recover a secret they own
	// (without it, a member could move the entry into a collection the creator
	// is not in and strip them of their own secret permanently). That right is
	// for recovering their own value; it is not a licence to keep reading the
	// delivery configuration of a collection they were removed from. A plain
	// viewer had the same reach for the same reason.
	//
	// Matching UpdateTargets means one rule covers both halves of the surface.
	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	raw, err := h.queries.GetVaultEntryTargets(r.Context(), id)
	if err != nil {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	targets := ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", "rotation_targets"))
	// The version pins the view the client is editing. UpdateTargets is a full
	// replace, so a panel held open across an offboarding would otherwise
	// resubmit the departed member's purged webhook, and since that target is no
	// longer stored it would be re-attributed to whoever pressed Save, silently
	// re-authorizing plaintext delivery to them.
	writeJSON(w, http.StatusOK, map[string]any{
		"targets": targets,
		"version": rotationTargetsVersion(raw.String),
	})
}

// UpdateTargets handles PUT /api/vault/{id}/targets - sets rotation targets
// for an entry. Trustissues keeps three target types: webhook (HMAC-signed
// POST), forgejo_secret (Forgejo Actions secret update), and notify (channel
// notification only). The dockyard control-plane types (env_var, file_write,
// reload_endpoint) are cut.
func (h *VaultHandler) UpdateTargets(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	userID := middleware.GetUserID(r.Context())

	// Load what is stored BEFORE overwriting, so unchanged rows keep their
	// original attribution (see below).
	existingTargets := ""
	if cur, curErr := h.queries.GetVaultEntryTargets(r.Context(), id); curErr == nil {
		existingTargets = cur.String
	}

	var targets []RotationTarget
	if err := json.NewDecoder(r.Body).Decode(&targets); err != nil {
		writeBadRequest(w, r, "invalid JSON array of targets")
		return
	}

	// Stamp the configuring identity server-side, overwriting anything the
	// client sent. A target's auth_token resolves against THIS id at delivery
	// time, so on a shared entry an editor can only reference their own
	// secrets, never the entry owner's unrelated ones.
	//
	// But stamp only rows that are actually NEW or whose destination changed.
	// Restamping the whole array laundered dead targets back to life: the
	// rotation panel PUTs everything it loaded, so an owner adding one target of
	// their own re-attributed a departed member's webhook to themselves, and
	// targetStillAuthorized (which asks whether ConfiguredBy still has write
	// access) then said yes. The next rotation POSTed the fresh plaintext secret
	// to the endpoint of someone who had left the collection, undoing the whole
	// offboarding chain in a single unrelated save.
	//
	// Preserving the stored attribution keeps the security question honest:
	// "who set this up" must not change because someone else pressed Save.
	// Never write over a targets column we could not read. decryptColumnOrLog
	// renders a decrypt failure as "[]", which GetTargets returns as 200 with an
	// empty list, so the panel shows "No delivery targets" and the next save
	// permanently replaces still-recoverable ciphertext, webhook HMAC signing
	// secrets included. Same class as the guard Update has on its metadata
	// columns; this surface never got the equivalent.
	if strings.TrimSpace(existingTargets) != "" {
		if _, decErr := h.decryptColumn(existingTargets); decErr != nil {
			logError(r, "vault.targets: refusing to overwrite an undecryptable targets column", "entry", id, "error", decErr)
			writeError(w, r, http.StatusConflict, "decrypt_failed",
				"the existing delivery targets could not be decrypted, so nothing was changed; saving would have overwritten data that is still recoverable with the correct key")
			return
		}
	}

	// Refuse a blind wipe. UpdateTargets is a full replace, so an empty array
	// deletes every stored target including webhook HMAC secrets that exist
	// nowhere else. The panel could send one by accident: a failed GET rendered
	// byte-identically to "this entry has no targets", so a user who added one
	// target on top of that empty view replaced the real ones, with a success
	// toast and no undo. Clearing must be deliberate.
	if len(targets) == 0 && strings.TrimSpace(existingTargets) != "" {
		if prior := ParseRotationTargets(h.decryptColumnOrLog(existingTargets, "[]", "rotation_targets")); len(prior) > 0 &&
			r.URL.Query().Get("clear") != "1" {
			writeError(w, r, http.StatusConflict, "targets_not_cleared",
				fmt.Sprintf("this would delete all %d delivery target(s); if that is intended, resend with ?clear=1", len(prior)))
			return
		}
	}

	// Refuse a stale view. Without this, a full replace posted from a panel
	// loaded before an offboarding purge writes the removed member's webhook back
	// and stamps it with the saver's id, so targetStillAuthorized then approves
	// delivery to an address the purge had just closed.
	// REQUIRED, not optional. An opt-in staleness check protects only the clients
	// that opt in, and the whole point is that a purge stays purged no matter who
	// writes next: a client omitting the version would still resurrect a removed
	// member's webhook and have it re-attributed to itself.
	//
	// Cheap to satisfy (GET returns it) and this is the only write path for the
	// column, so requiring it costs one extra field and closes the hole for every
	// caller including ones not written yet.
	want := r.URL.Query().Get("version")
	if want == "" {
		writeBadRequest(w, r,
			"version is required; GET this entry's targets first and send the version it returns")
		return
	}
	if got := rotationTargetsVersion(existingTargets); got != want {
		writeError(w, r, http.StatusConflict, "targets_changed",
			"the delivery targets changed since this panel was loaded; reload and reapply your edit")
		return
	}

	stored := ParseRotationTargets(h.decryptColumnOrLog(existingTargets, "[]", "rotation_targets"))
	priorBy := make(map[string]string, len(stored))
	for _, t := range stored {
		if t.ConfiguredBy != "" {
			priorBy[rotationTargetIdentity(t)] = t.ConfiguredBy
		}
	}
	for i := range targets {
		if who, ok := priorBy[rotationTargetIdentity(targets[i])]; ok {
			targets[i].ConfiguredBy = who
			continue
		}
		targets[i].ConfiguredBy = userID
	}

	// Validate targets
	for _, t := range targets {
		switch t.Type {
		case "forgejo_secret":
			if t.Instance == "" || t.Repo == "" || t.SecretName == "" {
				writeBadRequest(w, r, "forgejo_secret target requires instance, repo, and secret_name")
				return
			}
		case "webhook":
			if t.WebhookURL == "" {
				writeBadRequest(w, r, "webhook target requires webhook_url")
				return
			}
		case "notify":
			// no extra fields needed
		default:
			writeBadRequest(w, r, "unknown target type: "+t.Type)
			return
		}
	}

	data, _ := json.Marshal(targets)
	// Encrypt at rest: rotation_targets embeds webhook HMAC secrets that
	// should not sit in cleartext in a DB dump.
	encTargets, encErr := h.encryptColumn(string(data))
	if encErr != nil {
		logError(r, "vault.updateTargets: encrypt failed", "error", encErr)
		writeInternalError(w, r, "failed to update targets")
		return
	}
	if err := h.queries.UpdateVaultEntryRotationTargets(r.Context(), db.UpdateVaultEntryRotationTargetsParams{
		RotationTargets: toNullString(encTargets),
		ID:              id,
	}); err != nil {
		writeInternalError(w, r, "failed to update targets")
		return
	}

	LogActivityFromRequest(h.queries, r, "vault.targets_updated", fmt.Sprintf("Rotation targets updated for vault entry %s (user: %s, targets: %d)", id, userID, len(targets)))

	writeJSON(w, http.StatusOK, targets)
}

// UpdateSchedule handles PUT /api/vault/{id}/schedule - sets rotation interval and auto-rotate.
func (h *VaultHandler) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, canWrite := h.entryAccess(r, id); !canWrite {
		writeNotFound(w, r, "vault entry not found")
		return
	}

	var req struct {
		RotationIntervalDays int  `json:"rotation_interval_days"`
		AutoRotate           bool `json:"auto_rotate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}

	// Validate interval
	validIntervals := map[int]bool{0: true, 30: true, 45: true, 60: true, 90: true, 180: true, 365: true}
	if !validIntervals[req.RotationIntervalDays] {
		writeBadRequest(w, r, "rotation_interval_days must be 0, 30, 45, 60, 90, 180, or 365")
		return
	}

	ctx := r.Context()

	if err := h.queries.UpdateVaultEntryRotationInterval(ctx, db.UpdateVaultEntryRotationIntervalParams{
		RotationIntervalDays: sql.NullInt64{Int64: int64(req.RotationIntervalDays), Valid: req.RotationIntervalDays > 0},
		ID:                   id,
	}); err != nil {
		writeInternalError(w, r, "failed to update rotation interval")
		return
	}

	// Fetch current provider info to update auto_rotate
	current, err := h.queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		writeInternalError(w, r, "failed to fetch entry")
		return
	}

	if err := h.queries.UpdateVaultEntryProvider(ctx, db.UpdateVaultEntryProviderParams{
		Provider:     current.Provider,
		ProviderMeta: current.ProviderMeta,
		AutoRotate:   sql.NullInt64{Int64: boolToInt64(req.AutoRotate), Valid: true},
		ID:           id,
	}); err != nil {
		writeInternalError(w, r, "failed to update auto_rotate")
		return
	}

	// Return updated entry
	row, err := h.queries.GetVaultEntryMeta(ctx, id)
	if err != nil {
		writeInternalError(w, r, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, h.vaultMetaFromGetRow(row))
}

// Match handles GET /api/vault/match?url=... and returns vault entries whose
// URL matches the given domain. Used by the browser extension for autofill.
// Each user only sees their own matching entries.
func (h *VaultHandler) Match(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	ctx := r.Context()

	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		writeBadRequest(w, r, "url parameter is required")
		return
	}

	// url/alias_url are encrypted at rest, so match by blind index rather than a
	// LIKE on cleartext. The index is keyed per SCOPE (see bidxScope), which is
	// what keeps it unlinkable across users, so autofill has to look in every
	// scope the caller can reach: their personal vault plus each collection they
	// have ACCEPTED. Each lookup is a separate indexed query, and a single-team
	// vault has few collections, so this stays cheap.
	if normalizeVaultHost(rawURL) == "" {
		writeBadRequest(w, r, "invalid URL")
		return
	}

	entries := []vaultEntryMeta{}
	seen := map[string]bool{}
	appendRow := func(e vaultEntryMeta) {
		if seen[e.ID] {
			return
		}
		seen[e.ID] = true
		e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt, e.CreatedAt, &e.LastRotationError)
		entries = append(entries, e)
	}

	personalBidx := h.urlBlindIndex(bidxScope(userID, sql.NullString{}), rawURL)
	personalRows, err := h.queries.MatchPersonalVaultEntriesByURL(ctx, db.MatchPersonalVaultEntriesByURLParams{
		UserID:       userID,
		UrlBidx:      personalBidx,
		AliasUrlBidx: personalBidx,
	})
	if err != nil {
		logError(r, "vault.match: personal query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	for _, row := range personalRows {
		appendRow(h.vaultMetaFromMatchPersonalRow(row))
	}

	// ListCollectionsForUser returns accepted memberships only, so a pending
	// invitation contributes nothing to autofill.
	cols, err := h.queries.ListCollectionsForUser(ctx, userID)
	if err != nil {
		logError(r, "vault.match: collection lookup failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	for _, c := range cols {
		cb := h.urlBlindIndex(bidxScope("", sql.NullString{String: c.ID, Valid: true}), rawURL)
		if cb == "" {
			continue
		}
		rows, cErr := h.queries.MatchCollectionVaultEntriesByURL(ctx, db.MatchCollectionVaultEntriesByURLParams{
			CollectionID: sql.NullString{String: c.ID, Valid: true},
			UrlBidx:      cb,
			AliasUrlBidx: cb,
		})
		if cErr != nil {
			logError(r, "vault.match: collection query failed", "collection", c.ID, "error", cErr)
			continue
		}
		for _, row := range rows {
			appendRow(h.vaultMetaFromMatchCollectionRow(row))
		}
	}

	writeJSON(w, http.StatusOK, entries)
}

// vaultRefPattern matches {{vault:SECRET_NAME}} references in content.
var vaultRefPattern = regexp.MustCompile(`\{\{vault:([^}]+)\}\}`)

// ResolveReferences takes a string and replaces all {{vault:NAME}} references
// with their decrypted values from the specified user's vault. If a secret is not found,
// the reference is left as-is and a warning is logged.
func (h *VaultHandler) ResolveReferences(content string, userID string) string {
	if userID == "" {
		slog.Warn("vault.resolveReferences: called with empty userID, skipping resolution")
		return content
	}
	return vaultRefPattern.ReplaceAllStringFunc(content, func(match string) string {
		parts := vaultRefPattern.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		name := strings.TrimSpace(parts[1])

		// Scoped to what this user can CURRENTLY reach, not to who created the
		// entry. See resolveVaultReferenceFor: the raw (name, user_id) match kept
		// resolving for a member removed from the collection holding the secret.
		decrypted, err := h.resolveVaultReferenceFor(context.Background(), name, userID)
		if err != nil {
			slog.Warn("vault.resolveReferences: secret not resolvable for this user",
				"name", name, "user_id", userID, "error", err)
			return match
		}

		value := string(decrypted)
		// Zero out decrypted bytes
		for i := range decrypted {
			decrypted[i] = 0
		}
		return value
	})
}

// ─── Shared package helpers (mirrors dockyard's helpers.go) ─────────────────
//
// The platform helpers.go does not ship these null/bool converters, so the
// vault feature defines them here for the whole handlers package. Rotation
// agent: use these, do NOT redefine them in your files.

// nullTimePtr converts a sql.NullTime to a *string in "2006-01-02 15:04:05"
// format (nil if not valid).
// nullTimePtr renders a timestamp for the API as RFC3339.
//
// It used to emit "2006-01-02 15:04:05", which is not ISO: the edit form does
// entry.expires_at.split('T')[0] to seed <input type="date">, and with no "T"
// that returns the whole string, which the input rejects and renders BLANK. So
// every entry with an expiry showed an empty date field, and saving the form
// then cleared the expiry the user could not see. Safari also refuses to parse
// the space-separated form in new Date() at all.
func nullTimePtr(nt sql.NullTime) *string {
	if nt.Valid {
		s := nt.Time.UTC().Format(time.RFC3339)
		return &s
	}
	return nil
}

// stringPtrToNullTime parses a *string into a sql.NullTime, accepting the
// SQLite datetime format, RFC3339, and bare dates.
// stringPtrToNullTime parses a timestamp, returning an error for anything it
// cannot read.
//
// It used to fall through to a bare sql.NullTime{} on an unparseable value,
// which is byte-identical to the "clear this field" return for nil. So a typo or
// a locale-formatted date silently CLEARED the expiry and reported success. The
// caller must surface the error as a 400.
func stringPtrToNullTime(s *string) (sql.NullTime, error) {
	if s == nil || *s == "" {
		return sql.NullTime{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, *s); err == nil {
			return sql.NullTime{Time: t, Valid: true}, nil
		}
	}
	return sql.NullTime{}, fmt.Errorf("could not parse %q as a date; use YYYY-MM-DD or RFC3339", *s)
}

// nullInt64ToIntPtr converts a sql.NullInt64 to *int (nil if not valid).
func nullInt64ToIntPtr(ni sql.NullInt64) *int {
	if ni.Valid {
		v := int(ni.Int64)
		return &v
	}
	return nil
}

// intPtrToNullInt64 converts *int to sql.NullInt64.
func intPtrToNullInt64(p *int) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}

// boolToInt64 converts a bool to an int64 (SQLite has no bool type).
func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// generateToken creates a cryptographically random hex token of the given byte length.
func generateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

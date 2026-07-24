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
func (h *VaultHandler) urlBlindIndex(raw string) string {
	host := normalizeVaultHost(raw)
	if host == "" {
		return ""
	}
	mac := hmac.New(sha256.New, h.bidxKey[:])
	mac.Write([]byte(host))
	return hex.EncodeToString(mac.Sum(nil))
}

// encryptMetaColumns encrypts the free-text metadata columns of a vault entry
// for at-rest storage using the enc:v1: column scheme. Empty values pass through
// unchanged (encryptColumn skips them), and already-encrypted values are not
// double-wrapped, so callers may pass either cleartext or stored ciphertext.
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
		wantURLBidx := h.urlBlindIndex(urlPlain)
		wantAliasBidx := h.urlBlindIndex(aliasPlain)
		needsBidx := wantURLBidx != row.UrlBidx || wantAliasBidx != row.AliasUrlBidx

		if !needsMeta && !needsBidx {
			continue
		}

		// encryptColumn is idempotent, so passing the stored value (cleartext or
		// already-encrypted) never double-wraps it.
		encURL, encAlias, encUser, encCat, encNotes, encErr := h.encryptMetaColumns(
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
	ID                   string  `json:"id"`
	UserID               string  `json:"user_id,omitempty"`
	CollectionID         *string `json:"collection_id"`
	Name                 string  `json:"name"`
	URL                  string  `json:"url"`
	AliasURL             string  `json:"alias_url"`
	Username             string  `json:"username"`
	Category             string  `json:"category"`
	Notes                string  `json:"notes"`
	AutoLogin            bool    `json:"auto_login"`
	RotationIntervalDays *int    `json:"rotation_interval_days"`
	ExpiresAt            *string `json:"expires_at"`
	LastRotatedAt        *string `json:"last_rotated_at"`
	RotationStatus       string  `json:"rotation_status"`
	Provider             string  `json:"provider"`
	ProviderMeta         string  `json:"provider_meta"`
	AutoRotate           bool    `json:"auto_rotate"`
	LastRotationError    string  `json:"last_rotation_error"`
	CreatedAt            *string `json:"created_at"`
	UpdatedAt            *string `json:"updated_at"`
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
		CreatedAt:            nullTimePtr(row.CreatedAt),
		UpdatedAt:            nullTimePtr(row.UpdatedAt),
	}
	e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt)
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
func computeRotationStatus(rotationDays *int, expiresAt *string, lastRotatedAt *string) string {
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

	// If no rotation interval, it's fresh
	if rotationDays == nil || *rotationDays <= 0 {
		return "fresh"
	}

	if lastRotatedAt == nil || *lastRotatedAt == "" {
		return "fresh"
	}

	// Calculate age
	lastRotated, err := time.Parse("2006-01-02 15:04:05", *lastRotatedAt)
	if err != nil {
		lastRotated, err = time.Parse(time.RFC3339, *lastRotatedAt)
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
// membership role: viewer can read, editor and manager can also write; a
// non-member gets nothing. Returns (false, false) for a missing entry so callers
// 404 uniformly. This is the single authorization point for every single-entry
// operation; do not bypass it with a raw owner check.
func (h *VaultHandler) entryAccess(r *http.Request, entryID string) (canRead, canWrite bool) {
	userID := middleware.GetUserID(r.Context())
	isAdmin := middleware.IsAdmin(r.Context())

	info, err := h.queries.GetVaultEntryAccess(r.Context(), entryID)
	if err != nil {
		return false, false
	}
	if isAdmin {
		return true, true
	}
	if info.CollectionID.Valid && info.CollectionID.String != "" {
		role, err := h.queries.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
			CollectionID: info.CollectionID.String,
			UserID:       userID,
		})
		if err != nil {
			return false, false
		}
		switch role {
		case collRoleManager, collRoleEditor:
			return true, true
		case collRoleViewer:
			return true, false
		default:
			return false, false
		}
	}
	owns := info.UserID == userID
	return owns, owns
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
			e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt)
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
			e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt)
			entries = append(entries, e)
		}
	} else {
		// Non-admin: personal entries plus entries in collections the user
		// belongs to. Access is enforced in the query itself.
		rows, err := h.queries.ListAccessibleVaultEntries(ctx, db.ListAccessibleVaultEntriesParams{
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
			e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt)
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
		Name                 string  `json:"name"`
		Value                string  `json:"value"`
		URL                  string  `json:"url"`
		AliasURL             string  `json:"alias_url"`
		Username             string  `json:"username"`
		Category             string  `json:"category"`
		Notes                string  `json:"notes"`
		AutoLogin            bool    `json:"auto_login"`
		RotationIntervalDays *int    `json:"rotation_interval_days"`
		ExpiresAt            *string `json:"expires_at"`
		Provider             string  `json:"provider"`
		ProviderMeta         string  `json:"provider_meta"`
		AutoRotate           bool    `json:"auto_rotate"`
		CollectionID         *string `json:"collection_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
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
	urlBidx := h.urlBlindIndex(req.URL)
	aliasBidx := h.urlBlindIndex(req.AliasURL)

	// Use separate INSERT + SELECT instead of RETURNING (mattn/go-sqlite3 has bugs with RETURNING)
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
		ExpiresAt:            stringPtrToNullTime(req.ExpiresAt),
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
	h.seedCapabilityDefaults(ctx, r, entryID, req.Provider)

	LogActivityFromRequest(h.queries, r, "vault.entry_created", fmt.Sprintf("Vault secret created: %s (user: %s)", req.Name, userID))

	writeJSON(w, http.StatusCreated, entry)
}

// MoveToCollection handles PUT /api/vault/{id}/collection and moves an entry
// into a shared collection, or back to personal with a null/empty id. Requires
// write access to the entry and, for a non-empty target, editor/manager on the
// destination collection.
func (h *VaultHandler) MoveToCollection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, canWrite := h.entryAccess(r, id); !canWrite {
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
	var target sql.NullString
	if req.CollectionID != nil && *req.CollectionID != "" {
		if !h.canWriteCollection(r, *req.CollectionID) {
			writeForbidden(w, r, "you do not have write access to that collection")
			return
		}
		target = sql.NullString{String: *req.CollectionID, Valid: true}
	}
	if err := h.queries.SetVaultEntryCollection(r.Context(), db.SetVaultEntryCollectionParams{
		CollectionID: target,
		ID:           id,
	}); err != nil {
		logError(r, "vault.move: set collection failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	LogActivityFromRequest(h.queries, r, "vault.entry_moved", fmt.Sprintf("Vault entry moved to collection (id: %s)", id))
	w.WriteHeader(http.StatusNoContent)
}

// seedCapabilityDefaults fills destination_patterns + injection_spec from the
// provider's CapabilityDefaults when the entry still carries the untouched
// '[]' / '{}' defaults. Best-effort: a failure only means auto-routing stays
// off until patterns are set explicitly.
func (h *VaultHandler) seedCapabilityDefaults(ctx context.Context, r *http.Request, entryID, provider string) {
	if provider == "" {
		return
	}
	dests, inj := MarshalCapabilityDefaults(provider)
	if dests == "" && inj == "" {
		return
	}
	if dests == "" {
		dests = "[]"
	}
	if inj == "" {
		inj = "{}"
	}
	if err := h.queries.SeedVaultEntryCapabilityDefaults(ctx, db.SeedVaultEntryCapabilityDefaultsParams{
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
		Name                 *string `json:"name"`
		Value                *string `json:"value"`
		URL                  *string `json:"url"`
		AliasURL             *string `json:"alias_url"`
		Username             *string `json:"username"`
		Category             *string `json:"category"`
		Notes                *string `json:"notes"`
		AutoLogin            *bool   `json:"auto_login"`
		RotationIntervalDays *int    `json:"rotation_interval_days"`
		ExpiresAt            *string `json:"expires_at"`
		Provider             *string `json:"provider"`
		ProviderMeta         *string `json:"provider_meta"`
		AutoRotate           *bool   `json:"auto_rotate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}

	// If value is provided and non-empty, re-encrypt and update last_rotated_at
	if req.Value != nil && *req.Value != "" {
		encrypted, nonce, err := h.encrypt([]byte(*req.Value))
		if err != nil {
			logError(r, "vault.update: encryption failed", "error", err)
			writeInternalError(w, r, "failed to encrypt secret")
			return
		}

		if err := h.queries.UpdateVaultEntryValue(ctx, db.UpdateVaultEntryValueParams{
			EncryptedValue: encrypted,
			Nonce:          nonce,
			ID:             id,
		}); err != nil {
			logError(r, "vault.update: update value failed", "error", err)
			writeInternalError(w, r, "failed to update secret value")
			return
		}
	}

	// Update metadata fields
	if req.Name != nil {
		if err := h.queries.UpdateVaultEntryName(ctx, db.UpdateVaultEntryNameParams{Name: strings.TrimSpace(*req.Name), ID: id}); err != nil {
			logError(r, "vault.update: update name failed", "error", err)
		}
	}
	if req.Category != nil {
		if enc, encErr := h.encryptColumn(*req.Category); encErr != nil {
			logError(r, "vault.update: category encrypt failed", "error", encErr)
		} else if err := h.queries.UpdateVaultEntryCategory(ctx, db.UpdateVaultEntryCategoryParams{Category: toNullString(enc), ID: id}); err != nil {
			logError(r, "vault.update: update category failed", "error", err)
		}
	}
	if req.Notes != nil {
		if enc, encErr := h.encryptColumn(*req.Notes); encErr != nil {
			logError(r, "vault.update: notes encrypt failed", "error", encErr)
		} else if err := h.queries.UpdateVaultEntryNotes(ctx, db.UpdateVaultEntryNotesParams{Notes: toNullString(enc), ID: id}); err != nil {
			logError(r, "vault.update: update notes failed", "error", err)
		}
	}
	if req.RotationIntervalDays != nil {
		if err := h.queries.UpdateVaultEntryRotationInterval(ctx, db.UpdateVaultEntryRotationIntervalParams{RotationIntervalDays: sql.NullInt64{Int64: int64(*req.RotationIntervalDays), Valid: true}, ID: id}); err != nil {
			logError(r, "vault.update: update rotation_interval_days failed", "error", err)
		}
	}
	if req.ExpiresAt != nil {
		if err := h.queries.UpdateVaultEntryExpiresAt(ctx, db.UpdateVaultEntryExpiresAtParams{ExpiresAt: stringPtrToNullTime(req.ExpiresAt), ID: id}); err != nil {
			logError(r, "vault.update: update expires_at failed", "error", err)
		}
	}
	if req.URL != nil {
		if enc, encErr := h.encryptColumn(*req.URL); encErr != nil {
			logError(r, "vault.update: url encrypt failed", "error", encErr)
		} else if err := h.queries.UpdateVaultEntryURL(ctx, db.UpdateVaultEntryURLParams{Url: toNullString(enc), UrlBidx: h.urlBlindIndex(*req.URL), ID: id}); err != nil {
			logError(r, "vault.update: update url failed", "error", err)
		}
	}
	if req.AliasURL != nil {
		if enc, encErr := h.encryptColumn(*req.AliasURL); encErr != nil {
			logError(r, "vault.update: alias_url encrypt failed", "error", encErr)
		} else if err := h.queries.UpdateVaultEntryAliasURL(ctx, db.UpdateVaultEntryAliasURLParams{AliasUrl: toNullString(enc), AliasUrlBidx: h.urlBlindIndex(*req.AliasURL), ID: id}); err != nil {
			logError(r, "vault.update: update alias_url failed", "error", err)
		}
	}
	if req.Username != nil {
		if enc, encErr := h.encryptColumn(*req.Username); encErr != nil {
			logError(r, "vault.update: username encrypt failed", "error", encErr)
		} else if err := h.queries.UpdateVaultEntryUsername(ctx, db.UpdateVaultEntryUsernameParams{Username: toNullString(enc), ID: id}); err != nil {
			logError(r, "vault.update: update username failed", "error", err)
		}
	}
	if req.AutoLogin != nil {
		if err := h.queries.UpdateVaultEntryAutoLogin(ctx, db.UpdateVaultEntryAutoLoginParams{AutoLogin: boolToInt64(*req.AutoLogin), ID: id}); err != nil {
			logError(r, "vault.update: update auto_login failed", "error", err)
		}
	}
	if req.Provider != nil || req.ProviderMeta != nil || req.AutoRotate != nil {
		// Fetch current values for fields not being updated
		current, fetchErr := h.queries.GetVaultEntryMeta(ctx, id)
		if fetchErr == nil {
			provider := current.Provider.String
			providerMeta := current.ProviderMeta.String
			autoRotate := current.AutoRotate.Int64
			if req.Provider != nil {
				provider = *req.Provider
			}
			if req.ProviderMeta != nil {
				providerMeta = *req.ProviderMeta
			}
			if req.AutoRotate != nil {
				autoRotate = boolToInt64(*req.AutoRotate)
			}
			// Encrypt at rest. Idempotent: when provider_meta was NOT part of this
			// update, providerMeta is the already-encrypted current value and
			// encryptColumn passes it through unchanged (no double-wrap).
			encMeta, encErr := h.encryptColumn(providerMeta)
			if encErr != nil {
				logError(r, "vault.update: provider_meta encrypt failed", "error", encErr)
				writeInternalError(w, r, "internal server error")
				return
			}
			if err := h.queries.UpdateVaultEntryProvider(ctx, db.UpdateVaultEntryProviderParams{
				Provider:     toNullString(provider),
				ProviderMeta: toNullString(encMeta),
				AutoRotate:   sql.NullInt64{Int64: autoRotate, Valid: true},
				ID:           id,
			}); err != nil {
				logError(r, "vault.update: update provider failed", "error", err)
			}
			// A newly set provider seeds the capability-bridge columns
			// (untouched rows only, same as Create).
			if req.Provider != nil {
				h.seedCapabilityDefaults(ctx, r, id, provider)
			}
		}
	}

	// Fetch updated entry
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
		Email: email, IpAddress: clientIP(r), Success: 0,
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

		e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt)
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
	rotationMethod := "manual"
	providerName := meta.Provider.String

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
	if currentValue, decErr := h.decrypt(entryRow.EncryptedValue, entryRow.Nonce); decErr == nil {
		oldValue = string(currentValue)
		// Best-effort zero of the plaintext slice. oldValue copy outlives this.
		for i := range currentValue {
			currentValue[i] = 0
		}
	}

	if providerName != "" {
		provider, ok := ProviderRegistry[providerName]
		if ok && provider.CanAutoRotate() {
			providerMeta := ParseProviderMeta(h.decryptColumnOrLog(entryRow.ProviderMeta.String, "{}", "provider_meta"))
			rotatedValue, rotErr := provider.Rotate(ctx, oldValue, providerMeta)
			if rotErr == nil {
				newValue = rotatedValue
				rotationMethod = "auto"
				// Rotate mutated providerMeta with the NEW provider-side key id;
				// persist it (encrypted) so the NEXT rotation revokes THIS key
				// instead of a stale predecessor id. Strip the transient revoke
				// flag first (never persisted); a failed old-key revoke is
				// surfaced as a rotation error.
				revokeWarn := providerMeta["last_revoke_error"]
				delete(providerMeta, "last_revoke_error")
				if metaJSON, mErr := json.Marshal(providerMeta); mErr == nil {
					if encMeta, eErr := h.encryptColumn(string(metaJSON)); eErr == nil {
						_ = h.queries.UpdateVaultEntryProviderMeta(ctx, db.UpdateVaultEntryProviderMetaParams{
							ProviderMeta: toNullString(encMeta),
							ID:           id,
						})
					}
				}
				if revokeWarn != "" {
					logError(r, "vault.rotate: old key revoke failed (predecessor still live)", "entry", id, "detail", revokeWarn)
					_ = h.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
						LastRotationError: toNullString("old key not revoked (still live at provider); see server logs"),
						ID:                id,
					})
				}
			} else {
				// Log the error but fall through to manual rotation
				slog.Warn("vault.rotate: provider rotation failed, falling back to manual", "provider", providerName, "error", rotErr)
				// Redact before persisting: a provider/transport *url.Error embeds
				// the request URL, which can carry a query-injected secret in
				// cleartext. redactUpstreamError strips the query + userinfo.
				_ = h.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
					LastRotationError: toNullString(redactUpstreamError(rotErr)),
					ID:                id,
				})
			}
		}
	}

	// Fallback: generate a random value if provider rotation didn't produce one
	if newValue == "" {
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

	// Update the entry
	result, err := h.queries.RotateVaultEntryValue(ctx, db.RotateVaultEntryValueParams{
		EncryptedValue: encrypted,
		Nonce:          nonce,
		ID:             id,
	})
	if err != nil {
		logError(r, "vault.rotate: update failed", "error", err)
		writeInternalError(w, r, "failed to update secret")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		writeNotFound(w, r, "vault entry not found")
		return
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

	if len(targets) == 0 {
		_ = h.queries.UpdateVaultEntryRotationError(ctx, db.UpdateVaultEntryRotationErrorParams{
			LastRotationError: toNullString(""),
			ID:                id,
		})
		rotationRow, _ := h.queries.GetVaultEntryForRotation(ctx, id)
		updatedLog := AppendRotationLog(rotationRow.RotationLog.String, RotationLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Status:    "success",
			Provider:  providerName,
			Method:    rotationMethod,
		})
		_ = h.queries.UpdateVaultEntryRotationLog(ctx, db.UpdateVaultEntryRotationLogParams{
			RotationLog: toNullString(updatedLog),
			ID:          id,
		})
	} else {
		// Push the new value to configured targets in the background so the
		// user gets immediate feedback. The goroutine then finalises the
		// rotation_log with the REAL delivery+verify outcome (success or
		// partial) and alarms on failure.
		go func(eid, name, oldV, newV, uid, provider, method string, ts []RotationTarget) {
			deliveryCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			results := DeliverRotatedKey(deliveryCtx, h.queries, h, name, oldV, newV, ts, uid)
			status, errSummary := summarizeDelivery(results)
			slog.Info("vault.rotate: delivery complete", "entry", name, "status", status, "total_targets", len(ts))
			if status != "success" {
				slog.Error("vault.rotate: delivery had failures", "entry", name, "detail", errSummary)
				dispatchRotationAlert(deliveryCtx, h.queries, h, name, errSummary)
			}
			_ = h.queries.UpdateVaultEntryRotationError(deliveryCtx, db.UpdateVaultEntryRotationErrorParams{
				LastRotationError: toNullString(errSummary),
				ID:                eid,
			})
			rotationRow, _ := h.queries.GetVaultEntryForRotation(deliveryCtx, eid)
			updatedLog := AppendRotationLog(rotationRow.RotationLog.String, RotationLogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Status:    status,
				Provider:  provider,
				Error:     errSummary,
				Method:    method,
			})
			_ = h.queries.UpdateVaultEntryRotationLog(deliveryCtx, db.UpdateVaultEntryRotationLogParams{
				RotationLog: toNullString(updatedLog),
				ID:          eid,
			})
		}(id, entry.Name, oldValue, newValue, userID, providerName, rotationMethod, targets)
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

	if canRead, _ := h.entryAccess(r, id); !canRead {
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
	if canRead, _ := h.entryAccess(r, id); !canRead {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	raw, err := h.queries.GetVaultEntryTargets(r.Context(), id)
	if err != nil {
		writeNotFound(w, r, "vault entry not found")
		return
	}
	targets := ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", "rotation_targets"))
	writeJSON(w, http.StatusOK, targets)
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

	var targets []RotationTarget
	if err := json.NewDecoder(r.Body).Decode(&targets); err != nil {
		writeBadRequest(w, r, "invalid JSON array of targets")
		return
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

	userID := middleware.GetUserID(r.Context())
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
	// LIKE on cleartext: compute the same HMAC over the requested URL's
	// normalized host and look it up against url_bidx/alias_url_bidx. An
	// unparseable or hostless URL yields an empty index (matches nothing).
	bidx := h.urlBlindIndex(rawURL)
	if bidx == "" {
		writeBadRequest(w, r, "invalid URL")
		return
	}
	// Autofill spans personal entries plus entries in the user's collections.
	rows, err := h.queries.MatchAccessibleVaultEntriesByURL(ctx, db.MatchAccessibleVaultEntriesByURLParams{
		UserID:       userID,
		UserID_2:     userID,
		UrlBidx:      bidx,
		AliasUrlBidx: bidx,
	})
	if err != nil {
		logError(r, "vault.match: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	entries := []vaultEntryMeta{}
	for _, row := range rows {
		e := h.vaultMetaFromMatchAccessibleRow(row)
		e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt, e.LastRotatedAt)
		entries = append(entries, e)
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

		row, err := h.queries.ResolveVaultReference(context.Background(), db.ResolveVaultReferenceParams{
			Name:   name,
			UserID: userID,
		})
		if err != nil {
			slog.Warn("vault.resolveReferences: secret not found", "name", name, "user_id", userID)
			return match
		}

		decrypted, err := h.decrypt(row.EncryptedValue, row.Nonce)
		if err != nil {
			slog.Error("vault.resolveReferences: decrypt failed", "name", name, "error", err)
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
func nullTimePtr(nt sql.NullTime) *string {
	if nt.Valid {
		s := nt.Time.Format("2006-01-02 15:04:05")
		return &s
	}
	return nil
}

// stringPtrToNullTime parses a *string into a sql.NullTime, accepting the
// SQLite datetime format, RFC3339, and bare dates.
func stringPtrToNullTime(s *string) sql.NullTime {
	if s == nil || *s == "" {
		return sql.NullTime{}
	}
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, *s); err == nil {
			return sql.NullTime{Time: t, Valid: true}
		}
	}
	return sql.NullTime{}
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

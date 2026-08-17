package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/passwordhash"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
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
	// keySource is the master key string these three were derived from. The
	// rekey sweep needs it because columncrypto derives internally from the raw
	// string rather than taking a derived key.
	keySource string
	// previous holds the same three derivations for TRUSTISSUES_VAULT_KEY_PREVIOUS,
	// or nil when no rotation is configured. Every DECRYPT path falls back to it;
	// no ENCRYPT path ever touches it. That asymmetry is the whole design: reads
	// tolerate a half-rotated store, writes always land on the current key, so
	// the store converges on the current key with ordinary use and the sweep only
	// has to finish the job for rows nobody edits.
	previous *vaultKeyMaterial
	// auditKey lazily unwraps the audit-name DEK. See audit_name_crypto.go: it is
	// NOT derived from the master key, it is a random key WRAPPED by it, so a
	// master-key rotation rewraps one settings row instead of rewriting audit rows
	// the append-only triggers forbid touching.
	auditKey auditNameKey
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

// vaultKeyMaterial is every key the vault derives from ONE master key string.
//
// It exists so the previous key can be carried alongside the current one without
// three more loose fields on the handler. Grouping them also makes the rotation
// invariant checkable at a glance: a master key opens a row only if the RIGHT
// member of its material opens it, and the three members are not interchangeable
// (value is AES, bidx is HMAC, legacy is the pre-PBKDF2 derivation).
type vaultKeyMaterial struct {
	// source is the raw master key. columncrypto derives internally from the
	// string rather than accepting a derived key, so it has to be kept.
	source string
	value  [32]byte // PBKDF2("trustissues:vault:v2"), encryption_version 2 + enc:v1: columns
	legacy [32]byte // sha256(source + ":secrets-vault"), encryption_version 1
	bidx   [32]byte // PBKDF2("trustissues:vault:bidx:v1"), URL blind index HMAC
}

// deriveVaultKeyMaterial performs all three derivations for one master key.
func deriveVaultKeyMaterial(keySource string) vaultKeyMaterial {
	m := vaultKeyMaterial{source: keySource}

	// Version 2: PBKDF2-SHA256, 600k iterations, 32-byte output
	derived := pbkdf2.Key([]byte(keySource), []byte("trustissues:vault:v2"), 600_000, 32, sha256.New)
	copy(m.value[:], derived)
	// Zero the intermediate slice
	for i := range derived {
		derived[i] = 0
	}

	// Version 1 (legacy): single SHA-256 pass
	m.legacy = sha256.Sum256([]byte(keySource + ":secrets-vault"))

	// Blind-index key: a SEPARATE PBKDF2 derivation (distinct salt) from the same
	// vault key, used to HMAC normalized URLs so autofill can match on an
	// encrypted url column without ever storing the host in cleartext. It must
	// not equal the value-encryption key: reusing an encryption key as a MAC key
	// is a well-known cross-primitive footgun.
	bidxDerived := pbkdf2.Key([]byte(keySource), []byte("trustissues:vault:bidx:v1"), 600_000, 32, sha256.New)
	copy(m.bidx[:], bidxDerived)
	for i := range bidxDerived {
		bidxDerived[i] = 0
	}
	return m
}

// NewVaultHandler creates a new VaultHandler keyed off cfg.VaultKey. The
// encryption key is derived using PBKDF2-SHA256 with 600,000 iterations
// (OWASP 2024 recommendation). A legacy SHA-256 key is also derived to
// support transparent migration of version-1 entries (a fresh Trustissues
// database only ever writes version 2, but the v1 path keeps DecryptValue's
// encVersion contract honest for imported data).
//
// When cfg.VaultKeyPrevious is set the same three keys are derived for the OLD
// master key and kept for reads only. See VaultHandler.previous.
func NewVaultHandler(dbConn *sql.DB, queries *db.Queries, cfg *config.Config) *VaultHandler {
	cur := deriveVaultKeyMaterial(cfg.VaultKey)

	h := &VaultHandler{
		db:            dbConn,
		queries:       queries,
		encryptionKey: cur.value,
		legacyKey:     cur.legacy,
		bidxKey:       cur.bidx,
		keySource:     cur.source,
	}
	if cfg.VaultKeyPrevious != "" && cfg.VaultKeyPrevious != cfg.VaultKey {
		prev := deriveVaultKeyMaterial(cfg.VaultKeyPrevious)
		h.previous = &prev
	}
	return h
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
	return blindIndexWith(h.bidxKey, scope, raw)
}

func blindIndexWith(key [32]byte, scope, raw string) string {
	host := normalizeVaultHost(raw)
	if host == "" || scope == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key[:])
	fmt.Fprintf(mac, "%d:%s|%s", len(scope), scope, host)
	return hex.EncodeToString(mac.Sum(nil))
}

// nameBlindIndex derives the keyed lookup value for an entry NAME within one
// user's namespace. It is what enforces per-user name uniqueness now that the
// name column holds randomized ciphertext that no SQL constraint can compare.
//
// Scoped by USER and not by bidxScope, deliberately. The url index is keyed per
// scope so a shared collection still autofills for every member; this one stands
// in for UNIQUE(user_id, name), where user_id is the CUSTODIAN (00034) and the
// constraint is per user whether or not the entry sits in a collection. Keying
// it by collection would quietly change which renames are legal.
//
// THE NAME IS NOT NORMALIZED, and that is a decision rather than an omission.
// SQLite's default BINARY collation made the old constraint byte-exact, so
// "GitHub" and "github" are two legal entries today. Case-folding here would
// make them collide, which turns an upgrade into a backfill that cannot complete
// on a database that is currently valid. Same reasoning for whitespace.
func (h *VaultHandler) nameBlindIndex(userID, name string) string {
	return nameBlindIndexWith(h.bidxKey, userID, name)
}

// EntryNamePlain opens a stored vault_entries.name. It exists so callers that
// hold no vault key (the capability bridge) can still resolve and log an entry's
// name without a second decryption door being opened next to them.
func (h *VaultHandler) EntryNamePlain(stored string) string {
	return h.decryptColumnOrLog(stored, "", vaultFieldName)
}

func nameBlindIndexWith(key [32]byte, userID, name string) string {
	if userID == "" || name == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key[:])
	// Domain-separated from the url index by the leading tag, and
	// length-prefixed on the user id for the same reason blindIndexWith is: a
	// crafted id must not be able to collide with another user's by shifting the
	// separator.
	fmt.Fprintf(mac, "name:v1|%d:%s|%s", len(userID), userID, name)
	return hex.EncodeToString(mac.Sum(nil))
}

// nameBlindIndexCandidates returns every index value that could legitimately be
// stored for this name, current key first, then the previous key's while a
// rotation is in flight. Same reason as urlBlindIndexCandidates: an index
// computed under the old key does not match the new key's value and nothing
// errors, so a lookup that only asked the current key would report a name as
// free and let a duplicate through.
func (h *VaultHandler) nameBlindIndexCandidates(userID, name string) []string {
	cur := h.nameBlindIndex(userID, name)
	out := []string{}
	if cur != "" {
		out = append(out, cur)
	}
	if h.previous != nil {
		if prev := nameBlindIndexWith(h.previous.bidx, userID, name); prev != "" && prev != cur {
			out = append(out, prev)
		}
	}
	return out
}

// urlBlindIndexCandidates returns every index value that could legitimately be
// stored for this host and scope: the current key's, plus the previous key's
// when a rotation is configured.
//
// The blind index is the one keyed surface a dual-key READ cannot cover the way
// every other one does. Ciphertext can be tried against both keys; an index is
// an equality lookup, so a row whose index was computed under the old key simply
// does not match the value the new key computes. Nothing errors. Autofill just
// returns nothing, the extension shows an empty list, and the user concludes the
// entry was deleted.
//
// So the lookup asks under both keys instead. The alternative, relying on the
// boot backfill to recompute every index before anyone uses autofill, is a
// boot-ordering accident rather than a guarantee: BackfillMetadataAtRest is
// explicitly best-effort and retried next boot on failure, and the sweep can
// also be triggered from the admin API long after boot.
//
// Returns at most two values, deduplicated, empty ones dropped.
func (h *VaultHandler) urlBlindIndexCandidates(scope, raw string) []string {
	cur := h.urlBlindIndex(scope, raw)
	out := []string{}
	if cur != "" {
		out = append(out, cur)
	}
	if h.previous != nil {
		if prev := blindIndexWith(h.previous.bidx, scope, raw); prev != "" && prev != cur {
			out = append(out, prev)
		}
	}
	return out
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
		// A withheld field is a value the exit did NOT release to this caller,
		// rendered blank so the UI can say so. The edit form resubmits every
		// field it was shown, so writing one back would replace the real secret
		// with an empty string, permanently, with a 200 and a success toast.
		// Same class as the refuse-to-overwrite guards on the metadata columns
		// and on rotation_targets; this surface needs its own because the blank
		// is one this server produced.
		if f.Withheld {
			return fmt.Errorf("custom field %q was not released to you, so this save would blank it; "+
				"reload the entry and try again", f.Label)
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
//
// It is deliberately NOT the function a response path calls. A field the
// operator marked secret:true is a credential they deposited here, and it leaves
// this process in a response body exactly like the entry's own value does, so it
// goes through the exit: see customFieldsForCaller.
func (h *VaultHandler) decryptCustomFields(stored string) []CustomField {
	dec := h.decryptColumnOrLog(stored, "[]", vaultFieldCustomFields)
	if dec == "" {
		return nil
	}
	var fields []CustomField
	if err := json.Unmarshal([]byte(dec), &fields); err != nil {
		return nil
	}
	return fields
}

// customFieldsForCaller is THE ONE EXIT for the second credential an entry can
// hold.
//
// # Why this exists
//
// Round 7 made "every path by which a decrypted secret leaves this process" a
// set the compiler maintains, and then stated a SCOPE BOUNDARY naming the two
// encrypted things deliberately outside it. custom_fields was in neither list
// and is not metadata: a field with secret:true is operator-designated secret
// material, the UI masks it for exactly that reason, and it was decrypted and
// written into the same response body as the entry's own value with no
// Destination, no Chooser, no Authority, no receipt and no entry in
// theExitList. A boundary comment that misses a case reads as coverage.
//
// # What the exit adds here
//
// The chooser is the caller, because handing a value back to a principal is not
// choosing a network destination; the Authority asks grantFor(...).read about
// the entry the field belongs to. On the paths this serves the caller already
// holds read, which is how they obtained the row, so nothing legitimate changes.
// What changes is that a list query that widened by accident is refused field by
// field, the value can no longer be logged or interpolated on its way out
// (Plaintext redacts under every verb), and a NEW response path that wants these
// values has to answer the owner question in the same commit that adds it.
//
// A refusal BLANKS the value and marks it withheld rather than dropping the
// field: the edit form resubmits every field it was shown, so a silently blanked
// secret would be written back as empty on the next save. VaultHandler.Update
// refuses an array carrying a withheld marker for the same reason it refuses to
// overwrite an undecryptable column.
func (h *VaultHandler) customFieldsForCaller(ctx context.Context, entryID, entryName, stored,
	callerID string) []CustomField {

	fields := h.decryptCustomFields(stored)
	for i := range fields {
		if !fields[i].Secret || fields[i].Value == "" {
			continue
		}
		_, released, err := secretexit.ExitString(ctx,
			h.MintedEntrySecret([]byte(fields[i].Value), entryID, entryName),
			secretexit.ToCaller("the custom field "+strconv.Quote(fields[i].Label)+" of this entry",
				callerID))
		if err != nil {
			slog.Error("vault: a secret custom field was not released",
				"entry", entryID, "label", fields[i].Label, "caller", callerID, "error", err)
			fields[i].Value = ""
			fields[i].Withheld = true
			continue
		}
		fields[i].Value = released
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
		// Open with the legacy SHA-256 key and re-seal with the PBKDF2 one.
		//
		// Through the OPAQUE type, even though this is a purely in-process re-key
		// that transmits nothing. It used to call decryptWithKey and hold the
		// value as a bare []byte, which is a second way to open an entry secret
		// sitting in the tree for the next person to copy. Re-keying is not an
		// exit and does not appear in theExitList: nothing leaves, and the value
		// is ciphertext again on the other side.
		//
		// OpenEntrySecret also tries the PREVIOUS master key's legacy derivation,
		// which is why the rotation work did not have to reopen the bare-bytes
		// door to get that property back: on the first boot after a master-key
		// change a v1 row is still sealed under the OLD key, and an open against
		// the current legacy key alone fails. This function's error exits the
		// process in main.go, so that failure is a boot loop the operator cannot
		// get out of without reverting the key, which is exactly what
		// TRUSTISSUES_VAULT_KEY_PREVIOUS exists to avoid.
		plaintext, err := h.OpenEntrySecret(e.EncryptedValue, e.Nonce, 1, entryOrigin(e.ID, ""))
		if err != nil {
			return fmt.Errorf("decrypting entry %s with legacy key: %w", e.ID, err)
		}
		newCiphertext, newNonce, err := h.encryptEntrySecret(plaintext)
		plaintext.Wipe()
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
			metaColumnNeedsEncrypt(row.Notes.String) ||
			metaColumnNeedsEncrypt(row.Name)

		// Recover the cleartext host to (re)compute the blind index. decryptColumn
		// is idempotent on cleartext, so this works whether the column is still
		// plaintext or already encrypted.
		urlPlain, derr := h.decryptColumn(row.Url.String, vaultFieldURL)
		if derr != nil {
			slog.Error("vault: metadata backfill url decrypt failed", "id", row.ID, "error", derr)
			continue
		}
		aliasPlain, derr := h.decryptColumn(row.AliasUrl.String, vaultFieldAliasURL)
		if derr != nil {
			slog.Error("vault: metadata backfill alias_url decrypt failed", "id", row.ID, "error", derr)
			continue
		}
		// The name index is keyed by the CUSTODIAN alone, not by bidxScope: it
		// stands in for UNIQUE(user_id, name), which is a per-user constraint
		// regardless of which collection the entry sits in.
		namePlain, derr := h.decryptColumn(row.Name, vaultFieldName)
		if derr != nil {
			slog.Error("vault: metadata backfill name decrypt failed", "id", row.ID, "error", derr)
			continue
		}
		scope := bidxScope(row.UserID, row.CollectionID)
		wantURLBidx := h.urlBlindIndex(scope, urlPlain)
		wantAliasBidx := h.urlBlindIndex(scope, aliasPlain)
		wantNameBidx := h.nameBlindIndex(row.UserID, namePlain)
		needsBidx := wantURLBidx != row.UrlBidx || wantAliasBidx != row.AliasUrlBidx ||
			wantNameBidx != row.NameBidx

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
		encName, encErr := h.encryptColumnIfNeeded(row.Name)
		if encErr != nil {
			return updated, fmt.Errorf("encrypt name for %s: %w", row.ID, encErr)
		}
		if err := h.queries.UpdateVaultEntryMetaAtRest(ctx, db.UpdateVaultEntryMetaAtRestParams{
			Name:         encName,
			Url:          toNullString(encURL),
			AliasUrl:     toNullString(encAlias),
			Username:     toNullString(encUser),
			Category:     toNullString(encCat),
			Notes:        toNullString(encNotes),
			UrlBidx:      wantURLBidx,
			AliasUrlBidx: wantAliasBidx,
			NameBidx:     wantNameBidx,
			ID:           row.ID,
		}); err != nil {
			// A NAME COLLISION IS ONE ROW'S PROBLEM, NOT THE TABLE'S.
			//
			// This used to return, which aborts the sweep for every row after
			// it, on every boot, forever. Rows written before the import path
			// sealed its names carry cleartext names and an empty name_bidx, so
			// they sit OUTSIDE the partial unique index: two of a user's entries
			// can already share a name. The first boot that seals them computes
			// the same index for both, the second UPDATE is refused, and one
			// duplicate row stops at-rest encryption for the whole table. That
			// is a wedge anybody who could reach the import could plant.
			//
			// So the row is left as it is, loudly, and the sweep goes on. The
			// row id is safe to log; the name is not, which is why neither the
			// name nor the index token appears here.
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				slog.Error("vault: metadata backfill skipped a row whose name collides with "+
					"another entry of the same user; rename one of them and it will be "+
					"encrypted on the next sweep", "id", row.ID, "user", row.UserID)
				continue
			}
			return updated, fmt.Errorf("persist metadata for %s: %w", row.ID, err)
		}
		updated++
	}
	if updated > 0 {
		slog.Info("vault: backfilled metadata-at-rest encryption", "rows_updated", updated)
	}
	return updated, nil
}

// decryptWithKey decrypts data using a specific AES-256-GCM key, for one
// DECLARED field.
//
// TestRawAESIsReachedFromExactlyOnePlace pins its caller set to the
// instance-config door. The field argument is the second half of the same
// discipline: the caller set says who may call it, and the field says what they
// are allowed to be opening.
func decryptWithKey(key [32]byte, ciphertext, nonce []byte, field vaultfield.Field) ([]byte, error) {
	return vaultfield.Open(key, ciphertext, nonce, field)
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
	// No omitempty. With it, an entry whose last custom field was just deleted
	// answered without the key at all, which is indistinguishable from "this
	// response does not carry custom fields" to any client that merges a write
	// response into a cached entry: the deleted TOTP seed stayed on screen until
	// the next full unlock. Always sending the key (null or []) makes the
	// response self-describing.
	CustomFields []CustomField `json:"custom_fields"`
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
	// Withheld marks a secret field whose value the exit did not release to this
	// caller. Response-only: it is never stored, and Update REFUSES a save that
	// carries one, because the edit form resubmits every field it was shown and a
	// blanked value would otherwise be written back over the real one.
	Withheld bool `json:"withheld,omitempty"`
}

// vaultEntryFull includes the decrypted secret value (only returned on explicit unlock).
type vaultEntryFull struct {
	vaultEntryMeta
	Value string `json:"value"`
	// ValueWithheld is set when the rotation SUCCEEDED and the exit did not
	// release the new value to this caller. Without it the response is
	// `{"value": ""}` with a 200, which an operator cannot tell from "the new
	// value is empty" on a credential that has just been rolled upstream.
	ValueWithheld string `json:"value_withheld,omitempty"`
}

// vaultMetaFromGetRow converts a db.GetVaultEntryMetaRow to a vaultEntryMeta.
// Method (not free func) so it can decrypt the at-rest-encrypted provider_meta
// column before it is emitted to a client.
//
// It takes the CALLER, not because the row was not already authorized (it was:
// every caller reached this through entryAccess) but because custom_fields can
// carry operator-designated secret material and that leaves through the exit
// now. A converter with no principal in scope cannot ask the exit's question,
// which is exactly why this one used to hand those values out without asking.
func (h *VaultHandler) vaultMetaFromGetRow(ctx context.Context, row db.GetVaultEntryMetaRow,
	callerID string) vaultEntryMeta {
	e := vaultEntryMeta{
		ID: row.ID,
		// The projection used to omit collection_id, so every write response
		// built from this row claimed the entry was personal. A client that
		// merges the response into its cache moved every shared entry back to
		// "Personal" on save until it re-read the whole vault.
		CollectionID:         nullStringPtr(row.CollectionID),
		Name:                 h.decryptColumnOrLog(row.Name, "", vaultFieldName),
		URL:                  h.decryptColumnOrLog(row.Url.String, "", vaultFieldURL),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", vaultFieldAliasURL),
		Username:             h.decryptColumnOrLog(row.Username.String, "", vaultFieldUsername),
		Category:             h.decryptColumnOrLog(row.Category.String, "", vaultFieldCategory),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", vaultFieldNotes),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         redactReservedProviderMetaKeys(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)),
		AutoRotate:           row.AutoRotate.Int64 != 0,
		LastRotationError:    row.LastRotationError.String,
		CustomFields:         h.customFieldsForCaller(ctx, row.ID, row.Name, row.CustomFields, callerID),
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
		Name:                 h.decryptColumnOrLog(row.Name, "", vaultFieldName),
		URL:                  h.decryptColumnOrLog(row.Url.String, "", vaultFieldURL),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", vaultFieldAliasURL),
		Username:             h.decryptColumnOrLog(row.Username.String, "", vaultFieldUsername),
		Category:             h.decryptColumnOrLog(row.Category.String, "", vaultFieldCategory),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", vaultFieldNotes),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         redactReservedProviderMetaKeys(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)),
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
		Name:                 h.decryptColumnOrLog(row.Name, "", vaultFieldName),
		URL:                  h.decryptColumnOrLog(row.Url.String, "", vaultFieldURL),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", vaultFieldAliasURL),
		Username:             h.decryptColumnOrLog(row.Username.String, "", vaultFieldUsername),
		Category:             h.decryptColumnOrLog(row.Category.String, "", vaultFieldCategory),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", vaultFieldNotes),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         redactReservedProviderMetaKeys(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)),
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
		Name:                 h.decryptColumnOrLog(row.Name, "", vaultFieldName),
		URL:                  h.decryptColumnOrLog(row.Url.String, "", vaultFieldURL),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", vaultFieldAliasURL),
		Username:             h.decryptColumnOrLog(row.Username.String, "", vaultFieldUsername),
		Category:             h.decryptColumnOrLog(row.Category.String, "", vaultFieldCategory),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", vaultFieldNotes),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         redactReservedProviderMetaKeys(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)),
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
		Name:                 h.decryptColumnOrLog(row.Name, "", vaultFieldName),
		URL:                  h.decryptColumnOrLog(row.Url.String, "", vaultFieldURL),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", vaultFieldAliasURL),
		Username:             h.decryptColumnOrLog(row.Username.String, "", vaultFieldUsername),
		Category:             h.decryptColumnOrLog(row.Category.String, "", vaultFieldCategory),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", vaultFieldNotes),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         redactReservedProviderMetaKeys(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)),
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
		Name:                 h.decryptColumnOrLog(row.Name, "", vaultFieldName),
		URL:                  h.decryptColumnOrLog(row.Url.String, "", vaultFieldURL),
		AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", vaultFieldAliasURL),
		Username:             h.decryptColumnOrLog(row.Username.String, "", vaultFieldUsername),
		Category:             h.decryptColumnOrLog(row.Category.String, "", vaultFieldCategory),
		Notes:                h.decryptColumnOrLog(row.Notes.String, "", vaultFieldNotes),
		AutoLogin:            row.AutoLogin != 0,
		RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
		ExpiresAt:            nullTimePtr(row.ExpiresAt),
		LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
		Provider:             row.Provider.String,
		ProviderMeta:         redactReservedProviderMetaKeys(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)),
		AutoRotate:           row.AutoRotate.Int64 != 0,
		LastRotationError:    row.LastRotationError.String,
		CreatedAt:            nullTimePtr(row.CreatedAt),
		UpdatedAt:            nullTimePtr(row.UpdatedAt),
	}
}

// encrypt encrypts data using AES-256-GCM. Sealing names no field: the ledger
// records what can become PLAINTEXT, and this produces none.
func (h *VaultHandler) encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	return vaultfield.Seal(h.encryptionKey, plaintext, rand.Reader)
}

// OpenEntrySecret is the ONE WAY to decrypt a vault entry's value, and what it
// hands back is a secretexit.Plaintext: an opaque type whose bytes can only be
// obtained by calling secretexit.Exit with a destination and having the entry's
// OWNER authorise it.
//
// That is the whole shape of round 7. There is no method on the result that
// returns the value, so "every path by which a decrypted secret leaves this
// process" is not a list somebody maintains, it is a set the compiler maintains:
// a new exit that does not call secretexit.Exit does not compile.
//
// It handles both v1 (legacy SHA-256) and v2 (PBKDF2) encryption versions, and
// under each version it also tries the PREVIOUS master key when a rotation is
// configured.
func (h *VaultHandler) OpenEntrySecret(ciphertext, nonce []byte, encVersion int,
	o secretexit.Origin) (secretexit.Plaintext, error) {

	pt, _, err := h.openEntrySecretWithKeyAge(ciphertext, nonce, encVersion, o)
	return pt, err
}

// openEntrySecretWithKeyAge is OpenEntrySecret plus WHICH master key opened the
// value. The re-key sweep is the only caller that needs the second answer.
//
// THE TWO PROPERTIES THIS FUNCTION HOLDS TOGETHER.
//
// The rotation work and the opaque-secret work were built in parallel and each
// one, taken alone, undoes the other. Rotation's version of this was
// VaultHandler.decrypt / DecryptValue: raw AES-GCM under the current key, then
// the previous one, handing back a bare []byte. That is a second way to open an
// entry's value with no destination, no owner question and no receipt, which is
// exactly the door round 7 closed and TestRawAESIsReachedFromExactlyOnePlace
// pins shut. The opaque version had one key and no fallback, so every value
// written under the previous key stranded the moment a sweep was half done.
//
// So the trial lives HERE, inside the one door, and what it produces is still a
// secretexit.Plaintext. Both key attempts go through secretexit.Open, which is
// where vault_entries.encrypted_value is declared, so a rotation-era read is
// counted against that column like any other.
//
// The keys are not interchangeable across versions: a v1 row needs the SHA-256
// derivation of whichever master key sealed it, so the previous key's own legacy
// derivation is what the v1 fallback tries, not its PBKDF2 one.
//
// AES-GCM authenticates, so the fallback cannot produce a false positive: a
// wrong key fails the tag check. The error reported when nothing opens the value
// is the CURRENT key's. The previous key is a transitional convenience, the
// operator's configuration is the current one, and a message naming a key they
// are trying to retire would send them the wrong way.
func (h *VaultHandler) openEntrySecretWithKeyAge(ciphertext, nonce []byte, encVersion int,
	o secretexit.Origin) (pt secretexit.Plaintext, onPrevious bool, err error) {

	key := h.encryptionKey
	if encVersion == 1 {
		key = h.legacyKey
	}
	pt, err = secretexit.Open(key, ciphertext, nonce, o, h)
	if err == nil {
		return pt, false, nil
	}
	if h.previous != nil {
		prev := h.previous.value
		if encVersion == 1 {
			prev = h.previous.legacy
		}
		if prevPT, prevErr := secretexit.Open(prev, ciphertext, nonce, o, h); prevErr == nil {
			return prevPT, true, nil
		}
	}
	return secretexit.Plaintext{}, false, err
}

// entryOrigin names an entry for the exit gate. Every openEntrySecret call site
// passes one, and passing the WRONG one is the round-6 defect in a single
// argument: the delivery path used to authorise against the entry being rotated
// rather than against the entry the secret came from.
func entryOrigin(entryID, name string) secretexit.Origin {
	return secretexit.Origin{EntryID: entryID, Name: name}
}

// EntrySecretByID opens an entry's value by id. It does NOT do access control:
// the caller must have already authorized, and the exit gate asks the owner
// question at the moment the value is actually spent.
func (h *VaultHandler) EntrySecretByID(ctx context.Context, id string) (secretexit.Plaintext, error) {
	row, err := h.queries.GetVaultEntryForRotation(ctx, id)
	if err != nil {
		return secretexit.Plaintext{}, err
	}
	return h.OpenEntrySecret(row.EncryptedValue, row.Nonce, int(row.EncryptionVersion.Int64),
		entryOrigin(id, row.Name))
}

// MintedEntrySecret wraps a value this server CREATED for an entry (a locally
// generated rotation value, or the successor a provider handed back) as the same
// opaque type a decrypted one gets.
//
// It is exactly as dangerous as a decrypted value, so it goes through the same
// exit. Nothing in this package may hold a rotation's new value as a bare
// string: TestNoSecretValueEscapesTheExitType is what fails when it tries.
func (h *VaultHandler) MintedEntrySecret(value []byte, entryID, name string) secretexit.Plaintext {
	return secretexit.Minted(value, entryOrigin(entryID, name), h)
}

// EncryptValue encrypts a plaintext value using the current PBKDF2 key.
// Used by other handlers that need vault-compatible encryption.
func (h *VaultHandler) EncryptValue(plaintext []byte) (ciphertext, nonce []byte, err error) {
	return h.encrypt(plaintext)
}

// encryptEntrySecret re-seals an opaque entry secret for storage.
//
// Storing a value is not an exit, so it does not go through secretexit.Exit and
// deliberately does not appear in the exit list: nothing leaves the process and
// the value is ciphertext again on the other side.
func (h *VaultHandler) encryptEntrySecret(pt secretexit.Plaintext) (ciphertext, nonce []byte, err error) {
	return secretexit.Reseal(h.encryptionKey, pt, rand.Reader)
}

// DecryptInstanceConfig decrypts INSTANCE-OWNED encrypted configuration: the
// notification-channel config rows, which hold an operator's Slack webhook URL
// or SMTP credentials.
//
// It is deliberately a different door from openEntrySecret, and deliberately
// still returns bytes. Those rows belong to no vault entry, so there is no entry
// owner to ask, and only an instance admin can write them. Every value the exit
// gate governs is a vault_entries.encrypted_value, and this is not one.
//
// It returns bytes rather than a Plaintext because the value never leaves the
// process AS a value: alerts parses it to find the channel's URL or relay, and
// what goes on the wire is the operator's own alert text. Wrapping it in an
// origin nobody can authorise would be ceremony, and ceremony is what this round
// is removing.
//
// TestOnlyTheAlertsPathDecryptsInstanceConfig pins the caller set from the AST,
// so this cannot quietly become a second way to open an entry's secret. See the
// SCOPE BOUNDARY note in secret_exit_authority.go.
//
// It falls back to the PREVIOUS master key when a rotation is configured. This
// family used to be served by DecryptValue, which is where main's fallback lived
// before the exit types split entry values off from instance-owned config; a
// channel config left sealed under the retired key reads as a dispatcher that
// has silently stopped alerting, which is the worst kind of half-rotated store.
//
// The re-key sweep asks the same column a different question ("which key opened
// this"), and it cannot ask it here: TestOnlyTheAlertsPathDecryptsInstanceConfig
// forbids any caller inside this package. It opens through vaultfield with the
// SAME declared field instead (see classifyInstanceConfig), which is correct
// rather than a loophole, because a Field names the COLUMN and not the door.
func (h *VaultHandler) DecryptInstanceConfig(ciphertext, nonce []byte, encVersion int) ([]byte, error) {
	// One call to decryptWithKey, inside a loop over the keyring, rather than a
	// current attempt followed by a previous one. That is not style: the raw-AES
	// pin counts CALL SITES, so writing the fallback as a second call would make
	// this function look like two doors to the guard, and the honest way to keep
	// it one door is to have one call.
	var firstErr error
	for _, key := range h.instanceConfigKeyring(encVersion) {
		plain, err := decryptWithKey(key, ciphertext, nonce, vaultFieldAlertChannelConfig)
		if err == nil {
			return plain, nil
		}
		if firstErr == nil {
			// The CURRENT key's error, for the same reason
			// openEntrySecretWithKeyAge reports it: the operator's configuration is
			// the current key, and naming the one they are retiring sends them the
			// wrong way.
			firstErr = err
		}
	}
	return nil, firstErr
}

// instanceConfigKeyring is the keys to try for an instance-config row at this
// encryption version, current first. The derivations are not interchangeable
// across versions, so the version picks which member of each key's material is
// used rather than which key is tried.
func (h *VaultHandler) instanceConfigKeyring(encVersion int) [][32]byte {
	if encVersion == 1 {
		keys := [][32]byte{h.legacyKey}
		if h.previous != nil {
			keys = append(keys, h.previous.legacy)
		}
		return keys
	}
	keys := [][32]byte{h.encryptionKey}
	if h.previous != nil {
		keys = append(keys, h.previous.value)
	}
	return keys
}

// vaultFieldAlertChannelConfig is declared HERE, beside the door that opens it,
// which is the rule internal/vaultfield enforces without exception: a
// declaration belongs where the plaintext is produced, because that is the only
// place that cannot be forgotten.
// The column is notification_channels.config. The round-17 prose boundary and
// the round-18 ledger both called it "alert_channels.config", a table this
// database has never had, and nothing noticed for two rounds because no guard
// ever compared the ledger to the schema. TestEveryLedgerColumnExistsInTheSchema
// does now, and this was its first catch.
var vaultFieldAlertChannelConfig = vaultfield.Declare(
	"notification_channels.config", vaultfield.InstanceOwned, "",
	"notification-channel configuration (a Slack webhook URL, relay credentials), written only through "+
		"the admin-only notification-channel routes. It carries no entry's value: Dispatch sends the "+
		"entry NAME and a redacted detail string. TestOnlyTheAlertsPathDecryptsInstanceConfig pins its "+
		"caller set so this door cannot quietly become a second way to open an entry secret.")

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

	// Alphabetical by name, which every one of these queries used to get from
	// ORDER BY name. Since 00040 that column is ciphertext, so ordering it in
	// SQLite orders by nonce: the list came back in a different random order on
	// every request, which reads as corruption rather than as a missing sort. The
	// queries now order by id for determinism and the human-facing order is
	// applied here, on the decrypted name, once for all three branches.
	sortEntriesByName(entries)
	writeJSON(w, http.StatusOK, entries)
}

// sortEntriesByName orders entries the way the SQL used to, case-insensitively
// first so "aws" and "AWS" sit together, then by the raw name and finally by id
// so the order is total and stable across requests.
func sortEntriesByName(entries []vaultEntryMeta) {
	sort.Slice(entries, func(i, j int) bool {
		li, lj := strings.ToLower(entries[i].Name), strings.ToLower(entries[j].Name)
		if li != lj {
			return li < lj
		}
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].ID < entries[j].ID
	})
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

	// One validator for every write path (see vault_field_limits.go). These used
	// to be literals here, partly duplicated in Update, and entirely absent from
	// import, which is how import could write a row the edit form then refused
	// to save.
	fields := vaultEntryFields{
		Name: req.Name, Value: req.Value, URL: req.URL,
		AliasURL: req.AliasURL, Username: req.Username, Notes: req.Notes,
	}
	if msg := normalizeAndValidateEntryFields(&fields); msg != "" {
		writeBadRequest(w, r, msg)
		return
	}
	req.Name, req.URL, req.AliasURL, req.Username = fields.Name, fields.URL, fields.AliasURL, fields.Username
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
	encName, err := h.encryptColumn(req.Name)
	if err != nil {
		logError(r, "vault.create: name encrypt failed", "error", err)
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
	// The INSERT carries provider and provider_meta, so it is a host-choosing
	// write and it goes through the same door as every other one.
	//
	// The oracle is a constant true and says why in code rather than by being
	// absent: the row being created carries this caller's user_id, so they are
	// exactly the principal mayDirectSecretEgress would name. Asking the real
	// oracle here would query a row that does not exist yet and get false.
	createTicket, createTkErr := egressgate.Decide(egressgate.Request{
		EntryID:     entryID,
		What:        egressFieldProvider,
		After:       providerDestinations(req.Provider, ParseProviderMeta(req.ProviderMeta)),
		Covers:      providerDestinationCovers,
		MayRedirect: func() bool { return true }, // the creator, by construction
	})
	if createTkErr != nil {
		logError(r, "vault.create: egress decision failed", "entry", entryID, "error", createTkErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	err = vaultegress.CreateEntry(ctx, h.queries, createTicket, vaultegress.CreateEntryParams{
		ID:     entryID,
		UserID: userID,
		// The creator is the owner the exit asks about. The two columns are the
		// same value here and diverge only if a collection manager later adopts
		// the entry, which moves the custodian and not the authority.
		SecretOwnerUserID:    userID,
		Name:                 encName,
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
		// Keyed under the creator, who is the custodian at creation time. This is
		// what the UNIQUE index actually constrains; the inline UNIQUE(user_id,
		// name) the error below is caught from can no longer fire, because Name is
		// now randomized ciphertext.
		NameBidx: h.nameBlindIndex(userID, req.Name),
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

	entry := h.vaultMetaFromGetRow(ctx, row, userID)
	entry.CollectionID = nullStringPtr(collectionID)

	// Seed the capability-bridge columns from the provider's defaults so the
	// secret is immediately usable through /secrets/issue + /proxy (dockyard
	// did this in its vault-enroll path). Only untouched rows are filled.
	// The oracle is a constant true for the same reason as the INSERT above: this
	// caller is the row's user_id, which is the principal the widening right
	// belongs to.
	h.seedCapabilityDefaults(ctx, h.queries, r, entryID, req.Provider, func() bool { return true })

	LogActivityFromRequest(h.queries, r, "vault.entry_created", fmt.Sprintf("Vault secret created: %s (user: %s)", h.sealSecretName(r.Context(), req.Name), userID))

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
		urlPlain := h.decryptColumnOrLog(meta.Url.String, "", vaultFieldURL)
		aliasPlain := h.decryptColumnOrLog(meta.AliasUrl.String, "", vaultFieldAliasURL)
		if err := h.queries.UpdateVaultEntryMetaAtRest(ctx, db.UpdateVaultEntryMetaAtRestParams{
			// Passed through untouched. A move changes the collection, not the
			// custodian, so the name and its user-keyed index are unaffected;
			// leaving these at their zero value would blank the entry's name.
			Name:         meta.Name,
			NameBidx:     meta.NameBidx,
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

	storedName, nameErr := h.queries.GetVaultEntryName(ctx, id)
	name := h.EntryNamePlain(storedName)
	if nameErr != nil {
		name = "(unknown)"
	}
	// THE NAME IS SCRUBBED OF ANYTHING SHAPED LIKE AN ENTRY ID.
	//
	// The ownership backfill decides whether an entry has ever been in a
	// collection by asking whether any vault.entry_moved detail CONTAINS its id.
	// The name is caller-chosen and lands in that detail verbatim, so one move of
	// an entry named with seven 32-hex tokens tells the backfill that seven other
	// entries were shared, and it withholds all seven owners. The move route can
	// be driven as often as the caller likes and activity_log is append-only.
	//
	// 00036 recorded this as a residual and called it "a self-inflicted denial of
	// service on one row". It is neither self-inflicted nor one row.
	LogActivityFromRequest(h.queries, r, "vault.entry_moved", fmt.Sprintf(
		"Vault entry moved: %s (id: %s, from: %s, to: %s)",
		h.sealSecretName(r.Context(), scrubEntryIDLookalikes(name)), id, collectionLabel(source), collectionLabel(destination)))
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
//
// mayWiden is the authority oracle for the ceiling this seeds. It is a
// parameter rather than a recomputation because the two callers know different
// things: Create is the principal who just deposited the plaintext, while Update
// has already resolved mayDirectSecretEgress for the request. Passing it keeps
// the seed on the SAME decision as an explicit ceiling write, which matters
// because this IS a ceiling write: it turns "no agent access" into "one host",
// and three presets (supabase, auth0, grafana) expand a tenant value out of the
// entry's own provider_meta, which an editor can set.
func (h *VaultHandler) seedCapabilityDefaults(ctx context.Context, q *db.Queries, r *http.Request, entryID, provider string, mayWiden func() bool) {
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
		meta = ParseProviderMeta(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta))
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
	// The seed only lands on an UNTOUCHED row (the SQL carries
	// destination_patterns = '[]' AND injection_spec = '{}' in its WHERE), so the
	// set it moves from is empty and every seeded host is an addition.
	tk, tkErr := egressgate.Decide(egressgate.Request{
		EntryID:     entryID,
		What:        egressFieldDestinations,
		After:       ceilingDestinations(parseDestinationPatterns(dests)),
		Covers:      destinationCovers,
		MayRedirect: mayWiden,
	})
	if tkErr != nil {
		// Not seeding is fail-closed: the bridge refuses to mint until somebody
		// with the right sets a ceiling explicitly.
		logError(r, "vault: capability preset not seeded; the caller may not widen this secret's egress",
			"entry_id", entryID, "provider", provider, "reason", tkErr)
		return
	}
	if err := vaultegress.SeedCapabilityDefaults(ctx, q, tk, vaultegress.CapabilityDefaultsParams{
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
		if field, broken := h.anyMetaColumnUndecryptable(map[vaultfield.Field]string{
			vaultFieldURL:          damaged.Url.String,
			vaultFieldAliasURL:     damaged.AliasUrl.String,
			vaultFieldUsername:     damaged.Username.String,
			vaultFieldCategory:     damaged.Category.String,
			vaultFieldNotes:        damaged.Notes.String,
			vaultFieldCustomFields: damaged.CustomFields,
		}); broken {
			logError(r, "vault.update: refusing to overwrite an undecryptable column", "entry", id, "field", field)
			writeError(w, r, http.StatusConflict, "decrypt_failed",
				"part of this entry ("+field+") could not be decrypted, so nothing was changed; saving would have overwritten data that is still recoverable with the correct key")
			return
		}
	}

	// May this caller ADD or WIDEN a destination this secret is delivered to?
	//
	// Computed BEFORE the transaction opens, deliberately: mayDirectSecretEgress
	// reads through h.queries (the pool), and a pool read issued while this
	// handler holds the SQLite write lock contends with it on a second
	// connection. That is the measured 5.3s stall documented on
	// seedCapabilityDefaults, and the answer does not depend on anything the
	// transaction writes.
	//
	// manage is not enough for this, and that gap is the round-3 blocker: an
	// accepted collection editor (a role a public-signup vault_only account can
	// hold) rewrote destination_patterns here and had /proxy deliver the
	// operator's decrypted provider key to a host they chose. See
	// mayDirectSecretEgress and secret_egress.go.
	//
	// req.ProviderMeta is in this list, and adding it is the round-4 fix. The
	// previous cut asked the question only for destination_patterns and provider,
	// which is exactly the shape this stream keeps repeating: the guard names the
	// columns that were attacked last time and the next writer of a DIFFERENT
	// column walks straight past it. The set of egress-influencing fields is now
	// stated once in egress_authority.go and every one of them lands here.
	mayWidenEgress := false
	if req.DestinationPatterns != nil || req.Provider != nil || req.ProviderMeta != nil {
		mayWidenEgress = h.mayDirectSecretEgress(ctx, userID, middleware.IsAdmin(ctx), id)
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

		// Read the stored ceiling through qtx, not the pool: same connection,
		// under the write lock this transaction already holds, so the comparison
		// below cannot race a concurrent widening.
		stored, storedErr := qtx.GetVaultEntryMeta(ctx, id)
		if storedErr != nil {
			logError(r, "vault.update: could not read the current destination ceiling", "entry", id, "error", storedErr)
			writeInternalError(w, r, "internal server error")
			return
		}

		// A gateway-wired entry has a fixed destination and nobody edits it here,
		// admin included. Refusing the WRITE as well as the delivery keeps the
		// stored row honest: the alternative is a database that says the key may
		// go somewhere the proxy will always refuse, which reads as a bug at
		// exactly the moment an operator is trying to understand a refusal. The
		// documented way out is to unwire the entry in Settings > AI gateway,
		// which is an admin action and an audited one.
		pin, pinErr := providerPinFor(ctx, qtx, id)
		if pinErr != nil {
			logError(r, "vault.update: could not read the entry's provider pin", "entry", id, "error", pinErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if bad, outside := firstDestinationOutsidePin(pin, patterns); outside {
			logError(r, "vault.update: refused a destination outside the provider pin",
				"entry", id, "user", userID, "destination", bad)
			writeError(w, r, http.StatusForbidden, "destination_pinned",
				fmt.Sprintf("this secret is the instance's AI provider key; it is only ever delivered to %s, "+
					"so %q cannot be added. Unwire it in Settings > AI gateway first if it is meant to be a general-purpose secret",
					pin.describe(), bad))
			return
		}

		// Narrowing is open to anyone with manage (clearing the list is the only
		// per-secret agent revocation the product has). Widening is not.
		//
		// Covers is destinationCovers, the ceiling grammar, so replacing
		// "api.openai.com/*" with "api.openai.com/v1/chat" reads as a narrowing
		// rather than as an addition. That is the one thing a plain set
		// difference would get wrong here, and getting it wrong would put
		// tightening a ceiling behind the widening right.
		ceilingTicket, ceilErr := egressgate.Decide(egressgate.Request{
			EntryID:     id,
			What:        egressFieldDestinations,
			Before:      ceilingDestinations(parseDestinationPatterns(stored.DestinationPatterns)),
			After:       ceilingDestinations(patterns),
			Covers:      destinationCovers,
			MayRedirect: func() bool { return mayWidenEgress },
		})
		if ceilErr != nil {
			var denied *egressgate.DeniedError
			if errors.As(ceilErr, &denied) {
				logError(r, "vault.update: refused an egress widening", "entry", id, "user", userID, "added", denied.Added)
				writeError(w, r, http.StatusForbidden, "egress_widening_denied",
					fmt.Sprintf("you can narrow where this secret may be sent, but adding %v takes the secret's owner or an instance admin. "+
						"Editing an entry does not carry the right to choose where its value is delivered", denied.Added))
				return
			}
			logError(r, "vault.update: egress decision failed", "entry", id, "error", ceilErr)
			writeInternalError(w, r, "internal server error")
			return
		}

		encoded, mErr := json.Marshal(patterns)
		if mErr != nil {
			logError(r, "vault.update: encode destination patterns failed", "error", mErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if err := vaultegress.SetDestinationPatterns(ctx, qtx, ceilingTicket, vaultegress.DestinationPatternsParams{
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
		currentPlain, decErr := h.OpenEntrySecret(current.EncryptedValue, current.Nonce,
			int(current.EncryptionVersion.Int64), entryOrigin(id, current.Name))
		if decErr != nil {
			logError(r, "vault.update: refusing to overwrite an undecryptable secret", "entry", id, "error", decErr)
			writeError(w, r, http.StatusConflict, "decrypt_failed",
				"this secret could not be decrypted, so it was not changed; saving would have overwritten a value that is still recoverable")
			return
		}
		// NOT an exit. EqualsString is constant-time and emits one bit the caller
		// already knew how to obtain, because they supplied the candidate. It is
		// the only in-process use of a secret that does not go through
		// secretexit.Exit, and it cannot be turned into a read of the value.
		unchanged := currentPlain.EqualsString(*req.Value)
		currentPlain.Wipe()

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
		// Who owns the entry decides whether a rename may be attempted at all.
		//
		// UNIQUE(user_id, name) is scoped to the entry's CREATOR, and a shared
		// entry keeps its creator's user_id forever. So an editor in a shared
		// collection renaming somebody else's entry ran a query against a vault
		// they have no read path to: a 409 meant "the creator holds an entry with
		// exactly that name privately", and a 204 meant they do not. That is an
		// existence oracle over another user's personal vault, spendable one
		// guessed name at a time, and on a shared instance the creator is
		// somebody else's client.
		//
		// The refusal is therefore constant: it does not consult the creator's
		// namespace, so it says the same thing whether or not the name is taken
		// there. The owner and an instance admin keep the precise duplicate-name
		// feedback below, because for them the conflicting entry is one they can
		// already see (an admin lists every entry with ?all=true).
		//
		// A rename by a non-owner is also a correctness problem in its own right:
		// the name is the lookup key for service_identities.allowed_secrets and
		// for MCP list_secrets/use_secret, so renaming another user's entry
		// silently breaks resolution they configured and cannot see was broken.
		//
		// An UNCHANGED name is not a rename, and the edit form resubmits every
		// field, so it must not be refused: otherwise an editor could no longer
		// save a URL or a note on a shared entry at all.
		//
		// THE RULE, in full, because the first cut of this fix silently took
		// renaming away from collection MANAGERS and did not say so:
		//
		//  1. the entry's creator and an instance admin rename freely, with the
		//     precise 409 duplicate-name feedback, since the conflicting entry
		//     is one they can already see;
		//  2. a MANAGER of the collection may rename an entry whose creator has
		//     left that collection, and doing so ADOPTS it (user_id and name are
		//     written in one statement). Adoption is what makes it safe: the
		//     uniqueness question moves into the manager's own namespace, so the
		//     answer is about entries they can see and the creator's private
		//     vault is never consulted. It is unconditional on that path, not a
		//     fallback after a conflict, because a fallback would be the oracle
		//     again by its timing;
		//  3. everyone else, including a manager while the creator is still an
		//     accepted member of the collection, gets the constant 403. The
		//     creator is right there and can do it themselves, and the name is
		//     the lookup key for service_identities.allowed_secrets and MCP
		//     use_secret, so a rename behind their back breaks resolution they
		//     configured and cannot see is broken.
		//
		// Rule 2 exists because without it the name of a shared entry froze the
		// moment its creator left the team, with only an instance admin able to
		// fix a typo. Its cost is real and deliberate: adoption ends the
		// departed creator's residual recovery READ on that one entry
		// (grantFor row 7), so a manager takes responsibility for a secret that
		// was stranded in their collection. Rule 3 keeps the creator's own
		// namespace unreadable while they are still a colleague.
		//
		// ADOPTION MOVES THE CUSTODIAN AND NOT THE OWNER. Rule 2 was also, until
		// this round, a two-call route to becoming the principal the EXIT asks
		// about: a manager removes the creator from the collection (manager-
		// gated), renames the entry, and mayDirectSecretEgress then said yes,
		// which authorised the exact round-6 cross-entry delivery the exit exists
		// to refuse. secret_owner_user_id stays where it was, so a manager takes
		// responsibility for a stranded secret without acquiring the right to
		// choose where its plaintext goes. Narrowing and clearing its delivery
		// targets are still open to them, which is the lever that actually
		// matters for a secret nobody is left to own.
		access, accessErr := qtx.GetVaultEntryAccess(ctx, id)
		if accessErr != nil {
			logError(r, "vault.update: owner lookup for rename failed", "entry", id, "error", accessErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		ownerID := access.UserID
		storedName, nameErr := qtx.GetVaultEntryName(ctx, id)
		// Stored is ciphertext since 00040. Comparing the caller's cleartext to it
		// would find every rename to be a change, including a no-op one, and would
		// then rewrite the row (and its index) on every save.
		currentName := h.decryptColumnOrLog(storedName, "", vaultFieldName)
		if nameErr != nil {
			logError(r, "vault.update: current-name lookup for rename failed", "entry", id, "error", nameErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if newName != currentName {
			switch {
			case middleware.IsAdmin(ctx) || userID == ownerID:
				// The name stays in the OWNER's namespace on an ordinary rename, so
				// the index is derived under ownerID rather than under whoever is
				// making the call: an admin renaming somebody else's entry must not
				// move it into their own namespace.
				encName, encErr := h.encryptColumn(newName)
				if encErr != nil {
					logError(r, "vault.update: encrypt name failed", "error", encErr)
					writeInternalError(w, r, "internal server error")
					return
				}
				if err := qtx.UpdateVaultEntryName(ctx, db.UpdateVaultEntryNameParams{
					Name: encName, NameBidx: h.nameBlindIndex(ownerID, newName), ID: id,
				}); err != nil {
					if strings.Contains(err.Error(), "UNIQUE constraint") {
						writeConflict(w, r, "a vault entry with that name already exists")
						return
					}
					logError(r, "vault.update: update name failed", "error", err)
					writeInternalError(w, r, "internal server error")
					return
				}
			case h.managerMayAdoptOrphanedEntry(ctx, userID, ownerID, access.CollectionID):
				// Adoption moves the custodian, so the index moves with it: derived
				// under the ADOPTER's id, which is what puts the uniqueness question
				// in their namespace. Deriving it under ownerID here would keep
				// enforcing the departed owner's namespace on a row they no longer
				// hold.
				encName, encErr := h.encryptColumn(newName)
				if encErr != nil {
					logError(r, "vault.update: encrypt name failed", "error", encErr)
					writeInternalError(w, r, "internal server error")
					return
				}
				if err := qtx.AdoptAndRenameVaultEntry(ctx, db.AdoptAndRenameVaultEntryParams{
					UserID: userID, Name: encName, NameBidx: h.nameBlindIndex(userID, newName), ID: id,
				}); err != nil {
					if strings.Contains(err.Error(), "UNIQUE constraint") {
						// The conflict is inside the manager's OWN namespace, so
						// naming it leaks nothing they cannot already list.
						writeConflict(w, r, "you already have a vault entry with that name")
						return
					}
					logError(r, "vault.update: adopt and rename failed", "error", err)
					writeInternalError(w, r, "internal server error")
					return
				}
				// Queued, not written here: LogActivityFromRequest runs on its
				// own connection and would contend with the write lock this
				// transaction holds (measured 5.1s of stall and a lost row).
				deferredActivity = append(deferredActivity, queuedActivity{
					action: "vault.entry_adopted",
					detail: fmt.Sprintf("Entry %s renamed and adopted by a collection manager (its creator has left the collection)", id),
				})
			default:
				writeForbidden(w, r, "only the entry's owner or an instance admin can rename it")
				return
			}
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

			// THE SECOND HOST-CHOOSING SURFACE, held to the same right as the first.
			//
			// destination_patterns was pinned in round 3 and the attack simply moved
			// one column over: provider and provider_meta together decide the host a
			// rotation or a validation sends the decrypted secret to, and neither was
			// gated. datadog's "site" becomes "https://api."+site; grafana's
			// "instance" becomes "https://"+instance+".grafana.net". Neither reads
			// like a URL, both are one.
			//
			// The comparison is on the DECLARED HOST SET, never on the raw column
			// text, so it does not need to know which key is a host: providerEgress
			// says what the pair resolves to and this asks whether the resolution
			// grew. That is what makes a provider added next year covered on the day
			// it is added rather than after it is exploited.
			beforeMeta := ParseProviderMeta(h.decryptColumnOrLog(current.ProviderMeta.String, "{}", vaultFieldProviderMeta))
			afterMeta := beforeMeta
			if req.ProviderMeta != nil {
				afterMeta = ParseProviderMeta(*req.ProviderMeta)
				// Server-owned transient markers. pending_revoke_url is issued by
				// performPendingRevoke with the NEW secret as its bearer token, so a
				// client that could plant one would have the scheduler post the fresh
				// credential wherever it said. providerDo already refuses the request;
				// refusing the WRITE keeps the attempt out of the row entirely.
				if bad, found := rejectReservedProviderMetaKeys(afterMeta); found {
					logError(r, "vault.update: refused a client-supplied server-owned provider_meta key",
						"entry", id, "user", userID, "key", bad)
					writeValidationError(w, r,
						"provider_meta may not contain "+bad+": that key is written by the rotation engine itself")
					return
				}
				// THE WRITE IS A FULL COLUMN REPLACE, SO THE SERVER'S OWN KEYS
				// MUST BE CARRIED ACROSS IT EXPLICITLY.
				//
				// This is the third surface that had encoded "the markers never
				// reach the database". While that held, replacing the column
				// wholesale with the client's map lost nothing, because there was
				// never anything of the server's in it. Now a failed deferred
				// revoke deliberately leaves its retry coordinates here, and the
				// client is handed the column with them REDACTED
				// (redactReservedProviderMetaKeys) so it cannot be locked out by
				// echoing them back. Those two facts together mean an ordinary
				// untouched Save would silently wipe the only record of what to
				// revoke and how: the exact stranded-key outcome the deferral
				// exists to prevent, reached through the UI instead of through a
				// second rotation.
				//
				// Preserved only when the provider is UNCHANGED. The coordinates
				// name a host and a key id at ONE provider; carrying them onto a
				// different provider would let a later rotation that did not
				// defer inherit a stale marker and fire it with a freshly minted
				// secret. Changing the provider is the operator deliberately
				// abandoning the old configuration, and the old provider's
				// pending revoke goes with it. last_revoke_error is a warning
				// about that same abandoned configuration and is dropped with it.
				//
				// The structural alternative is a server-only column, which would
				// make this impossible rather than merely handled. It is a schema
				// migration and is not what these markers cost today.
				if provider == current.Provider.String {
					for _, k := range reservedProviderMetaKeys {
						if v, ok := beforeMeta[k]; ok {
							afterMeta[k] = v
						}
					}
				}
			}
			// One decision, one ticket, and the ticket is what the write demands.
			// authorityForEgressChange still computes the resulting host set for
			// the pin loop below; the AUTHORITY half now goes through the same
			// egressgate.Decide every other host-choosing column uses, so the
			// three of them cannot drift into three different answers again.
			change := authorityForEgressChange(current.Provider.String, beforeMeta, provider, afterMeta)
			providerTicket, provErr := egressgate.Decide(egressgate.Request{
				EntryID:     id,
				What:        egressFieldProvider,
				Before:      providerDestinations(current.Provider.String, beforeMeta),
				After:       providerDestinations(provider, afterMeta),
				Covers:      providerDestinationCovers,
				MayRedirect: func() bool { return mayWidenEgress },
			})
			if provErr != nil {
				var denied *egressgate.DeniedError
				if errors.As(provErr, &denied) {
					logError(r, "vault.update: refused an egress widening through provider/provider_meta",
						"entry", id, "user", userID, "added", denied.Added)
					writeError(w, r, http.StatusForbidden, "egress_widening_denied",
						fmt.Sprintf("changing the provider configuration would let this secret be sent to %v, "+
							"which takes the secret's owner or an instance admin. Editing an entry does not carry "+
							"the right to choose where its value is delivered (the fields that decide this are the "+
							"provider and the provider_meta keys %v)", denied.Added, egressInfluencingMetaKeys()))
					return
				}
				logError(r, "vault.update: provider egress decision failed", "entry", id, "error", provErr)
				writeInternalError(w, r, "internal server error")
				return
			}
			if change.widensEgress() {
				// The pin outranks the widening right, exactly as it does for
				// destination_patterns: while an admin has the instance pointed at
				// this entry, its key goes to that provider and nowhere else, and
				// not even the creator may move it.
				pin, pinErr := providerPinFor(ctx, qtx, id)
				if pinErr != nil {
					logError(r, "vault.update: could not read the entry's provider pin", "entry", id, "error", pinErr)
					writeInternalError(w, r, "internal server error")
					return
				}
				if pin.pinned() {
					for _, host := range change.after {
						if pin.allowsHost(host) {
							continue
						}
						logError(r, "vault.update: refused a provider change outside the provider pin",
							"entry", id, "user", userID, "host", host)
						writeError(w, r, http.StatusForbidden, "destination_pinned",
							fmt.Sprintf("this secret is the instance's AI provider key; it is only ever delivered to %s, "+
								"so a provider configuration reaching %q cannot be stored. Unwire it in "+
								"Settings > AI gateway first", pin.describe(), host))
						return
					}
				}
			}
			// provider_meta at rest. The two cases are kept explicitly apart:
			// client-supplied meta is ALWAYS encrypted, while an untouched column
			// is carried forward exactly as stored. Never decide by content
			// (a passthrough of client input that already looks encrypted is a
			// decryption oracle; see vaultColumnEncPrefix).
			encMeta := providerMeta // untouched: already-stored value, verbatim
			if req.ProviderMeta != nil {
				// WHAT IS STORED IS afterMeta, THE MAP THE EGRESS GATE JUST
				// DECIDED ON, not the client's bytes.
				//
				// This used to encrypt *req.ProviderMeta directly, which made the
				// evaluated value and the persisted value two different things.
				// Harmless while they could not disagree; not harmless once
				// afterMeta carries the server-owned pending_revoke_* markers
				// across the write (see above), because storing the raw request
				// instead dropped every one of them on an ordinary Save and
				// stranded the old upstream key with no record of how to revoke
				// it. Marshalling afterMeta is what makes that carry-across real.
				//
				// Nothing else is lost by it: ParseProviderMeta is already the
				// lens the validator and the gate both look through, so a
				// non-string value it drops was invisible to every server-side
				// consumer before this line and to RotationManager's own parse
				// after it. Storing the parse makes stored state equal to
				// evaluated state.
				//
				// Still ALWAYS encrypted on the client-supplied branch, and now
				// re-encoded from a server-built map rather than passed through,
				// so the decryption-oracle hazard the two-branch split exists for
				// is further away, not closer.
				metaJSON, mErr := json.Marshal(afterMeta)
				if mErr != nil {
					logError(r, "vault.update: provider_meta marshal failed", "error", mErr)
					writeInternalError(w, r, "internal server error")
					return
				}
				enc, encErr := h.encryptColumn(string(metaJSON))
				if encErr != nil {
					logError(r, "vault.update: provider_meta encrypt failed", "error", encErr)
					writeInternalError(w, r, "internal server error")
					return
				}
				encMeta = enc
			}
			if err := vaultegress.SetProvider(ctx, qtx, providerTicket, vaultegress.ProviderParams{
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
			//
			// Gated by the same right as an explicit ceiling write, because this
			// IS a ceiling write: it turns "no agent access" into "one host",
			// and three presets (supabase, auth0, grafana) expand a tenant value
			// out of the entry's own provider_meta, which an editor can set. So
			// an editor enrolling a provider could otherwise seed
			// attacker.auth0.com/* on somebody else's secret. Skipping leaves the
			// ceiling empty, which is fail-closed: the bridge refuses to mint at
			// all until the owner sets one.
			if req.Provider != nil {
				h.seedCapabilityDefaults(ctx, qtx, r, id, provider, func() bool { return mayWidenEgress })
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

	entry := h.vaultMetaFromGetRow(ctx, row, userID)

	LogActivityFromRequest(h.queries, r, "vault.entry_updated", fmt.Sprintf("Vault secret updated: %s (user: %s)", h.sealSecretName(r.Context(), entry.Name), userID))

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
	// Opened, because GetVaultEntryName returns what is STORED and 00040 made
	// that ciphertext. The only consumer here is the activity line below, and an
	// audit row reading "Vault secret deleted: enc:v1:PT5r..." names nothing at
	// the one moment the log is the last place the name still exists: after the
	// row is gone, this line IS the record of what was deleted.
	name = h.EntryNamePlain(name)

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

	LogActivityFromRequest(h.queries, r, "vault.entry_deleted", fmt.Sprintf("Vault secret deleted: %s (user: %s)", h.sealSecretName(r.Context(), name), userID))

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
		// Capacity is not a wrong password, and recordReauthFailure writes the SAME
		// login_attempts rows that reauthLocked counts, so counting it here is the
		// same lockout vector as on login. See capacityExhausted.
		if capacityExhausted(w, r, verifyErr, "vault.reauth") {
			return
		}
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
				Name:                 h.decryptColumnOrLog(row.Name, "", vaultFieldName),
				URL:                  h.decryptColumnOrLog(row.Url.String, "", vaultFieldURL),
				AliasURL:             h.decryptColumnOrLog(row.AliasUrl.String, "", vaultFieldAliasURL),
				Username:             h.decryptColumnOrLog(row.Username.String, "", vaultFieldUsername),
				Category:             h.decryptColumnOrLog(row.Category.String, "", vaultFieldCategory),
				Notes:                h.decryptColumnOrLog(row.Notes.String, "", vaultFieldNotes),
				AutoLogin:            row.AutoLogin != 0,
				RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
				ExpiresAt:            nullTimePtr(row.ExpiresAt),
				LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
				Provider:             row.Provider.String,
				ProviderMeta:         redactReservedProviderMetaKeys(h.decryptColumnOrLog(row.ProviderMeta.String, "{}", vaultFieldProviderMeta)),
				AutoRotate:           row.AutoRotate.Int64 != 0,
				LastRotationError:    row.LastRotationError.String,
				// Through the exit, like the entry's own value below. A
				// secret:true custom field is a credential the operator
				// deposited here and it rides out in this same body.
				CustomFields:        h.customFieldsForCaller(ctx, row.ID, row.Name, row.CustomFields, userID),
				DestinationPatterns: parseDestinationPatterns(row.DestinationPatterns),
				CreatedAt:           nullTimePtr(row.CreatedAt),
				UpdatedAt:           nullTimePtr(row.UpdatedAt),
			},
		}

		// THE ONE EXIT, caller form. Unlock is password-re-verified above, and
		// this asks the second half: does the OWNER of each entry admit this
		// caller to it? A list query that widened by accident would otherwise
		// hand over rows the caller may not read, and the exit is the one place
		// that cannot be widened by accident.
		// Version 2: this query only ever returns rows this build wrote, which
		// matches the h.decrypt call it replaces.
		decrypted, err := h.OpenEntrySecret(row.EncryptedValue, row.Nonce, 2,
			entryOrigin(row.ID, row.Name))
		if err == nil {
			var value string
			_, value, err = secretexit.ExitString(ctx, decrypted,
				secretexit.ToCaller("POST /api/vault/unlock", userID))
			decrypted.Wipe()
			e.Value = value
		}
		if err != nil {
			logError(r, "vault.unlock: value not released", "name", e.Name, "error", err)
			e.Value = "[decryption error]"
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
		// Capacity is not a wrong password, and recordReauthFailure writes the SAME
		// login_attempts rows that reauthLocked counts, so counting it here is the
		// same lockout vector as on login. See capacityExhausted.
		if capacityExhausted(w, r, verifyErr, "vault.reauth") {
			return
		}
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
	// Opened ONCE, into the local copy, for the reason rotateOneEntry states at
	// its own EntryNamePlain call: the fourteen places below that use this name
	// are then all correct without each having to remember. meta is a value, so
	// this changes nothing in the database, and Rotate never writes Name back.
	//
	// This was a live regression rather than a precaution. 00040 made the stored
	// name ciphertext, and the MANUAL rotation path kept reading it raw while the
	// auto path opened it, so a manual rotation put enc:v1: blobs into the
	// activity log, into every recordRotationFailure record (which is what the
	// rotation alert email and the entry's rotation log render), and into the
	// origin label stamped on the minted secret. The auto path was correct and
	// the manual twin was not, which is the shape this codebase keeps finding.
	meta.Name = h.EntryNamePlain(meta.Name)

	// newValue and oldValue are OPAQUE. They are the entry's secret, so they are
	// the same type a decrypted one is, and neither can be read, logged or sent
	// anywhere except through secretexit.Exit. Holding them as strings is what
	// used to make the delivery path's destination question invisible.
	var newValue secretexit.Plaintext
	var oldValue secretexit.Plaintext // current plaintext, needed by provider.Rotate()
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
	oldValue, decErr := h.OpenEntrySecret(entryRow.EncryptedValue, entryRow.Nonce,
		int(entryRow.EncryptionVersion.Int64), entryOrigin(id, meta.Name))
	if decErr != nil {
		logError(r, "vault.rotate: decrypt failed, refusing to rotate", "entry", id, "error", decErr)
		recordRotationFailure(ctx, h.queries, h, id, meta.Name, providerName,
			entryRow.RotationLog.String, rotFailDecrypt, rotationMethod, &userID)
		writeError(w, r, http.StatusConflict, "decrypt_failed",
			"this secret could not be decrypted, so it was not rotated; rotating would have overwritten a value that is still recoverable")
		return
	}

	// Declared out here so the deferred revoke after the value is persisted can
	// still reach it; the revoke must not run until the new value is stored.
	var providerMeta map[string]string
	// rotateCtx carries the exit receipt for the provider spend, so the deferred
	// revoke after the CAS runs under the same authorisation the Rotate call did.
	rotateCtx := ctx
	// Set if an EARLIER rotation's revoke was retried before this mint and failed
	// again; that predecessor is still live upstream, so it has to reach the
	// rotation outcome and not just a log line.
	var staleRevokeWarn string
	{
		if providerRoleFor == providerAuto {
			// A provider that destroys its predecessor IN PLACE (see
			// predecessorDestroysInPlace) has no recoverable CAS-conflict path yet:
			// by the time persistRotatedValue would run, the OLD value is already
			// dead at the provider, so a lost write is a credential that exists
			// nowhere, not the "both keys live, reload and retry" conflict this
			// handler otherwise reports. Refuse BEFORE calling provider.Rotate, so
			// nothing is ever minted that a CAS miss could then lose.
			if predecessorDestroysInPlace[providerName] {
				logError(r, "vault.rotate: refusing to auto-rotate a provider that destroys its "+
					"predecessor in place; no CAS-safe recovery exists yet",
					"entry", id, "provider", providerName)
				recordRotationFailure(ctx, h.queries, h, id, meta.Name, providerName,
					entryRow.RotationLog.String, rotFailDestroysInPlace, rotationMethod, &userID)
				writeError(w, r, http.StatusConflict, "destroys_in_place_unsupported",
					"this provider replaces the credential in place with no separable revoke step, "+
						"so a write conflict here could destroy it with no copy anywhere; rotate it in "+
						"the provider's own dashboard, then edit this entry and paste the new value. "+
						"Nothing was changed.")
				return
			}
			provider := resolvedProvider
			providerMeta = ParseProviderMeta(h.decryptColumnOrLog(entryRow.ProviderMeta.String, "{}", vaultFieldProviderMeta))
			// THE ONE EXIT, network form. The old value is released only if the
			// entry's OWN record authorises the provider hosts it is about to
			// authenticate against, and the returned context carries the receipt
			// providerDo checks when the request actually leaves.
			spendCtx, oldPlain, egressErr := spendProviderSecret(ctx, h.queries, oldValue,
				id, providerName, providerMeta)
			if egressErr != nil {
				logError(r, "vault.rotate: refusing to rotate through this provider configuration",
					"entry", id, "user", userID, "error", egressErr)
				writeError(w, r, http.StatusForbidden, "destination_pinned", egressErr.Error())
				return
			}
			rotateCtx = spendCtx

			// Consume any revoke left outstanding by an earlier rotation BEFORE
			// Rotate overwrites its coordinates. See
			// retryOutstandingRevokeBeforeMint.
			staleRevokeWarn = retryOutstandingRevokeBeforeMint(rotateCtx, providerMeta, meta.Name, providerName, oldValue)

			rotatedValue, rotErr := provider.Rotate(rotateCtx, oldPlain, providerMeta)
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
				// Routed through the SHARED recorder, not hand-rolled.
				//
				// This branch wrote last_rotation_error and rotation_log itself and
				// stopped there, so the most common manual rotation failure notified
				// nobody: no EventRotationFailed alert and no vault.rotation_failed
				// activity row, which is exactly what recordRotationFailure exists to
				// emit. The failure lived only in a column and the container log, and
				// for an on-demand entry (auto_rotate = 0) the sweep never re-attempts
				// it, so NO path ever alerted. An operator rotating a key they believe
				// is compromised was told only in a browser tab they may have closed.
				//
				// The sweep has always called recordRotationFailure for the identical
				// condition (rotFailProvider), so this also removes the duplicated
				// message and the drift between the two.
				logError(r, "vault.rotate: provider rotation failed", "provider", providerName, "entry", id, "error", rotErr)
				recordRotationFailure(ctx, h.queries, h, id, meta.Name, providerName,
					entryRow.RotationLog.String, rotFailProvider, rotationMethod, &userID)
				writeError(w, r, http.StatusBadGateway, "upstream_error",
					"the provider rejected the rotation; the stored secret was left unchanged")
				return
			}
			// The successor the provider handed back is as dangerous as a
			// decrypted one, so it re-enters the type immediately and leaves
			// again only through the exit.
			newValue = h.MintedEntrySecret([]byte(rotatedValue), id, meta.Name)
			// rotationMethod stays "manual".
			//
			// It used to be reassigned to "auto" here, so every user-clicked rotation
			// of a provider-backed entry was recorded as the scheduler's work: the
			// history row said "auto", and on the persist-failure path
			// recordRotationFailure's kind selector produced "Auto-rotation failed for
			// vault secret: X" while simultaneously attributing it to the acting user,
			// an internally contradictory audit row.
			//
			// "auto" versus "manual" answers WHO TRIGGERED THIS, which is the only
			// question an audit trail is asked about a secret. Whether a provider or
			// the local generator produced the value is a different question and is
			// already recorded in the Provider field.
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
	if newValue.IsZero() {
		switch providerRoleFor {
		case providerReminder:
			// Appended through the CAS writer, not over entryRow's snapshot: the
			// scheduled sweep can be mid-pass on this same entry.
			appendRotationLog(ctx, h.queries, id, h.decryptColumnOrLog(meta.Name, "", vaultFieldName), RotationLogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Status:    "reminder",
				Provider:  providerName,
				Method:    rotationMethod,
			})
			LogActivityFromRequest(h.queries, r, "vault.rotation_reminder",
				fmt.Sprintf("Rotation reminder for vault secret: %s (provider: %s cannot rotate automatically)", h.sealSecretName(r.Context(), meta.Name), providerName))
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
	if newValue.IsZero() {
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
		generated, gErr := generateToken(32)
		if gErr != nil {
			logError(r, "vault.rotate: failed to generate token", "error", gErr)
			writeInternalError(w, r, "failed to generate new secret")
			return
		}
		newValue = h.MintedEntrySecret([]byte(generated), id, meta.Name)
	}

	// Encrypt the new value. encryptEntrySecret is inside the type, so a
	// rotation never converts the value to bytes just to store it.
	encrypted, nonce, err := h.encryptEntrySecret(newValue)
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
		snapshotFromRotationRow(id, entryRow.UpdatedAtText, entryRow.EncryptedValue), encrypted, nonce)
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
		// dropping it silently.
		//
		// "The old key is still live" is true ONLY for a provider whose revoke is
		// DEFERRED past this CAS (deferRevokeOldProviderKey runs later, after a
		// successful persist) -- backblaze, resend, sendgrid, twilio, neon. For
		// those, both keys are live and reload-and-retry is genuinely recoverable.
		// A provider in predecessorDestroysInPlace (e.g. cloudflare) cannot reach
		// this branch at all: the providerAuto guard above refuses it before
		// provider.Rotate is ever called, specifically because for that provider
		// the old key is ALREADY dead by the time a mint would complete, so a lost
		// write here would strand the new value with no copy anywhere and no live
		// predecessor to fall back to.
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

	// THE ONE EXIT, caller form, for the value this response carries.
	//
	// Rotate returns the new plaintext so the operator can copy it, which is a
	// release of a secret to a principal and is therefore asked the same way
	// unlock is. A failure here does NOT unwind the rotation: the value is
	// already durably stored and the predecessor may already be revoked upstream,
	// so refusing the whole request would report a failure that did not happen
	// and leave the operator with a live key they were told was not minted.
	//
	// It withholds the value from the body AND SAYS SO IN THE BODY. The first cut
	// of this said so only in the server log, and shipped `{"value": ""}` with a
	// 200 and a success toast: the operator could not tell "we rotated and cannot
	// hand you the value" from "the new value is an empty string", on a
	// credential that has just been rolled at the provider. A response that
	// withholds something has to say it withheld it.
	_, rotatedForCaller, callerErr := secretexit.ExitString(ctx, newValue,
		secretexit.ToCaller("POST /api/vault/{id}/rotate", userID))
	valueWithheld := ""
	if callerErr != nil {
		logError(r, "vault.rotate: the rotated value was not released to the caller",
			"entry", id, "user", userID, "error", callerErr)
		rotatedForCaller = ""
		valueWithheld = "the secret was rotated and stored, but its value was not released to you: " +
			callerErr.Error()
	}

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
	//
	// Under the entry's egress authority, like the Rotate call itself: the
	// deferred revoke sends "Authorization: Bearer <the new secret>" to a method
	// and URL taken out of provider_meta, so it is the same question as every
	// other outbound call and it gets the same answer.
	deps := rotationDeps{queries: h.queries, vault: h}
	if warn := revokeOldKeyAndPersistMeta(ctx, deps, id, meta.Name, providerName,
		providerMeta, newValue); warn != "" {
		revokeWarn = warn
	}
	// A predecessor that could not be revoked on retry is still live upstream,
	// so it belongs in the rotation's own outcome rather than only in a log
	// line. This rotation's revoke warning wins when both fired, because it
	// names the key that was just replaced.
	if revokeWarn == "" {
		revokeWarn = staleRevokeWarn
	}

	// Record the rotation outcome. The TRUE status depends on whether each
	// configured target applied + verified the new key, so with targets we
	// finalise the rotation_log in the delivery goroutine below (the HTTP
	// response stays immediate). Without targets the rotation is complete now.
	// An undecryptable rotation_targets column is NOT "no targets".
	//
	// decryptColumnOrLog degrades to the fallback, so a column that failed to
	// decrypt produced "[]", which reads as "nothing configured": the rotation then
	// stored the new value, revoked the predecessor upstream, recorded status
	// "success" with last_rotation_error NULL and dispatched no alert, while the
	// configured webhooks and Actions secrets were never contacted and kept the key
	// that had just been destroyed. A live outage recorded as a clean rotation.
	//
	// "The column is empty" and "the column would not open" are opposite facts, so
	// they are distinguished here rather than at the read helper (which is correct
	// to degrade for the metadata fields it was written for).
	targetsUndecryptable := false
	rawTargets := "[]"
	if stored := entryRow.RotationTargets.String; stored != "" {
		if plain, tErr := h.decryptColumn(stored, vaultFieldRotationTargets); tErr != nil {
			targetsUndecryptable = true
			logError(r, "vault.rotate: rotation_targets did not decrypt; the new key cannot be delivered",
				"entry", id, "error", tErr)
		} else {
			rawTargets = plain
		}
	}
	targets := ParseRotationTargets(rawTargets)

	rec := rotationRecord{
		EntryID: id,
		// Opened, like the scheduled path does. This name goes into the activity
		// log, the alert email and the delivery payload the consuming service
		// receives; stored form would be an enc:v1: blob in all three.
		EntryName:   meta.Name, // already opened at the top of Rotate
		Provider:    providerName,
		Method:      rotationMethod,
		UserID:      userID,
		RotationLog: entryRow.RotationLog.String,
		Targets:     targets,
		OldValue:    oldValue,
		NewValue:    newValue,
		RevokeWarn:  revokeWarn,
	}
	if targetsUndecryptable {
		// The value IS rotated and the predecessor IS revoked, so this is a partial
		// rotation, not a failure to rotate. Say so, and alarm it: nobody received
		// the new key and the old one is already dead.
		rec.RevokeWarn = ""
		recordRotationOutcomeUndeliverable(ctx, deps, rec)
		LogActivityFromRequest(h.queries, r, "vault.rotated",
			fmt.Sprintf("Vault secret rotated but NOT delivered (%s/%s): %s (user: %s, rotation_targets unreadable)",
				rotationMethod, providerName, h.sealSecretName(r.Context(), meta.Name), userID))
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		// Re-read so the response carries the outcome we JUST recorded.
		//
		// This used to return the PRE-rotation snapshot, so last_rotation_error came
		// back empty even though "rotated but NOT delivered" had just been written to
		// it. The client then had nothing to render and showed a clean success, which
		// silently undid the whole point of recording a partial outcome. A fix that
		// writes the truth to the database and hands the caller a stale copy of it is
		// only half a fix.
		out := vaultEntryFull{
			vaultEntryMeta: h.vaultMetaFromGetRow(ctx, meta, userID),
			Value:          rotatedForCaller,
			ValueWithheld:  valueWithheld,
		}
		if fresh, fErr := h.queries.GetVaultEntryMeta(ctx, id); fErr == nil {
			out.vaultEntryMeta = h.vaultMetaFromGetRow(ctx, fresh, userID)
			out.Value = rotatedForCaller
			out.ValueWithheld = valueWithheld
		}
		writeJSON(w, http.StatusOK, out)
		return
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

	LogActivityFromRequest(h.queries, r, "vault.rotated", fmt.Sprintf("Vault secret rotated (%s/%s): %s (user: %s, targets: %d)", rotationMethod, providerName, h.sealSecretName(r.Context(), meta.Name), userID, len(targets)))

	// The response body is fetched LAST, and a failure here degrades it instead of
	// aborting.
	//
	// This read used to sit between the CAS and the outcome block, and its error
	// path returned 500 immediately. By that point the value was durably rotated
	// AND the predecessor key was already destroyed upstream, so the abort skipped
	// everything that records or acts on it: no rotation_log entry, no
	// last_rotation_error, no alert, no activity row, and no DeliverRotatedKey, so
	// every configured webhook and CI secret kept the key that had just been
	// revoked. The row reads "rotated seconds ago, no error" while its consumers are
	// dead. If the entry was deleted in the window (delete needs no re-auth), the
	// new plaintext is lost entirely and the successor key is stranded at the
	// provider with nothing left to revoke it.
	//
	// Nothing about this read is load-bearing: it exists to fill the response body,
	// and meta.Name (already in hand) is all the outcome recording needs. So the
	// order is now record-then-render, and if the render input is gone we still
	// return the new secret, which is the one thing the caller cannot obtain
	// anywhere else.
	entry := vaultEntryFull{}
	if row, fErr := h.queries.GetVaultEntryMeta(ctx, id); fErr == nil {
		entry.vaultEntryMeta = h.vaultMetaFromGetRow(ctx, row, userID)
	} else {
		logError(r, "vault.rotate: post-rotation fetch failed, returning the rotated value with "+
			"pre-rotation metadata", "entry", id, "error", fErr)
		entry.vaultEntryMeta = h.vaultMetaFromGetRow(ctx, meta, userID)
	}
	entry.Value = rotatedForCaller
	entry.ValueWithheld = valueWithheld

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, entry)
}

// Providers handles GET /api/vault/providers and returns available key providers.
func (h *VaultHandler) Providers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ListProviders())
}

// validateFailUnreachable is the ONE structural reason ValidateKey ever puts
// in the "error" field of its response.
//
// It replaces validErr.Error() for every failure of provider.Validate,
// regardless of cause, because provider.Validate's error is the RAW result of
// dialling a host the caller (up to and including a vault_only role) chose via
// their own entry's provider_meta. That error text tells apart:
//
//   - resolves to a private address: GuardedWebhookClient's dial control
//     returns "blocked outbound to private address <resolved-ip>:<port>",
//     naming the address it just resolved
//   - does not resolve at all: "no such host"
//   - resolves publicly but refuses or times out: "connection refused" vs
//     "i/o timeout"
//
// which is exactly the triage an internal-network prober wants: create an
// entry, point provider "forgejo" at provider_meta.instance, POST validate
// with your own password, read which of the three you got, adjust, repeat.
// Modelled on the rotFail* constants in vault_rotation_failure.go, which never
// let a rotation failure's raw error reach anything an operator's UI renders
// either. The real validErr still reaches slog, keyed by entry and user, so an
// operator debugging a real outage loses nothing.
const validateFailUnreachable = "the provider could not be reached"

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
		// Capacity is not a wrong password, and recordReauthFailure writes the SAME
		// login_attempts rows that reauthLocked counts, so counting it here is the
		// same lockout vector as on login. See capacityExhausted.
		if capacityExhausted(w, r, verifyErr, "vault.reauth") {
			return
		}
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

	plaintext, err := h.OpenEntrySecret(entryRow.EncryptedValue, entryRow.Nonce,
		int(entryRow.EncryptionVersion.Int64), entryOrigin(id, meta.Name))
	if err != nil {
		writeInternalError(w, r, "failed to decrypt secret")
		return
	}
	defer plaintext.Wipe()

	providerMeta := ParseProviderMeta(h.decryptColumnOrLog(meta.ProviderMeta.String, "{}", vaultFieldProviderMeta))
	// Validate AUTHENTICATES with the decrypted key against the provider, so it
	// is a live spend of the credential and the fastest of the three paths that
	// carry it off the box: no scheduler wait, no rotation, just the caller's own
	// password. Whoever holds this key may only ever send it to the hosts the
	// entry's OWN record authorises. THE ONE EXIT, network form.
	egressCtx, secret, egressErr := spendProviderSecret(ctx, h.queries, plaintext,
		id, meta.Provider.String, providerMeta)
	if egressErr != nil {
		logError(r, "vault.validate: refusing to spend the secret against this provider configuration",
			"entry", id, "user", userID, "error", egressErr)
		writeError(w, r, http.StatusForbidden, "destination_pinned", egressErr.Error())
		return
	}
	valid, validErr := provider.Validate(egressCtx, secret, providerMeta)

	result := map[string]any{
		"valid":    valid,
		"provider": meta.Provider.String,
	}
	if validErr != nil {
		// STRUCTURAL REASON ONLY. validErr can be GuardedWebhookClient's dial-time
		// SSRF block ("blocked outbound to private address 10.0.1.42:8500", which
		// names the RESOLVED address), a DNS failure ("no such host"), or a refused
		// or timed-out TCP connect, and those three read differently on purpose:
		// resolves-and-is-private vs does-not-resolve vs resolves-and-is-refused is
		// exactly the triage an internal-network prober wants. Any authenticated
		// caller, including the vault_only role the public invite-redeem endpoint
		// hands out, may create their own entry with an attacker-chosen provider
		// host (forgejo's/zitadel's "instance" is a whole URL) and read this field
		// back, which turns the vault into a port-scanning, DNS-resolving oracle
		// for the server's own network.
		//
		// The rotFail* constants in vault_rotation_failure.go are the model: what
		// gets PERSISTED never carries validErr.Error(), only a fixed structural
		// reason, with the real error going to slog. This is the same discipline
		// applied to what gets RETURNED, which had never had it: rotate and the
		// scheduler both call recordRotationFailure and never leak, but validate
		// wrote the raw error straight into the response body.
		logError(r, "vault.validate: provider validation failed", "entry", id, "user", userID,
			"provider", meta.Provider.String, "error", validErr)
		result["error"] = validateFailUnreachable
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
	targets := ParseRotationTargets(h.decryptColumnOrLog(raw.String, "[]", vaultFieldRotationTargets))
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
		if _, decErr := h.decryptColumn(existingTargets, vaultFieldRotationTargets); decErr != nil {
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
		if prior := ParseRotationTargets(h.decryptColumnOrLog(existingTargets, "[]", vaultFieldRotationTargets)); len(prior) > 0 &&
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

	stored := ParseRotationTargets(h.decryptColumnOrLog(existingTargets, "[]", vaultFieldRotationTargets))
	priorBy := make(map[string]string, len(stored))
	for _, t := range stored {
		if t.ConfiguredBy != "" {
			priorBy[rotationTargetAttribution(t)] = t.ConfiguredBy
		}
	}
	for i := range targets {
		if who, ok := priorBy[rotationTargetAttribution(targets[i])]; ok {
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

	// THE AUTH_TOKEN QUESTION, ASKED AT THE WRITE BECAUSE THE EXIT ASKS IT AT
	// DELIVERY.
	//
	// A forgejo_secret target names ANOTHER vault entry in auth_token and spends
	// its secret as the bearer of this delivery. The exit asks whether the
	// configurer may choose where THAT entry's secret goes; this validator never
	// looked at auth_token at all. So the ordinary team configuration (Alice
	// wires her entry's rotation to Forgejo using the collection's shared CI
	// token, which Bob owns) was accepted, reported as saved, shown as a live
	// target, and then dropped at the next rotation: weeks later, unattended,
	// right after the credential was rolled at the provider.
	//
	// Round 5 named that shape as the worst of the three possible behaviours and
	// fixed it once, for the admin case. This is the same defect with the
	// argument changed. checkAuthTokenAuthority is the ONE implementation, and
	// the boot audit calls the same function, so the two halves cannot drift.
	for _, t := range targets {
		if refusal := h.checkAuthTokenAuthority(r.Context(), t); !refusal.empty() {
			logError(r, "vault.targets: refused a target whose auth_token its configurer may not spend",
				"entry", id, "user", userID, "auth_token", refusal.AuthToken)
			writeError(w, r, http.StatusForbidden, "auth_token_not_yours", refusal.Reason)
			return
		}
	}

	// The provider pin. A rotation target is a DELIVERY
	// destination: deliverToWebhook POSTs {"new_value": <the secret>} to a URL
	// the caller names. So an entry wired as the instance's AI provider key must
	// not carry one, or "the operator's key only ever goes to the provider"
	// would hold at /proxy and fail here, which is precisely the two-doors
	// pattern this audit stream keeps re-finding. Refused at the write AND at
	// delivery (DeliverRotatedKey), so a row planted by anything else is refused
	// too.
	pin, pinErr := providerPinFor(r.Context(), h.queries, id)
	if pinErr != nil {
		logError(r, "vault.targets: could not read the entry's provider pin", "entry", id, "error", pinErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	if pin.pinned() {
		for _, t := range targets {
			if !targetTransmitsSecret(t) {
				continue
			}
			logError(r, "vault.targets: refused a delivery target on the instance's AI provider key",
				"entry", id, "user", userID, "type", t.Type)
			writeError(w, r, http.StatusForbidden, "destination_pinned",
				fmt.Sprintf("this secret is the instance's AI provider key (%s); it is only ever sent to the provider, "+
					"so it cannot have a %s delivery target. Unwire it in Settings > AI gateway first",
					pin.describe(), t.Type))
			return
		}
	}

	// MAY THIS CALLER REDIRECT THIS SECRET? The round-5 blocker, in one call.
	//
	// A delivery target is a destination. deliverToWebhook POSTs
	// {"new_value": <the freshly minted plaintext>} to a URL the caller named,
	// which is the same act as pointing the capability proxy at a host the caller
	// named, and until now the two were held to different rights on the same
	// entry: PUT /api/vault/{id} refused an accepted editor with 403
	// egress_widening_denied, while PUT /api/vault/{id}/targets took whatever
	// they sent. A vault_only account (the role the PUBLIC invite-redeem endpoint
	// hands out) holding an EDITOR seat on somebody else's shared entry used the
	// second door and the scheduler delivered the credential.
	//
	// Same question, same answer, one implementation: egressgate.Decide asks
	// mayDirectSecretEgress exactly when the write ADDS a destination, and hands
	// back the ticket setEntryRotationTargets demands.
	//
	// NARROWING IS STILL OPEN TO ANYONE WITH MANAGE. Removing a target, clearing
	// the list, renaming a label, rotating a webhook's HMAC secret and re-saving
	// the panel unchanged all add nothing and never reach the oracle. So the
	// revocation lever an operator needs in a hurry is not behind the stricter
	// right, and neither is configuring a "notify" target, which transmits no
	// value at all.
	//
	// THIS CHANGES A PREMISE FOUR OTHER GUARDS WERE WRITTEN AGAINST, deliberately.
	// leave-purge, the stale-panel version check, ConfiguredBy stamping and the
	// target read gate were all built on "a member with manage may configure
	// delivery, safely, by attribution". The safety-by-attribution machinery is
	// unchanged and still load-bearing (an admin or the creator can also be
	// offboarded, and notify targets are still configured by editors); what
	// changed is that attribution is no longer the ONLY thing standing between an
	// editor and the plaintext. See DEFERRED (i).
	tk, egErr := h.decideDeliveryEgress(r.Context(), userID, id, stored, targets)
	if egErr != nil {
		var denied *egressgate.DeniedError
		if errors.As(egErr, &denied) {
			hosts := deliveryDestinationHosts(denied.Added)
			logError(r, "vault.targets: refused an egress widening",
				"entry", id, "user", userID, "added", hosts)
			writeError(w, r, http.StatusForbidden, "egress_widening_denied",
				fmt.Sprintf("you can remove or narrow this secret's delivery targets, but adding one that "+
					"sends it to %v takes the secret's owner or an instance admin. Editing an entry does "+
					"not carry the right to choose where its value is delivered", hosts))
			return
		}
		logError(r, "vault.targets: egress decision failed", "entry", id, "error", egErr)
		writeInternalError(w, r, "internal server error")
		return
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
	if err := vaultegress.SetRotationTargets(r.Context(), h.queries, tk, vaultegress.RotationTargetsParams{
		RotationTargets: toNullString(encTargets),
		ID:              id,
	}); err != nil {
		logError(r, "vault.updateTargets: persist failed", "entry", id, "error", err)
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

	// This route carries the STORED provider and provider_meta forward verbatim
	// and changes only auto_rotate, so it moves the reachable host set nowhere.
	// Deriving both sides from the SAME loaded row rather than passing a
	// "trust me, nothing changed" flag is the point: if a future edit ever puts
	// a caller-supplied provider into this request body, the two sides stop
	// matching and the ticket is refused instead of silently reopening round 4
	// through a door nobody is watching.
	scheduleMeta := ParseProviderMeta(h.decryptColumnOrLog(current.ProviderMeta.String, "{}", vaultFieldProviderMeta))
	scheduleTicket, schedTkErr := egressgate.Decide(egressgate.Request{
		EntryID: id,
		What:    egressFieldProvider,
		Before:  providerDestinations(current.Provider.String, scheduleMeta),
		After:   providerDestinations(current.Provider.String, scheduleMeta),
		Covers:  providerDestinationCovers,
		MayRedirect: func() bool {
			return h.mayDirectSecretEgress(ctx, middleware.GetUserID(ctx), middleware.IsAdmin(ctx), id)
		},
	})
	if schedTkErr != nil {
		logError(r, "vault.schedule: egress decision failed", "entry", id, "error", schedTkErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	if err := vaultegress.SetProvider(ctx, h.queries, scheduleTicket, vaultegress.ProviderParams{
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

	writeJSON(w, http.StatusOK, h.vaultMetaFromGetRow(ctx, row, middleware.GetUserID(ctx)))
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

	// One query per candidate index (see urlBlindIndexCandidates): normally one,
	// two while a master-key rotation is in flight. appendRow dedupes, so an entry
	// whose index has already been converted cannot appear twice.
	for _, personalBidx := range h.urlBlindIndexCandidates(bidxScope(userID, sql.NullString{}), rawURL) {
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
		for _, cb := range h.urlBlindIndexCandidates(bidxScope("", sql.NullString{String: c.ID, Valid: true}), rawURL) {
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
	}

	writeJSON(w, http.StatusOK, entries)
}

// vaultRefPattern matches {{vault:SECRET_NAME}} references in content.
var vaultRefPattern = regexp.MustCompile(`\{\{vault:([^}]+)\}\}`)

// ResolveReferences takes a string and replaces all {{vault:NAME}} references
// with their decrypted values from the specified user's vault. If a secret is not
// found, or the destination is not authorised by the secret's owner, the
// reference is left as-is and a warning is logged.
//
// THE dest ARGUMENT IS NOT DECORATION. This function renders a secret into
// arbitrary text, which is the most dangerous shape in this codebase: the string
// it returns can be a URL, a request body, a log line or an email. Before round 7
// it took no destination at all, and it has no production caller, so it was a
// fully-formed exfiltration primitive sitting in the tree waiting for its first
// one. Requiring a destination means the first caller has to answer the owner
// question in the same commit that adds it.
func (h *VaultHandler) ResolveReferences(ctx context.Context, content, userID string,
	dest secretexit.Destination) string {

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
		decrypted, err := h.resolveVaultReferenceFor(ctx, name, userID)
		if err != nil {
			slog.Warn("vault.resolveReferences: secret not resolvable for this user",
				"name", name, "user_id", userID, "error", err)
			return match
		}
		defer decrypted.Wipe()

		_, value, exitErr := secretexit.ExitString(ctx, decrypted, dest)
		if exitErr != nil {
			slog.Warn("vault.resolveReferences: the secret's owner did not authorise this destination",
				"name", name, "user_id", userID, "error", exitErr)
			return match
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

// entryIDLookalike matches the shape vault_entries.id is generated in:
// lower(hex(randomblob(16))), so exactly 32 lowercase hex characters.
var entryIDLookalike = regexp.MustCompile(`[0-9a-f]{32}`)

// scrubEntryIDLookalikes removes entry-id-shaped tokens from caller-supplied
// text before it is written into an activity detail that a migration reads by
// containment.
//
// It is deliberately blunt. A name that legitimately contains 32 hex characters
// loses them from ONE audit line and keeps them everywhere else; a name that
// contains them on purpose loses its ability to speak for another entry. The
// asymmetry is the point, and it is the same reason the ownership claim stopped
// rendering the previous holder's bytes at all.
func scrubEntryIDLookalikes(s string) string {
	return entryIDLookalike.ReplaceAllString(s, "[redacted-id-shaped]")
}

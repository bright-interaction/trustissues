package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
)

// VaultImportHandler handles password manager imports to the vault.
type VaultImportHandler struct {
	db      *sql.DB
	handler *VaultHandler
}

// NewVaultImportHandler creates a new vault import handler.
func NewVaultImportHandler(dbConn *sql.DB, vaultHandler *VaultHandler) *VaultImportHandler {
	return &VaultImportHandler{
		db:      dbConn,
		handler: vaultHandler,
	}
}

// PasswordManagerFormat represents supported password manager formats
type PasswordManagerFormat string

const (
	Format1Password PasswordManagerFormat = "1password"
	FormatBitwarden PasswordManagerFormat = "bitwarden"
	FormatLastPass  PasswordManagerFormat = "lastpass"
	FormatUnknown   PasswordManagerFormat = "unknown"
)

// ImportEntry represents a single entry to be imported
type ImportEntry struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Value    string `json:"value"`
	Category string `json:"category,omitempty"`
	Notes    string `json:"notes,omitempty"`
	Skip     bool   `json:"skip,omitempty"` // for conflict resolution
	// CustomFields carries everything the source export held that has no
	// dedicated column: Bitwarden's `fields` and `login_totp`, LastPass's
	// `totp`, 1Password's one-time-password column.
	//
	// These used to be dropped server-side with no log line and no entry in
	// `skipped`, because `skipped` reports dropped ROWS and these rows import
	// fine. So a 240-entry Bitwarden migration reported plain success while
	// every 2FA seed and every recovery PIN was discarded, and the documented
	// responsible next step after an import is deleting the plaintext export.
	// custom_fields has existed since migration 00025 and its own comment cites
	// "a recovery PIN, a second token" as the use case, so the destination was
	// already there.
	CustomFields []CustomField `json:"custom_fields,omitempty"`
}

// importedCustomFields builds the custom-field set for one imported row from
// the columns the source format carries but Trustissues has no column for.
// Bitwarden emits `fields` as newline-separated "label: value" pairs.
func importedCustomFields(extra, totp string) []CustomField {
	var out []CustomField
	for _, line := range strings.Split(extra, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		label, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		label, value = strings.TrimSpace(label), strings.TrimSpace(value)
		if label == "" || value == "" {
			continue
		}
		out = append(out, CustomField{Label: label, Value: value, Secret: false})
	}
	if t := strings.TrimSpace(totp); t != "" {
		// secret:true so the UI masks it: a TOTP seed is a credential.
		out = append(out, CustomField{Label: "TOTP", Value: t, Secret: true})
	}
	return out
}

// maxImportEntries caps one import batch.
//
// ImportConfirm holds SQLite's single write lock for the whole batch, so this
// is really a cap on how long every other writer in the instance is blocked.
// 5,000 entries is far above any real password-manager export and far below the
// ~200k a 10 MB body of minimal CSV rows can carry.
const maxImportEntries = 5000

// VaultImportPreview represents the preview of what will be imported
type VaultImportPreview struct {
	Format    string        `json:"format"`
	Entries   []ImportEntry `json:"entries"`
	Conflicts []string      `json:"conflicts"`
	Total     int           `json:"total"`
	// Skipped names the rows the parser could not turn into entries, and
	// SourceRows is the count BEFORE those drops.
	//
	// Total is len(entries), which is the post-drop number, so on its own it can
	// never reveal that anything went missing: an export of 500 items with 120
	// secure notes previewed as "500 rows -> 380 entries" indistinguishably from
	// a clean export of 380. Reporting both numbers is what makes the loss
	// visible at the only moment the operator can still act on it.
	Skipped    []skippedEntry `json:"skipped"`
	SourceRows int            `json:"source_rows"`
}

// detectFormat attempts to detect the password manager format from CSV headers
func detectFormat(headers []string) PasswordManagerFormat {
	headersStr := strings.ToLower(strings.Join(headers, ","))

	// Check for 1Password format
	if containsAll(headersStr, []string{"title", "website", "username", "password"}) {
		return Format1Password
	}

	// Check for Bitwarden format
	if containsAll(headersStr, []string{"folder", "type", "name", "notes", "login_uri", "login_username", "login_password"}) {
		return FormatBitwarden
	}

	// Check for LastPass format
	if containsAll(headersStr, []string{"url", "username", "password", "name"}) {
		return FormatLastPass
	}

	return FormatUnknown
}

// containsAll checks if the string contains all required substrings
func containsAll(s string, required []string) bool {
	s = strings.ToLower(s)
	for _, r := range required {
		if !strings.Contains(s, r) {
			return false
		}
	}
	return true
}

// parseCSV parses a CSV file and returns import entries
func (h *VaultImportHandler) parseCSV(reader io.Reader, format PasswordManagerFormat) ([]ImportEntry, []skippedEntry, error) {
	csvReader := csv.NewReader(reader)
	headers, err := csvReader.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CSV headers: %w", err)
	}

	var entries []ImportEntry
	skipped := []skippedEntry{}
	lineNum := 1

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("error reading CSV line %d: %w", lineNum, err)
		}

		if len(record) != len(headers) {
			return nil, nil, fmt.Errorf("mismatched column count at line %d", lineNum)
		}

		entry, reason := parseRecordByFormat(headers, record, format)
		switch {
		case entry != nil:
			entries = append(entries, *entry)
		case reason != "":
			// A dropped row is reported, never swallowed.
			//
			// This discarded every nil silently, and Total is len(entries), the
			// POST-drop count, so a Bitwarden export of 500 items where 120 are
			// secure notes, cards or identities previewed as 380 with nothing
			// naming the missing 120, imported 380, and showed a plain success
			// toast. A secure note carries its content in the notes field, so
			// those are secrets the operator believed they had migrated.
			name := rowLabel(headers, record)
			skipped = append(skipped, skippedEntry{Name: name, Reason: reason})
		}
		lineNum++
	}

	return entries, skipped, nil
}

// importSkipReason explains why a row with no name or no value was dropped.
//
// The reason has to match the branch actually taken. One message covered both
// causes ("no password value in the export row (secure notes, cards and
// identities have none)"), so a row that HAD a good password and merely lacked
// a name was explained to the operator as a secure note. That sends them
// looking in the wrong place in their export for the one problem they could
// have fixed in a minute.
func importSkipReason(entry ImportEntry) string {
	switch {
	case entry.Name == "" && entry.Value == "":
		return "the export row has neither a name nor a password value"
	case entry.Name == "":
		return "no name in the export row, so there is nothing to file it under"
	default:
		return "no password value in the export row (secure notes, cards and identities have none)"
	}
}

// rowLabel picks the most name-like column available so a reported skip points
// at something the operator can find in their export.
func rowLabel(headers, record []string) string {
	for _, want := range []string{"name", "title", "account"} {
		for i, h := range headers {
			if strings.ToLower(strings.TrimSpace(h)) == want && i < len(record) {
				if v := strings.TrimSpace(record[i]); v != "" {
					return v
				}
			}
		}
	}
	return "(unnamed row)"
}

// parseRecordByFormat parses a CSV record based on the detected format.
//
// Returns (entry, "") when the row becomes an entry, and (nil, reason) when it
// is dropped. The reason is not decoration: a dropped row used to vanish here
// with nothing recording it, and every count downstream is computed AFTER the
// drop, so nothing anywhere could tell the operator that part of their export
// did not arrive.
func parseRecordByFormat(headers []string, record []string, format PasswordManagerFormat) (*ImportEntry, string) {
	// Create a map for easier field access
	fields := make(map[string]string)
	for i, header := range headers {
		fields[strings.ToLower(strings.TrimSpace(header))] = strings.TrimSpace(record[i])
	}

	switch format {
	case Format1Password:
		return &ImportEntry{
			Name:     getFirstField(fields, []string{"title", "name"}),
			URL:      getFirstField(fields, []string{"website", "url"}),
			Username: fields["username"],
			Value:    fields["password"],
			Category: fields["categories"],
			Notes:    fields["notes"],
			CustomFields: importedCustomFields("",
				getFirstField(fields, []string{"otpauth", "one-time password", "one_time_password", "totp"})),
		}, ""

	case FormatBitwarden:
		if fields["type"] != "login" {
			// Secure notes, cards and identities have no password, so they
			// cannot become vault entries. Reporting them is the point: a
			// secure note keeps its content in the notes field, so these are
			// secrets the operator believes they are migrating.
			kind := fields["type"]
			if kind == "" {
				kind = "unknown"
			}
			return nil, "Bitwarden item of type \"" + kind + "\" has no password, so it cannot become a vault entry"
		}
		return &ImportEntry{
			Name:         fields["name"],
			URL:          getFirstField(fields, []string{"login_uri", "uri"}),
			Username:     fields["login_username"],
			Value:        fields["login_password"],
			Notes:        fields["notes"],
			CustomFields: importedCustomFields(fields["fields"], fields["login_totp"]),
		}, ""

	case FormatLastPass:
		return &ImportEntry{
			Name:         getFirstField(fields, []string{"name", "title"}),
			URL:          fields["url"],
			Username:     fields["username"],
			Value:        fields["password"],
			Notes:        fields["extra"],
			CustomFields: importedCustomFields("", fields["totp"]),
		}, ""
	}

	return nil, "the export format could not be recognised for this row"
}

// getFirstField returns the first non-empty field from the list
func getFirstField(fields map[string]string, keys []string) string {
	for _, key := range keys {
		if val := fields[key]; val != "" {
			return val
		}
	}
	return ""
}

// checkConflicts checks for existing entries with the same name
func (h *VaultImportHandler) checkConflicts(ctx context.Context, userID string, entries []ImportEntry) []string {
	var conflicts []string
	existing := make(map[string]bool)

	// Get existing entry names for this user
	names, err := h.handler.queries.ListVaultEntryNamesByUser(ctx, userID)
	if err != nil {
		slog.Error("failed to check existing entries", "error", err)
		return conflicts
	}
	// Stored names are ciphertext since 00040, so the map is built from the
	// DECRYPTED name. Comparing the import's cleartext against ciphertext would
	// find no conflict ever, and the import would then hit the unique index and
	// fail row by row instead of reporting the clash up front.
	for _, name := range names {
		existing[h.handler.decryptColumnOrLog(name, "", vaultFieldName)] = true
	}

	// Check for conflicts
	for _, entry := range entries {
		if existing[entry.Name] {
			conflicts = append(conflicts, entry.Name)
		}
	}

	return conflicts
}

// ImportPreview handles POST /api/vault/import/preview
// Returns a preview of what will be imported without actually importing.
// The entries in the response (values included) are round-tripped by the
// client into ImportConfirm after conflict resolution, so values are NOT
// masked here (the client already holds the raw CSV anyway, and masking
// would corrupt the confirm payload).
func (h *VaultImportHandler) ImportPreview(w http.ResponseWriter, r *http.Request) {
	// Verify user is authenticated
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "unauthorized")
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeBadRequest(w, r, "file too large")
		return
	}

	// Get uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		writeBadRequest(w, r, "no file uploaded")
		return
	}
	defer file.Close()

	// Validate file type
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".csv") {
		writeBadRequest(w, r, "only CSV files are supported")
		return
	}

	// Read first few rows to detect format
	limitedReader := io.LimitReader(file, 1024*1024) // Read max 1MB
	csvReader := csv.NewReader(limitedReader)
	headers, err := csvReader.Read()
	if err != nil {
		writeBadRequest(w, r, "invalid CSV format")
		return
	}

	// Honour the operator's choice; auto-detect only when they left it on Auto.
	//
	// The modal has shipped a four-option selector (auto / 1password / bitwarden
	// / lastpass) whose value was posted as a multipart field that no handler
	// ever read, so detectFormat always won and a misdetection could not be
	// corrected. A rendered control that changes nothing is a broken feature,
	// not a preference.
	format := detectFormat(headers)
	if chosen := strings.ToLower(strings.TrimSpace(r.FormValue("format"))); chosen != "" && chosen != "auto" {
		switch chosen {
		case string(Format1Password), string(FormatBitwarden), string(FormatLastPass):
			format = PasswordManagerFormat(chosen)
		default:
			writeBadRequest(w, r, "unknown import format: "+chosen)
			return
		}
	}
	if format == FormatUnknown {
		writeBadRequest(w, r, "unsupported format")
		return
	}

	// Reset file pointer to read full file
	if _, err := file.Seek(0, 0); err != nil {
		writeInternalError(w, r, "failed to read file")
		return
	}

	// Parse full CSV
	entries, skipped, err := h.parseCSV(file, format)
	if err != nil {
		logError(r, "failed to parse CSV", "error", err)
		writeBadRequest(w, r, "failed to parse CSV")
		return
	}

	// Refuse a batch too large to import in one transaction.
	//
	// ImportConfirm runs the WHOLE batch inside one BEGIN IMMEDIATE, which takes
	// the single write lock for the duration. There was no cap on entry count,
	// only a 10 MB body limit, and 10 MB of minimal CSV rows is on the order of
	// 200k entries, each doing an encrypt plus an insert. Every other writer in
	// the instance (a login touching sessions, the rotation sweep, any edit)
	// blocks on that lock and gives up at the 5s busy timeout, so one import
	// stalls the product. Refusing at preview is the honest place: the operator
	// finds out before committing, not halfway through.
	if len(entries) > maxImportEntries {
		writeBadRequest(w, r, fmt.Sprintf(
			"this export has %d entries, which is over the %d limit for a single import. "+
				"Split the file and import it in parts.", len(entries), maxImportEntries))
		return
	}

	// Check for conflicts
	conflicts := h.checkConflicts(r.Context(), userID, entries)

	// Return preview
	preview := VaultImportPreview{
		Format:     string(format),
		Entries:    entries,
		Conflicts:  conflicts,
		Total:      len(entries),
		Skipped:    skipped,
		SourceRows: len(entries) + len(skipped),
	}

	writeJSON(w, http.StatusOK, preview)
}

// ImportConfirm handles POST /api/vault/import/confirm
// Actually imports the entries after user confirmation.
func (h *VaultImportHandler) ImportConfirm(w http.ResponseWriter, r *http.Request) {
	// Verify user is authenticated
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "unauthorized")
		return
	}

	// Parse request
	var req struct {
		Entries []ImportEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}

	if len(req.Entries) == 0 {
		writeBadRequest(w, r, "no entries to import")
		return
	}
	// The cap is enforced HERE too, not only at preview.
	//
	// Confirm takes its entries from the request body, not from the preview, so
	// a caller can post any batch it likes without ever calling preview. A limit
	// checked only on the advisory path is not a limit.
	if len(req.Entries) > maxImportEntries {
		writeBadRequest(w, r, fmt.Sprintf(
			"%d entries is over the %d limit for a single import; split the file and import it in parts",
			len(req.Entries), maxImportEntries))
		return
	}

	// Import entries in a transaction
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		logError(r, "failed to begin transaction", "error", err)
		writeInternalError(w, r, "database error")
		return
	}
	defer tx.Rollback()

	qtx := h.handler.queries.WithTx(tx)

	// Entries the import could not create. They used to be dropped with only a
	// slog line, while the response reported just `imported` and the UI showed a
	// success toast: a 200-entry export with 12 duplicate titles silently became
	// 188 entries and the user had no way to know which 12 were missing until
	// they needed one. Every drop is now named and returned.
	imported := 0
	skipped := []skippedEntry{}
	for _, entry := range req.Entries {
		// entry.Skip is a user decision made in the conflict step, so it is the
		// only silent drop. Name/Value being empty is NOT a user decision: it is
		// how Bitwarden secure notes, cards and identities, and LastPass secure
		// notes, come out of an export. Those rows were discarded here with no
		// slog line and no entry in `skipped`, so a 500-item export could import
		// 380 and still show a plain success toast. That is the exact failure the
		// duplicate-title reporting was added for; it was only ever closed for
		// the UNIQUE-constraint branch, and this guard sat two lines above it.
		if entry.Skip {
			continue
		}
		if entry.Name == "" || entry.Value == "" {
			name := entry.Name
			if name == "" {
				name = "(unnamed row)"
			}
			skipped = append(skipped, skippedEntry{Name: name, Reason: importSkipReason(entry)})
			continue
		}

		// Same field rules as Create and Update.
		//
		// Import applied none of them, so a legitimate CSV could write a row the
		// edit form could never save again (Update re-validates on every save and
		// the form resubmits every field), and an untrimmed name defeated both
		// checkConflicts and UNIQUE(user_id, name). Reported as a skip rather
		// than failing the batch: one bad row out of 400 should not cost the
		// other 399, and the operator now gets told which one and why.
		fields := vaultEntryFields{
			Name: entry.Name, Value: entry.Value, URL: entry.URL,
			Username: entry.Username, Notes: entry.Notes,
		}
		if msg := normalizeAndValidateEntryFields(&fields); msg != "" {
			skipped = append(skipped, skippedEntry{Name: entry.Name, Reason: msg})
			continue
		}
		entry.Name, entry.URL, entry.Username = fields.Name, fields.URL, fields.Username

		// Encrypt the value
		encrypted, nonce, err := h.handler.encrypt([]byte(entry.Value))
		if err != nil {
			slog.Error("failed to encrypt entry", "name", entry.Name, "error", err)
			skipped = append(skipped, skippedEntry{Name: entry.Name, Reason: "could not be encrypted"})
			continue
		}

		// Determine category (enforce allowlist)
		category := entry.Category
		validCategories := map[string]bool{"password": true, "ssh_key": true, "api_key": true, "certificate": true, "login": true, "other": true}
		if !validCategories[category] {
			category = "password"
		}

		// Generate a random ID
		idBytes := make([]byte, 16)
		if _, err := rand.Read(idBytes); err != nil {
			slog.Error("failed to generate ID", "error", err)
			skipped = append(skipped, skippedEntry{Name: entry.Name, Reason: "could not generate an entry id"})
			continue
		}
		entryID := fmt.Sprintf("%x", idBytes)

		// Encrypt the free-text metadata at rest and compute the URL blind index,
		// exactly as Create does, so imported rows are never stored in cleartext.
		// (Imports carry no alias_url, so that column is left empty.)
		encURL, _, encUser, encCat, encNotes, encErr := h.handler.encryptMetaColumns(entry.URL, "", entry.Username, category, entry.Notes)
		if encErr != nil {
			slog.Error("failed to encrypt entry metadata", "name", entry.Name, "error", encErr)
			skipped = append(skipped, skippedEntry{Name: entry.Name, Reason: "could not be encrypted"})
			continue
		}

		err = qtx.ImportVaultEntry(r.Context(), db.ImportVaultEntryParams{
			ID:     entryID,
			UserID: userID,
			// The importer is the entry's owner for exit purposes, the same way
			// the creator of a hand-entered secret is. Left at the '' default the
			// row would have no owner at all and nobody could configure delivery
			// for anything they imported.
			SecretOwnerUserID: userID,
			Name:              entry.Name,
			EncryptedValue:    encrypted,
			Nonce:             nonce,
			Url:               toNullString(encURL),
			Username:          toNullString(encUser),
			Category:          toNullString(encCat),
			Notes:             toNullString(encNotes),
			// Imported entries land in the user's PERSONAL vault, so the blind
			// index is keyed to that scope.
			UrlBidx: h.handler.urlBlindIndex(bidxScope(userID, sql.NullString{}), entry.URL),
		})
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				slog.Warn("skipping duplicate entry", "name", entry.Name)
				skipped = append(skipped, skippedEntry{
					Name:   entry.Name,
					Reason: "a secret with this name already exists (names are unique per user)",
				})
				continue
			}
			slog.Error("failed to insert entry", "name", entry.Name, "error", err)
			skipped = append(skipped, skippedEntry{Name: entry.Name, Reason: "could not be saved (details in server logs)"})
			continue
		}

		// Persist the fields the source export carried that have no dedicated
		// column (Bitwarden `fields` / `login_totp`, LastPass `totp`, 1Password
		// OTP). Encrypted at rest exactly like an interactively added one.
		if len(entry.CustomFields) > 0 {
			if cfErr := validateCustomFields(entry.CustomFields); cfErr != nil {
				slog.Warn("import: dropping invalid custom fields", "name", entry.Name, "error", cfErr)
				skipped = append(skipped, skippedEntry{
					Name:   entry.Name,
					Reason: "imported, but its extra fields were rejected: " + cfErr.Error(),
				})
			} else if encCF, encErr := h.handler.encryptCustomFields(entry.CustomFields); encErr != nil {
				slog.Error("import: could not encrypt custom fields", "name", entry.Name, "error", encErr)
				skipped = append(skipped, skippedEntry{
					Name:   entry.Name,
					Reason: "imported, but its extra fields could not be encrypted and were not saved",
				})
			} else if cfErr := qtx.UpdateVaultEntryCustomFields(r.Context(), db.UpdateVaultEntryCustomFieldsParams{
				CustomFields: encCF, ID: entryID,
			}); cfErr != nil {
				slog.Error("import: could not save custom fields", "name", entry.Name, "error", cfErr)
				skipped = append(skipped, skippedEntry{
					Name:   entry.Name,
					Reason: "imported, but its extra fields could not be saved",
				})
			}
		}

		imported++
	}

	if err := tx.Commit(); err != nil {
		logError(r, "failed to commit transaction", "error", err)
		writeInternalError(w, r, "failed to import entries")
		return
	}

	// Log activity
	detail := fmt.Sprintf("Imported %d vault entries", imported)
	if len(skipped) > 0 {
		detail = fmt.Sprintf("Imported %d vault entries, skipped %d", imported, len(skipped))
	}
	LogActivityFromRequest(h.handler.queries, r, "vault.imported", detail)

	writeJSON(w, http.StatusOK, map[string]any{
		"skipped":  skipped,
		"imported": imported,
		"total":    len(req.Entries),
	})
}

// skippedEntry names one entry the import could not create, and why. Returned
// to the caller so a partial import is visible rather than silently partial.
type skippedEntry struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

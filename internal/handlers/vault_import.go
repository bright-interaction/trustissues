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

	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
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
}

// VaultImportPreview represents the preview of what will be imported
type VaultImportPreview struct {
	Format    string        `json:"format"`
	Entries   []ImportEntry `json:"entries"`
	Conflicts []string      `json:"conflicts"`
	Total     int           `json:"total"`
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
func (h *VaultImportHandler) parseCSV(reader io.Reader, format PasswordManagerFormat) ([]ImportEntry, error) {
	csvReader := csv.NewReader(reader)
	headers, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV headers: %w", err)
	}

	var entries []ImportEntry
	lineNum := 1

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV line %d: %w", lineNum, err)
		}

		if len(record) != len(headers) {
			return nil, fmt.Errorf("mismatched column count at line %d", lineNum)
		}

		entry := parseRecordByFormat(headers, record, format)
		if entry != nil {
			entries = append(entries, *entry)
		}
		lineNum++
	}

	return entries, nil
}

// parseRecordByFormat parses a CSV record based on the detected format
func parseRecordByFormat(headers []string, record []string, format PasswordManagerFormat) *ImportEntry {
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
		}

	case FormatBitwarden:
		if fields["type"] != "login" {
			return nil // Skip non-login items
		}
		return &ImportEntry{
			Name:     fields["name"],
			URL:      getFirstField(fields, []string{"login_uri", "uri"}),
			Username: fields["login_username"],
			Value:    fields["login_password"],
			Notes:    fields["notes"],
		}

	case FormatLastPass:
		return &ImportEntry{
			Name:     getFirstField(fields, []string{"name", "title"}),
			URL:      fields["url"],
			Username: fields["username"],
			Value:    fields["password"],
			Notes:    fields["extra"],
		}
	}

	return nil
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
	for _, name := range names {
		existing[name] = true
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

	// Detect format
	format := detectFormat(headers)
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
	entries, err := h.parseCSV(file, format)
	if err != nil {
		logError(r, "failed to parse CSV", "error", err)
		writeBadRequest(w, r, "failed to parse CSV")
		return
	}

	// Check for conflicts
	conflicts := h.checkConflicts(r.Context(), userID, entries)

	// Return preview
	preview := VaultImportPreview{
		Format:    string(format),
		Entries:   entries,
		Conflicts: conflicts,
		Total:     len(entries),
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

	// Import entries in a transaction
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		logError(r, "failed to begin transaction", "error", err)
		writeInternalError(w, r, "database error")
		return
	}
	defer tx.Rollback()

	qtx := h.handler.queries.WithTx(tx)

	imported := 0
	for _, entry := range req.Entries {
		// Skip if requested or unusable
		if entry.Skip || entry.Name == "" || entry.Value == "" {
			continue
		}

		// Encrypt the value
		encrypted, nonce, err := h.handler.encrypt([]byte(entry.Value))
		if err != nil {
			slog.Error("failed to encrypt entry", "name", entry.Name, "error", err)
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
			continue
		}
		entryID := fmt.Sprintf("%x", idBytes)

		// Encrypt the free-text metadata at rest and compute the URL blind index,
		// exactly as Create does, so imported rows are never stored in cleartext.
		// (Imports carry no alias_url, so that column is left empty.)
		encURL, _, encUser, encCat, encNotes, encErr := h.handler.encryptMetaColumns(entry.URL, "", entry.Username, category, entry.Notes)
		if encErr != nil {
			slog.Error("failed to encrypt entry metadata", "name", entry.Name, "error", encErr)
			continue
		}

		err = qtx.ImportVaultEntry(r.Context(), db.ImportVaultEntryParams{
			ID:             entryID,
			UserID:         userID,
			Name:           entry.Name,
			EncryptedValue: encrypted,
			Nonce:          nonce,
			Url:            toNullString(encURL),
			Username:       toNullString(encUser),
			Category:       toNullString(encCat),
			Notes:          toNullString(encNotes),
			// Imported entries land in the user's PERSONAL vault, so the blind
			// index is keyed to that scope.
			UrlBidx: h.handler.urlBlindIndex(bidxScope(userID, sql.NullString{}), entry.URL),
		})
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				slog.Warn("skipping duplicate entry", "name", entry.Name)
				continue
			}
			slog.Error("failed to insert entry", "name", entry.Name, "error", err)
			continue
		}

		imported++
	}

	if err := tx.Commit(); err != nil {
		logError(r, "failed to commit transaction", "error", err)
		writeInternalError(w, r, "failed to import entries")
		return
	}

	// Log activity
	LogActivityFromRequest(h.handler.queries, r, "vault.imported", fmt.Sprintf("Imported %d vault entries", imported))

	writeJSON(w, http.StatusOK, map[string]any{
		"imported": imported,
		"total":    len(req.Entries),
	})
}

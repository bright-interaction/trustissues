package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

const (
	vaultExportFormat        = "trustissues-vault"
	vaultExportLegacyVersion = 1
	vaultExportVersion       = 2
	vaultExportScopePublic   = "public"
	vaultExportScopePrivate  = "private"
)

// vaultExportDocument is the native, versioned TrustIssues interchange format.
//
// It deliberately contains user-authored vault data, not a dump of the database:
// ownership and membership rows are instance-local authority, rotation status is
// derived, and pending-revoke metadata is server-owned operational state. Source
// IDs are retained only so a future importer can map references without having to
// preserve those IDs in the destination instance.
type vaultExportDocument struct {
	Format       string                  `json:"format"`
	Version      int                     `json:"version"`
	ExportedAt   string                  `json:"exported_at"`
	IngressScope string                  `json:"ingress_scope,omitempty"`
	Collections  []vaultExportCollection `json:"collections"`
	Entries      []vaultExportEntry      `json:"entries"`
}

type vaultExportCollection struct {
	SourceID            string               `json:"source_id"`
	Name                string               `json:"name"`
	Description         string               `json:"description"`
	PrivateAccessPolicy privateaccess.Policy `json:"private_access_policy,omitempty"`
	CreatedAt           *string              `json:"created_at"`
	UpdatedAt           *string              `json:"updated_at"`
}

// vaultExportEntry is intentionally separate from vaultEntryFull. An API
// response can gain derived or server-owned fields without silently changing a
// durable backup format; additions to this type are explicit format decisions.
type vaultExportEntry struct {
	SourceID             string        `json:"source_id"`
	CollectionID         *string       `json:"collection_id"`
	Name                 string        `json:"name"`
	URL                  string        `json:"url"`
	AliasURL             string        `json:"alias_url"`
	Username             string        `json:"username"`
	Value                string        `json:"value"`
	Category             string        `json:"category"`
	Notes                string        `json:"notes"`
	AutoLogin            bool          `json:"auto_login"`
	RotationIntervalDays *int          `json:"rotation_interval_days"`
	ExpiresAt            *string       `json:"expires_at"`
	LastRotatedAt        *string       `json:"last_rotated_at"`
	Provider             string        `json:"provider"`
	ProviderMeta         string        `json:"provider_meta"`
	AutoRotate           bool          `json:"auto_rotate"`
	CustomFields         []CustomField `json:"custom_fields"`
	DestinationPatterns  []string      `json:"destination_patterns"`
	CreatedAt            *string       `json:"created_at"`
	UpdatedAt            *string       `json:"updated_at"`
}

func (h *VaultHandler) revealMetadataColumn(stored, fallback string, field vaultfield.Field,
	requireComplete bool) (string, error) {
	if !requireComplete {
		return h.decryptColumnOrLog(stored, fallback, field), nil
	}
	plain, err := h.decryptColumn(stored, field)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", field.Name(), err)
	}
	return plain, nil
}

func (h *VaultHandler) validateExportCustomFields(stored string) error {
	raw, err := h.decryptColumn(stored, vaultFieldCustomFields)
	if err != nil {
		return fmt.Errorf("open %s: %w", vaultFieldCustomFields.Name(), err)
	}
	if raw == "" {
		raw = "[]"
	}
	fields := []CustomField{}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fields); err != nil {
		return fmt.Errorf("parse %s: %w", vaultFieldCustomFields.Name(), err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("parse %s: trailing JSON", vaultFieldCustomFields.Name())
	}
	if fields == nil {
		return fmt.Errorf("parse %s: expected a JSON array", vaultFieldCustomFields.Name())
	}
	for _, field := range fields {
		if field.Withheld {
			return fmt.Errorf("parse %s: response-only withheld marker is stored", vaultFieldCustomFields.Name())
		}
	}
	if err := validatePortableCustomFields(fields); err != nil {
		return fmt.Errorf("validate %s: %w", vaultFieldCustomFields.Name(), err)
	}
	return nil
}

func validateExportProviderMeta(raw string) error {
	if raw == "" {
		raw = "{}"
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &object); err != nil {
		return fmt.Errorf("parse %s: %w", vaultFieldProviderMeta.Name(), err)
	}
	if object == nil {
		return fmt.Errorf("parse %s: expected a JSON object", vaultFieldProviderMeta.Name())
	}
	return nil
}

func parseExportDestinationPatterns(raw string) ([]string, error) {
	if raw == "" {
		return []string{}, nil
	}
	patterns := []string{}
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&patterns); err != nil {
		return nil, fmt.Errorf("parse vault_entries.destination_patterns: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse vault_entries.destination_patterns: trailing JSON")
	}
	if patterns == nil {
		return nil, fmt.Errorf("parse vault_entries.destination_patterns: expected a JSON array")
	}
	if err := ValidateDestinationPatterns(patterns); err != nil {
		return nil, fmt.Errorf("validate vault_entries.destination_patterns: %w", err)
	}
	if !slices.Equal(patterns, NormalizeDestinationPatterns(patterns)) {
		return nil, fmt.Errorf("validate vault_entries.destination_patterns: expected canonical patterns")
	}
	return patterns, nil
}

// revealAccessibleVaultEntries is the shared bulk-reveal path for Unlock and
// Export. The database query provides the ordinary access scope; every value and
// secret custom field then passes through the same caller-form secret-exit
// authority, so a widened query cannot become a widened plaintext response.
//
// Unlock is best-effort for historical compatibility and marks a row it cannot
// open. Export sets requireComplete: a backup containing a decryption sentinel
// or a withheld custom field is not a backup, so the whole request fails before
// any attachment bytes are written.
func (h *VaultHandler) revealAccessibleVaultEntries(r *http.Request, userID, operation string,
	requireComplete bool) ([]vaultEntryFull, error) {
	return h.revealAccessibleVaultEntriesWithQueries(r, h.queries, userID, operation, requireComplete)
}

// revealAccessibleVaultEntriesWithQueries is the transaction-aware form used
// by native export. Keeping count, reveal, and collection lookup on one read
// snapshot makes the entry ceiling a guarantee rather than a racy pre-check.
// Unlock uses the wrapper above and retains its ordinary connection pool path.
func (h *VaultHandler) revealAccessibleVaultEntriesWithQueries(r *http.Request, queries *db.Queries,
	userID, operation string, requireComplete bool) ([]vaultEntryFull, error) {

	ctx := r.Context()
	rows, err := queries.ListAccessibleVaultEntriesWithSecrets(ctx, db.ListAccessibleVaultEntriesWithSecretsParams{
		ID:             userID,
		UserID:         userID,
		UserID_2:       userID,
		PrivateIngress: privateIngressSQLFlag(ctx),
	})
	if err != nil {
		return nil, fmt.Errorf("list accessible vault entries: %w", err)
	}

	entries := make([]vaultEntryFull, 0, len(rows))
	for _, row := range rows {
		// Hoisted so redaction and the derived pending-revoke status read the
		// same plaintext snapshot.
		rawProviderMeta, err := h.revealMetadataColumn(row.ProviderMeta.String, "{}",
			vaultFieldProviderMeta, requireComplete)
		if err != nil {
			return nil, fmt.Errorf("entry %s metadata is unreadable: %w", row.ID, err)
		}
		if requireComplete {
			if err := validateExportProviderMeta(rawProviderMeta); err != nil {
				return nil, fmt.Errorf("entry %s metadata is invalid: %w", row.ID, err)
			}
		}
		visibleProviderMeta, providerMetaWithheld := h.providerMetaForCaller(ctx, row.ID, row.Name,
			row.Provider.String, rawProviderMeta, userID)
		if requireComplete && len(providerMetaWithheld) > 0 {
			return nil, fmt.Errorf("provider metadata credentials of entry %s were not released", row.ID)
		}

		name, err := h.revealMetadataColumn(row.Name, "", vaultFieldName, requireComplete)
		if err != nil {
			return nil, fmt.Errorf("entry %s metadata is unreadable: %w", row.ID, err)
		}
		entryURL, err := h.revealMetadataColumn(row.Url.String, "", vaultFieldURL, requireComplete)
		if err != nil {
			return nil, fmt.Errorf("entry %s metadata is unreadable: %w", row.ID, err)
		}
		aliasURL, err := h.revealMetadataColumn(row.AliasUrl.String, "", vaultFieldAliasURL, requireComplete)
		if err != nil {
			return nil, fmt.Errorf("entry %s metadata is unreadable: %w", row.ID, err)
		}
		username, err := h.revealMetadataColumn(row.Username.String, "", vaultFieldUsername, requireComplete)
		if err != nil {
			return nil, fmt.Errorf("entry %s metadata is unreadable: %w", row.ID, err)
		}
		category, err := h.revealMetadataColumn(row.Category.String, "", vaultFieldCategory, requireComplete)
		if err != nil {
			return nil, fmt.Errorf("entry %s metadata is unreadable: %w", row.ID, err)
		}
		notes, err := h.revealMetadataColumn(row.Notes.String, "", vaultFieldNotes, requireComplete)
		if err != nil {
			return nil, fmt.Errorf("entry %s metadata is unreadable: %w", row.ID, err)
		}

		if requireComplete {
			if err := h.validateExportCustomFields(row.CustomFields); err != nil {
				return nil, fmt.Errorf("entry %s custom fields are invalid: %w", row.ID, err)
			}
		}
		customFields := h.customFieldsForCaller(ctx, row.ID, row.Name, row.CustomFields, userID, true)
		if requireComplete {
			for _, field := range customFields {
				if field.Withheld {
					return nil, fmt.Errorf("a custom field of entry %s was not released", row.ID)
				}
			}
		}
		destinationPatterns := parseDestinationPatterns(row.DestinationPatterns)
		if requireComplete {
			destinationPatterns, err = parseExportDestinationPatterns(row.DestinationPatterns)
			if err != nil {
				return nil, fmt.Errorf("entry %s destinations are invalid: %w", row.ID, err)
			}
		}

		e := vaultEntryFull{
			vaultEntryMeta: vaultEntryMeta{
				ID:                   row.ID,
				CollectionID:         nullStringPtr(row.CollectionID),
				Name:                 name,
				URL:                  entryURL,
				AliasURL:             aliasURL,
				Username:             username,
				Category:             category,
				Notes:                notes,
				AutoLogin:            row.AutoLogin != 0,
				RotationIntervalDays: nullInt64ToIntPtr(row.RotationIntervalDays),
				ExpiresAt:            nullTimePtr(row.ExpiresAt),
				LastRotatedAt:        nullTimePtr(row.LastRotatedAt),
				Provider:             row.Provider.String,
				ProviderMeta:         redactReservedProviderMetaKeys(visibleProviderMeta),
				ProviderMetaWithheld: providerMetaWithheld,
				AutoRotate:           row.AutoRotate.Int64 != 0,
				LastRotationError:    row.LastRotationError.String,
				PendingRevoke:        pendingRevokeStatusFrom(rawProviderMeta),
				CustomFields:         customFields,
				DestinationPatterns:  destinationPatterns,
				CreatedAt:            nullTimePtr(row.CreatedAt),
				UpdatedAt:            nullTimePtr(row.UpdatedAt),
			},
		}

		opened, openErr := h.OpenEntrySecret(row.EncryptedValue, row.Nonce, 2,
			entryOrigin(row.ID, row.Name))
		if openErr == nil {
			var value string
			_, value, openErr = secretexit.ExitString(ctx, opened,
				secretexit.ToCaller(operation, userID))
			opened.Wipe()
			e.Value = value
		}
		if openErr != nil {
			if requireComplete {
				return nil, fmt.Errorf("entry %s was not released: %w", row.ID, openErr)
			}
			// Entry IDs are safe operational identifiers; names and values are
			// intentionally absent from the log.
			logError(r, "vault.reveal: value not released", "entry_id", row.ID, "error", openErr)
			e.Value = "[decryption error]"
		}

		e.RotationStatus = computeRotationStatus(e.RotationIntervalDays, e.ExpiresAt,
			e.LastRotatedAt, e.CreatedAt, &e.LastRotationError)
		entries = append(entries, e)
	}

	// Names are encrypted at rest, so the query's ORDER BY e.name orders random
	// nonces. Sort after decryption for deterministic UI and export output.
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

func makeVaultExportEntries(revealed []vaultEntryFull) []vaultExportEntry {
	out := make([]vaultExportEntry, 0, len(revealed))
	for _, e := range revealed {
		fields := append([]CustomField{}, e.CustomFields...)
		patterns := append([]string{}, e.DestinationPatterns...)
		out = append(out, vaultExportEntry{
			SourceID:             e.ID,
			CollectionID:         e.CollectionID,
			Name:                 e.Name,
			URL:                  e.URL,
			AliasURL:             e.AliasURL,
			Username:             e.Username,
			Value:                e.Value,
			Category:             e.Category,
			Notes:                e.Notes,
			AutoLogin:            e.AutoLogin,
			RotationIntervalDays: e.RotationIntervalDays,
			ExpiresAt:            e.ExpiresAt,
			LastRotatedAt:        e.LastRotatedAt,
			Provider:             e.Provider,
			ProviderMeta:         e.ProviderMeta,
			AutoRotate:           e.AutoRotate,
			CustomFields:         fields,
			DestinationPatterns:  patterns,
			CreatedAt:            e.CreatedAt,
			UpdatedAt:            e.UpdatedAt,
		})
	}
	return out
}

// exportCollections returns only scopes referenced by entries that passed the
// reveal authority. It exports no member list or role: those are live authority
// in the source instance, not portable vault contents.
func (h *VaultHandler) exportCollections(r *http.Request, queries *db.Queries,
	entries []vaultEntryFull) ([]vaultExportCollection, error) {

	ids := make(map[string]struct{})
	for _, e := range entries {
		if e.CollectionID != nil && *e.CollectionID != "" {
			ids[*e.CollectionID] = struct{}{}
		}
	}

	out := make([]vaultExportCollection, 0, len(ids))
	for id := range ids {
		collection, err := queries.GetCollection(r.Context(), id)
		if err != nil {
			return nil, fmt.Errorf("read referenced collection %s: %w", id, err)
		}
		policy, ok := privateaccess.Parse(collection.PrivateAccessPolicy)
		if !ok {
			return nil, fmt.Errorf("collection %s has invalid private access policy", id)
		}
		out = append(out, vaultExportCollection{
			SourceID:            collection.ID,
			Name:                collection.Name,
			Description:         collection.Description,
			PrivateAccessPolicy: policy,
			CreatedAt:           nullTimePtr(collection.CreatedAt),
			UpdatedAt:           nullTimePtr(collection.UpdatedAt),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].SourceID < out[j].SourceID
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func setVaultExportNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// Export handles POST /api/vault/export. It password-re-verifies the caller,
// strictly reveals exactly the entries Unlock may reveal, and returns a native
// JSON attachment suitable for a future lossless importer.
func (h *VaultHandler) Export(w http.ResponseWriter, r *http.Request) {
	// Set before parsing or re-authentication so errors from this secret-bearing
	// endpoint are never cacheable either.
	setVaultExportNoStoreHeaders(w)

	var req struct {
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid vault export request")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeBadRequest(w, r, "invalid vault export request")
		return
	}
	if req.Password == "" {
		writeBadRequest(w, r, "password is required to export the vault")
		return
	}

	userID := middleware.GetUserID(r.Context())
	if !h.reauthOrRefuse(w, r, r.Context(), userID, req.Password) {
		return
	}

	// Count and reveal inside one snapshot. A standalone count followed by a
	// pooled list has a TOCTOU gap: entries added between them could make the
	// supposedly bounded export allocate and decrypt an unbounded result set.
	// CountAccessibleVaultEntries itself stops after maxImportEntries+1 rows.
	snapshot, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		logError(r, "vault.export: begin snapshot failed", "error", err)
		writeInternalError(w, r, "vault export could not be completed")
		return
	}
	defer func() { _ = snapshot.Rollback() }()
	qtx := h.queries.WithTx(snapshot)
	preflight, err := qtx.CountAccessibleVaultEntries(r.Context(), db.CountAccessibleVaultEntriesParams{
		ID: userID, UserID: userID, UserID_2: userID,
		PrivateIngress: privateIngressSQLFlag(r.Context()), MaxRows: maxImportEntries + 1,
	})
	if err != nil {
		logError(r, "vault.export: count failed", "error", err)
		writeInternalError(w, r, "vault export could not be completed")
		return
	}
	if preflight.EntryCount > maxImportEntries {
		writeError(w, r, http.StatusRequestEntityTooLarge, "native_export_too_large",
			fmt.Sprintf("native export supports at most %d accessible entries", maxImportEntries))
		return
	}
	// This is a conservative lower bound computed from ciphertext lengths and
	// unencrypted portable fields. If even the minimum representation is over
	// the file ceiling, no amount of JSON compaction can make it importable. Stop
	// here, before the bulk query allocates or any secret is decrypted.
	if preflight.MinimumPortableBytes > MaxNativeVaultFileBytes {
		writeError(w, r, http.StatusRequestEntityTooLarge, "native_export_too_large",
			fmt.Sprintf("native export exceeds the %d MiB portable file limit",
				MaxNativeVaultFileBytes/(1<<20)))
		return
	}

	revealed, err := h.revealAccessibleVaultEntriesWithQueries(r, qtx, userID,
		"POST /api/vault/export", true)
	if err != nil {
		logError(r, "vault.export: reveal failed", "error", err)
		writeInternalError(w, r, "vault export could not be completed")
		return
	}
	// This should be implied by the snapshot count. Keep the postcondition next
	// to the plaintext slice so a future query-scope drift fails closed.
	if len(revealed) > maxImportEntries {
		logError(r, "vault.export: bounded count/reveal scope mismatch", "count", preflight.EntryCount,
			"revealed", len(revealed))
		writeInternalError(w, r, "vault export could not be completed")
		return
	}
	collections, err := h.exportCollections(r, qtx, revealed)
	if err != nil {
		logError(r, "vault.export: collection query failed", "error", err)
		writeInternalError(w, r, "vault export could not be completed")
		return
	}

	now := time.Now().UTC()
	ingressScope := vaultExportScopePublic
	if middleware.IsPrivateIngress(r.Context()) {
		ingressScope = vaultExportScopePrivate
	}
	document := vaultExportDocument{
		Format:       vaultExportFormat,
		Version:      vaultExportVersion,
		ExportedAt:   now.Format(time.RFC3339Nano),
		IngressScope: ingressScope,
		Collections:  collections,
		Entries:      makeVaultExportEntries(revealed),
	}
	// The importer owns the executable native-v1 schema contract. Applying that
	// same validator here catches any legacy stored shape or future exporter
	// drift before we claim to have produced a restorable backup. Name conflicts
	// are reported in the returned plan, not as validation errors, because they
	// depend on the destination vault and do not make the document malformed.
	if _, err := validateNativeImportDocument(document); err != nil {
		logError(r, "vault.export: native document validation failed", "error", err)
		writeInternalError(w, r, "vault export could not be completed")
		return
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		logError(r, "vault.export: encoding failed", "error", err)
		writeInternalError(w, r, "vault export could not be completed")
		return
	}
	// Marshal and append may use different backing arrays. Wipe both so the
	// complete plaintext vault does not wait for a later garbage collection on
	// either a refused export or a successful response.
	defer clear(encoded)
	payload := append(encoded, '\n')
	defer clear(payload)
	if len(payload) > MaxNativeVaultFileBytes {
		writeError(w, r, http.StatusRequestEntityTooLarge, "native_export_too_large",
			fmt.Sprintf("native export exceeds the %d MiB portable file limit",
				MaxNativeVaultFileBytes/(1<<20)))
		return
	}
	// End the read transaction before the required activity insert takes a write
	// lock. Commit is only a snapshot close here (the transaction performed no
	// writes); spelling the boundary explicitly also keeps later pool-backed work
	// outside the transaction scope enforced by tx_scope_test.go.
	if err := snapshot.Commit(); err != nil {
		logError(r, "vault.export: close snapshot failed", "error", err)
		writeInternalError(w, r, "vault export could not be completed")
		return
	}

	filename := "trustissues-vault-" + now.Format("20060102-150405") + ".json"
	// No entry names, usernames, URLs, provider configuration or secret values
	// enter the append-only activity trail. Unlike ordinary best-effort activity
	// rows, this insert is a precondition for releasing a bulk plaintext export:
	// an audit outage must fail before attachment headers or bytes are written.
	if err := logActivityFromRequestRequired(h.queries, r, "vault.exported",
		fmt.Sprintf("Vault exported (user: %s, entries: %d)", userID, len(revealed))); err != nil {
		logError(r, "vault.export: required audit insert failed", "error", err)
		writeInternalError(w, r, "vault export could not be completed")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{
		"filename": filename,
	}))
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(payload); err != nil {
		logError(r, "vault.export: response write failed", "error", err)
	}
}

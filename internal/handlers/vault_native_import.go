package handlers

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

const (
	maxNativeImportFileBytes = MaxNativeVaultFileBytes
	maxNativeConflictNames   = 100
)

type nativeImportTimes struct {
	created time.Time
	updated time.Time
}

type nativeImportEntryPlan struct {
	expiresAt     sql.NullTime
	lastRotatedAt sql.NullTime
	createdAt     time.Time
	updatedAt     time.Time
	providerRaw   string
	providerMeta  map[string]string
	knownProvider bool
}

type nativeImportPlan struct {
	document           vaultExportDocument
	collectionTimes    []nativeImportTimes
	entryPlans         []nativeImportEntryPlan
	intraConflicts     []string
	autoRotateDisabled int
}

type nativeImportPreview struct {
	Format             string   `json:"format"`
	Version            int      `json:"version"`
	IngressScope       string   `json:"ingress_scope"`
	EntryCount         int      `json:"entry_count"`
	CollectionCount    int      `json:"collection_count"`
	Conflicts          []string `json:"conflicts"`
	AutoRotateDisabled int      `json:"auto_rotate_disabled"`
}

type nativeImportConflictError struct {
	Error     string   `json:"error"`
	Code      string   `json:"code"`
	RequestID string   `json:"request_id,omitempty"`
	Conflicts []string `json:"conflicts"`
}

func requireNativeImportIngress(w http.ResponseWriter, r *http.Request, plan nativeImportPlan) bool {
	if middleware.IsPrivateIngress(r.Context()) {
		return true
	}
	for _, collection := range plan.document.Collections {
		if collection.PrivateAccessPolicy != privateaccess.PolicyStandard {
			writePrivateIngressRequired(w, r)
			return false
		}
	}
	return true
}

type nativeImportUpload struct {
	file multipart.File
}

func openNativeImportUpload(r *http.Request) (nativeImportUpload, error) {
	if err := r.ParseMultipartForm(maxNativeImportFileBytes); err != nil {
		cleanupNativeMultipartForm(r)
		return nativeImportUpload{}, fmt.Errorf("invalid multipart upload")
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		cleanupNativeMultipartForm(r)
		return nativeImportUpload{}, fmt.Errorf("file is required")
	}
	if !strings.EqualFold(filepath.Ext(header.Filename), ".json") {
		_ = file.Close()
		cleanupNativeMultipartForm(r)
		return nativeImportUpload{}, fmt.Errorf("only .json native vault files are supported")
	}
	return nativeImportUpload{file: file}, nil
}

func cleanupNativeMultipartForm(r *http.Request) {
	if r.MultipartForm != nil {
		_ = r.MultipartForm.RemoveAll()
		r.MultipartForm = nil
	}
}

var (
	errNativeJSONMalformed       = errors.New("invalid native vault JSON")
	errNativeJSONTrailing        = errors.New("native vault JSON has trailing data")
	errNativeTooManyCollections  = errors.New("native vault JSON has too many collections")
	errNativeTooManyEntries      = errors.New("native vault JSON has too many entries")
	errNativeTooManyCustomFields = errors.New("native vault JSON has too many custom fields")
	errNativeTooManyDestinations = errors.New("native vault JSON has too many destination patterns")
)

func nativeJSONStart(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return errNativeJSONMalformed
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != want {
		return errNativeJSONMalformed
	}
	return nil
}

func nativeJSONEnd(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return errNativeJSONMalformed
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != want {
		return errNativeJSONMalformed
	}
	return nil
}

func nativeJSONField(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", errNativeJSONMalformed
	}
	field, ok := token.(string)
	if !ok {
		return "", errNativeJSONMalformed
	}
	return field, nil
}

func nativeJSONDecode(decoder *json.Decoder, target any) error {
	if err := decoder.Decode(target); err != nil {
		return errNativeJSONMalformed
	}
	return nil
}

type nativeJSONNonNull struct{ target any }

func (value *nativeJSONNonNull) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errNativeJSONMalformed
	}
	return json.Unmarshal(raw, value.target)
}

func nativeJSONDecodeNonNull(decoder *json.Decoder, target any) error {
	if err := decoder.Decode(&nativeJSONNonNull{target: target}); err != nil {
		return errNativeJSONMalformed
	}
	return nil
}

func nativeJSONOnce(seen *uint64, bit uint64) error {
	if *seen&bit != 0 {
		return errNativeJSONMalformed
	}
	*seen |= bit
	return nil
}

func decodeNativeCollection(decoder *json.Decoder) (vaultExportCollection, error) {
	var collection vaultExportCollection
	if err := nativeJSONStart(decoder, '{'); err != nil {
		return collection, err
	}
	var seen uint64
	for decoder.More() {
		field, err := nativeJSONField(decoder)
		if err != nil {
			return collection, err
		}
		var bit uint64
		var target any
		switch field {
		case "source_id":
			bit, target = 1<<0, &collection.SourceID
		case "name":
			bit, target = 1<<1, &collection.Name
		case "description":
			bit, target = 1<<2, &collection.Description
		case "private_access_policy":
			bit, target = 1<<5, &collection.PrivateAccessPolicy
		case "created_at":
			bit, target = 1<<3, &collection.CreatedAt
		case "updated_at":
			bit, target = 1<<4, &collection.UpdatedAt
		default:
			return collection, errNativeJSONMalformed
		}
		if err := nativeJSONOnce(&seen, bit); err != nil {
			return collection, err
		}
		if err := nativeJSONDecodeNonNull(decoder, target); err != nil {
			return collection, err
		}
	}
	if err := nativeJSONEnd(decoder, '}'); err != nil {
		return collection, err
	}
	if seen&(1<<5-1) != 1<<5-1 || seen & ^uint64(1<<6-1) != 0 {
		return collection, errNativeJSONMalformed
	}
	return collection, nil
}

func decodeNativeCollections(decoder *json.Decoder) ([]vaultExportCollection, error) {
	if err := nativeJSONStart(decoder, '['); err != nil {
		return nil, err
	}
	collections := make([]vaultExportCollection, 0)
	for decoder.More() {
		// Check before decoding or appending the next element: an adversarial
		// compact array never allocates collection max+1.
		if len(collections) >= maxImportEntries {
			return nil, errNativeTooManyCollections
		}
		collection, err := decodeNativeCollection(decoder)
		if err != nil {
			return nil, err
		}
		collections = append(collections, collection)
	}
	if err := nativeJSONEnd(decoder, ']'); err != nil {
		return nil, err
	}
	return collections, nil
}

func decodeNativeCustomField(decoder *json.Decoder) (CustomField, error) {
	var custom CustomField
	if err := nativeJSONStart(decoder, '{'); err != nil {
		return custom, err
	}
	var seen uint64
	for decoder.More() {
		field, err := nativeJSONField(decoder)
		if err != nil {
			return custom, err
		}
		var bit uint64
		var target any
		switch field {
		case "label":
			bit, target = 1<<0, &custom.Label
		case "value":
			bit, target = 1<<1, &custom.Value
		case "secret":
			bit, target = 1<<2, &custom.Secret
		case "withheld":
			bit, target = 1<<3, &custom.Withheld
		default:
			return custom, errNativeJSONMalformed
		}
		if err := nativeJSONOnce(&seen, bit); err != nil {
			return custom, err
		}
		if err := nativeJSONDecodeNonNull(decoder, target); err != nil {
			return custom, err
		}
	}
	if err := nativeJSONEnd(decoder, '}'); err != nil {
		return custom, err
	}
	// withheld is response-only and omitted when false; the three durable
	// custom-field members are required in every native-v1 document.
	if seen&(1<<3-1) != 1<<3-1 {
		return custom, errNativeJSONMalformed
	}
	return custom, nil
}

func decodeNativeCustomFields(decoder *json.Decoder) ([]CustomField, error) {
	if err := nativeJSONStart(decoder, '['); err != nil {
		return nil, err
	}
	fields := make([]CustomField, 0)
	for decoder.More() {
		if len(fields) >= maxCustomFields {
			return nil, errNativeTooManyCustomFields
		}
		field, err := decodeNativeCustomField(decoder)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	if err := nativeJSONEnd(decoder, ']'); err != nil {
		return nil, err
	}
	return fields, nil
}

func decodeNativeDestinationPatterns(decoder *json.Decoder) ([]string, error) {
	if err := nativeJSONStart(decoder, '['); err != nil {
		return nil, err
	}
	patterns := make([]string, 0)
	for decoder.More() {
		if len(patterns) >= maxDestinationPatterns {
			return nil, errNativeTooManyDestinations
		}
		var pattern string
		if err := nativeJSONDecodeNonNull(decoder, &pattern); err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}
	if err := nativeJSONEnd(decoder, ']'); err != nil {
		return nil, err
	}
	return patterns, nil
}

func decodeNativeEntry(decoder *json.Decoder) (vaultExportEntry, error) {
	var entry vaultExportEntry
	if err := nativeJSONStart(decoder, '{'); err != nil {
		return entry, err
	}
	var seen uint64
	for decoder.More() {
		field, err := nativeJSONField(decoder)
		if err != nil {
			return entry, err
		}
		var bit uint64
		var target any
		nonNull := true
		switch field {
		case "source_id":
			bit, target = 1<<0, &entry.SourceID
		case "collection_id":
			bit, target = 1<<1, &entry.CollectionID
			nonNull = false
		case "name":
			bit, target = 1<<2, &entry.Name
		case "url":
			bit, target = 1<<3, &entry.URL
		case "alias_url":
			bit, target = 1<<4, &entry.AliasURL
		case "username":
			bit, target = 1<<5, &entry.Username
		case "value":
			bit, target = 1<<6, &entry.Value
		case "category":
			bit, target = 1<<7, &entry.Category
		case "notes":
			bit, target = 1<<8, &entry.Notes
		case "auto_login":
			bit, target = 1<<9, &entry.AutoLogin
		case "rotation_interval_days":
			bit, target = 1<<10, &entry.RotationIntervalDays
			nonNull = false
		case "expires_at":
			bit, target = 1<<11, &entry.ExpiresAt
			nonNull = false
		case "last_rotated_at":
			bit, target = 1<<12, &entry.LastRotatedAt
			nonNull = false
		case "provider":
			bit, target = 1<<13, &entry.Provider
		case "provider_meta":
			bit, target = 1<<14, &entry.ProviderMeta
		case "auto_rotate":
			bit, target = 1<<15, &entry.AutoRotate
		case "custom_fields":
			bit = 1 << 16
			if err := nativeJSONOnce(&seen, bit); err != nil {
				return entry, err
			}
			entry.CustomFields, err = decodeNativeCustomFields(decoder)
			if err != nil {
				return entry, err
			}
			continue
		case "destination_patterns":
			bit = 1 << 17
			if err := nativeJSONOnce(&seen, bit); err != nil {
				return entry, err
			}
			entry.DestinationPatterns, err = decodeNativeDestinationPatterns(decoder)
			if err != nil {
				return entry, err
			}
			continue
		case "created_at":
			bit, target = 1<<18, &entry.CreatedAt
		case "updated_at":
			bit, target = 1<<19, &entry.UpdatedAt
		default:
			return entry, errNativeJSONMalformed
		}
		if err := nativeJSONOnce(&seen, bit); err != nil {
			return entry, err
		}
		if nonNull {
			err = nativeJSONDecodeNonNull(decoder, target)
		} else {
			err = nativeJSONDecode(decoder, target)
		}
		if err != nil {
			return entry, err
		}
	}
	if err := nativeJSONEnd(decoder, '}'); err != nil {
		return entry, err
	}
	if seen != 1<<20-1 {
		return entry, errNativeJSONMalformed
	}
	return entry, nil
}

func decodeNativeEntries(decoder *json.Decoder) ([]vaultExportEntry, error) {
	if err := nativeJSONStart(decoder, '['); err != nil {
		return nil, err
	}
	entries := make([]vaultExportEntry, 0)
	for decoder.More() {
		if len(entries) >= maxImportEntries {
			return nil, errNativeTooManyEntries
		}
		entry, err := decodeNativeEntry(decoder)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := nativeJSONEnd(decoder, ']'); err != nil {
		return nil, err
	}
	return entries, nil
}

func decodeNativeDocument(decoder *json.Decoder) (vaultExportDocument, error) {
	var document vaultExportDocument
	if err := nativeJSONStart(decoder, '{'); err != nil {
		return document, err
	}
	var seen uint64
	for decoder.More() {
		field, err := nativeJSONField(decoder)
		if err != nil {
			return document, err
		}
		switch field {
		case "format":
			if err := nativeJSONOnce(&seen, 1<<0); err != nil {
				return document, err
			}
			err = nativeJSONDecodeNonNull(decoder, &document.Format)
		case "version":
			if err := nativeJSONOnce(&seen, 1<<1); err != nil {
				return document, err
			}
			err = nativeJSONDecodeNonNull(decoder, &document.Version)
		case "exported_at":
			if err := nativeJSONOnce(&seen, 1<<2); err != nil {
				return document, err
			}
			err = nativeJSONDecodeNonNull(decoder, &document.ExportedAt)
		case "ingress_scope":
			if err := nativeJSONOnce(&seen, 1<<5); err != nil {
				return document, err
			}
			err = nativeJSONDecodeNonNull(decoder, &document.IngressScope)
		case "collections":
			if err := nativeJSONOnce(&seen, 1<<3); err != nil {
				return document, err
			}
			document.Collections, err = decodeNativeCollections(decoder)
		case "entries":
			if err := nativeJSONOnce(&seen, 1<<4); err != nil {
				return document, err
			}
			document.Entries, err = decodeNativeEntries(decoder)
		default:
			return document, errNativeJSONMalformed
		}
		if err != nil {
			return document, err
		}
	}
	if err := nativeJSONEnd(decoder, '}'); err != nil {
		return document, err
	}
	if seen&(1<<5-1) != 1<<5-1 || seen & ^uint64(1<<6-1) != 0 {
		return document, errNativeJSONMalformed
	}
	return document, nil
}

func decodeNativeImportDocument(file io.Reader) (vaultExportDocument, error) {
	raw, err := io.ReadAll(io.LimitReader(file, maxNativeImportFileBytes+1))
	if err != nil {
		clear(raw)
		return vaultExportDocument{}, fmt.Errorf("read native vault document")
	}
	if len(raw) > maxNativeImportFileBytes {
		clear(raw)
		return vaultExportDocument{}, fmt.Errorf("native vault document is too large")
	}
	// This file contains every plaintext secret in the backup. Decode directly
	// from the mutable byte buffer (not string(raw), which creates a second,
	// immutable whole-file copy) and wipe it on every return.
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	document, err := decodeNativeDocument(decoder)
	if err != nil {
		return vaultExportDocument{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return vaultExportDocument{}, errNativeJSONTrailing
	}
	return document, nil
}

func parseNativeRequiredTime(raw *string) (time.Time, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return time.Time{}, errors.New("required timestamp is missing")
	}
	t, err := time.Parse(time.RFC3339Nano, *raw)
	if err != nil {
		return time.Time{}, errors.New("timestamp is not RFC3339")
	}
	return t.UTC(), nil
}

func parseNativeOptionalTime(raw *string) (sql.NullTime, error) {
	if raw == nil {
		return sql.NullTime{}, nil
	}
	if strings.TrimSpace(*raw) == "" {
		return sql.NullTime{}, errors.New("optional timestamp must be null or RFC3339")
	}
	t, err := time.Parse(time.RFC3339Nano, *raw)
	if err != nil {
		return sql.NullTime{}, errors.New("timestamp is not RFC3339")
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}, nil
}

func validateNativeSourceID(id string) error {
	// Source ids are document-local reference keys and are never stored. The
	// whole-file ceiling already bounds them; imposing a second size/whitespace
	// policy would only make an otherwise valid legacy export unrestorable.
	if id == "" {
		return errors.New("source_id is missing or invalid")
	}
	return nil
}

func parseNativeProviderMeta(raw string) (string, map[string]string, error) {
	if raw == "" {
		// Legacy rows can carry an empty column, and strict export deliberately
		// treats that as the empty object. Canonicalize it before encryption so a
		// subsequent export is unambiguous JSON.
		raw = "{}"
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return "", nil, errors.New("provider metadata must be a JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", nil, errors.New("provider metadata has trailing JSON")
	}
	for _, reserved := range reservedProviderMetaKeys {
		if _, found := object[reserved]; found {
			return "", nil, errors.New("provider metadata contains a server-owned key")
		}
	}
	// The durable format preserves arbitrary JSON values for forward
	// compatibility. Only string values participate in today's provider egress
	// declarations and capability-default expansion; derive that view without
	// coercing or dropping anything from the bytes stored at rest.
	stringsOnly := make(map[string]string, len(object))
	for key, value := range object {
		var text string
		if err := json.Unmarshal(value, &text); err == nil {
			stringsOnly[key] = text
		}
	}
	return raw, stringsOnly, nil
}

func validateNativeImportDocument(document vaultExportDocument) (nativeImportPlan, error) {
	plan := nativeImportPlan{document: document}
	if document.Format != vaultExportFormat ||
		(document.Version != vaultExportLegacyVersion && document.Version != vaultExportVersion) {
		return plan, fmt.Errorf("unsupported native vault format or version")
	}
	if document.Version == vaultExportLegacyVersion {
		if document.IngressScope != "" {
			return plan, fmt.Errorf("native v1 document must not contain ingress_scope")
		}
		document.IngressScope = vaultExportScopePublic
		plan.document = document
	} else if document.IngressScope != vaultExportScopePublic && document.IngressScope != vaultExportScopePrivate {
		return plan, fmt.Errorf("ingress_scope must be public or private")
	}
	if _, err := time.Parse(time.RFC3339Nano, document.ExportedAt); err != nil {
		return plan, fmt.Errorf("exported_at must be RFC3339")
	}
	if document.Collections == nil {
		return plan, fmt.Errorf("collections must be a JSON array")
	}
	if document.Entries == nil {
		return plan, fmt.Errorf("entries must be a JSON array")
	}
	if len(document.Entries) > maxImportEntries {
		return plan, fmt.Errorf("native vault document exceeds the %d-entry limit", maxImportEntries)
	}
	// Every collection must be referenced below, so there can never be more
	// collections than entries. Refuse that impossible shape before allocating
	// maps from an attacker-controlled count.
	if len(document.Collections) > len(document.Entries) {
		return plan, fmt.Errorf("native vault document contains too many collections")
	}

	allSourceIDs := make(map[string]struct{}, len(document.Collections)+len(document.Entries))
	collectionIndex := make(map[string]int, len(document.Collections))
	plan.collectionTimes = make([]nativeImportTimes, len(document.Collections))
	for i, collection := range document.Collections {
		if err := validateNativeSourceID(collection.SourceID); err != nil {
			return plan, fmt.Errorf("collection %d has an invalid source_id", i+1)
		}
		if _, duplicate := allSourceIDs[collection.SourceID]; duplicate {
			return plan, fmt.Errorf("native vault document contains duplicate source IDs")
		}
		allSourceIDs[collection.SourceID] = struct{}{}
		collectionIndex[collection.SourceID] = i
		if collection.PrivateAccessPolicy == "" {
			if document.Version != vaultExportLegacyVersion {
				return plan, fmt.Errorf("collection %d is missing private_access_policy", i+1)
			}
			// Native v1 predates private ingress, so it can only represent the
			// compatibility-standard policy.
			collection.PrivateAccessPolicy = privateaccess.PolicyStandard
			document.Collections[i].PrivateAccessPolicy = privateaccess.PolicyStandard
		}
		policy, ok := privateaccess.Parse(string(collection.PrivateAccessPolicy))
		if !ok {
			return plan, fmt.Errorf("collection %d has an invalid private_access_policy", i+1)
		}
		if document.IngressScope == vaultExportScopePublic && policy != privateaccess.PolicyStandard {
			return plan, fmt.Errorf("a public-scope export cannot contain protected collections")
		}
		if collection.Name == "" || strings.TrimSpace(collection.Name) != collection.Name {
			return plan, fmt.Errorf("collection %d has invalid fields", i+1)
		}
		created, err := parseNativeRequiredTime(collection.CreatedAt)
		if err != nil {
			return plan, fmt.Errorf("collection %d has an invalid created_at", i+1)
		}
		updated, err := parseNativeRequiredTime(collection.UpdatedAt)
		if err != nil || updated.Before(created) {
			return plan, fmt.Errorf("collection %d has an invalid updated_at", i+1)
		}
		plan.collectionTimes[i] = nativeImportTimes{created: created, updated: updated}
	}
	plan.document = document

	referencedCollections := make(map[string]struct{}, len(document.Collections))
	seenNames := make(map[string]map[string]struct{}, len(document.Collections)+1)
	intraConflicts := make(map[string]struct{})
	plan.entryPlans = make([]nativeImportEntryPlan, len(document.Entries))
	for i, entry := range document.Entries {
		if err := validateNativeSourceID(entry.SourceID); err != nil {
			return plan, fmt.Errorf("entry %d has an invalid source_id", i+1)
		}
		if _, duplicate := allSourceIDs[entry.SourceID]; duplicate {
			return plan, fmt.Errorf("native vault document contains duplicate source IDs")
		}
		allSourceIDs[entry.SourceID] = struct{}{}

		// Native-v1 is a durable interchange format, including for rows written
		// by older versions. Current Export can faithfully emit free-text fields
		// that exceed today's interactive-form limits, padded URL/user fields,
		// and historical category strings. The 10 MiB document ceiling bounds all
		// of them; refusing them here would make a successful backup unrestorable.
		if entry.Name == "" || entry.Value == "" {
			return plan, fmt.Errorf("entry %d is missing a name or value", i+1)
		}
		_, knownProvider := ProviderRegistry[entry.Provider]
		providerRaw, meta, err := parseNativeProviderMeta(entry.ProviderMeta)
		if err != nil {
			return plan, fmt.Errorf("entry %d has invalid provider metadata", i+1)
		}
		if entry.CustomFields == nil {
			return plan, fmt.Errorf("entry %d custom_fields must be a JSON array", i+1)
		}
		if err := validatePortableCustomFields(entry.CustomFields); err != nil {
			return plan, fmt.Errorf("entry %d has invalid custom fields", i+1)
		}
		if entry.DestinationPatterns == nil {
			return plan, fmt.Errorf("entry %d destination_patterns must be a JSON array", i+1)
		}
		if err := ValidateDestinationPatterns(entry.DestinationPatterns); err != nil ||
			!slices.Equal(entry.DestinationPatterns, NormalizeDestinationPatterns(entry.DestinationPatterns)) {
			return plan, fmt.Errorf("entry %d has invalid or non-canonical destination patterns", i+1)
		}
		if entry.CollectionID != nil {
			if *entry.CollectionID == "" {
				return plan, fmt.Errorf("entry %d has an empty collection reference", i+1)
			}
			if _, exists := collectionIndex[*entry.CollectionID]; !exists {
				return plan, fmt.Errorf("entry %d references an unknown collection", i+1)
			}
			referencedCollections[*entry.CollectionID] = struct{}{}
		}

		expires, err := parseNativeOptionalTime(entry.ExpiresAt)
		if err != nil {
			return plan, fmt.Errorf("entry %d has an invalid expires_at", i+1)
		}
		lastRotated, err := parseNativeOptionalTime(entry.LastRotatedAt)
		if err != nil {
			return plan, fmt.Errorf("entry %d has an invalid last_rotated_at", i+1)
		}
		created, err := parseNativeRequiredTime(entry.CreatedAt)
		if err != nil {
			return plan, fmt.Errorf("entry %d has an invalid created_at", i+1)
		}
		updated, err := parseNativeRequiredTime(entry.UpdatedAt)
		if err != nil || updated.Before(created) {
			return plan, fmt.Errorf("entry %d has an invalid updated_at", i+1)
		}
		plan.entryPlans[i] = nativeImportEntryPlan{expiresAt: expires, lastRotatedAt: lastRotated,
			createdAt: created, updatedAt: updated, providerRaw: providerRaw, providerMeta: meta,
			knownProvider: knownProvider}
		nameScope := "personal"
		if entry.CollectionID != nil {
			nameScope = "collection:" + *entry.CollectionID
		}
		if seenNames[nameScope] == nil {
			seenNames[nameScope] = make(map[string]struct{})
		}
		if _, duplicate := seenNames[nameScope][entry.Name]; duplicate {
			intraConflicts[entry.Name] = struct{}{}
		}
		seenNames[nameScope][entry.Name] = struct{}{}
		if entry.AutoRotate {
			plan.autoRotateDisabled++
		}
	}

	if len(referencedCollections) != len(document.Collections) {
		return plan, fmt.Errorf("native vault document contains an unreferenced collection")
	}
	for name := range intraConflicts {
		plan.intraConflicts = append(plan.intraConflicts, name)
	}
	sort.Strings(plan.intraConflicts)
	return plan, nil
}

func (h *VaultImportHandler) findNativeImportConflicts(ctx *http.Request, q *db.Queries,
	userID string, entries []vaultExportEntry, intra []string) ([]string, error) {
	existing, err := h.personalImportNameSet(ctx.Context(), q, userID)
	if err != nil {
		return nil, fmt.Errorf("list existing personal entry names: %w", err)
	}
	conflicts := make(map[string]struct{}, len(intra))
	for _, name := range intra {
		conflicts[name] = struct{}{}
	}
	for _, entry := range entries {
		// Every collection in a native document is created with a fresh id, so
		// it cannot conflict with an existing collection scope. Personal entries
		// alone share an existing destination scope.
		if entry.CollectionID != nil {
			continue
		}
		if _, found := existing[entry.Name]; found {
			conflicts[entry.Name] = struct{}{}
		}
	}
	out := make([]string, 0, len(conflicts))
	for name := range conflicts {
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) > maxNativeConflictNames {
		out = out[:maxNativeConflictNames]
	}
	return out, nil
}

func writeNativeImportConflict(w http.ResponseWriter, r *http.Request, conflicts []string) {
	writeJSON(w, http.StatusConflict, nativeImportConflictError{
		Error: "native vault import has name conflicts; no entries were imported", Code: ErrCodeConflict,
		RequestID: getRequestID(r), Conflicts: conflicts,
	})
}

// NativeImportPreview validates a native-v1 document and reports only counts
// and conflicting entry names. It never echoes values or other secret fields.
func (h *VaultImportHandler) NativeImportPreview(w http.ResponseWriter, r *http.Request) {
	setVaultExportNoStoreHeaders(w)
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "unauthorized")
		return
	}
	upload, err := openNativeImportUpload(r)
	if err != nil {
		writeBadRequest(w, r, err.Error())
		return
	}
	defer func() {
		_ = upload.file.Close()
		cleanupNativeMultipartForm(r)
	}()
	document, err := decodeNativeImportDocument(upload.file)
	if err != nil {
		writeBadRequest(w, r, err.Error())
		return
	}
	plan, err := validateNativeImportDocument(document)
	if err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if !requireNativeImportIngress(w, r, plan) {
		return
	}
	conflicts, err := h.findNativeImportConflicts(r, h.handler.queries, userID,
		plan.document.Entries, plan.intraConflicts)
	if err != nil {
		logError(r, "vault.native_import.preview: conflict check failed", "error", err)
		writeInternalError(w, r, "native vault preview could not be completed")
		return
	}
	writeJSON(w, http.StatusOK, nativeImportPreview{Format: plan.document.Format,
		Version: plan.document.Version, IngressScope: plan.document.IngressScope,
		EntryCount:      len(plan.document.Entries),
		CollectionCount: len(plan.document.Collections), Conflicts: conflicts,
		AutoRotateDisabled: plan.autoRotateDisabled})
}

func nativeImportRandomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (h *VaultImportHandler) executeNativeImport(r *http.Request, userID string,
	plan nativeImportPlan) error {
	collectionIDs := make(map[string]string, len(plan.document.Collections))
	usedIDs := make(map[string]struct{}, len(plan.document.Collections)+len(plan.document.Entries))
	newID := func() (string, error) {
		for {
			id, err := nativeImportRandomID()
			if err != nil {
				return "", err
			}
			if _, duplicate := usedIDs[id]; !duplicate {
				usedIDs[id] = struct{}{}
				return id, nil
			}
		}
	}
	for _, collection := range plan.document.Collections {
		id, err := newID()
		if err != nil {
			return fmt.Errorf("generate collection id: %w", err)
		}
		collectionIDs[collection.SourceID] = id
	}
	entryIDs := make([]string, len(plan.document.Entries))
	for i := range entryIDs {
		id, err := newID()
		if err != nil {
			return fmt.Errorf("generate entry id: %w", err)
		}
		entryIDs[i] = id
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		return fmt.Errorf("begin native import: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	qtx := h.handler.queries.WithTx(tx)
	// Re-check under the write transaction so preview/confirmation time cannot
	// race another entry creation into this user's uniqueness namespace.
	conflicts, err := h.findNativeImportConflicts(r, qtx, userID, plan.document.Entries, plan.intraConflicts)
	if err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return &nativeConflictList{names: conflicts}
	}

	acceptedAt := sql.NullTime{Time: time.Now().UTC(), Valid: true}
	for i, collection := range plan.document.Collections {
		id := collectionIDs[collection.SourceID]
		if err := qtx.CreateCollectionWithPolicy(r.Context(), db.CreateCollectionWithPolicyParams{ID: id,
			Name: collection.Name, Description: collection.Description,
			CreatedBy:           sql.NullString{String: userID, Valid: true},
			PrivateAccessPolicy: string(collection.PrivateAccessPolicy)}); err != nil {
			return fmt.Errorf("create collection: %w", err)
		}
		if err := qtx.AddCollectionMember(r.Context(), db.AddCollectionMemberParams{
			CollectionID: id, UserID: userID, Role: "manager", AcceptedAt: acceptedAt,
			InvitedBy: sql.NullString{},
		}); err != nil {
			return fmt.Errorf("create private collection membership: %w", err)
		}
		times := plan.collectionTimes[i]
		if err := qtx.RestoreNativeImportedCollectionTimestamps(r.Context(),
			db.RestoreNativeImportedCollectionTimestampsParams{CreatedAt: sql.NullTime{Time: times.created, Valid: true},
				UpdatedAt: sql.NullTime{Time: times.updated, Valid: true}, ID: id}); err != nil {
			return fmt.Errorf("restore collection timestamps: %w", err)
		}
	}

	for i, entry := range plan.document.Entries {
		id := entryIDs[i]
		entryPlan := plan.entryPlans[i]
		var collectionID sql.NullString
		if entry.CollectionID != nil {
			collectionID = sql.NullString{String: collectionIDs[*entry.CollectionID], Valid: true}
		}
		encrypted, nonce, err := h.handler.encrypt([]byte(entry.Value))
		if err != nil {
			return fmt.Errorf("encrypt entry value: %w", err)
		}
		encName, err := h.handler.encryptColumn(entry.Name)
		if err != nil {
			return fmt.Errorf("encrypt entry name: %w", err)
		}
		encURL, encAlias, encUsername, encCategory, encNotes, err := h.handler.encryptMetaColumns(
			entry.URL, entry.AliasURL, entry.Username, entry.Category, entry.Notes)
		if err != nil {
			return fmt.Errorf("encrypt entry metadata: %w", err)
		}
		encProviderMeta, err := h.handler.encryptColumn(entryPlan.providerRaw)
		if err != nil {
			return fmt.Errorf("encrypt provider metadata: %w", err)
		}
		encCustomFields, err := h.handler.encryptCustomFields(entry.CustomFields)
		if err != nil {
			return fmt.Errorf("encrypt custom fields: %w", err)
		}
		providerAfter := []string(nil)
		if entryPlan.knownProvider {
			providerAfter = providerDestinations(entry.Provider, entryPlan.providerMeta)
		}
		createTicket, err := egressgate.Decide(egressgate.Request{EntryID: id,
			What: egressFieldProvider, After: providerAfter,
			Covers: providerDestinationCovers, MayRedirect: func() bool { return true }})
		if err != nil {
			return fmt.Errorf("authorize imported provider: %w", err)
		}
		scope := bidxScope(userID, collectionID)
		if err := vaultegress.CreateEntry(r.Context(), qtx, createTicket, vaultegress.CreateEntryParams{
			ID: id, UserID: userID, SecretOwnerUserID: userID, Name: encName,
			EncryptedValue: encrypted, Nonce: nonce, Url: toNullString(encURL), AliasUrl: toNullString(encAlias),
			Username: toNullString(encUsername), Category: toNullString(encCategory), Notes: toNullString(encNotes),
			AutoLogin: boolToInt64(entry.AutoLogin), RotationIntervalDays: intPtrToNullInt64(entry.RotationIntervalDays),
			ExpiresAt: entryPlan.expiresAt, Provider: toNullString(entry.Provider), ProviderMeta: toNullString(encProviderMeta),
			AutoRotate: sql.NullInt64{Int64: 0, Valid: true}, UrlBidx: h.handler.urlBlindIndex(scope, entry.URL),
			AliasUrlBidx: h.handler.urlBlindIndex(scope, entry.AliasURL),
			NameBidx:     h.handler.scopedNameBlindIndex(scope, entry.Name),
			CollectionID: collectionID,
		}); err != nil {
			// A concurrent writer can claim this exact name after the preflight
			// read but before this transaction acquires SQLite's write lock. The
			// unique blind index is the final authority; surface the same bounded
			// conflict and let the deferred rollback erase all earlier rows.
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				return &nativeConflictList{names: []string{entry.Name}}
			}
			return fmt.Errorf("create imported entry: %w", err)
		}

		// Preserve retired/future provider names as inert data. Without a local
		// adapter there is no declared egress and, critically, no injection spec
		// that could release the imported secret through the capability bridge.
		// Known providers regenerate defaults from their local declaration so
		// tenant-scoped host choices still pass through the egress chokepoint.
		defaultDestinations, injectionSpec := "", ""
		if entryPlan.knownProvider {
			defaultDestinations, injectionSpec = MarshalCapabilityDefaults(entry.Provider, entryPlan.providerMeta)
		}
		if defaultDestinations == "" {
			defaultDestinations = "[]"
		}
		if injectionSpec == "" {
			injectionSpec = "{}"
		}
		seedTicket, err := egressgate.Decide(egressgate.Request{EntryID: id,
			What: egressFieldDestinations, After: ceilingDestinations(parseDestinationPatterns(defaultDestinations)),
			Covers: destinationCovers, MayRedirect: func() bool { return true }})
		if err != nil {
			return fmt.Errorf("authorize provider capability defaults: %w", err)
		}
		if err := vaultegress.SeedCapabilityDefaults(r.Context(), qtx, seedTicket,
			vaultegress.CapabilityDefaultsParams{DestinationPatterns: defaultDestinations,
				InjectionSpec: injectionSpec, ID: id}); err != nil {
			return fmt.Errorf("seed provider capability defaults: %w", err)
		}
		encodedDestinations, err := json.Marshal(entry.DestinationPatterns)
		if err != nil {
			return fmt.Errorf("encode destination patterns: %w", err)
		}
		ceilingTicket, err := egressgate.Decide(egressgate.Request{EntryID: id,
			What: egressFieldDestinations, Before: ceilingDestinations(parseDestinationPatterns(defaultDestinations)),
			After: ceilingDestinations(entry.DestinationPatterns), Covers: destinationCovers,
			MayRedirect: func() bool { return true }})
		if err != nil {
			return fmt.Errorf("authorize destination patterns: %w", err)
		}
		if err := vaultegress.SetDestinationPatterns(r.Context(), qtx, ceilingTicket,
			vaultegress.DestinationPatternsParams{DestinationPatterns: string(encodedDestinations), ID: id}); err != nil {
			return fmt.Errorf("store destination patterns: %w", err)
		}
		if err := qtx.FinalizeNativeImportedVaultEntry(r.Context(), db.FinalizeNativeImportedVaultEntryParams{
			CustomFields: encCustomFields, LastRotatedAt: entryPlan.lastRotatedAt,
			CreatedAt: sql.NullTime{Time: entryPlan.createdAt, Valid: true},
			UpdatedAt: sql.NullTime{Time: entryPlan.updatedAt, Valid: true}, ID: id,
		}); err != nil {
			return fmt.Errorf("finalize imported entry: %w", err)
		}
	}

	detail := fmt.Sprintf("Native vault imported (user: %s, entries: %d, collections: %d, auto_rotate_disabled: %d)",
		userID, len(plan.document.Entries), len(plan.document.Collections), plan.autoRotateDisabled)
	if err := qtx.InsertActivity(r.Context(), db.InsertActivityParams{
		UserID: sql.NullString{String: userID, Valid: true}, Action: "vault.native_imported",
		Detail:    sql.NullString{String: truncateAudit(detail, maxAuditDetailLen), Valid: true},
		IpAddress: sql.NullString{String: truncateAudit(middleware.ClientIP(r), maxAuditIPLen), Valid: true},
		UserAgent: sql.NullString{String: truncateAudit(r.Header.Get("User-Agent"), maxAuditUserAgentLen),
			Valid: r.Header.Get("User-Agent") != ""},
	}); err != nil {
		return fmt.Errorf("write required native import audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit native import: %w", err)
	}
	return nil
}

type nativeConflictList struct{ names []string }

func (e *nativeConflictList) Error() string { return "native vault import has name conflicts" }

// NativeImportConfirm re-authenticates, reparses, revalidates, and imports the
// whole document in one transaction. Every failure, including the required
// audit write, rolls back every collection and entry.
func (h *VaultImportHandler) NativeImportConfirm(w http.ResponseWriter, r *http.Request) {
	setVaultExportNoStoreHeaders(w)
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeUnauthorized(w, r, "unauthorized")
		return
	}
	upload, err := openNativeImportUpload(r)
	if err != nil {
		writeBadRequest(w, r, err.Error())
		return
	}
	defer func() {
		_ = upload.file.Close()
		cleanupNativeMultipartForm(r)
	}()
	password := r.FormValue("password")
	if password == "" {
		writeBadRequest(w, r, "password is required to import a native vault")
		return
	}
	if !h.handler.reauthOrRefuse(w, r, r.Context(), userID, password) {
		return
	}
	document, err := decodeNativeImportDocument(upload.file)
	if err != nil {
		writeBadRequest(w, r, err.Error())
		return
	}
	plan, err := validateNativeImportDocument(document)
	if err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if !requireNativeImportIngress(w, r, plan) {
		return
	}
	conflicts, err := h.findNativeImportConflicts(r, h.handler.queries, userID,
		plan.document.Entries, plan.intraConflicts)
	if err != nil {
		logError(r, "vault.native_import.confirm: conflict check failed", "error", err)
		writeInternalError(w, r, "native vault import could not be completed")
		return
	}
	if len(conflicts) > 0 {
		writeNativeImportConflict(w, r, conflicts)
		return
	}
	if err := h.executeNativeImport(r, userID, plan); err != nil {
		var conflict *nativeConflictList
		if errors.As(err, &conflict) {
			writeNativeImportConflict(w, r, conflict.names)
			return
		}
		logError(r, "vault.native_import.confirm: transaction failed", "error", err)
		writeInternalError(w, r, "native vault import could not be completed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"imported": len(plan.document.Entries),
		"collections_created": len(plan.document.Collections), "auto_rotate_disabled": plan.autoRotateDisabled})
}

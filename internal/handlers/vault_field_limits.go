package handlers

import (
	"fmt"
	"strings"
)

// Field limits for a vault entry, in ONE place.
//
// These existed as literals inside CreateVaultEntry and (partly) UpdateVaultEntry,
// and the import path had none of them at all. That is the shape this codebase
// keeps producing: a rule enforced per call site drifts, and the site that
// forgets it is the one nobody tests.
//
// The import gap was not cosmetic. Update re-validates on every save and the edit
// form resubmits every metadata field, so a 300-character name written by import
// produced a row the operator could never save again: every edit came back 400
// about a field they had not touched. The missing trim also defeats
// checkConflicts and the scope-bound name index, because "GitHub" and
// "GitHub " are different strings to both.
const (
	maxEntryNameLen     = 255
	maxEntryValueLen    = 65536
	maxEntryURLLen      = 2048
	maxEntryUsernameLen = 255
	maxEntryNotesLen    = 10000
	minRotationDays     = 1
	maxRotationDays     = 3650
)

// vaultEntryFields is the mutable text of one entry, as any write path sees it.
type vaultEntryFields struct {
	Name     string
	Value    string
	URL      string
	AliasURL string
	Username string
	Notes    string
}

// vaultEntryTextInput is the JSON-facing form of the mutable text fields. The
// pointers preserve the distinction Update needs between "not supplied" and
// "supplied as empty". In particular, an empty Value on Update deliberately
// means "keep the current secret" and must not be mistaken for Create's
// required-value rule.
type vaultEntryTextInput struct {
	Name     *string
	Value    *string
	URL      *string
	AliasURL *string
	Username *string
	Notes    *string
}

// validateLiveEntryText is the canonical gate for the two JSON write surfaces.
// Create passes requireName/requireValue; Update passes only the fields present
// in its patch. Both retain the product's user-friendly normalization contract:
// identifier-like text is trimmed in place before validation and storage.
func validateLiveEntryText(in vaultEntryTextInput, requireName, requireValue bool) string {
	if in.Name == nil {
		if requireName {
			return "name is required"
		}
	} else {
		*in.Name = strings.TrimSpace(*in.Name)
		if *in.Name == "" {
			return "name is required"
		}
		if len(*in.Name) > maxEntryNameLen {
			return fmt.Sprintf("name must be %d characters or less", maxEntryNameLen)
		}
	}

	if in.Value == nil {
		if requireValue {
			return "value is required"
		}
	} else if *in.Value == "" {
		if requireValue {
			return "value is required"
		}
		// Update's established contract: an explicitly empty value is a no-op.
	} else if len(*in.Value) > maxEntryValueLen {
		return "value must be 64KB or less"
	}

	for _, field := range []struct {
		name  string
		value *string
		max   int
	}{
		{"url", in.URL, maxEntryURLLen},
		{"alias url", in.AliasURL, maxEntryURLLen},
		{"username", in.Username, maxEntryUsernameLen},
	} {
		if field.value == nil {
			continue
		}
		*field.value = strings.TrimSpace(*field.value)
		if len(*field.value) > field.max {
			return fmt.Sprintf("%s must be %d characters or less", field.name, field.max)
		}
	}
	if in.Notes != nil && len(*in.Notes) > maxEntryNotesLen {
		return fmt.Sprintf("notes must be %d characters or less", maxEntryNotesLen)
	}
	return ""
}

func vaultEntryCategoryValid(category string) bool {
	switch category {
	case "", "login", "password", "api_key", "database", "certificate", "credit_card",
		"ssh_key", "server", "identity", "bank_account", "email", "other":
		return true
	default:
		return false
	}
}

func validateRotationIntervalDays(interval *int) string {
	if interval == nil {
		return ""
	}
	if *interval < minRotationDays || *interval > maxRotationDays {
		return fmt.Sprintf("rotation_interval_days must be between %d and %d", minRotationDays, maxRotationDays)
	}
	return ""
}

// normalizeAndValidateEntryFields trims what should be trimmed and returns the
// first violation as a client-safe message, or "" when the entry is acceptable.
//
// Trimming happens BEFORE the length checks so " x " * 100 cannot pass a check
// it would fail once stored, and before the caller compares names, so conflict
// detection and the UNIQUE constraint see the same string the database will.
func normalizeAndValidateEntryFields(f *vaultEntryFields) string {
	f.Name = strings.TrimSpace(f.Name)
	f.URL = strings.TrimSpace(f.URL)
	f.AliasURL = strings.TrimSpace(f.AliasURL)
	f.Username = strings.TrimSpace(f.Username)

	switch {
	case f.Name == "":
		return "name is required"
	case len(f.Name) > maxEntryNameLen:
		return fmt.Sprintf("name must be %d characters or less", maxEntryNameLen)
	case f.Value == "":
		return "value is required"
	case len(f.Value) > maxEntryValueLen:
		return "value must be 64KB or less"
	case len(f.URL) > maxEntryURLLen:
		return fmt.Sprintf("url must be %d characters or less", maxEntryURLLen)
	case len(f.AliasURL) > maxEntryURLLen:
		return fmt.Sprintf("alias url must be %d characters or less", maxEntryURLLen)
	case len(f.Username) > maxEntryUsernameLen:
		return fmt.Sprintf("username must be %d characters or less", maxEntryUsernameLen)
	case len(f.Notes) > maxEntryNotesLen:
		return fmt.Sprintf("notes must be %d characters or less", maxEntryNotesLen)
	}
	return ""
}

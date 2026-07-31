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
// checkConflicts, which compares raw names, and UNIQUE(user_id, name), because
// "GitHub" and "GitHub " are different strings to both.
const (
	maxEntryNameLen     = 255
	maxEntryValueLen    = 65536
	maxEntryURLLen      = 2048
	maxEntryUsernameLen = 255
	maxEntryNotesLen    = 10000
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

package db

import (
	"strings"
	"testing"
)

// Nothing cleared last_rotation_error until 2026-07-27: it was only ever SET,
// never reset to NULL. Not even a SUCCESSFUL rotation cleared it, so once an
// entry failed once the error string was permanent.
//
// That was survivable only while the status badge ignored the field. Now that a
// recorded error makes computeRotationStatus return "error", a stale value
// pins an entry red forever and the badge becomes noise people learn to ignore
// exactly like the "fresh" it replaced.
//
// Both write paths must clear it, for the same reason: they replace the value
// the failure was about.
//
//	RotateVaultEntryValue -> the rotation just succeeded
//	UpdateVaultEntryValue -> a human replaced the credential by hand
func TestVaultValueWritesClearRotationError(t *testing.T) {
	for name, query := range map[string]string{
		"RotateVaultEntryValueUnchecked": rotateVaultEntryValueUnchecked,
		"UpdateVaultEntryValue":          updateVaultEntryValue,
	} {
		if !strings.Contains(query, "last_rotation_error = NULL") {
			t.Errorf("%s must clear last_rotation_error, otherwise a stale failure pins the entry to the error badge forever:\n%s", name, query)
		}
		// Guard the pairing too: clearing the error without stamping the
		// timestamp (or vice versa) leaves the two fields disagreeing.
		if !strings.Contains(query, "last_rotated_at = CURRENT_TIMESTAMP") {
			t.Errorf("%s must also stamp last_rotated_at", name)
		}
	}
}

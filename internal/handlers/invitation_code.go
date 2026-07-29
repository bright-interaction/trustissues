package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
)

// Invitation codes are bearer credentials, so they get the same at-rest
// treatment as every sibling credential in this database.
//
// They were the ONE exception: api_keys stores a SHA-256 hash,
// service_identities stores key_hash, and sessions store only a jti while the
// real bearer is a JWT signed with a secret that never touches the DB. The
// invite code sat in the clear.
//
// That mattered because THREAT-MODEL.md tells operators a stolen .db without the
// vault key "is safe to back up off-host", and /api/invitations/redeem is
// unauthenticated by design. So a keyless backup taken while an invite was
// pending could be read for the code and redeemed against the live server. An
// admin-role invite yields a real admin account, and an admin can reset another
// user's password and then unlock their vault. A copy documented as inert became
// a path to every secret.
//
// A bare hash is not enough on its own, because "resend invitation" has to email
// the original code. So both: the hash is what redemption looks up, and the code
// column holds vault-key ciphertext for resend.

// hashInviteCode returns the lookup value stored in invitations.code_hash.
//
// SHA-256 with no salt is deliberate and matches api_keys: the code is 80 bits
// of CSPRNG output from generateInviteCode, so it is not guessable and there is
// no dictionary to attack. A per-row salt would also make the O(1) index lookup
// impossible without changing redemption into a table scan.
func hashInviteCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// sealInviteCode encrypts an invite code for storage. On failure it returns an
// empty string, which stores nothing recoverable: redemption still works (it
// uses the hash), and only resend degrades. Failing closed on the ciphertext is
// better than falling back to cleartext, which is the bug this closes.
func (h *UserHandler) sealInviteCode(code string) string {
	if h.vault == nil {
		slog.Error("invitations: no vault wired, invite code cannot be stored encrypted")
		return ""
	}
	enc, err := h.vault.encryptColumn(code)
	if err != nil {
		slog.Error("invitations: sealing invite code failed", "error", err)
		return ""
	}
	return enc
}

// openInviteCode decrypts a stored invite code for display or resend. An empty
// result means the code cannot be shown, which the caller must render as such
// rather than as a blank code.
func (h *UserHandler) openInviteCode(stored string) string {
	if stored == "" || h.vault == nil {
		return ""
	}
	plain, err := h.vault.decryptColumn(stored)
	if err != nil {
		slog.Error("invitations: opening invite code failed", "error", err)
		return ""
	}
	return plain
}

// nullableField distinguishes three JSON states that a plain pointer collapses
// into two: absent, explicit null, and a value.
//
// With `*string`, both "the key was omitted" and `"expires_at": null` decode to
// nil, so a handler written as `if req.X != nil` treats an explicit null as
// "leave it alone". That is why emptying the expiry date in the vault edit form
// was a silent no-op that still toasted "Secret updated": the form sends null to
// mean clear, and the server read it as unchanged. The user sees the old date
// come back on reload with nothing explaining why.
type nullableField[T any] struct {
	Set   bool // the key was present in the JSON at all
	Value *T   // nil when the caller sent an explicit null
}

// UnmarshalJSON records that the key was present, then decodes the value.
func (n *nullableField[T]) UnmarshalJSON(b []byte) error {
	n.Set = true
	if string(b) == "null" {
		n.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	n.Value = &v
	return nil
}

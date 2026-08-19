package handlers

import (
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
)

// THE PENDING-REVOKE MARKER SET IS A QUEUE, NOT A SLOT.
//
// The four pending_revoke_* scalars can describe exactly ONE outstanding
// revoke. deferRevokeOldProviderKey used to overwrite them unconditionally, so
// a second stranded key EVICTED the first: rotation N's revoke of K1 fails,
// rotation N+1 mints K3 and overwrites the markers with K2's coordinates, and
// K1 is now live at the vendor with nothing anywhere in the product naming it.
// The audit measured exactly that (sink [503 /keys/K1, 503 /keys/K2,
// 200 /keys/K2]) and it is the reason this file exists.
//
// The fix keeps the four scalars as the HEAD -- the revoke the retry endpoint,
// the chip, the resolve dialog and pendingRevokeStatusFrom all act on, unchanged
// -- and adds ONE more server-owned key holding everything the head displaced.
// Nothing is evicted: a defer over a surviving head pushes that head onto the
// backlog first, and discharging the head promotes the oldest backlog entry into
// it. So the product always names one key at a time, but it never FORGETS one.
//
// WHY A JSON-ENCODED STRING AND NOT A JSON ARRAY.
//
// provider_meta is read as map[string]string everywhere in this package
// (ParseProviderMeta), and json.Unmarshal into a string map does not drop a
// non-string value: it records a type error, discards it, and leaves the key
// present holding "". A real JSON array under this key would therefore be
// silently emptied by the very next reader, which is the exact data-loss class
// this column has already produced three times (see
// providerMetaBytesPreservingTypes, reconcileProviderMetaForStorage and
// redactReservedProviderMetaKeys, all of which were fixed for it). A string
// value round-trips through every one of those unchanged.
//
// NO MIGRATION, AND THAT IS DELIBERATE.
//
// The key is purely ADDITIVE. Every production row written before this change
// simply lacks it, parseStrandedRevokes reads absent as "no backlog", and every
// path behaves exactly as it did. Relaxing an invariant IS a migration in this
// project (the 2026-08-17 transient-marker lockout); adding a key that every
// reader already treats as optional is not. TestOldShapeProviderMetaRowsStill-
// ReadAndDischargeCorrectly seeds a row in the pre-change shape and proves it.
const pendingRevokeStranded = "pending_revoke_stranded"

// maxStrandedRevokes bounds the backlog. It is a cap on an ENCRYPTED column that
// no operator can prune by hand, so it cannot be unbounded.
//
// On overflow the OLDEST entries are kept and the newest is refused, which is
// the opposite of the usual ring-buffer instinct and is the whole point: the
// oldest stranded key is the one whose coordinates have survived the most
// rotations without being retried, so it is the one closest to being forgotten
// forever. The refused key is not silent either -- it goes out through
// last_revoke_error, the same channel an unnameable predecessor id already uses,
// so the rotation downgrades to partial and alarms.
//
// Reaching 32 stranded keys on one entry means 32 consecutive rotations each
// failed their revoke, which is a provider outage measured in months. The bound
// exists so that state degrades loudly rather than growing a column without
// limit.
const maxStrandedRevokes = 32

// strandedRevoke is one displaced pending-revoke marker set. The field names are
// the four head markers with their pending_revoke_ prefix dropped; the JSON tags
// are the wire format of the backlog and must not be renamed casually, because
// they are what a production row already holds.
type strandedRevoke struct {
	KeyID  string `json:"key_id"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Auth   string `json:"auth"`
}

// parseStrandedRevokes reads the backlog. malformed reports that the key is
// PRESENT but unreadable, which callers must treat as "leave it alone" rather
// than "there is nothing there": the only writer is this file, so an unreadable
// value is corruption, and deleting it would destroy the coordinates of keys
// that are live at a vendor.
func parseStrandedRevokes(m map[string]string) (list []strandedRevoke, malformed bool) {
	raw := strings.TrimSpace(m[pendingRevokeStranded])
	if raw == "" {
		return nil, false
	}
	var out []strandedRevoke
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		slog.Error("vault pending revoke: the stranded-revoke backlog did not parse; leaving it untouched "+
			"rather than discarding the coordinates of keys that may be live at the provider",
			"error", err)
		return nil, true
	}
	return out, false
}

// setStrandedRevokes writes the backlog, removing the key entirely when the list
// is empty so a discharged row carries no residue.
func setStrandedRevokes(m map[string]string, list []strandedRevoke) {
	if len(list) == 0 {
		delete(m, pendingRevokeStranded)
		return
	}
	b, err := json.Marshal(list)
	if err != nil {
		// Unreachable for a slice of plain string structs. The safe direction is
		// to leave whatever is stored rather than blank it.
		slog.Error("vault pending revoke: could not encode the stranded-revoke backlog", "error", err)
		return
	}
	m[pendingRevokeStranded] = string(b)
}

// pushDisplacedHeadOntoBacklog moves a surviving head marker set onto the
// backlog when a NEW defer is about to overwrite it with a different key.
//
// It is the refusal-to-evict deferRevokeOldProviderKey was missing. Three cases
// and only the third moves anything:
//
//   - no head at all: nothing to displace.
//   - the head names the SAME key the caller is deferring: this is a re-defer of
//     one key (a retry that failed and is being recorded again), so overwriting
//     it in place is correct and appending would duplicate it.
//   - the head names a DIFFERENT key: it is a stranded predecessor whose
//     coordinates are the only record of how to kill it. Push it.
//
// Identity is the recorded id when both sides have one, and the URL otherwise,
// because a row written before deferRevokeOldProviderKey started recording ids
// has no id to compare and its URL is what distinguishes it.
func pushDisplacedHeadOntoBacklog(m map[string]string, newURL, newKeyID string) {
	headURL := m[pendingRevokeURL]
	headKeyID := m[pendingRevokeKeyID]
	if headURL == "" && headKeyID == "" {
		return
	}
	if sameRevokeTarget(headKeyID, headURL, newKeyID, newURL) {
		return
	}
	backlog, malformed := parseStrandedRevokes(m)
	if malformed {
		// Do not rewrite a value we could not read. The head is still overwritten
		// by the caller, so say so through the alarm channel rather than dropping
		// the fact.
		m["last_revoke_error"] = "a previous key's revoke coordinates could not be preserved because this " +
			"entry's stranded-revoke record is unreadable; delete the predecessor at the provider by hand"
		return
	}
	for _, s := range backlog {
		if sameRevokeTarget(s.KeyID, s.URL, headKeyID, headURL) {
			return // already recorded; a re-defer must not duplicate it
		}
	}
	if len(backlog) >= maxStrandedRevokes {
		// Keep the oldest, refuse the newest, and be loud about it. See the doc
		// on maxStrandedRevokes for why this direction.
		slog.Error("vault pending revoke: the stranded-revoke backlog is full, so this predecessor's "+
			"coordinates were not preserved; it must be deleted at the provider by hand",
			"key_id", headKeyID, "backlog", len(backlog))
		m["last_revoke_error"] = "too many previous keys are already stranded on this entry, so this one's " +
			"revoke coordinates were not preserved; delete it at the provider by hand"
		return
	}
	setStrandedRevokes(m, append(backlog, strandedRevoke{
		KeyID:  headKeyID,
		Method: m[pendingRevokeMethod],
		URL:    headURL,
		Auth:   m[pendingRevokeAuth],
	}))
}

// sameRevokeTarget reports whether two marker sets describe one key.
func sameRevokeTarget(aID, aURL, bID, bURL string) bool {
	if aID != "" && bID != "" {
		return aID == bID
	}
	return aURL != "" && aURL == bURL
}

// dischargePendingRevokeHead retires the head marker set and PROMOTES the oldest
// backlog entry into it.
//
// It replaces the former deletePendingRevokeMarkers, and the rename is load
// bearing: a reader who sees "delete" and gets "delete and promote" is exactly
// the trap this package keeps documenting. Every caller wants the promotion --
// performPendingRevoke on a confirmed success, the retry endpoint's transform,
// and the resolve endpoint's acknowledgement all mean "this key is settled",
// which says nothing about the older ones behind it.
//
// A backlog that does not parse is left exactly as found, so the head is
// discharged and nothing is destroyed.
func dischargePendingRevokeHead(m map[string]string) {
	for _, k := range pendingRevokeMarkerKeys {
		delete(m, k)
	}
	backlog, malformed := parseStrandedRevokes(m)
	if malformed || len(backlog) == 0 {
		if !malformed {
			delete(m, pendingRevokeStranded)
		}
		return
	}
	next := backlog[0]
	m[pendingRevokeMethod] = next.Method
	m[pendingRevokeURL] = next.URL
	m[pendingRevokeAuth] = next.Auth
	if next.KeyID != "" {
		m[pendingRevokeKeyID] = next.KeyID
	}
	setStrandedRevokes(m, backlog[1:])
}

// outstandingRevokeKeyIDs names every key this row still says is live at the
// provider: the head first, then the backlog oldest-first.
//
// The head id comes from pendingRevokeStatusFromMeta, the SAME derivation the
// chip and the resolve dialog use, so the alarm can never name a key the
// operator is not also shown.
func outstandingRevokeKeyIDs(m map[string]string) []string {
	var out []string
	if st := pendingRevokeStatusFromMeta(m); st != nil && st.PredecessorKeyID != "" {
		out = append(out, st.PredecessorKeyID)
	}
	backlog, _ := parseStrandedRevokes(m)
	for _, s := range backlog {
		if s.KeyID != "" {
			out = append(out, s.KeyID)
		}
	}
	return out
}

// ─── the alarm, and its identity ─────────────────────────────────────────────

// revokeKeyListPrefix and revokeKeyListSuffix bracket the key identity appended
// to revokeStillLiveMsg. They are parsed back out by splitRevokeClause, so the
// two must move together.
const (
	revokeKeyListPrefix = " [keys: "
	revokeKeyListSuffix = "]"
	revokeKeyListSep    = ", "
)

// sanitizeRevokeKeyIDs bounds what may be written into last_rotation_error, and
// is the reason carrying identity there is not a new disclosure.
//
// conservativeKeyIDPattern is the SAME filter pendingRevokeStatusFrom already
// applies to predecessor_key_id, which every client that can read the entry
// already receives on its GET and list responses. So an id that reaches the
// alarm is an id that surface has already handed out, to the same readers, under
// the same authorization. Nothing else may: no URL, no host, no upstream body,
// no raw provider error. An id that fails the charset is DROPPED, and an alarm
// left with no nameable id degrades to the bare revokeStillLiveMsg, which is
// precisely the pre-change behaviour.
//
// Sorted and deduped because the rendered string is a CAS pre-image
// (CASVaultEntryRotationError compares it byte-for-byte), so a nondeterministic
// order would make the clear miss for no reason.
func sanitizeRevokeKeyIDs(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !conservativeKeyIDPattern.MatchString(id) || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// revokeStillLiveMsgFor renders the still-live alarm naming the keys it is about.
//
// With no nameable id it returns the bare const, byte-identical to what every
// row written before this change already holds.
func revokeStillLiveMsgFor(keyIDs []string) string {
	ids := sanitizeRevokeKeyIDs(keyIDs)
	if len(ids) == 0 {
		return revokeStillLiveMsg
	}
	return revokeStillLiveMsg + revokeKeyListPrefix + strings.Join(ids, revokeKeyListSep) + revokeKeyListSuffix
}

// splitRevokeClause takes last_rotation_error apart into the part that is NOT
// about the revoke and the key list the revoke clause names.
//
// It recognises exactly the shapes foldRevokeOutcome produces and nothing else:
// the message alone, or the message as a trailing "; "-joined suffix, each with
// an optional key list. A value that merely CONTAINS the message somewhere the
// join never puts it is left alone, which is the property the former
// withoutRevokeStillLive had and must keep.
func splitRevokeClause(s string) (head, keyList string, ok bool) {
	rest := s
	if strings.HasSuffix(rest, revokeKeyListSuffix) {
		if i := strings.LastIndex(rest, revokeKeyListPrefix); i >= 0 {
			keyList = rest[i+len(revokeKeyListPrefix) : len(rest)-len(revokeKeyListSuffix)]
			rest = rest[:i]
		}
	}
	switch {
	case rest == revokeStillLiveMsg:
		return "", keyList, true
	case strings.HasSuffix(rest, "; "+revokeStillLiveMsg):
		return strings.TrimSuffix(rest, "; "+revokeStillLiveMsg), keyList, true
	}
	return "", "", false
}

// withoutRevokeStillLiveKeys settles the named keys in a last_rotation_error
// value and returns what remains.
//
// THIS IS THE PER-KEY CLEAR, AND IT IS THE HALF THAT MAKES THE MARKER QUEUE
// WORTH ANYTHING. Settling one of two still-live keys used to erase the alarm
// for both, because the alarm was one identity-free const that stood for N
// facts. Now the clause carries its own subject: remove only the settled ids,
// and drop the clause only when none are left.
//
// Three behaviours worth stating, because each is a decision:
//
//   - An alarm with NO key list (every row written before this change, and any
//     alarm whose ids all failed the charset filter) is cleared wholesale, which
//     is exactly the pre-change behaviour. The value literally does not encode
//     which keys it is about, so there is nothing better available and pretending
//     otherwise would strand the alarm forever with no way to clear it.
//   - Settling nothing leaves the value byte-identical, so the caller's
//     `cleared == current` early return fires and no write happens.
//   - A co-resident failure (a delivery error joined by foldRevokeOutcome) is
//     preserved in every case. It is still true.
func withoutRevokeStillLiveKeys(s string, settled []string) string {
	head, keyList, ok := splitRevokeClause(s)
	if !ok {
		return s
	}
	settledSet := map[string]bool{}
	for _, id := range settled {
		settledSet[strings.TrimSpace(id)] = true
	}
	var remaining []string
	for _, id := range strings.Split(keyList, ",") {
		id = strings.TrimSpace(id)
		if id == "" || settledSet[id] {
			continue
		}
		remaining = append(remaining, id)
	}
	if len(remaining) == 0 {
		return head
	}
	clause := revokeStillLiveMsgFor(remaining)
	if head == "" {
		return clause
	}
	return head + "; " + clause
}

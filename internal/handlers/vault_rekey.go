package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// Master-key rotation.
//
// Before this existed, changing TRUSTISSUES_VAULT_KEY orphaned every encrypted
// value. The boot gate (EnforceVaultKey) refused to start, which was correct
// because the data was still recoverable, but the only documented way forward
// was a manual export / re-import through the UI. That is not a procedure you
// want to be discovering during a suspected key compromise, and it is not one a
// second operator can execute from a runbook at 2am.
//
// The shape here is:
//
//	dual-key READ  (VaultHandler.previous, columncrypto.DecryptStringAny)
//	    + one exhaustive re-encrypt SWEEP (RekeyVault, below)
//	    + an operator surface that says which state you are in without being asked
//
// The read half is what makes the write half optional-in-time: a store that is
// unswept, half-swept, or restored from a backup taken before the sweep keeps
// serving, so the sweep is never load-bearing for availability. The sweep just
// makes it safe to delete the old key.
//
// # Why there is no per-row key id column
//
// The original design note asked for a key id stamped on every row. This does
// not: trial decryption under the keyring answers "which key opens this row"
// authoritatively, and a stored key id would be a SECOND source of truth that
// can disagree with the bytes it describes. Every recent data-loss bug in this
// codebase has that shape (a declared property nothing enforces, a probe that
// understood one of three crypto families, a version filter that excluded the
// rows it was meant to check). Ciphertext cannot lie about which key opens it.
//
// Resumability is preserved without the stamp: the sweep is idempotent because
// "needs conversion" is recomputed from the data every run, so a crashed or
// rolled-back sweep is fixed by running it again, and a half-swept store is
// simply a store where some rows still answer "previous".

// rekeyFamily labels which crypto scheme a keyed surface uses. There are FOUR
// live schemes plus one keyed non-ciphertext, and they do not share a
// derivation, a marker, or even a notion of where the nonce lives. A sweep that
// understands one of them silently skips the rest, which is how the boot key
// gate shipped inert over two thirds of its own surface area (see
// vaultKeyOpensExistingData). Every surface below carries its family so the
// conversion code cannot accidentally apply the wrong rules.
type rekeyFamily string

const (
	// familyVaultValue: raw AES-256-GCM with the nonce in its OWN column and no
	// marker in the payload. encryption_version says which derivation sealed it:
	// 2 = PBKDF2("trustissues:vault:v2"), 1 = sha256(key + ":secrets-vault").
	familyVaultValue rekeyFamily = "vaultvalue"
	// familyVaultColumn: the vault handler's own column scheme, "enc:v1:" +
	// base64(nonce || ciphertext), keyed by the v2 derivation. An UNPREFIXED
	// value is cleartext by contract, not ciphertext under an unknown key.
	familyVaultColumn rekeyFamily = "vaultcolumn"
	// familyColumnCrypto: internal/columncrypto, "tienc:v1:" + base64(nonce ||
	// ciphertext), keyed by PBKDF2("trustissues:column:v1"). Legacy rows are bare
	// base64 with no marker, which is why "is this plaintext" is answered by
	// trying to decrypt rather than by a prefix alone.
	familyColumnCrypto rekeyFamily = "columncrypto"
	// familyRawGCM: AES-256-GCM with the nonce in a sibling column and no marker
	// anywhere, stored BASE64-ENCODED in a TEXT column. Only
	// notification_channels.config. The ciphertext is produced by the same
	// EncryptValue as familyVaultValue, but the column is text rather than a
	// BLOB, so the bytes are base64 on the way in and base64-decoded on the way
	// out (see decodeRawGCMColumn / encodeRawGCMColumn). That encoding is the
	// entire reason this is a separate family and not folded into
	// familyVaultValue.
	familyRawGCM rekeyFamily = "rawgcm"
	// familyBlindIndex: NOT ciphertext. A deterministic HMAC-SHA256 of a
	// normalized URL host under PBKDF2("trustissues:vault:bidx:v1"), used so
	// autofill can match on an encrypted url column.
	//
	// This is the surface a rotation is most likely to miss and the one whose
	// failure is quietest. Nothing "fails to decrypt": the index simply stops
	// matching the index the new key computes, so browser autofill returns no
	// entries and the vault looks empty for that host. No error, no log line, no
	// [decryption error] in the UI. It must be RECOMPUTED, not re-encrypted.
	familyBlindIndex rekeyFamily = "blindindex"
)

// keyedSurface is one column (or one settings key) holding material derived from
// the master vault key.
//
// This slice is the LIST in "the sweep must be exhaustive and list-driven". Two
// things walk it: RekeyVault, which converts each surface, and
// TestRekeyCoversEveryKeyedColumn, which walks the REAL schema and fails when a
// column exists that is neither listed here nor explicitly classified as
// unkeyed. Adding an encrypted column without touching either is what orphans
// that column's data on the next rotation, so the guard refuses to let a new
// column go unclassified.
type keyedSurface struct {
	Table  string
	Column string
	Family rekeyFamily
	// SettingKey narrows a key/value row. settings.value holds a dozen unrelated
	// things and only two of them are ciphertext, so the surface is the (key,
	// value) pair rather than the column.
	SettingKey string
	// NonceColumn names the sibling column holding the GCM nonce, for the two
	// families that keep it out of band. Empty for self-contained formats.
	NonceColumn string
	// Why records what this column holds and what breaks if a rotation skips it.
	Why string
	// Field is the ledger handle for the column, for the families whose scan
	// DECRYPTS to classify (familyVaultColumn and familyColumnCrypto). It is the
	// zero Field for the families that do not need one here: familyBlindIndex is
	// an HMAC and is never opened, familyVaultValue goes through secretexit,
	// which declares vault_entries.encrypted_value beside its own door, and
	// familyRawGCM reuses the field declared beside DecryptInstanceConfig.
	//
	// It is on the surface rather than at the call site because this inventory is
	// already the one list that says which columns hold key-derived material, and
	// a second list saying which column each one is would be a second thing to
	// keep in step. vaultfield refuses the zero Field at the first open, so a
	// surface that gains a decrypting scan without gaining a field fails loudly
	// rather than opening something the ledger never heard of.
	Field vaultfield.Field
}

// rekeySurfaces is the complete inventory of vault-key-derived material.
//
// Ordering is presentation only; the sweep converts each table in one pass.
var rekeySurfaces = []keyedSurface{
	{Table: "vault_entries", Column: "encrypted_value", NonceColumn: "nonce", Family: familyVaultValue,
		Why: "the secret itself"},
	{Table: "vault_entries", Column: "name", Family: familyVaultColumn, Field: vaultFieldName,
		Why: "the operator's label for the entry, the column that describes it best"},
	{Table: "vault_entries", Column: "url", Family: familyVaultColumn, Field: vaultFieldURL,
		Why: "which site a credential belongs to"},
	{Table: "vault_entries", Column: "alias_url", Family: familyVaultColumn, Field: vaultFieldAliasURL,
		Why: "a second host the same credential logs into"},
	{Table: "vault_entries", Column: "username", Family: familyVaultColumn, Field: vaultFieldUsername,
		Why: "the account name the secret pairs with"},
	{Table: "vault_entries", Column: "category", Family: familyVaultColumn, Field: vaultFieldCategory,
		Why: "user-chosen grouping label"},
	{Table: "vault_entries", Column: "notes", Family: familyVaultColumn, Field: vaultFieldNotes,
		Why: "free text, routinely holds recovery codes and second factors"},
	{Table: "vault_entries", Column: "provider_meta", Family: familyVaultColumn, Field: vaultFieldProviderMeta,
		Why: "provider account ids and key ids used by auto-rotation"},
	{Table: "vault_entries", Column: "rotation_targets", Family: familyVaultColumn, Field: vaultFieldRotationTargets,
		Why: "delivery endpoints, embeds webhook HMAC secrets"},
	{Table: "vault_entries", Column: "custom_fields", Family: familyVaultColumn, Field: vaultFieldCustomFields,
		Why: "arbitrary per-entry fields, explicitly allowed to be secret"},
	{Table: "vault_entries", Column: "url_bidx", Family: familyBlindIndex,
		Why: "autofill lookup token; a stale one matches nothing and reports no error"},
	{Table: "vault_entries", Column: "alias_url_bidx", Family: familyBlindIndex,
		Why: "same, for the alias host"},
	{Table: "vault_entries", Column: "name_bidx", Family: familyBlindIndex,
		Why: "per-vault-scope name uniqueness token; a stale one stops colliding, so a rotation that " +
			"skipped it would let two entries share a name and neither would be reported"},
	{Table: "invitations", Column: "code", Family: familyVaultColumn, Field: vaultFieldRekeyInvitationCode,
		Why: "the pending invite code, kept recoverable so it can be re-sent"},
	{Table: "users", Column: "totp_secret", Family: familyColumnCrypto, Field: vaultFieldTOTPSecret,
		Why: "2FA seed; orphaning it locks every enrolled user out"},
	{Table: "settings", Column: "value", SettingKey: "smtp_password", Family: familyColumnCrypto,
		Field: vaultFieldSMTPPassword,
		Why:   "SMTP relay credential, the only way invitations get delivered"},
	{Table: "settings", Column: "value", SettingKey: vaultKeyCheckSetting, Family: familyColumnCrypto,
		Field: vaultFieldKeySentinel,
		Why:   "the boot key sentinel; if it stays on the old key the next boot is refused"},
	{Table: "settings", Column: "value", SettingKey: auditDEKSetting, Family: familyColumnCrypto,
		Field: vaultFieldAuditDEK,
		Why: "the WRAPPED audit-name DEK, and the reason this rotation never has to touch an " +
			"append-only audit row. capability_log.secret_name and service_secret_audit.secret_names " +
			"are encrypted under this key, not under the master key, so rewrapping this one value is " +
			"the whole rotation for both of those columns. Orphan it and every recorded secret name " +
			"in the audit trail becomes unreadable, permanently, because the rows themselves can " +
			"never be rewritten to fix it"},
	{Table: "notification_channels", Column: "config", NonceColumn: "config_nonce", Family: familyRawGCM,
		Why: "channel config, holds webhook URLs and bot tokens"},
}

// RekeySurfaceReport is the per-surface outcome of a scan or a sweep.
type RekeySurfaceReport struct {
	Table      string `json:"table"`
	Column     string `json:"column"`
	SettingKey string `json:"setting_key,omitempty"`
	Family     string `json:"family"`
	Why        string `json:"why"`
	// Scanned counts rows examined, including ones with nothing in the column.
	Scanned int `json:"scanned"`
	// OnCurrent / OnPrevious / Plaintext / Stale / Collided / Unreadable
	// partition the values that actually hold something.
	OnCurrent  int `json:"on_current"`
	OnPrevious int `json:"on_previous"`
	Plaintext  int `json:"plaintext"`
	// Stale counts blind indexes that match no key on the ring. Only
	// familyBlindIndex can be stale: it is an HMAC recomputed from cleartext, so
	// unlike ciphertext it can be repaired with no previous key.
	Stale int `json:"stale"`
	// Collided counts blind indexes the sweep CANNOT write because another row
	// of the same user already holds that token. Only vault_entries.name_bidx
	// can reach this state. See RekeyReport.NameIndexCollisions.
	Collided   int `json:"collided"`
	Unreadable int `json:"unreadable"`
	// Converted is populated by a sweep, zero by a read-only scan.
	Converted int `json:"converted"`
}

// RekeyBlocker names one value that no configured key opens.
//
// It carries the row id and never the value, because this is rendered in the
// admin UI and written to logs.
type RekeyBlocker struct {
	Table      string `json:"table"`
	Column     string `json:"column"`
	SettingKey string `json:"setting_key,omitempty"`
	RowID      string `json:"row_id"`
	Reason     string `json:"reason"`
}

// RekeyReport is what both the status endpoint and the sweep endpoint return.
type RekeyReport struct {
	// Status is one of:
	//   already_current  every keyed value opens under the current key
	//   needs_rekey      at least one value is still on the previous key, or at
	//                    least one blind index is stale
	//   converted        a sweep ran and moved everything to the current key
	//   blocked          at least one value opens under NEITHER key
	Status string `json:"status"`
	// PreviousKeyConfigured reports whether TRUSTISSUES_VAULT_KEY_PREVIOUS is set.
	PreviousKeyConfigured bool `json:"previous_key_configured"`
	// Fingerprints let an operator confirm WHICH keys are loaded without ever
	// displaying one. Truncated salted hashes: useless for recovering a key,
	// enough to tell two keys apart in a screenshot or a support thread.
	CurrentKeyFingerprint  string `json:"current_key_fingerprint"`
	PreviousKeyFingerprint string `json:"previous_key_fingerprint,omitempty"`

	Surfaces []RekeySurfaceReport `json:"surfaces"`
	// Blockers is capped: a store where everything is unreadable would otherwise
	// produce one entry per row, and the operator needs the shape of the problem,
	// not a dump of it.
	Blockers      []RekeyBlocker `json:"blockers"`
	BlockersTotal int            `json:"blockers_total"`

	ValuesOnCurrent  int `json:"values_on_current"`
	ValuesOnPrevious int `json:"values_on_previous"`
	// ValuesStale counts blind indexes that match no key on the ring. Kept
	// separate from ValuesOnPrevious because the remedy is different: a stale
	// index is repaired by recomputing it, which needs no previous key, so a
	// store whose only problem is stale indexes must NOT be told to go and find
	// an old key it never lost.
	ValuesStale int `json:"values_stale"`
	// NameIndexCollisions counts entry name indexes the sweep left alone because
	// writing them would violate UNIQUE(user_id, name_bidx).
	//
	// This is NOT work the sweep can do, which is why it is not folded into
	// ValuesStale: two of one user's entries genuinely share a name, and the
	// remedy is an operator renaming one of them, not another sweep. Counting it
	// as stale would either wedge the verify pass or, once tolerated there, keep
	// the status page saying "needs rekey" forever for a state no rekey fixes.
	//
	// It is a REPORTED number rather than a silent skip because the uniqueness
	// that index stands in for is not being enforced for that pair until somebody
	// renames one. The row ids go to the log, never to this struct's siblings that
	// might carry a name.
	NameIndexCollisions int `json:"name_index_collisions"`
	ValuesUnreadable    int `json:"values_unreadable"`
	RowsConverted       int `json:"rows_converted"`

	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMS int64  `json:"duration_ms"`
	// Error explains an aborted sweep in operator language. Never contains key
	// material or plaintext.
	Error string `json:"error,omitempty"`
}

// maxReportedBlockers caps RekeyReport.Blockers. See the field comment.
const maxReportedBlockers = 25

// ErrRekeyBlocked reports that at least one stored value opens under neither the
// current nor the previous key, so the sweep refused to write anything.
//
// Refusing is the whole point. A sweep that "skipped the ones it could not read"
// would commit a store that is PARTLY on the new key with a handful of rows
// still sealed under something else, and the operator would then delete the old
// key believing the rotation succeeded. Loud refusal keeps every recovery option
// open; a silent skip closes them permanently.
var ErrRekeyBlocked = errors.New("re-encrypt sweep refused: some stored values open under no configured key")

// ErrRekeyNoPreviousKey reports that a sweep was requested with no previous key
// configured and data that needs one.
var ErrRekeyNoPreviousKey = errors.New("TRUSTISSUES_VAULT_KEY_PREVIOUS is not set, so there is no old key to convert from")

// ErrRekeyInProgress reports a concurrent sweep.
var ErrRekeyInProgress = errors.New("a re-encrypt sweep is already running")

// errRekeyPrivateIngressRequired is returned only by the HTTP-bound wrapper.
// Boot-time rekey is server-initiated work and deliberately calls RekeyVault,
// which does not pretend an ingress transport exists.
var errRekeyPrivateIngressRequired = errors.New("private ingress required for a protected-vault rekey")

// vaultKeyFingerprint returns a short, non-reversible label for a master key.
//
// It is salted with a fixed context string so it is not a bare sha256 of the
// key, and truncated to 4 bytes so it is obviously an identifier rather than a
// digest anyone would try to attack. Its only job is letting an operator say
// "the store is on a1b2c3d4 and my env has e5f6a7b8" without pasting keys into a
// support thread.
func vaultKeyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("trustissues:vault:keyfp:v1|" + key))
	return hex.EncodeToString(sum[:4])
}

// rekeyMu serialises sweeps process-wide.
//
// Two concurrent sweeps would each read the pre-conversion state, and the second
// one to commit would be operating on a plan computed against rows the first one
// already rewrote. SQLite would serialise the writes, so nothing would be
// corrupted, but the second sweep's verify pass would fail on rows it did not
// expect to have changed and it would roll back a rotation that had in fact
// succeeded. A double-clicked button is not an error the operator should have to
// interpret, so the second call gets a clean 409.
var rekeyMu sync.Mutex
var rekeyRunning bool

// keyAge says which configured key opened a value.
type keyAge int

const (
	keyAgeEmpty     keyAge = iota // nothing stored
	keyAgePlaintext               // stored, but not ciphertext under any key
	keyAgeCurrent                 // opens under the current master key
	keyAgePrevious                // opens only under the previous master key
	// keyAgeStale is a blind index matching NO key on the ring. Blind indexes
	// only: an HMAC is recomputed from cleartext rather than decrypted, so this
	// is repairable with no previous key, unlike keyAgeUnknown ciphertext.
	keyAgeStale
	// keyAgeCollided is a blind index the sweep must NOT write, because another
	// row already holds the token it would have to write. vault_entries.name_bidx
	// only: it is the one blind index carrying a UNIQUE constraint.
	//
	// It is separated from keyAgeStale because the two need opposite handling. A
	// stale index is work the sweep does; a collided one is work no sweep can do,
	// and treating it as stale is what let one duplicate name make the whole
	// rotation impossible. See scanVaultEntries.
	keyAgeCollided
	keyAgeUnknown // marked ciphertext that opens under neither
)

// surfaceReports builds the report skeleton in registry order and an index into
// it, so the conversion code can bump counters by (table, column) without
// worrying about ordering.
func surfaceReports() ([]RekeySurfaceReport, map[string]*RekeySurfaceReport) {
	out := make([]RekeySurfaceReport, len(rekeySurfaces))
	idx := make(map[string]*RekeySurfaceReport, len(rekeySurfaces))
	for i, s := range rekeySurfaces {
		out[i] = RekeySurfaceReport{
			Table:      s.Table,
			Column:     s.Column,
			SettingKey: s.SettingKey,
			Family:     string(s.Family),
			Why:        s.Why,
		}
		idx[surfaceKey(s.Table, s.Column, s.SettingKey)] = &out[i]
	}
	return out, idx
}

func surfaceKey(table, column, settingKey string) string {
	if settingKey != "" {
		return table + "." + column + "[" + settingKey + "]"
	}
	return table + "." + column
}

// rekeyPlan is the fully computed set of writes, produced BEFORE anything is
// written.
//
// Computing every replacement first is the preflight. The alternative (convert
// and write row by row) means a failure halfway through leaves a store where
// some rows moved and some did not, and the operator has no way to know which.
// Everything in here is already ciphertext under the CURRENT key: plaintext is
// zeroed as soon as it has been re-encrypted, so a plan sitting in memory is no
// more sensitive than the database file.
type rekeyPlan struct {
	entries  []rekeyEntryWrite
	invites  []db.RekeyInvitationCodeParams
	totp     []db.StoreTOTPSecretParams
	settings []db.UpsertSettingParams
	channels []db.RekeyNotificationChannelConfigParams
}

// rekeyEntryWrite is one entry's replacement columns plus the egress ticket that
// authorises writing them.
//
// The ticket travels WITH the params rather than being minted when the plan is
// applied, and that is not tidiness. A ticket states the destinations a write
// moves between, and by apply time every value in the plan is ciphertext again,
// so the only place the sweep can honestly answer "where could this secret reach
// before, and where after" is the scan, which is holding both plaintexts.
type rekeyEntryWrite struct {
	params vaultegress.RekeyEntryParams
	// ticket is minted with Before == After: a re-encryption changes the
	// encoding of a destination, never the destination. egressgate.Decide
	// therefore grants it with nothing added and never consults the authority
	// oracle, which is what a re-encryption pass should look like at the gate.
	ticket egressgate.Ticket
	// nameScope and storedNameBidx exist for the ONE write that can be refused by
	// a constraint rather than by a bug: the per-vault name index. nameScope is
	// what the operator needs in the log line, and storedNameBidx is what the retry
	// puts back so a refused index does not cost the row its re-encryption. See
	// applyPlan.
	nameScope      string
	storedNameBidx string
}

func (p *rekeyPlan) rows() int {
	return len(p.entries) + len(p.invites) + len(p.totp) + len(p.settings) + len(p.channels)
}

// RekeyStatus scans every keyed surface and reports which key each value is on,
// without writing anything.
//
// This is what the admin UI polls. It is deliberately callable with NO previous
// key configured, because the most valuable thing it can tell an operator is
// "17 values in this store open under no key you have loaded", which is exactly
// the state a naive in-place key change produces and exactly the state that used
// to be invisible until someone opened an entry and saw blanks.
func (h *VaultHandler) RekeyStatus(ctx context.Context) (*RekeyReport, error) {
	started := time.Now()
	rep, _, err := h.scanAndPlan(ctx, h.queries)
	if err != nil {
		return nil, err
	}
	h.finishReport(rep, started)
	switch {
	case rep.ValuesUnreadable > 0:
		rep.Status = "blocked"
	case rep.ValuesOnPrevious > 0 || rep.ValuesStale > 0:
		// Stale counts here too. A stale lookup index is silent (autofill returns
		// nothing, no error anywhere), so a status page that called that store
		// "already current" would be the one surface that could have reported it
		// saying nothing.
		rep.Status = "needs_rekey"
	default:
		rep.Status = "already_current"
	}
	return rep, nil
}

// RekeyVault re-encrypts every keyed surface under the CURRENT master key.
//
// Contract, in order:
//  1. Plan. Every keyed value in the store is read and its replacement computed
//     in memory. Nothing is written yet.
//  2. Refuse. If ANY marked ciphertext opens under neither configured key, the
//     whole sweep aborts with ErrRekeyBlocked and the store is untouched.
//  3. Write, inside ONE transaction, so a crash cannot leave a row (or a store)
//     half converted.
//  4. Verify, still inside the transaction: re-read every surface and assert it
//     now opens under the current key ALONE. Any failure rolls the whole thing
//     back.
//  5. Re-seal the key sentinel under the current key, last, in the same
//     transaction. If it were written outside, it would survive a rollback and
//     the next boot would accept a key that no longer opens the data.
//
// Idempotent: a second run finds everything already on the current key and
// writes nothing. Safe to run when no rotation is in flight.
func (h *VaultHandler) RekeyVault(ctx context.Context) (*RekeyReport, error) {
	return h.rekeyVault(ctx, false)
}

// rekeyVaultForIngress is the admin HTTP form. The global private-access scan
// happens inside the very transaction that plans and rewrites every keyed row,
// so a promotion cannot commit between admission and the sweep.
func (h *VaultHandler) rekeyVaultForIngress(ctx context.Context) (*RekeyReport, error) {
	return h.rekeyVault(ctx, true)
}

func (h *VaultHandler) rekeyVault(ctx context.Context, enforceIngress bool) (*RekeyReport, error) {
	rekeyMu.Lock()
	if rekeyRunning {
		rekeyMu.Unlock()
		return nil, ErrRekeyInProgress
	}
	rekeyRunning = true
	rekeyMu.Unlock()
	defer func() {
		rekeyMu.Lock()
		rekeyRunning = false
		rekeyMu.Unlock()
	}()

	started := time.Now()

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin rekey transaction: %w", err)
	}
	// Rolls back everything unless the verify pass below passes and Commit runs.
	// A rollback after a successful commit is a no-op, which is why this is safe
	// to defer unconditionally (same pattern as MigrateEncryption).
	defer tx.Rollback()
	qtx := h.queries.WithTx(tx)
	if enforceIngress && !middleware.IsPrivateIngress(ctx) {
		required, policyErr := globalProtectedPrivateAccessRequired(ctx, qtx)
		if policyErr != nil {
			return nil, fmt.Errorf("verify global private-access policy: %w", policyErr)
		}
		if required {
			return nil, errRekeyPrivateIngressRequired
		}
	}

	// 1. Plan.
	rep, plan, err := h.scanAndPlan(ctx, qtx)
	if err != nil {
		return nil, err
	}

	// 2. Refuse.
	if rep.ValuesUnreadable > 0 {
		h.finishReport(rep, started)
		rep.Status = "blocked"
		rep.Error = fmt.Sprintf("%d stored value(s) open under neither the current nor the previous vault key. "+
			"Nothing was written. Restore the key those values were sealed under, or remove those rows, then retry.",
			rep.ValuesUnreadable)
		return rep, ErrRekeyBlocked
	}
	if rep.ValuesOnPrevious > 0 && h.previous == nil {
		// Every classifier reaches keyAgePrevious only by opening (or matching)
		// the value under h.previous, so this cannot happen. It is stated as an
		// assertion rather than assumed, and it is deliberately NOT extended to
		// ValuesStale: a stale blind index is recomputed from cleartext, so the
		// sweep repairs it with no previous key at all. Refusing that case is
		// what used to leave an operator with a "needs rekey" banner, a disabled
		// button and a 400 from the endpoint, for a state the sweep could fix.
		return nil, ErrRekeyNoPreviousKey
	}

	// 3. Write.
	if err := h.applyPlan(ctx, qtx, plan); err != nil {
		return nil, err
	}

	// 5 (part of the same statement stream as 3, before the verify): re-seal the
	// sentinel. Done unconditionally rather than only when it changed, because it
	// is a single constant-size row and the cost of getting it wrong is a refused
	// boot.
	if err := ResealVaultKeycheck(ctx, qtx, h.keySource); err != nil {
		return nil, fmt.Errorf("reseal key sentinel: %w", err)
	}

	// 4. Verify, before committing.
	verifyRep, _, err := h.scanAndPlan(ctx, qtx)
	if err != nil {
		return nil, fmt.Errorf("verify after rekey: %w", err)
	}
	if verifyRep.ValuesOnPrevious > 0 || verifyRep.ValuesUnreadable > 0 || verifyRep.ValuesStale > 0 {
		// Roll back via the deferred Rollback. This is the guard that turns "the
		// sweep says it covered everything" into "the sweep proved it": if a
		// surface exists that the conversion code does not handle, the values stay
		// on the previous key and this catches it here instead of after the
		// operator has deleted the old key.
		return nil, fmt.Errorf("rekey verification failed: %d value(s) still on the previous key, "+
			"%d stale lookup index(es), %d unreadable; the transaction was rolled back and nothing changed",
			verifyRep.ValuesOnPrevious, verifyRep.ValuesStale, verifyRep.ValuesUnreadable)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit rekey: %w", err)
	}

	rep.RowsConverted = plan.rows()
	h.finishReport(rep, started)
	rep.Status = "converted"
	if rep.RowsConverted == 0 {
		rep.Status = "already_current"
	}

	slog.Info("vault: master-key re-encrypt sweep complete",
		"rows_converted", rep.RowsConverted,
		"values_moved", rep.ValuesOnPrevious,
		"name_index_collisions", rep.NameIndexCollisions,
		"current_key_fingerprint", rep.CurrentKeyFingerprint,
		"duration_ms", rep.DurationMS)
	if rep.RowsConverted > 0 {
		slog.Warn("vault: rotation complete. Remove TRUSTISSUES_VAULT_KEY_PREVIOUS from the environment " +
			"and restart, otherwise the retired key is still loaded and still opens this data.")
	}
	return rep, nil
}

// finishReport fills the timing and fingerprint fields shared by every path.
func (h *VaultHandler) finishReport(rep *RekeyReport, started time.Time) {
	rep.StartedAt = started.UTC().Format(time.RFC3339)
	rep.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	rep.DurationMS = time.Since(started).Milliseconds()
	rep.CurrentKeyFingerprint = vaultKeyFingerprint(h.keySource)
	rep.PreviousKeyConfigured = h.previous != nil
	if h.previous != nil {
		rep.PreviousKeyFingerprint = vaultKeyFingerprint(h.previous.source)
	}
}

// scanCtx carries the accumulating report through the per-table scanners.
type scanCtx struct {
	rep *RekeyReport
	idx map[string]*RekeySurfaceReport
}

func (s *scanCtx) surface(table, column, settingKey string) *RekeySurfaceReport {
	r, ok := s.idx[surfaceKey(table, column, settingKey)]
	if !ok {
		// Registry and scanner disagree. Panicking here would take down the
		// server for an operator action, so instead this returns a throwaway
		// counter and the coverage test is what makes the disagreement
		// impossible to ship.
		return &RekeySurfaceReport{Table: table, Column: column, SettingKey: settingKey}
	}
	return r
}

// record folds one value's classification into the report.
func (s *scanCtx) record(sr *RekeySurfaceReport, age keyAge, table, column, settingKey, rowID string) {
	sr.Scanned++
	switch age {
	case keyAgeCurrent:
		sr.OnCurrent++
		s.rep.ValuesOnCurrent++
	case keyAgePrevious:
		sr.OnPrevious++
		s.rep.ValuesOnPrevious++
	case keyAgePlaintext:
		sr.Plaintext++
	case keyAgeStale:
		sr.Stale++
		s.rep.ValuesStale++
	case keyAgeCollided:
		sr.Collided++
		s.rep.NameIndexCollisions++
	case keyAgeUnknown:
		s.blocked(sr, table, column, settingKey, rowID,
			"marked ciphertext that opens under neither the current nor the previous vault key")
	}
}

// recordUnreadable folds in a value that no key opens, with a reason of its own.
// Same accounting as record(keyAgeUnknown), for callers that know something more
// specific than "wrong key" (a corrupt encoding, say), because the operator's
// next action differs.
func (s *scanCtx) recordUnreadable(sr *RekeySurfaceReport, table, column, settingKey, rowID, reason string) {
	sr.Scanned++
	s.blocked(sr, table, column, settingKey, rowID, reason)
}

func (s *scanCtx) blocked(sr *RekeySurfaceReport, table, column, settingKey, rowID, reason string) {
	sr.Unreadable++
	s.rep.ValuesUnreadable++
	s.rep.BlockersTotal++
	if len(s.rep.Blockers) < maxReportedBlockers {
		s.rep.Blockers = append(s.rep.Blockers, RekeyBlocker{
			Table: table, Column: column, SettingKey: settingKey, RowID: rowID,
			Reason: reason,
		})
	}
}

// scanAndPlan reads every keyed surface, classifies every value, and computes
// the replacement writes. It never writes. q may be a transaction handle.
func (h *VaultHandler) scanAndPlan(ctx context.Context, q *db.Queries) (*RekeyReport, *rekeyPlan, error) {
	surfaces, idx := surfaceReports()
	rep := &RekeyReport{Surfaces: surfaces, Blockers: []RekeyBlocker{}}
	sc := &scanCtx{rep: rep, idx: idx}
	plan := &rekeyPlan{}

	if err := h.scanVaultEntries(ctx, q, sc, plan); err != nil {
		return nil, nil, err
	}
	if err := h.scanInvitations(ctx, q, sc, plan); err != nil {
		return nil, nil, err
	}
	if err := h.scanTOTPSecrets(ctx, q, sc, plan); err != nil {
		return nil, nil, err
	}
	if err := h.scanSettings(ctx, q, sc, plan); err != nil {
		return nil, nil, err
	}
	if err := h.scanNotificationChannels(ctx, q, sc, plan); err != nil {
		return nil, nil, err
	}
	return rep, plan, nil
}

// applyPlan executes every computed write. It runs inside the caller's
// transaction.
func (h *VaultHandler) applyPlan(ctx context.Context, q *db.Queries, plan *rekeyPlan) error {
	for _, e := range plan.entries {
		err := vaultegress.RekeyEntry(ctx, q, e.ticket, e.params)
		if err != nil && isUniqueConstraintErr(err) && e.params.NameBidx != e.storedNameBidx {
			// THE SECOND LINE OF DEFENCE ON THE NAME INDEX, and the only one that
			// does not depend on the planner having been right.
			//
			// scanVaultEntries claims every name index before it plans any, so a
			// refused index should be unreachable here. "Should be" is how the
			// first version of this shipped, and one duplicate name then made
			// master-key rotation impossible for the whole store, because the
			// error aborted the loop and the transaction with it. A constraint on
			// ONE row must never be able to do that again, however the planner
			// changes, so the write is retried with the index the row already had
			// and the row keeps its re-encryption. Only the index is given up, and
			// only for the row that could not have it.
			//
			// SQLite's default ON CONFLICT ABORT rolls back the failed STATEMENT,
			// not the transaction, so the retry runs on live state.
			retry := e.params
			retry.NameBidx = e.storedNameBidx
			slog.Error("vault: re-encrypt sweep could not write an entry's name index because "+
				"another entry in the same vault scope holds it; the entry was re-encrypted without it, "+
				"rename one of the two and the next sweep will seal it",
				"id", e.params.ID, "scope", e.nameScope)
			err = vaultegress.RekeyEntry(ctx, q, e.ticket, retry)
		}
		if err != nil {
			return fmt.Errorf("rekey vault entry %s: %w", e.params.ID, err)
		}
	}
	for _, p := range plan.invites {
		if err := q.RekeyInvitationCode(ctx, p); err != nil {
			return fmt.Errorf("rekey invitation %s: %w", p.ID, err)
		}
	}
	for _, p := range plan.totp {
		if err := q.StoreTOTPSecret(ctx, p); err != nil {
			return fmt.Errorf("rekey totp secret for user %s: %w", p.ID, err)
		}
	}
	for _, p := range plan.settings {
		if err := q.UpsertSetting(ctx, p); err != nil {
			return fmt.Errorf("rekey setting %s: %w", p.Key, err)
		}
	}
	for _, p := range plan.channels {
		if err := q.RekeyNotificationChannelConfig(ctx, p); err != nil {
			return fmt.Errorf("rekey notification channel %s: %w", p.ID, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Per-family classification
// ---------------------------------------------------------------------------

// classifyVaultColumn classifies an "enc:v1:" column and returns its plaintext
// when it opened.
//
// An UNPREFIXED value is cleartext by the documented contract of
// vaultColumnEncPrefix, not ciphertext under an unknown key, so it classifies as
// plaintext and the sweep leaves it alone. Encrypting it is BackfillMetadataAtRest's
// job on the next boot. Keeping the two jobs apart matters: a sweep that also
// encrypted "plaintext" would, on any classification mistake, produce
// Enc_new(Enc_old(value)), which is the irreversible double-encryption this
// codebase already shipped once through the TOTP boot migration.
//
// It takes the DECLARED FIELD for the column it is classifying, because
// classifying is decrypting: every attempt goes through the same door an
// ordinary read uses, and that door will not open anything for the zero Field.
// A sweep is exactly the wrong place for a decryption the ledger cannot see,
// since it touches every keyed column in the store in one pass.
func (h *VaultHandler) classifyVaultColumn(stored string, field vaultfield.Field) (plain string, age keyAge) {
	if stored == "" {
		return "", keyAgeEmpty
	}
	if !strings.HasPrefix(stored, vaultColumnEncPrefix) {
		return stored, keyAgePlaintext
	}
	plain, onPrevious, err := h.decryptColumnWithKeyAge(stored, field)
	if err != nil {
		return "", keyAgeUnknown
	}
	if onPrevious {
		return plain, keyAgePrevious
	}
	return plain, keyAgeCurrent
}

// classifyColumnCrypto classifies a columncrypto ("tienc:v1:") value.
//
// The unmarked case is the delicate one. Legacy binaries wrote bare base64 with
// no marker, so an unmarked value can be either genuine plaintext or real
// ciphertext. Trying BOTH keys is what keeps a legacy-unmarked value sealed
// under the OLD key from being classified as plaintext: that misclassification
// is exactly how a value gets re-encrypted into Enc_new(Enc_old(v)) and lost for
// good. Unmarked ciphertext that opens under the CURRENT key is left for the
// boot migration to mark; it is not orphaned by the rotation, so it is not this
// sweep's problem.
//
// It takes the DECLARED FIELD for the same reason classifyVaultColumn does, and
// passes the SAME one to both key attempts: which key opens a value is not a
// different column.
func (h *VaultHandler) classifyColumnCrypto(stored string, field vaultfield.Field) (plain string, age keyAge) {
	if stored == "" {
		return "", keyAgeEmpty
	}
	if dec, err := columncrypto.DecryptString(stored, h.keySource, field); err == nil {
		return dec, keyAgeCurrent
	}
	if h.previous != nil {
		if dec, err := columncrypto.DecryptString(stored, h.previous.source, field); err == nil {
			return dec, keyAgePrevious
		}
	}
	if columncrypto.IsEncrypted(stored) {
		// Marked as ciphertext and opened by nothing we hold. Never guess.
		return "", keyAgeUnknown
	}
	return stored, keyAgePlaintext
}

// THE TWO RAW-AES-GCM FAMILIES THE SWEEP CLASSIFIES, AND WHY THEY ARE TWO
// FUNCTIONS RATHER THAN ONE.
//
// This used to be a single classifyVaultValue over "a raw AES-GCM value (the
// vault secret, or a notification channel config)", opening both with
// decryptWithKey and handing back a bare []byte. The two columns are not one
// family, and treating them as one is what the exit types exist to stop:
//
//   - vault_entries.encrypted_value is a vault entry's SECRET. Round 7 made
//     secretexit.Plaintext the only shape it can be held in, so that "every path
//     by which a decrypted secret leaves this process" is a set the compiler
//     maintains. A sweep that opened it as []byte would be a second door with no
//     destination, no owner question and no receipt, which is exactly what
//     TestRawAESIsReachedFromExactlyOnePlace pins shut. Re-keying is not an exit
//     and needs none: the value is ciphertext again on the other side, so this
//     goes Open -> Reseal through the opaque type, the way MigrateEncryption
//     already does.
//   - notification_channels.config is INSTANCE-OWNED configuration that belongs
//     to no entry, so there is no owner to ask and it legitimately stays bytes.
//
// Both still answer the rotation question (which key opened it), which is the
// half the sweep cannot do without.
//
// encVersion 0 means "never encrypted" for notification_channels, where at-rest
// encryption arrived after the table. For vault_entries the column is NOT NULL
// and the default is 2, so a zero there means an empty row rather than
// cleartext, which the length check catches.

// classifyEntryValue classifies a vault entry's stored secret and returns it in
// the opaque type when it opened. The caller MUST Wipe the result.
func (h *VaultHandler) classifyEntryValue(ciphertext, nonce []byte, encVersion int,
	o secretexit.Origin) (secretexit.Plaintext, keyAge) {

	if len(ciphertext) == 0 || len(nonce) == 0 {
		return secretexit.Plaintext{}, keyAgeEmpty
	}
	pt, onPrevious, err := h.openEntrySecretWithKeyAge(ciphertext, nonce, encVersion, o)
	if err != nil {
		return secretexit.Plaintext{}, keyAgeUnknown
	}
	if onPrevious {
		return pt, keyAgePrevious
	}
	return pt, keyAgeCurrent
}

// classifyInstanceConfig classifies a notification-channel config and returns
// its plaintext when it opened. The caller MUST zero the result.
//
// It opens through vaultfield with vaultFieldAlertChannelConfig, the field
// declared beside DecryptInstanceConfig, rather than calling that method:
// TestOnlyTheAlertsPathDecryptsInstanceConfig forbids any caller of it inside
// this package, and rightly so, because a handler reaching for it is usually a
// handler opening an entry secret through the wrong door. Reusing the FIELD is
// not the same as reusing the door. A Field names the column, so the ledger
// still records this decryption against notification_channels.config, which is
// the column it genuinely opens.
//
// The v1 key is RE-DERIVED from the master key string rather than read from
// h.legacyKey, for the reason legacyKeyFor documents: MigrateEncryption zeroes
// that field after it runs, so a sweep triggered from the admin API later in the
// process would find zero bytes and report every v1 row unreadable.
func (h *VaultHandler) classifyInstanceConfig(ciphertext, nonce []byte, encVersion int) (plain []byte, age keyAge) {
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return nil, keyAgeEmpty
	}
	cur := h.encryptionKey
	if encVersion == 1 {
		cur = h.legacyKeyFor(h.keySource)
	}
	if pt, err := vaultfield.Open(cur, ciphertext, nonce, vaultFieldAlertChannelConfig); err == nil {
		return pt, keyAgeCurrent
	}
	if h.previous != nil {
		prev := h.previous.value
		if encVersion == 1 {
			prev = h.legacyKeyFor(h.previous.source)
		}
		if pt, err := vaultfield.Open(prev, ciphertext, nonce, vaultFieldAlertChannelConfig); err == nil {
			return pt, keyAgePrevious
		}
	}
	return nil, keyAgeUnknown
}

// decodeRawGCMColumn / encodeRawGCMColumn are the on-disk encoding of
// notification_channels.config. It is NOT raw ciphertext: the column is TEXT and
// the ciphertext is base64.
//
// The failure that motivates this pair. The sweep read row.Config as if it were
// the AES-GCM ciphertext itself and handed the base64 TEXT to gcm.Open. Nothing
// opens that, so every store that had ever created a notification channel
// classified its config as "marked ciphertext that opens under neither key", the
// sweep refused with ErrRekeyBlocked, and the status page permanently told the
// operator to restore a key they never lost. The feature was inert on any real
// instance.
//
// Patching only the READ half is worse than leaving it broken. The plan wrote
// string(ciphertext) back with no base64, which the production reader
// (internal/alerts.decryptConfig base64-decodes BEFORE decrypting) cannot parse,
// and the sweep has by then re-encrypted under the new key. Every webhook URL
// and bot token would be unrecoverable. So the two halves live as one pair, and
// TestEveryRekeyFamilyMatchesItsProductionWireFormat asserts they agree with
// the real writer (notifications.go) and the real reader (alerts/channels.go).
func decodeRawGCMColumn(stored string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(stored)
}

func encodeRawGCMColumn(ciphertext []byte) string {
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// classifyBlindIndex answers which key an existing blind index was computed
// under by CONSULTING THE KEYRING, rather than inferring "previous" from any
// mismatch.
//
// The failure this fixes: a stale index was reported as keyAgePrevious even with
// no previous key configured. A backfill that timed out (BackfillMetadataAtRest
// has a two-minute budget) or that hit a decrypt error and `continue`d leaves
// exactly that state, and the operator was then told "N values are still
// encrypted with the previous key ... only because the old key is still loaded"
// when no old key existed, handed a disabled button, and answered 400
// "TRUSTISSUES_VAULT_KEY_PREVIOUS is not set" if they called the endpoint
// directly. A dead end with a false diagnosis, for the one surface the sweep can
// repair with no old key at all: an index is RECOMPUTED from cleartext, never
// decrypted.
//
// keyAgeStale is therefore its own answer: work the sweep must do, that needs no
// previous key.
func (h *VaultHandler) classifyBlindIndex(stored, want, scope, plain string) keyAge {
	if stored == "" && want == "" {
		return keyAgeEmpty
	}
	if stored == want {
		return keyAgeCurrent
	}
	if h.previous != nil && stored != "" && stored == blindIndexWith(h.previous.bidx, scope, plain) {
		return keyAgePrevious
	}
	return keyAgeStale
}

// classifyNameBlindIndex is deliberately separate from classifyBlindIndex.
// URL tokens normalize a host through blindIndexWith; name tokens preserve the
// exact label and use their own domain separator. Reusing the URL classifier
// made every previous-key name token look stale unless the label happened to be
// a parseable host, which defeated dual-key compatibility during rotation.
func (h *VaultHandler) classifyNameBlindIndex(stored, want, scope, plain string) keyAge {
	if stored == "" && want == "" {
		return keyAgeEmpty
	}
	if stored == want {
		return keyAgeCurrent
	}
	if h.previous != nil && stored != "" && stored == nameBlindIndexWith(h.previous.bidx, scope, plain) {
		return keyAgePrevious
	}
	return keyAgeStale
}

// legacyKeyFor re-derives the v1 key from a master key string.
//
// It does NOT read h.legacyKey, on purpose: MigrateEncryption zeroes that field
// after it runs, so a sweep triggered from the admin API later in the process
// lifetime would find it full of zero bytes and report every v1 row as
// unreadable. Re-deriving is one SHA-256.
func (h *VaultHandler) legacyKeyFor(source string) [32]byte {
	return sha256.Sum256([]byte(source + ":secrets-vault"))
}

// isUniqueConstraintErr reports whether a write was refused by a UNIQUE index.
//
// Matching on the driver's message is what every caller in this package already
// does; modernc.org/sqlite does not export a typed constraint error that survives
// the generated query layer. It is named here rather than inlined because the
// sweep's use of it is a DECISION (one row's constraint is not the table's
// problem) and not an error string it happens to look at.
func isUniqueConstraintErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint")
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------------------
// Per-table scanners
// ---------------------------------------------------------------------------

// scanVaultEntries covers eleven of the sixteen registered surfaces: the secret
// value, the eight enc:v1: metadata columns, and the two blind indexes.
func (h *VaultHandler) scanVaultEntries(ctx context.Context, q *db.Queries, sc *scanCtx, plan *rekeyPlan) error {
	rows, err := q.ListVaultEntriesForRekey(ctx)
	if err != nil {
		return fmt.Errorf("list vault entries for rekey: %w", err)
	}

	// THE NAME INDEX IS THE ONE SURFACE WITH A CONSTRAINT ON IT, SO IT IS THE ONE
	// THE SWEEP CAN BE REFUSED AT.
	//
	// The personal and collection partial indexes are unique within their
	// respective vault scopes. Rows written before the import path sealed names carry
	// a CLEARTEXT name and an EMPTY index, which puts them outside that partial
	// index: one scope can already hold two entries whose names are equal, one
	// sealed and one not, because the inline UNIQUE(user_id, name) compares
	// randomized ciphertext against cleartext and never fires.
	//
	// The sweep then recomputes the index for the unsealed one from its
	// cleartext, gets exactly the token the sealed one already stores, and SQLite
	// refuses the UPDATE. That error used to abort applyPlan, which rolls back
	// the whole transaction, which means master-key rotation is impossible for
	// the entire store until somebody finds and renames the pair by hand. Rekey
	// is the only recovery path there is for a compromised master key, so two
	// rows sharing a name were a permanent, silent denial of it. The at-rest
	// backfill was taught this same lesson first (BackfillMetadataAtRest); this
	// is its twin, and it recomputes the identical index.
	//
	// claimedNameBidx is what stops the sweep from planning a write it will be
	// refused. Every index ALREADY STORED is claimed first, before any row is
	// planned, so the row that holds a token keeps it and the row that cannot
	// have it is the one deferred. A row is then deferred rather than skipped:
	// it keeps the index it arrived with and everything else about it is still
	// re-keyed, because a name collision must never cost a row its SECRET.
	claimedNameBidx := make(map[string]string, len(rows))
	for _, row := range rows {
		if row.NameBidx != "" {
			nameScope := bidxScope(row.UserID, row.CollectionID)
			claimedNameBidx[nameScope+"|"+row.NameBidx] = row.ID
		}
	}
	// WHICH ROW OF A COLLIDING PAIR KEEPS THE INDEX IS NOT A COIN TOSS.
	//
	// The row that already HOLDS an index has a working one, just possibly under
	// the retired key; the row that holds none never had one. If the row holding
	// none claimed the token first, the sweep would hand it the index and leave
	// the other row stuck on a token the current key no longer computes: a
	// working lookup broken BY the rotation, which is the exact failure the blind
	// index surface was added to the sweep to prevent.
	//
	// Rows are therefore planned holders-first, so the holder's recomputed token
	// is claimed before any empty row can ask for it. Stable, so rows that are
	// alike keep the store's own order and two runs of the sweep make the same
	// decision. This is ordering for CORRECTNESS, not for tidiness, and without
	// it the answer depends on the order ListVaultEntriesForRekey happens to
	// return, which is by id.
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].NameBidx != "" && rows[j].NameBidx == ""
	})

	for _, row := range rows {
		needsWrite := false

		// --- the secret value ---
		encVersion := 2
		if row.EncryptionVersion.Valid {
			encVersion = int(row.EncryptionVersion.Int64)
		}
		valueSurface := sc.surface("vault_entries", "encrypted_value", "")
		plain, age := h.classifyEntryValue(row.EncryptedValue, row.Nonce, encVersion,
			entryOrigin(row.ID, ""))
		sc.record(valueSurface, age, "vault_entries", "encrypted_value", "", row.ID)

		newValue, newNonce := row.EncryptedValue, row.Nonce
		newVersion := row.EncryptionVersion
		// A v1 row is re-sealed as v2 even when the CURRENT key already opens it.
		// That is not scope creep: MigrateEncryption does exactly this at boot,
		// and leaving a v1 row behind means the next rotation has to keep the v1
		// derivation of two different master keys alive to read it.
		//
		// Open -> Reseal, both halves on the opaque type. The plaintext is never a
		// []byte in this loop, so re-keying an entry cannot become a way to read
		// one. See the note above classifyEntryValue.
		if age == keyAgePrevious || (age == keyAgeCurrent && encVersion == 1) {
			ct, nc, encErr := h.encryptEntrySecret(plain)
			plain.Wipe()
			if encErr != nil {
				return fmt.Errorf("re-encrypt vault entry %s: %w", row.ID, encErr)
			}
			newValue, newNonce = ct, nc
			newVersion = sql.NullInt64{Int64: 2, Valid: true}
			needsWrite = true
		} else {
			plain.Wipe()
		}

		// --- the enc:v1: metadata columns ---
		type metaCol struct {
			name   string
			stored string
			field  vaultfield.Field
		}
		cols := []metaCol{
			{"name", row.Name, vaultFieldName},
			{"url", nullStringToString(row.Url), vaultFieldURL},
			{"alias_url", nullStringToString(row.AliasUrl), vaultFieldAliasURL},
			{"username", nullStringToString(row.Username), vaultFieldUsername},
			{"category", nullStringToString(row.Category), vaultFieldCategory},
			{"notes", nullStringToString(row.Notes), vaultFieldNotes},
			{"provider_meta", nullStringToString(row.ProviderMeta), vaultFieldProviderMeta},
			{"rotation_targets", nullStringToString(row.RotationTargets), vaultFieldRotationTargets},
			{"custom_fields", row.CustomFields, vaultFieldCustomFields},
		}
		newCols := make(map[string]string, len(cols))
		plains := make(map[string]string, len(cols))
		for _, c := range cols {
			p, a := h.classifyVaultColumn(c.stored, c.field)
			sc.record(sc.surface("vault_entries", c.name, ""), a, "vault_entries", c.name, "", row.ID)
			plains[c.name] = p
			newCols[c.name] = c.stored
			if a == keyAgePrevious {
				reenc, encErr := h.encryptColumn(p)
				if encErr != nil {
					return fmt.Errorf("re-encrypt vault_entries.%s for %s: %w", c.name, row.ID, encErr)
				}
				newCols[c.name] = reenc
				needsWrite = true
			}
		}

		// --- the blind indexes ---
		//
		// Recomputed from the CLEARTEXT host every time rather than only when the
		// url column moved keys. The index is keyed by its own derivation, so it
		// goes stale on a key change even for a row whose url column was already
		// cleartext and therefore classified "plaintext" with nothing to convert.
		// A stale index does not error, it just stops matching, so nothing else in
		// the system would ever notice.
		scope := bidxScope(row.UserID, row.CollectionID)
		wantURLBidx := h.urlBlindIndex(scope, plains["url"])
		wantAliasBidx := h.urlBlindIndex(scope, plains["alias_url"])

		urlBidxAge := h.classifyBlindIndex(row.UrlBidx, wantURLBidx, scope, plains["url"])
		aliasBidxAge := h.classifyBlindIndex(row.AliasUrlBidx, wantAliasBidx, scope, plains["alias_url"])
		if urlBidxAge == keyAgePrevious || urlBidxAge == keyAgeStale ||
			aliasBidxAge == keyAgePrevious || aliasBidxAge == keyAgeStale {
			needsWrite = true
		}
		sc.record(sc.surface("vault_entries", "url_bidx", ""), urlBidxAge, "vault_entries", "url_bidx", "", row.ID)
		sc.record(sc.surface("vault_entries", "alias_url_bidx", ""), aliasBidxAge, "vault_entries", "alias_url_bidx", "", row.ID)

		// The name index uses the same personal/collection scope as the URL index.
		// A collection label must not constrain, or be probed through, the
		// custodian's personal vault or an unrelated collection.
		// A stale one is quieter than a stale url index, because it does not merely
		// stop matching a lookup: it stops COLLIDING, so two entries silently share
		// a name and the constraint that was supposed to prevent it reports nothing.
		wantNameBidx := h.scopedNameBlindIndex(scope, plains["name"])
		nameBidxAge := h.classifyNameBlindIndex(row.NameBidx, wantNameBidx, scope, plains["name"])
		if nameBidxAge == keyAgePrevious || nameBidxAge == keyAgeStale {
			// The claim, checked against the state the whole sweep is converging
			// on rather than against the row alone. holder != row.ID is the whole
			// test: a row that already owns its token is not colliding with
			// itself, and a row whose token is owned by a DIFFERENT row cannot be
			// given it, in this sweep or any later one.
			holder, taken := "", false
			if wantNameBidx != "" {
				holder, taken = claimedNameBidx[scope+"|"+wantNameBidx]
			}
			if taken && holder != row.ID {
				nameBidxAge = keyAgeCollided
				wantNameBidx = row.NameBidx
				slog.Warn("vault: re-encrypt sweep left an entry's name index alone because another "+
					"entry in the same vault scope already holds it; rename one of the two and the next "+
					"sweep will seal it",
					"id", row.ID, "scope", scope, "holder", holder)
			} else {
				if wantNameBidx != "" {
					claimedNameBidx[scope+"|"+wantNameBidx] = row.ID
				}
				needsWrite = true
			}
		}
		sc.record(sc.surface("vault_entries", "name_bidx", ""), nameBidxAge, "vault_entries", "name_bidx", "", row.ID)

		if !needsWrite {
			continue
		}
		// The ticket for this row. Both sides of the comparison are derived from
		// the values the sweep just DECRYPTED, so they are the same set by
		// construction and the decision adds nothing. Stating it that way rather
		// than passing empty sets is the difference between a gate that says "this
		// write moves the secret nowhere new" and one that was never asked.
		reachable := append(providerDestinations(row.Provider.String, ParseProviderMeta(plains["provider_meta"])),
			deliveryDestinations(ParseRotationTargets(plains["rotation_targets"]))...)
		tk, tkErr := egressgate.Decide(egressgate.Request{
			EntryID: row.ID,
			What:    vaultegress.FieldRekey,
			Before:  reachable,
			After:   reachable,
			Covers:  providerDestinationCovers,
		})
		if tkErr != nil {
			return fmt.Errorf("egress decision for the re-encryption of %s: %w", row.ID, tkErr)
		}
		plan.entries = append(plan.entries, rekeyEntryWrite{
			ticket:         tk,
			nameScope:      scope,
			storedNameBidx: row.NameBidx,
			params: vaultegress.RekeyEntryParams{
				EncryptedValue:    newValue,
				Nonce:             newNonce,
				EncryptionVersion: newVersion,
				Url:               toNullString(newCols["url"]),
				AliasUrl:          toNullString(newCols["alias_url"]),
				Username:          toNullString(newCols["username"]),
				Category:          toNullString(newCols["category"]),
				Notes:             toNullString(newCols["notes"]),
				ProviderMeta:      toNullString(newCols["provider_meta"]),
				RotationTargets:   toNullString(newCols["rotation_targets"]),
				CustomFields:      newCols["custom_fields"],
				Name:              newCols["name"],
				UrlBidx:           wantURLBidx,
				AliasUrlBidx:      wantAliasBidx,
				NameBidx:          wantNameBidx,
				ID:                row.ID,
			}})
	}
	return nil
}

// vaultFieldRekeyInvitationCode is the SWEEP's door onto invitations.code, and
// it is a second declaration rather than a reuse of vaultFieldInvitationCode on
// purpose.
//
// That field is pinned by TestTheInvitationCodeGoesThroughTheDeclaredDoor to
// exactly one opener, UserHandler.openInviteCode, and the pin is right: a second
// caller of it would be a second answer to "may this caller be handed a
// credential that redeems into an account". The sweep is not asking that
// question at all. It opens the code to seal it under the current master key and
// puts it straight back, and it answers to a different one: "would this value
// survive the operator deleting the old key".
//
// Declaring it separately is the pattern vaultFieldEntryValueProbe already uses
// for the boot key check over vault_entries.encrypted_value: same column, a
// different door, its own ruling, and the ledger records both instead of one
// door borrowing the other's entry.
var vaultFieldRekeyInvitationCode = vaultfield.Declare(
	"invitations.code (re-key sweep)", vaultfield.InProcessOnly, "",
	"a pending invitation's setup code, opened by the master-key re-encrypt sweep so it can be sealed "+
		"under the current key instead of being orphaned when the operator retires the old one. It is "+
		"in-process-only and not instance-owned like the door that SERVES the code: this one emits "+
		"nothing at all. The plaintext exists for the length of one re-encrypt inside a transaction, "+
		"goes back into the same column, and never reaches a response, a log line or an email. A code "+
		"the sweep skipped would be worse than one it converted: it stays redeemable and stops being "+
		"readable, so the invite silently cannot be re-sent.")

func (h *VaultHandler) scanInvitations(ctx context.Context, q *db.Queries, sc *scanCtx, plan *rekeyPlan) error {
	rows, err := q.ListInvitationCodesForRekey(ctx)
	if err != nil {
		return fmt.Errorf("list invitation codes for rekey: %w", err)
	}
	sr := sc.surface("invitations", "code", "")
	for _, row := range rows {
		plain, age := h.classifyVaultColumn(row.Code, vaultFieldRekeyInvitationCode)
		sc.record(sr, age, "invitations", "code", "", row.ID)
		if age != keyAgePrevious {
			continue
		}
		reenc, encErr := h.encryptColumn(plain)
		if encErr != nil {
			return fmt.Errorf("re-encrypt invitation code %s: %w", row.ID, encErr)
		}
		plan.invites = append(plan.invites, db.RekeyInvitationCodeParams{Code: reenc, ID: row.ID})
	}
	return nil
}

func (h *VaultHandler) scanTOTPSecrets(ctx context.Context, q *db.Queries, sc *scanCtx, plan *rekeyPlan) error {
	rows, err := q.ListUsersWithTOTPSecret(ctx)
	if err != nil {
		return fmt.Errorf("list totp secrets for rekey: %w", err)
	}
	sr := sc.surface("users", "totp_secret", "")
	for _, row := range rows {
		stored := nullStringToString(row.TotpSecret)
		seed, age := h.classifyColumnCrypto(stored, vaultFieldTOTPSecret)
		sc.record(sr, age, "users", "totp_secret", "", row.ID)
		if age != keyAgePrevious {
			continue
		}
		reenc, encErr := columncrypto.EncryptString(seed, h.keySource)
		if encErr != nil {
			return fmt.Errorf("re-encrypt totp secret for user %s: %w", row.ID, encErr)
		}
		plan.totp = append(plan.totp, db.StoreTOTPSecretParams{
			TotpSecret: sql.NullString{String: reenc, Valid: true},
			ID:         row.ID,
		})
	}
	return nil
}

// scanSettings covers the two settings rows that hold ciphertext.
//
// settings is key/value, so the surface is the (key, value) pair. Iterating the
// whole table and guessing which values are ciphertext would be a content-based
// decision on stored data, and the registry already knows the answer.
func (h *VaultHandler) scanSettings(ctx context.Context, q *db.Queries, sc *scanCtx, plan *rekeyPlan) error {
	for _, s := range rekeySurfaces {
		if s.Table != "settings" || s.SettingKey == "" {
			continue
		}
		stored, err := q.GetSetting(ctx, s.SettingKey)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read setting %s for rekey: %w", s.SettingKey, err)
		}
		plain, age := h.classifyColumnCrypto(stored, s.Field)
		sc.record(sc.surface("settings", "value", s.SettingKey), age, "settings", "value", s.SettingKey, s.SettingKey)
		if age != keyAgePrevious {
			continue
		}
		// The sentinel is a known constant, so it is re-sealed by
		// ResealVaultKeycheck rather than round-tripped through the plan. Adding
		// it here too would write the row twice in one transaction for no reason.
		if s.SettingKey == vaultKeyCheckSetting {
			continue
		}
		reenc, encErr := columncrypto.EncryptString(plain, h.keySource)
		if encErr != nil {
			return fmt.Errorf("re-encrypt setting %s: %w", s.SettingKey, encErr)
		}
		plan.settings = append(plan.settings, db.UpsertSettingParams{Key: s.SettingKey, Value: reenc})
	}
	return nil
}

func (h *VaultHandler) scanNotificationChannels(ctx context.Context, q *db.Queries, sc *scanCtx, plan *rekeyPlan) error {
	rows, err := q.ListNotificationChannelConfigsForRekey(ctx)
	if err != nil {
		return fmt.Errorf("list notification channel configs for rekey: %w", err)
	}
	sr := sc.surface("notification_channels", "config", "")
	for _, row := range rows {
		encVersion := 0
		if row.EncryptionVersion.Valid {
			encVersion = int(row.EncryptionVersion.Int64)
		}
		if encVersion == 0 {
			// Written before at-rest encryption existed. Plain JSON, not sealed
			// under any key, so a rotation cannot orphan it.
			age := keyAgeEmpty
			if row.Config != "" {
				age = keyAgePlaintext
			}
			sc.record(sr, age, "notification_channels", "config", "", row.ID)
			continue
		}
		// The column is base64 TEXT, not raw ciphertext. See decodeRawGCMColumn.
		raw, decErr := decodeRawGCMColumn(row.Config)
		if decErr != nil {
			// Marked as encrypted (encryption_version > 0) but not even valid
			// base64, so no key can open it and guessing would destroy it. Report
			// it as a blocker with its own reason rather than the generic
			// wrong-key one, because the fix is different: the row is corrupt, not
			// sealed under a key that is missing.
			sc.recordUnreadable(sr, "notification_channels", "config", "", row.ID,
				"encryption_version says this config is encrypted, but the stored value is not valid base64, "+
					"so it is corrupt rather than sealed under a missing key")
			continue
		}
		plain, age := h.classifyInstanceConfig(raw, row.ConfigNonce, encVersion)
		sc.record(sr, age, "notification_channels", "config", "", row.ID)
		if age != keyAgePrevious && !(age == keyAgeCurrent && encVersion == 1) {
			zero(plain)
			continue
		}
		ct, nc, encErr := h.encrypt(plain)
		zero(plain)
		if encErr != nil {
			return fmt.Errorf("re-encrypt notification channel %s: %w", row.ID, encErr)
		}
		plan.channels = append(plan.channels, db.RekeyNotificationChannelConfigParams{
			Config:            encodeRawGCMColumn(ct),
			ConfigNonce:       nc,
			EncryptionVersion: sql.NullInt64{Int64: 2, Valid: true},
			ID:                row.ID,
		})
	}
	return nil
}

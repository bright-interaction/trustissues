package handlers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/database"
)

// TestRekeyCoversEveryKeyedColumn is the guard that makes the re-encrypt sweep
// stay exhaustive.
//
// The failure it exists to prevent is not subtle and has already happened twice
// in this file's neighbourhood: someone adds a column that holds vault-key
// material, ships it, and the next master-key rotation silently orphans that
// column's data. The boot key gate shipped with a probe that recognised one of
// its three crypto families; the retention sweep in the sibling product shipped
// three tables late, each time discovered only after rows had outlived their
// window. In both cases the code was correct for the surfaces its author knew
// about, and the list is what fell behind.
//
// So the list cannot be a comment. This walks the REAL schema (the embedded
// goose migrations, applied to a scratch database) and requires every single
// column to be classified as exactly one of:
//
//   - a registered keyed surface in rekeySurfaces, which the sweep converts, or
//   - an explicit entry in notKeyedColumns with a stated reason
//
// A new column is neither, so adding one fails this test until its author
// decides which it is. That decision takes ten seconds and is impossible to
// make correctly two years later during an incident.
//
// Modelled on atomicsite's retention coverage_test.go, which enforces the same
// shape for per-site data retention.
func TestRekeyCoversEveryKeyedColumn(t *testing.T) {
	dbConn, err := database.Connect(t.TempDir())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer dbConn.Close()
	if err := database.RunMigrations(dbConn); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	// Columns the sweep owns, derived from the registry rather than restated, so
	// the two can never drift. A nonce column belongs to the ciphertext column it
	// serves and is rewritten with it.
	keyed := map[string]string{}
	for _, s := range rekeySurfaces {
		keyed[s.Table+"."+s.Column] = string(s.Family)
		if s.NonceColumn != "" {
			keyed[s.Table+"."+s.NonceColumn] = string(s.Family) + " (nonce)"
		}
	}

	tables, err := listTables(dbConn)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) < 15 {
		t.Fatalf("ABORT: only %d tables found; this guard is matching almost nothing and is vacuous", len(tables))
	}

	var unclassified []string
	seenTables := map[string]bool{}
	for _, table := range tables {
		if schemaInternalTables[table] {
			continue
		}
		seenTables[table] = true
		cols, cErr := listColumns(dbConn, table)
		if cErr != nil {
			t.Fatalf("columns of %s: %v", table, cErr)
		}
		if len(cols) == 0 {
			t.Fatalf("ABORT: table %s reported no columns; the guard cannot check it", table)
		}
		for _, col := range cols {
			full := table + "." + col
			if _, ok := keyed[full]; ok {
				continue
			}
			if _, ok := notKeyedColumns[full]; ok {
				continue
			}
			unclassified = append(unclassified, full)
		}
	}

	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		t.Errorf(`%d database column(s) are not classified for master-key rotation:

  %s

Every column must be one of two things, decided by whoever added it:

  1. It holds material derived from TRUSTISSUES_VAULT_KEY (ciphertext, a GCM
     nonce, or a keyed blind index). Add it to rekeySurfaces in vault_rekey.go
     WITH its crypto family, and teach the matching scanner to convert it.
     Skipping this orphans that column's data on the next key rotation, and
     nothing will report it: the value simply stops decrypting, or in the blind
     index case stops matching with no error at all.

  2. It holds nothing keyed by the vault key. Add it to notKeyedColumns below
     with a one-line reason. Hashes, plaintext, foreign keys and timestamps all
     belong here.

This test fails on ANY new column precisely because the alternative is a list
that silently falls behind the schema, which is how the boot key gate ended up
inert over two thirds of its own surface area.`,
			len(unclassified), strings.Join(unclassified, "\n  "))
	}

	// The registry must not name columns that do not exist. A renamed or dropped
	// column would otherwise leave a surface the sweep reports on and never finds
	// anything in, which reads as "clean" for exactly the wrong reason.
	for _, s := range rekeySurfaces {
		if !seenTables[s.Table] {
			t.Errorf("rekeySurfaces names table %q, which does not exist in the schema", s.Table)
			continue
		}
		cols, cErr := listColumns(dbConn, s.Table)
		if cErr != nil {
			t.Fatalf("columns of %s: %v", s.Table, cErr)
		}
		if !contains(cols, s.Column) {
			t.Errorf("rekeySurfaces names %s.%s, which does not exist in the schema", s.Table, s.Column)
		}
		if s.NonceColumn != "" && !contains(cols, s.NonceColumn) {
			t.Errorf("rekeySurfaces names nonce column %s.%s, which does not exist", s.Table, s.NonceColumn)
		}
		if s.Why == "" {
			t.Errorf("rekeySurfaces entry %s.%s has no Why; the next person needs to know what breaks "+
				"if a rotation skips it", s.Table, s.Column)
		}
	}

	// notKeyedColumns must not carry stale entries either, or it silently becomes
	// a place where a real column's exemption outlives the column and a
	// same-named new column inherits it.
	for full := range notKeyedColumns {
		table, col, ok := strings.Cut(full, ".")
		if !ok {
			t.Errorf("notKeyedColumns key %q is not table.column", full)
			continue
		}
		if !seenTables[table] {
			t.Errorf("notKeyedColumns exempts %q, but table %q no longer exists", full, table)
			continue
		}
		cols, cErr := listColumns(dbConn, table)
		if cErr != nil {
			t.Fatalf("columns of %s: %v", table, cErr)
		}
		if !contains(cols, col) {
			t.Errorf("notKeyedColumns exempts %q, but that column no longer exists", full)
		}
	}
}

// TestRekeySurfacesAreAllReachableFromTheScanner asserts every registered
// surface is actually visited by the scan.
//
// Registering a surface and forgetting to teach a scanner about it produces the
// worst possible report: the surface appears in the operator's status page with
// zero rows scanned, which reads as "nothing to do here". Running a real scan
// over a store seeded with one of everything and requiring a non-zero scan count
// on every surface closes that gap.
func TestRekeySurfacesAreAllReachableFromTheScanner(t *testing.T) {
	dbConn, queries := newRekeyDB(t)
	h := rekeyHandler(dbConn, queries, rekeyOldKey, "")
	seedUnderKey(t, h, queries)

	rep, err := h.RekeyStatus(t.Context())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(rep.Surfaces) != len(rekeySurfaces) {
		t.Fatalf("report has %d surfaces, registry has %d", len(rep.Surfaces), len(rekeySurfaces))
	}
	for _, s := range rep.Surfaces {
		if s.Scanned == 0 {
			t.Errorf("surface %s.%s%s reports 0 rows scanned. Either the fixture does not seed it "+
				"(a test gap) or no scanner reads it (a rotation gap that would orphan this column "+
				"on the next key change). Both need fixing.",
				s.Table, s.Column, settingSuffix(s.SettingKey))
		}
		if s.Family == "" {
			t.Errorf("surface %s.%s has no crypto family; the converter cannot know which rules apply",
				s.Table, s.Column)
		}
	}
}

// schemaInternalTables are not application data.
var schemaInternalTables = map[string]bool{
	"goose_db_version": true,
	"sqlite_sequence":  true,
}

// notKeyedColumns is the explicit "reviewed, holds nothing keyed by the vault
// key" list. The value is the reason, which is the whole point: a bare list of
// names ages into noise, a reason can be re-checked.
//
// Two recurring shapes appear here and both are worth naming, because they look
// like ciphertext at a glance:
//
//   - key_hash / password_hash / code_hash / totp_recovery_codes are ONE-WAY
//     hashes. They are not encrypted, so no key opens them and no key change
//     touches them. Putting one in the sweep would be actively harmful: there
//     is no plaintext to recover and re-seal.
//   - shield_tokens.ciphertext IS ciphertext, but under TRUSTISSUES_SHIELD_KEY,
//     a deliberately separate key so a Shield leak does not touch the vault.
//     Rotating the vault key must not touch it, and rotating the shield key is a
//     different (and much easier) problem: those rows are session-scoped and
//     expire, so they are dropped rather than converted.
var notKeyedColumns = map[string]string{
	// activity_log: append-only audit trail, all plaintext by design.
	"activity_log.id":         "surrogate key",
	"activity_log.user_id":    "FK to users",
	"activity_log.action":     "event name, plaintext",
	"activity_log.detail":     "human-readable detail, plaintext, never holds a secret value",
	"activity_log.ip_address": "plaintext",
	"activity_log.user_agent": "plaintext",
	"activity_log.created_at": "timestamp",

	// api_keys: the bearer is hashed, never stored recoverably.
	"api_keys.user_id":      "FK to users",
	"api_keys.id":           "surrogate key",
	"api_keys.name":         "user-chosen label, plaintext",
	"api_keys.key_hash":     "SHA-256 of the key; a one-way hash, not encrypted",
	"api_keys.key_prefix":   "first characters of the key, shown in the UI for identification",
	"api_keys.last_used_at": "timestamp",
	"api_keys.expires_at":   "timestamp",
	"api_keys.created_at":   "timestamp",
	"api_keys.revoked_at":   "timestamp",

	// capability_grants / capability_log / spent nonces: references and outcomes,
	// never a secret value. The capability SIGNING key is derived from the vault
	// key via HKDF, but it signs short-lived tokens held in memory; nothing keyed
	// is stored, so a rotation invalidates in-flight tokens (5 minute TTL) and
	// needs no data conversion.
	"capability_grants.agent_id":   "agent identifier, plaintext",
	"capability_grants.secret_id":  "FK to vault_entries",
	"capability_grants.granted_by": "actor id",
	"capability_grants.granted_at": "timestamp",
	"capability_grants.revoked_at": "timestamp",
	"capability_grants.notes":      "operator note, plaintext",
	"capability_log.id":            "surrogate key",
	"capability_log.agent_id":      "agent identifier, plaintext",
	"capability_log.secret_id":     "FK to vault_entries",
	// ENCRYPTED, but deliberately NOT a rekey surface. It is sealed under the
	// audit DEK, and settings.audit_name_dek IS registered, so a master-key
	// rotation rewraps the key and leaves these rows alone. That indirection is
	// the point rather than an oversight: 00039 made this table append-only, so a
	// sweep that had to rewrite it could not, and a trigger carve-out letting the
	// application rewrite secret_name would reopen the cover-up path 00039 closed.
	"capability_log.secret_name": "entry name, sealed under the audit DEK (settings.audit_name_dek, " +
		"which is the registered surface). Rotating the master key rewraps that key; these rows are " +
		"never rewritten, because they cannot be",
	"capability_log.destination":         "destination host, plaintext",
	"capability_log.method":              "HTTP method",
	"capability_log.event":               "outcome label",
	"capability_log.status_code":         "upstream HTTP status",
	"capability_log.error":               "error text, plaintext",
	"capability_log.nonce":               "replay nonce from a token payload, not a GCM nonce",
	"capability_log.issued_at":           "timestamp",
	"capability_spent_nonces.nonce":      "replay nonce, not a GCM nonce",
	"capability_spent_nonces.expires_at": "timestamp",

	// collection_invitations (migration 00033): a pending seat recorded by the
	// ADDRESS the inviter typed, so a pending invite looks identical whether or
	// not the address has an account. Nothing here is sealed: it is the same
	// shape of data collection_members already holds in cleartext, and the table
	// exists to stop the members list answering "does this address have an
	// account", not to protect the address at rest.
	"collection_invitations.collection_id": "FK to collections",
	"collection_invitations.email":         "the invited address, plaintext, lower-cased by the handler",
	"collection_invitations.role":          "role label, CHECK-constrained vocabulary",
	"collection_invitations.invited_by":    "FK to users",
	"collection_invitations.created_at":    "timestamp",

	// The ownership bookkeeping tables (migrations 00034 and 00037). They record
	// WHO decided what about a secret's owner, never the secret.
	//
	// withdrawn_json is the one worth arguing about and the argument lands here:
	// it holds the capability ceiling and the host-choosing provider_meta keys a
	// claim took out of the row, marshalled as ordinary JSON by
	// withdrawnEvidence.json and read back as json.RawMessage. No key touches it
	// on either side, so a rotation cannot orphan it, which is the only question
	// this guard asks. (Whether that configuration should be sealed at rest the
	// way vault_entries.provider_meta is, is a separate question and belongs in
	// DEFERRED.md rather than in the rotation registry, because registering it
	// here would make the sweep try to re-encrypt cleartext.)
	"secret_owner_backfill.entry_id":                     "FK to vault_entries",
	"secret_owner_backfill.decided_owner":                "user id the 00034 backfill stamped, or empty where it refused",
	"secret_owner_backfill.decided_at":                   "timestamp",
	"secret_ownership_claims.entry_id":                   "FK to vault_entries",
	"secret_ownership_claims.claimed_by":                 "actor id",
	"secret_ownership_claims.claimed_at":                 "timestamp",
	"secret_ownership_claims.previous_owner_user_id":     "the holder the claim displaced; restore reads it and hands the entry back to nobody else",
	"secret_ownership_claims.previous_custodian_user_id": "the custodian at claim time, plaintext user id",
	"secret_ownership_claims.withdrawn_json":             "JSON of the ceiling and provider_meta keys the claim cleared, plaintext, never sealed",

	// collections + membership: names and roles.
	"collection_members.collection_id": "FK",
	"collection_members.user_id":       "FK",
	"collection_members.role":          "role label",
	"collection_members.added_at":      "timestamp",
	"collection_members.accepted_at":   "timestamp",
	"collection_members.invited_by":    "FK to users",
	"collections.id":                   "surrogate key",
	"collections.name":                 "collection name, plaintext",
	"collections.description":          "plaintext",
	"collections.created_by":           "FK to users",
	"collections.created_at":           "timestamp",
	"collections.updated_at":           "timestamp",

	// invitations: only `code` is keyed (registered). code_hash is what redemption
	// looks up and is one-way.
	"invitations.id":          "surrogate key",
	"invitations.email":       "plaintext",
	"invitations.name":        "plaintext",
	"invitations.status":      "state label",
	"invitations.target_role": "role label",
	"invitations.created_by":  "FK to users",
	"invitations.redeemed_by": "FK to users",
	"invitations.redeemed_at": "timestamp",
	"invitations.expires_at":  "timestamp",
	"invitations.created_at":  "timestamp",
	"invitations.code_hash":   "SHA-256 of the code; a one-way hash, not encrypted",

	"login_attempts.id":         "surrogate key",
	"login_attempts.email":      "plaintext",
	"login_attempts.ip_address": "plaintext",
	"login_attempts.success":    "boolean",
	"login_attempts.created_at": "timestamp",
	"login_attempts.scope":      "which door recorded the attempt; a fixed label, not keyed material",

	// notification_channels: only `config` (+ its nonce) is keyed; those come from
	// the registry. encryption_version says WHICH derivation sealed the config and
	// is rewritten alongside it by the sweep.
	"notification_channels.id":                 "surrogate key",
	"notification_channels.name":               "channel name, plaintext",
	"notification_channels.type":               "channel type label",
	"notification_channels.enabled":            "boolean",
	"notification_channels.encryption_version": "derivation version for config; rewritten with it by the sweep",
	"notification_channels.events":             "event subscription list, plaintext",
	"notification_channels.created_at":         "timestamp",
	"notification_channels.updated_at":         "timestamp",

	// service_identities: the service key is hashed, same as api_keys.
	"service_identities.id":                 "surrogate key",
	"service_identities.name":               "service name, plaintext",
	"service_identities.description":        "plaintext",
	"service_identities.allowed_secrets":    "JSON list of vault entry NAMES, plaintext (names are not encrypted today)",
	"service_identities.key_hash":           "SHA-256 of the service key; a one-way hash, not encrypted",
	"service_identities.key_prefix":         "identification prefix",
	"service_identities.last_used_at":       "timestamp",
	"service_identities.expires_at":         "timestamp",
	"service_identities.revoked_at":         "timestamp",
	"service_identities.created_at":         "timestamp",
	"service_identities.created_by_user_id": "FK to users",

	"service_secret_audit.id":                  "surrogate key",
	"service_secret_audit.service_identity_id": "FK",
	"service_secret_audit.service_name":        "denormalised name for audit-after-delete, plaintext",
	"service_secret_audit.event":               "outcome label",
	"service_secret_audit.secret_names": "JSON list of entry names, never values, sealed as a whole " +
		"under the audit DEK (settings.audit_name_dek, the registered surface). Same reasoning as " +
		"capability_log.secret_name: append-only rows cannot be rewritten by a rotation, so the KEY " +
		"rotates instead of the data",
	"service_secret_audit.error":       "error text, plaintext",
	"service_secret_audit.remote_ip":   "plaintext",
	"service_secret_audit.occurred_at": "timestamp",

	// sessions store only a jti; the bearer is a JWT signed with TRUSTISSUES_JWT_SECRET,
	// which is a separate secret with its own rotation story (revoke all sessions).
	"sessions.id":           "session jti, not a credential",
	"sessions.user_id":      "FK to users",
	"sessions.created_at":   "timestamp",
	"sessions.last_used_at": "timestamp",
	"sessions.expires_at":   "timestamp",
	"sessions.revoked_at":   "timestamp",

	// settings is key/value. settings.value is registered per KEY (smtp_password
	// and the vault sentinel); every other key holds plain configuration.
	"settings.key":        "setting name",
	"settings.updated_at": "timestamp",

	// Shield: a SEPARATE key (TRUSTISSUES_SHIELD_KEY) by design, so a Shield
	// compromise cannot touch the vault. Rotating the vault key must not rewrite
	// these, and Shield rows are session-scoped with a TTL, so its own key change
	// is handled by expiry rather than conversion.
	"shield_sessions.id":         "session id",
	"shield_sessions.created_at": "timestamp",
	"shield_sessions.last_seen":  "timestamp",
	"shield_sessions.expires_at": "timestamp",
	"shield_tokens.token":        "opaque marker handed to the model",
	"shield_tokens.session_id":   "FK to shield_sessions",
	"shield_tokens.kind":         "PII kind label",
	"shield_tokens.hint":         "value-derived hint, deliberately not the value",
	"shield_tokens.ciphertext":   "AES-GCM under TRUSTISSUES_SHIELD_KEY, NOT the vault key; out of scope for vault-key rotation",
	"shield_tokens.created_at":   "timestamp",

	// users: only totp_secret is vault-keyed (registered).
	"users.id":                   "surrogate key",
	"users.email":                "plaintext",
	"users.password_hash":        "Argon2id hash; one-way, not encrypted",
	"users.name":                 "plaintext",
	"users.role":                 "role label",
	"users.disabled":             "boolean",
	"users.totp_enabled":         "boolean",
	"users.totp_recovery_codes":  "JSON list of HASHED recovery codes; one-way, not encrypted",
	"users.sessions_valid_after": "timestamp watermark",
	"users.created_at":           "timestamp",
	"users.updated_at":           "timestamp",
	"users.totp_last_step":       "last spent TOTP time step, a replay watermark",

	// vault_entries: the keyed columns come from the registry. Everything below is
	// deliberately NOT encrypted, and two of them are worth reading twice.
	"vault_entries.id":      "surrogate key",
	"vault_entries.user_id": "FK to users",
	// vault_entries.name is NOT here any more. It was exempted as "stored in
	// cleartext; encrypting it behind a blind index is designed but deferred",
	// and 00040 did it, so it is a registered surface in rekeySurfaces along with
	// its name_bidx. If a future change drops either registration, this map is
	// where the guard will tell you to put it back rather than here.
	"vault_entries.encryption_version":     "derivation version for encrypted_value; rewritten with it by the sweep",
	"vault_entries.rotation_interval_days": "integer policy",
	"vault_entries.expires_at":             "timestamp",
	"vault_entries.last_rotated_at":        "timestamp",
	"vault_entries.auto_login":             "boolean",
	"vault_entries.provider":               "provider slug, plaintext",
	"vault_entries.auto_rotate":            "boolean",
	"vault_entries.rotation_log": "JSON history of rotation attempts; outcomes and timestamps, " +
		"never a secret value",
	"vault_entries.last_rotation_error": "error text from the provider, plaintext",
	"vault_entries.destination_patterns": "host globs the capability bridge may route to; a ceiling, " +
		"deliberately visible in the UI so an operator can narrow it",
	"vault_entries.injection_spec": "how to inject the secret into a request (header name, format); " +
		"a template, never the value",
	"vault_entries.created_at":    "timestamp",
	"vault_entries.updated_at":    "timestamp",
	"vault_entries.collection_id": "FK to collections",
	// Migration 00034 split user_id into a CUSTODIAN (this row's user_id, which
	// governs namespace and listing) and an OWNER, the only principal the secret
	// exit asks about. It is a plaintext user id like the custodian beside it; an
	// EMPTY one is meaningful and denies, which is a value no key protects and no
	// rotation can orphan.
	"vault_entries.secret_owner_user_id": "FK to users, the principal the exit asks about",
}

func listTables(dbConn *sql.DB) ([]string, error) {
	rows, err := dbConn.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func listColumns(dbConn *sql.DB, table string) ([]string, error) {
	// table comes from sqlite_master, not from user input, and PRAGMA does not
	// accept a bind parameter. Quoted so an odd table name cannot change the
	// statement's shape.
	rows, err := dbConn.Query(fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, ctype      string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestEveryColumnCryptoWriterIsARegisteredSurface closes the hole the schema
// walk cannot see.
//
// settings is a key/value table, so `settings.value` is ONE column holding a
// dozen unrelated things, only two of which are ciphertext. The schema walk
// classifies that column once and is then blind to a NEW setting key that
// happens to be encrypted: adding `settings['backup_passphrase']` sealed with
// columncrypto would add no column, trip no guard, and be silently orphaned by
// the next rotation.
//
// What a new columncrypto surface DOES require is a call to
// columncrypto.EncryptString. So this pins the set of files allowed to make that
// call. A new file calling it is a new surface, and the failure message says
// what to do about it.
//
// Deliberately file-level rather than line-level: this must not turn into a
// tripwire that fires on every unrelated edit inside a file it already knows.
func TestEveryColumnCryptoWriterIsARegisteredSurface(t *testing.T) {
	// Each file here is accounted for in rekeySurfaces, and says how.
	allowed := map[string]string{
		"auth.go":           "users.totp_secret (registered)",
		"settings.go":       "settings['smtp_password'] (registered)",
		"vault_keycheck.go": "settings['vault_keycheck'], the boot sentinel (registered)",
		"vault_rekey.go":    "the sweep itself, re-sealing the two surfaces above",
		"audit_name_crypto.go": "settings['audit_name_dek'], the WRAPPED audit DEK (registered). This " +
			"is the one entry here whose point is what it does NOT write: the audit name columns are " +
			"sealed under the DEK, not under the master key, so they are not surfaces and the sweep " +
			"never touches them. Rewrapping this settings row rotates both of those columns at once, " +
			"which is what lets them live in append-only tables the sweep is forbidden to UPDATE.",
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// Assembled rather than written literally so this file does not match itself.
	needle := "columncrypto." + "EncryptString("

	callers := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, rErr := os.ReadFile(f)
		if rErr != nil {
			t.Fatalf("read %s: %v", f, rErr)
		}
		if strings.Contains(string(src), needle) {
			callers[filepath.Base(f)] = true
		}
	}

	if len(callers) == 0 {
		t.Fatal("ABORT: no columncrypto encrypt call sites found at all; this guard is matching " +
			"nothing and is vacuous (did the call get renamed?)")
	}

	for f := range callers {
		if _, ok := allowed[f]; !ok {
			t.Errorf(`%s encrypts a value with columncrypto but is not a known keyed surface.

columncrypto ciphertext is sealed under TRUSTISSUES_VAULT_KEY, so whatever %s
writes is orphaned by the next master-key rotation unless the sweep converts it.

Add the destination to rekeySurfaces in vault_rekey.go (Family:
familyColumnCrypto, and SettingKey if it is a row in the settings table), teach
scanSettings or a sibling scanner to convert it, then add this file to the
allowed map above.

This exists because the schema walk in TestRekeyCoversEveryKeyedColumn cannot
see a new SETTINGS KEY: settings is key/value, so a new encrypted setting adds
no column and trips no schema guard.`, f, f)
		}
	}
	for f, why := range allowed {
		if !callers[f] {
			t.Errorf("the allowed list still names %s (%s) but that file no longer encrypts anything; "+
				"drop the entry so this list keeps meaning something", f, why)
		}
	}
}

// TestRegisteredSettingsKeysAreTheEncryptedOnes checks the other direction: the
// settings surfaces in the registry must name settings keys that this build
// actually uses. A typo in a SettingKey produces a surface that scans nothing,
// reports zero, and reads as clean.
func TestRegisteredSettingsKeysAreTheEncryptedOnes(t *testing.T) {
	want := map[string]bool{
		"smtp_password":      true,
		vaultKeyCheckSetting: true,
		// The wrapped audit-name DEK. Losing this one to a rotation is worse than
		// losing the others: the sentinel can be rewritten and the SMTP password
		// re-entered, but the audit rows this key opens are append-only and can
		// never be re-sealed under a new key.
		auditDEKSetting: true,
	}
	got := map[string]bool{}
	for _, s := range rekeySurfaces {
		if s.Table != "settings" {
			continue
		}
		if s.SettingKey == "" {
			t.Errorf("settings surface for column %q has no SettingKey; settings is key/value, so a "+
				"whole-column surface would sweep plaintext configuration as if it were ciphertext", s.Column)
			continue
		}
		got[s.SettingKey] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("settings key %q holds vault-key ciphertext but is not a registered rekey surface", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("settings key %q is registered as a rekey surface but is not one of the encrypted "+
				"settings this build writes; a typo here creates a surface that scans nothing and "+
				"reports clean", k)
		}
	}
}

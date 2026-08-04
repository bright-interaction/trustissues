// Package vaultegress is the only way, from anywhere in this module, to write a
// column of vault_entries that can change where a decrypted secret is sent.
//
// WHY THIS IS A PACKAGE AND NOT A FILE.
//
// Round 5 put every host-choosing write behind one file,
// internal/handlers/vault_egress_writes.go, and behind an egressgate.Ticket that
// only egressgate.Decide can mint. That was the right shape and the wrong
// enforcement: "one file" is not a thing Go knows about, so the rule was held up
// by a test that read the source and matched it against regular expressions. A
// skeptic planted four write paths through the gaps in those patterns. The
// sharpest was a query spelled
//
//	UPDATE vault_entries AS ve SET rotation_targets = ?, updated_at = CURRENT_TIMESTAMP WHERE ve.id = ?
//
// which is the ordinary sqlc shape with a table alias, and the guard's pattern
// was `update\s+vault_entries\s+set`. Every plant built, vetted clean and passed
// all four guards.
//
// PROVING A PROPERTY BY RECOGNISING ITS TEXTUAL FORM ALWAYS LOSES. The answer is
// not a better pattern.
//
// So the write methods are gone from every type a handler can name. The sqlc
// output for those statements is generated into
// internal/vaultegress/internal/egressq, and Go's `internal` rule says a package
// under a directory named internal is importable only by code rooted at that
// directory's parent. The parent here is internal/vaultegress. Package handlers
// cannot import it; the compiler says so, in the editor, before any test runs:
//
//	use of internal package .../internal/vaultegress/internal/egressq not allowed
//
// and `h.queries.UpdateVaultEntryRotationTargets(...)`, the round-5 defect
// written out literally, no longer names anything:
//
//	h.queries.UpdateVaultEntryRotationTargets undefined
//	(type *db.Queries has no field or method UpdateVaultEntryRotationTargets)
//
// What remains reachable is this package's exported surface, and every function
// in it takes an egressgate.Ticket for the same entry and the same field before
// it does anything. A Ticket has no exported fields and one constructor, so the
// zero value authorizes nothing: "forgot to ask" cannot be spelled to look like
// "asked and was allowed".
//
// WHAT THIS DOES NOT MAKE IMPOSSIBLE, stated here rather than left to be found:
// somebody can still add a NEW query to internal/db/queries, or write a raw
// statement with database/sql, that touches one of these columns. The compiler
// has no opinion about SQL text. That residual is covered by
// TestNoStatementOutsideTheEgressPackageWritesAHostChoosingColumn, which does
// not read the SQL: it hands every statement in the module to SQLite against a
// schema where the host-choosing columns are GENERATED, and lets the engine
// refuse to prepare any statement that assigns one. Aliases, comments, casing
// and whitespace are the parser's problem, not ours.
package vaultegress

import (
	"context"
	"database/sql"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/egressgate"
	"github.com/bright-interaction/trustissues/internal/vaultegress/internal/egressq"
)

// The field names a Ticket is issued against. A Ticket for one of these cannot
// be spent on another, so permission to narrow a capability ceiling cannot be
// used to write a delivery target.
//
// Exported so the callers that mint tickets and the wrappers that check them
// name the same strings. Two spellings of one field name is the drift this
// package exists to prevent.
const (
	FieldDestinations    = "destination_patterns"
	FieldProvider        = "provider+provider_meta"
	FieldProviderMeta    = "provider_meta"
	FieldRotationTargets = "rotation_targets"
)

// HostChoosingColumns is every vault_entries column whose value can change where
// a decrypted secret is sent.
//
// It is the list the guards check themselves against, and it is stated here, in
// the package that owns the writes, rather than in a test file, so that
// reclassifying a column and forgetting to move its writer are not two
// independent edits.
func HostChoosingColumns() []string {
	return []string{"destination_patterns", "provider", "provider_meta", "rotation_targets"}
}

// ── parameter types ─────────────────────────────────────────────────────────
//
// Deliberately not aliases for the generated ones. egressq is unreachable from
// outside this directory, so its parameter structs are unnameable elsewhere and
// a caller has to come through a function here, which is the function that
// checks the ticket.

// DestinationPatternsParams writes the capability ceiling.
type DestinationPatternsParams struct {
	DestinationPatterns string
	ID                  string
}

// CapabilityDefaultsParams seeds the provider preset into an untouched ceiling.
type CapabilityDefaultsParams struct {
	DestinationPatterns string
	InjectionSpec       string
	ID                  string
}

// ProviderParams writes provider, provider_meta and auto_rotate together.
type ProviderParams struct {
	Provider     sql.NullString
	ProviderMeta sql.NullString
	AutoRotate   sql.NullInt64
	ID           string
}

// ProviderMetaParams writes provider_meta alone.
type ProviderMetaParams struct {
	ProviderMeta sql.NullString
	ID           string
}

// RotationTargetsParams writes the delivery targets. THE round-5 column.
type RotationTargetsParams struct {
	RotationTargets sql.NullString
	ID              string
}

// CreateEntryParams inserts a vault entry, which carries provider and
// provider_meta on the INSERT.
type CreateEntryParams struct {
	ID                   string
	UserID               string
	Name                 string
	EncryptedValue       []byte
	Nonce                []byte
	Url                  sql.NullString
	AliasUrl             sql.NullString
	Username             sql.NullString
	Category             sql.NullString
	Notes                sql.NullString
	AutoLogin            int64
	RotationIntervalDays sql.NullInt64
	ExpiresAt            sql.NullTime
	Provider             sql.NullString
	ProviderMeta         sql.NullString
	AutoRotate           sql.NullInt64
	UrlBidx              string
	AliasUrlBidx         string
}

// writer builds the generated querier on the caller's own handle.
//
// The caller's handle, never the pool: a helper called between BeginTx and
// Commit that reached for the pool would write outside the transaction it thinks
// it is in, and these are exactly the writes where that matters.
func writer(q *db.Queries) *egressq.Queries { return egressq.New(q.Handle()) }

// ── the wrappers ────────────────────────────────────────────────────────────
//
// The ticket check is first in every one of them. A wrapper that performed the
// write and then complained would have already moved the secret.

// SetDestinationPatterns writes the capability ceiling.
func SetDestinationPatterns(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p DestinationPatternsParams) error {

	if err := tk.Authorizes(p.ID, FieldDestinations); err != nil {
		return err
	}
	return writer(q).UpdateVaultEntryDestinationPatterns(ctx, egressq.UpdateVaultEntryDestinationPatternsParams{
		DestinationPatterns: p.DestinationPatterns,
		ID:                  p.ID,
	})
}

// SeedCapabilityDefaults writes the provider preset into the ceiling. It is a
// ceiling write like any other: it turns "no agent access" into "one host", and
// three presets expand a tenant value out of the entry's own provider_meta.
func SeedCapabilityDefaults(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p CapabilityDefaultsParams) error {

	if err := tk.Authorizes(p.ID, FieldDestinations); err != nil {
		return err
	}
	return writer(q).SeedVaultEntryCapabilityDefaults(ctx, egressq.SeedVaultEntryCapabilityDefaultsParams{
		DestinationPatterns: p.DestinationPatterns,
		InjectionSpec:       p.InjectionSpec,
		ID:                  p.ID,
	})
}

// SetProvider writes provider, provider_meta and auto_rotate together.
func SetProvider(ctx context.Context, q *db.Queries, tk egressgate.Ticket, p ProviderParams) error {
	if err := tk.Authorizes(p.ID, FieldProvider); err != nil {
		return err
	}
	return writer(q).UpdateVaultEntryProvider(ctx, egressq.UpdateVaultEntryProviderParams{
		Provider:     p.Provider,
		ProviderMeta: p.ProviderMeta,
		AutoRotate:   p.AutoRotate,
		ID:           p.ID,
	})
}

// SetProviderMeta writes provider_meta alone. Two callers, both of them the
// server recording its own work (the rotation write-back of a minted key id, and
// the at-rest encryption backfill), and neither may change the reachable hosts.
func SetProviderMeta(ctx context.Context, q *db.Queries, tk egressgate.Ticket, p ProviderMetaParams) error {
	if err := tk.Authorizes(p.ID, FieldProviderMeta); err != nil {
		return err
	}
	return writer(q).UpdateVaultEntryProviderMeta(ctx, egressq.UpdateVaultEntryProviderMetaParams{
		ProviderMeta: p.ProviderMeta,
		ID:           p.ID,
	})
}

// SetRotationTargets writes the delivery targets. THE round-5 column: a
// vault_only account holding an accepted EDITOR seat on somebody else's shared
// entry PUT a webhook_url at a host it controlled, got 200, and the next
// scheduled rotation POSTed the freshly minted plaintext there.
func SetRotationTargets(ctx context.Context, q *db.Queries, tk egressgate.Ticket,
	p RotationTargetsParams) error {

	if err := tk.Authorizes(p.ID, FieldRotationTargets); err != nil {
		return err
	}
	return writer(q).UpdateVaultEntryRotationTargets(ctx, egressq.UpdateVaultEntryRotationTargetsParams{
		RotationTargets: p.RotationTargets,
		ID:              p.ID,
	})
}

// CreateEntry inserts a vault entry.
//
// The authority is not in question here and the Ticket says so explicitly rather
// than by omission: the row being created carries the caller's own user_id, so
// they ARE the principal the authority oracle would name. Routing it through a
// wrapper anyway is the point of a chokepoint. The alternative is one query
// exempted "because it is obviously fine", which is how the next reviewer
// discovers a second door.
func CreateEntry(ctx context.Context, q *db.Queries, tk egressgate.Ticket, p CreateEntryParams) error {
	if err := tk.Authorizes(p.ID, FieldProvider); err != nil {
		return err
	}
	return writer(q).CreateVaultEntry(ctx, egressq.CreateVaultEntryParams{
		ID:                   p.ID,
		UserID:               p.UserID,
		Name:                 p.Name,
		EncryptedValue:       p.EncryptedValue,
		Nonce:                p.Nonce,
		Url:                  p.Url,
		AliasUrl:             p.AliasUrl,
		Username:             p.Username,
		Category:             p.Category,
		Notes:                p.Notes,
		AutoLogin:            p.AutoLogin,
		RotationIntervalDays: p.RotationIntervalDays,
		ExpiresAt:            p.ExpiresAt,
		Provider:             p.Provider,
		ProviderMeta:         p.ProviderMeta,
		AutoRotate:           p.AutoRotate,
		UrlBidx:              p.UrlBidx,
		AliasUrlBidx:         p.AliasUrlBidx,
	})
}

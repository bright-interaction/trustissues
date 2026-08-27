package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
)

const privateAccessAuditLatchSetting = "private_access_audit_ever_fully_private"

// privateAccessOperation keeps the two policy questions explicit. Metadata is
// still available for sensitive_private collections; anything that reveals,
// changes, spends, rotates, delegates, or changes access to a secret is a
// sensitive operation. fully_private collections require private ingress for
// both classes.
type privateAccessOperation uint8

const (
	privateAccessMetadata privateAccessOperation = iota
	privateAccessSensitive
)

func storedPrivateAccessPolicy(raw string) (privateaccess.Policy, error) {
	policy, ok := privateaccess.Parse(raw)
	if !ok {
		// The database CHECK should make this unreachable. Treating an unknown
		// value as standard would turn corruption or an out-of-band write into a
		// silent authorization downgrade.
		return "", fmt.Errorf("unknown collection private_access_policy %q", raw)
	}
	return policy, nil
}

func privateIngressRequired(policy privateaccess.Policy, operation privateAccessOperation) bool {
	switch policy {
	case privateaccess.PolicyStandard:
		return false
	case privateaccess.PolicySensitivePrivate:
		return operation == privateAccessSensitive
	case privateaccess.PolicyFullyPrivate:
		return true
	default:
		// Callers parse stored values first, but fail closed if a future caller
		// accidentally passes an unvalidated policy.
		return true
	}
}

func writePrivateIngressRequired(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeError(w, r, http.StatusForbidden, middleware.PrivateIngressRequiredCode,
		"private ingress required")
}

// requireConfiguredPrivateControlPlaneIngress makes selected instance-wide
// control-plane surfaces uniformly private whenever the deployment has made a
// private listener available. This check intentionally performs no database
// reads: a public request must get the same answer whether protected state (or
// a particular target) exists or not. Deployments without the optional
// listener retain the older row/latch-dependent compatibility checks.
func requireConfiguredPrivateControlPlaneIngress(w http.ResponseWriter, r *http.Request) bool {
	if !middleware.IsPrivateIngressConfigured(r.Context()) || middleware.IsPrivateIngress(r.Context()) {
		return true
	}
	writePrivateIngressRequired(w, r)
	return false
}

// enforcePrivateAccessPolicy applies a parsed collection policy to this
// request. Fully-private resources use an ordinary 404 on public ingress so
// the public surface does not become an existence oracle. sensitive_private
// resources return the stable private_ingress_required code so clients can
// direct an authorised user to the private URL.
func enforcePrivateAccessPolicy(w http.ResponseWriter, r *http.Request,
	policy privateaccess.Policy, operation privateAccessOperation, hideFullyPrivate bool,
	hiddenNotFoundMessage string) bool {

	if middleware.IsPrivateIngress(r.Context()) || !privateIngressRequired(policy, operation) {
		return true
	}
	if hideFullyPrivate && policy == privateaccess.PolicyFullyPrivate {
		if hiddenNotFoundMessage == "" {
			hiddenNotFoundMessage = "resource not found"
		}
		writeNotFound(w, r, hiddenNotFoundMessage)
		return false
	}
	writePrivateIngressRequired(w, r)
	return false
}

func collectionPrivateAccessPolicy(ctx context.Context, queries *db.Queries,
	collectionID string) (privateaccess.Policy, error) {
	collection, err := queries.GetCollection(ctx, collectionID)
	if err != nil {
		return "", err
	}
	return storedPrivateAccessPolicy(collection.PrivateAccessPolicy)
}

// entryPrivateAccessPolicy returns standard for a personal entry and the
// collection's stored policy for a shared entry. found=false preserves each
// handler's existing not-found response when a row disappears between its
// normal authorization lookup and this additional gate.
func entryPrivateAccessPolicy(ctx context.Context, queries *db.Queries,
	entryID string) (policy privateaccess.Policy, found bool, err error) {
	access, err := queries.GetVaultEntryAccess(ctx, entryID)
	if err != nil {
		if err == sql.ErrNoRows {
			return privateaccess.PolicyStandard, false, nil
		}
		return "", false, err
	}
	if !access.CollectionID.Valid || access.CollectionID.String == "" {
		return privateaccess.PolicyStandard, true, nil
	}
	policy, err = collectionPrivateAccessPolicy(ctx, queries, access.CollectionID.String)
	return policy, true, err
}

func entryPrivateAccessPolicyFromDB(ctx context.Context, dbConn *sql.DB,
	entryID string) (policy privateaccess.Policy, found bool, err error) {
	var raw sql.NullString
	err = dbConn.QueryRowContext(ctx, `
SELECT c.private_access_policy
FROM vault_entries e
LEFT JOIN collections c ON c.id = e.collection_id
WHERE e.id = ?`, entryID).Scan(&raw)
	if err != nil {
		if err == sql.ErrNoRows {
			return privateaccess.PolicyStandard, false, nil
		}
		return "", false, err
	}
	if !raw.Valid || raw.String == "" {
		return privateaccess.PolicyStandard, true, nil
	}
	policy, err = storedPrivateAccessPolicy(raw.String)
	return policy, true, err
}

func privateIngressSQLFlag(ctx context.Context) int64 {
	if middleware.IsPrivateIngress(ctx) {
		return 1
	}
	return 0
}

// entryAllowsExternalNotificationMetadata decides whether a global webhook or
// notification channel may receive metadata about an entry. fully_private is
// an ingress-and-egress metadata boundary: configured channels are not scoped
// to a collection or tailnet, so those events are suppressed rather than
// sending a name/existence signal off-box. A policy lookup failure also
// suppresses delivery (fail closed); the local activity/server logs remain.
func entryAllowsExternalNotificationMetadata(ctx context.Context, queries *db.Queries,
	entryID string) bool {
	if entryID == "" {
		// Instance-wide failures such as an auto-rotation query failure do not
		// describe a particular collection.
		return true
	}
	policy, found, err := entryPrivateAccessPolicy(ctx, queries, entryID)
	if err != nil {
		slog.Error("private access: suppressing notification after policy lookup failure",
			"entry", entryID, "error", err)
		return false
	}
	return found && policy != privateaccess.PolicyFullyPrivate
}

func (h *VaultHandler) requireEntryPrivateAccess(w http.ResponseWriter, r *http.Request,
	entryID string, operation privateAccessOperation) bool {
	policy, found, err := entryPrivateAccessPolicy(r.Context(), h.queries, entryID)
	if err != nil {
		slog.Error("private access: entry policy lookup failed", "entry", entryID, "error", err)
		writeInternalError(w, r, "private access policy could not be verified")
		return false
	}
	if !found {
		return true
	}
	return enforcePrivateAccessPolicy(w, r, policy, operation, true, "vault entry not found")
}

func (h *CapabilityHandler) requireEntryPrivateAccess(w http.ResponseWriter, r *http.Request,
	entryID string, operation privateAccessOperation) bool {
	policy, found, err := entryPrivateAccessPolicyFromDB(r.Context(), h.db, entryID)
	if err != nil {
		slog.Error("private access: capability entry policy lookup failed", "entry", entryID, "error", err)
		writeInternalError(w, r, "private access policy could not be verified")
		return false
	}
	if !found {
		return true
	}
	return enforcePrivateAccessPolicy(w, r, policy, operation, true, "secret not found")
}

func (h *CollectionHandler) requireCollectionPrivateAccess(w http.ResponseWriter, r *http.Request,
	collectionID string, operation privateAccessOperation) bool {
	policy, err := collectionPrivateAccessPolicy(r.Context(), h.queries, collectionID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeNotFound(w, r, "collection not found")
		} else {
			slog.Error("private access: collection policy lookup failed", "collection", collectionID, "error", err)
			writeInternalError(w, r, "private access policy could not be verified")
		}
		return false
	}
	return enforcePrivateAccessPolicy(w, r, policy, operation, true, "collection not found")
}

func (h *VaultHandler) requireCollectionPrivateAccess(w http.ResponseWriter, r *http.Request,
	collectionID string, operation privateAccessOperation) bool {
	policy, err := collectionPrivateAccessPolicy(r.Context(), h.queries, collectionID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeNotFound(w, r, "collection not found")
		} else {
			slog.Error("private access: collection policy lookup failed", "collection", collectionID, "error", err)
			writeInternalError(w, r, "private access policy could not be verified")
		}
		return false
	}
	return enforcePrivateAccessPolicy(w, r, policy, operation, true, "collection not found")
}

// requireWritableCollectionDestination orders the three destination checks so
// neither collection existence nor its private policy becomes an oracle:
// fully_private is concealed before membership is considered; standard and
// sensitive_private produce the same ordinary no-write response for outsiders;
// and only an authorised writer receives sensitive_private's actionable
// private-ingress response. Callers run this helper on their write transaction
// so policy and membership are one authorization snapshot.
func (h *VaultHandler) requireWritableCollectionDestination(w http.ResponseWriter, r *http.Request,
	collectionID string) bool {
	policy, err := collectionPrivateAccessPolicy(r.Context(), h.queries, collectionID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeNotFound(w, r, "collection not found")
		} else {
			slog.Error("private access: destination policy lookup failed", "collection", collectionID, "error", err)
			writeInternalError(w, r, "private access policy could not be verified")
		}
		return false
	}

	// Metadata admission is enough to conceal fully_private while allowing a
	// sensitive_private collection to reach the membership check.
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessMetadata, true, "collection not found") {
		return false
	}
	if !h.canWriteCollection(r, collectionID) {
		writeForbidden(w, r, "you do not have write access to that collection")
		return false
	}
	return enforcePrivateAccessPolicy(w, r, policy, privateAccessSensitive, true, "collection not found")
}

// requireHistoricalPrivateAuditIngress protects global, append-only audit
// readers. An audit row can retain a collection or secret name after its source
// row is downgraded or deleted, so the database migration keeps a monotonic
// latch once a fully-private collection has ever existed. Looking only at live
// collections here would reopen that historical metadata.
func requireHistoricalPrivateAuditIngress(w http.ResponseWriter, r *http.Request,
	queries *db.Queries) bool {
	if middleware.IsPrivateIngress(r.Context()) {
		return true
	}
	value, err := queries.GetSetting(r.Context(), privateAccessAuditLatchSetting)
	if err == sql.ErrNoRows {
		return true
	}
	if err != nil {
		slog.Error("private access: audit latch lookup failed", "error", err)
		writeInternalError(w, r, "private access policy could not be verified")
		return false
	}
	if value != "1" {
		// The latch has a closed, monotonic representation. Treating an
		// unexpected stored value as disabled would make corruption an
		// authorization downgrade.
		slog.Error("private access: audit latch has invalid value", "value", value)
		writeInternalError(w, r, "private access policy could not be verified")
		return false
	}
	writePrivateIngressRequired(w, r)
	return false
}

// requireGlobalProtectedPrivateAccess is for whole-vault operations that scan
// or rewrite every keyed row (for example master-key status/rekey). If any live
// collection requires private ingress for sensitive work, the global operation
// must use that ingress too; otherwise it becomes a public side door around a
// row-level policy.
func requireGlobalProtectedPrivateAccess(w http.ResponseWriter, r *http.Request,
	queries *db.Queries) bool {
	if middleware.IsPrivateIngress(r.Context()) {
		return true
	}
	required, err := globalProtectedPrivateAccessRequired(r.Context(), queries)
	if err != nil {
		slog.Error("private access: global policy scan failed", "error", err)
		writeInternalError(w, r, "private access policy could not be verified")
		return false
	}
	if required {
		writePrivateIngressRequired(w, r)
		return false
	}
	return true
}

// globalProtectedPrivateAccessRequired is the response-free form of the global
// policy scan. Callers that operate on the whole keyed store run this against
// the same transaction as the scan or rewrite it authorizes; checking through
// the pool first would let a concurrent promotion land between gate and use.
func globalProtectedPrivateAccessRequired(ctx context.Context, queries *db.Queries) (bool, error) {
	rows, err := queries.ListAllCollections(ctx)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		policy, err := storedPrivateAccessPolicy(row.PrivateAccessPolicy)
		if err != nil {
			return false, fmt.Errorf("collection %s: %w", row.ID, err)
		}
		if privateIngressRequired(policy, privateAccessSensitive) {
			return true, nil
		}
	}
	return false, nil
}

func privateMetadataVisible(ctx context.Context, rawPolicy string) (bool, error) {
	policy, err := storedPrivateAccessPolicy(rawPolicy)
	if err != nil {
		return false, err
	}
	return middleware.IsPrivateIngress(ctx) || policy != privateaccess.PolicyFullyPrivate, nil
}

// collectionPolicyMap validates every stored policy once for metadata list
// handlers. The handlers then filter locally, avoiding one policy query per
// entry while still failing closed if any persisted authorization input is not
// in the closed vocabulary.
func collectionPolicyMap(ctx context.Context, queries *db.Queries) (map[string]privateaccess.Policy, error) {
	rows, err := queries.ListAllCollections(ctx)
	if err != nil {
		return nil, err
	}
	policies := make(map[string]privateaccess.Policy, len(rows))
	for _, row := range rows {
		policy, err := storedPrivateAccessPolicy(row.PrivateAccessPolicy)
		if err != nil {
			return nil, err
		}
		policies[row.ID] = policy
	}
	return policies, nil
}

func entryMetadataVisibleOnIngress(ctx context.Context, collectionID *string,
	policies map[string]privateaccess.Policy) bool {
	if middleware.IsPrivateIngress(ctx) || collectionID == nil || *collectionID == "" {
		return true
	}
	policy, ok := policies[*collectionID]
	// A dangling collection id should be prevented by the foreign key. Failing
	// closed here ensures metadata does not leak if a damaged/legacy database
	// violates that invariant.
	return ok && policy != privateaccess.PolicyFullyPrivate
}

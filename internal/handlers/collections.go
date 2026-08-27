package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/emailidentity"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
	"github.com/go-chi/chi/v5"
)

// CollectionHandler manages shared team vaults (collections) and their members.
// A collection groups vault entries that several teammates can access via a
// per-collection role: viewer (read), editor (read/write entries), manager
// (editor plus member and collection management).
type CollectionHandler struct {
	queries *db.Queries
	// vault is needed to decrypt/re-encrypt rotation_targets when purging a
	// departing member's delivery endpoints. Nil-safe: the purge is skipped.
	vault *VaultHandler
}

func NewCollectionHandler(queries *db.Queries, vault *VaultHandler) *CollectionHandler {
	return &CollectionHandler{queries: queries, vault: vault}
}

func validCollectionRole(role string) bool {
	return role == collRoleViewer || role == collRoleEditor || role == collRoleManager
}

const (
	maxCollectionNameLen        = 255
	maxCollectionDescriptionLen = 10000
)

// validateLiveCollectionFields is shared by Create and Update so a collection
// cannot become valid on one surface and uneditable or non-portable on the
// other. Names retain the API's user-friendly normalization contract and are
// trimmed in place before validation and storage; descriptions are free text
// and retain whitespace.
func validateLiveCollectionFields(name *string, description string) string {
	*name = strings.TrimSpace(*name)
	if *name == "" {
		return "name is required"
	}
	if len(*name) > maxCollectionNameLen {
		return fmt.Sprintf("name must be %d characters or less", maxCollectionNameLen)
	}
	if len(description) > maxCollectionDescriptionLen {
		return fmt.Sprintf("description must be %d characters or less", maxCollectionDescriptionLen)
	}
	return ""
}

// role returns the caller's role in a collection. Instance admins are treated as
// managers of every collection. The second return is false when the caller is
// neither a member nor an admin.
func (h *CollectionHandler) role(r *http.Request, collectionID string) (string, bool) {
	return h.roleWithQueries(r, h.queries, collectionID)
}

// roleWithQueries is role pinned to the caller's database snapshot. Every
// collection mutation uses this form with its transaction-bound query set so a
// concurrent demotion/removal cannot land between the authorization check and
// the write it authorized.
func (h *CollectionHandler) roleWithQueries(r *http.Request, queries *db.Queries, collectionID string) (string, bool) {
	if middleware.IsAdmin(r.Context()) {
		return collRoleManager, true
	}
	role, err := queries.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
		CollectionID: collectionID,
		UserID:       middleware.GetUserID(r.Context()),
	})
	if err != nil {
		return "", false
	}
	return role, true
}

// collectionForRequest resolves the collection and applies only the metadata
// half of its ingress policy. That ordering is deliberate:
//
//   - a fully_private collection is hidden with the exact same 404 as a missing
//     id before any role-specific 403 can reveal that it exists;
//   - sensitive_private metadata remains public, so the caller's role is still
//     checked before the sensitive-operation gate returns its actionable 403.
//
// Mutation callers pass their transaction-bound query set. The returned policy
// and every later authorization/write then describe one SQLite snapshot.
func (h *CollectionHandler) collectionForRequest(w http.ResponseWriter, r *http.Request,
	queries *db.Queries, collectionID string) (db.Collection, privateaccess.Policy, bool) {

	collection, err := queries.GetCollection(r.Context(), collectionID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeNotFound(w, r, "collection not found")
		} else {
			logError(r, "collections: collection lookup failed", "collection", collectionID, "error", err)
			writeInternalError(w, r, "private access policy could not be verified")
		}
		return db.Collection{}, "", false
	}
	policy, err := storedPrivateAccessPolicy(collection.PrivateAccessPolicy)
	if err != nil {
		logError(r, "collections: invalid private access policy", "collection", collectionID, "error", err)
		writeInternalError(w, r, "private access policy could not be verified")
		return db.Collection{}, "", false
	}
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessMetadata, true, "collection not found") {
		return db.Collection{}, "", false
	}
	return collection, policy, true
}

func (h *CollectionHandler) beginMutation(w http.ResponseWriter, r *http.Request, action string) (*sql.Tx, *db.Queries, bool) {
	tx, qtx, err := beginQueriesTx(r.Context(), h.queries, nil)
	if err != nil {
		logError(r, action+": begin transaction failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return nil, nil, false
	}
	return tx, qtx, true
}

func commitCollectionMutation(w http.ResponseWriter, r *http.Request, tx *sql.Tx, action string) bool {
	if err := tx.Commit(); err != nil {
		logError(r, action+": commit failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return false
	}
	return true
}

type collectionResponse struct {
	ID                  string               `json:"id"`
	Name                string               `json:"name"`
	Description         string               `json:"description"`
	PrivateAccessPolicy privateaccess.Policy `json:"private_access_policy"`
	Role                string               `json:"role,omitempty"`
	MemberCount         int                  `json:"member_count,omitempty"`
	EntryCount          int64                `json:"entry_count,omitempty"`
	CreatedAt           *string              `json:"created_at"`
	UpdatedAt           *string              `json:"updated_at"`
}

// List handles GET /api/collections. Admins see every collection; others see
// only the collections they belong to, with their role.
func (h *CollectionHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := []collectionResponse{}

	if middleware.IsAdmin(ctx) {
		rows, err := h.queries.ListAllCollections(ctx)
		if err != nil {
			logError(r, "collections.list: query failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		for _, c := range rows {
			visible, policyErr := privateMetadataVisible(ctx, c.PrivateAccessPolicy)
			if policyErr != nil {
				logError(r, "collections.list: invalid private access policy", "collection", c.ID, "error", policyErr)
				writeInternalError(w, r, "private access policy could not be verified")
				return
			}
			if !visible {
				continue
			}
			out = append(out, collectionResponse{
				ID: c.ID, Name: c.Name, Description: c.Description,
				PrivateAccessPolicy: privateaccess.Policy(c.PrivateAccessPolicy), Role: collRoleManager,
				CreatedAt: nullTimePtr(c.CreatedAt), UpdatedAt: nullTimePtr(c.UpdatedAt),
			})
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	rows, err := h.queries.ListCollectionsForUser(ctx, middleware.GetUserID(ctx))
	if err != nil {
		logError(r, "collections.list: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	for _, c := range rows {
		visible, policyErr := privateMetadataVisible(ctx, c.PrivateAccessPolicy)
		if policyErr != nil {
			logError(r, "collections.list: invalid private access policy", "collection", c.ID, "error", policyErr)
			writeInternalError(w, r, "private access policy could not be verified")
			return
		}
		if !visible {
			continue
		}
		out = append(out, collectionResponse{
			ID: c.ID, Name: c.Name, Description: c.Description,
			PrivateAccessPolicy: privateaccess.Policy(c.PrivateAccessPolicy), Role: c.Role,
			CreatedAt: nullTimePtr(c.CreatedAt), UpdatedAt: nullTimePtr(c.UpdatedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// Create handles POST /api/collections. Any authenticated user may create a
// collection; the creator becomes its first manager.
func (h *CollectionHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	var req struct {
		Name                string `json:"name"`
		Description         string `json:"description"`
		PrivateAccessPolicy string `json:"private_access_policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	if message := validateLiveCollectionFields(&req.Name, req.Description); message != "" {
		writeBadRequest(w, r, message)
		return
	}
	policy, ok := privateaccess.ParseOrDefault(req.PrivateAccessPolicy)
	if !ok {
		writeBadRequest(w, r, "private_access_policy must be standard, sensitive_private, or fully_private")
		return
	}
	// Enabling a protected policy is a two-phase operation: prove that the
	// private listener works by creating/updating through it, then persist the
	// policy. This prevents a public-only deployment from locking itself out.
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessSensitive, false, "") {
		return
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		logError(r, "collections.create: id gen failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	id := hex.EncodeToString(idBytes)

	tx, qtx, ok := h.beginMutation(w, r, "collections.create")
	if !ok {
		return
	}
	defer tx.Rollback()
	if err := qtx.CreateCollectionWithPolicy(r.Context(), db.CreateCollectionWithPolicyParams{
		ID:                  id,
		Name:                req.Name,
		Description:         req.Description,
		CreatedBy:           sql.NullString{String: userID, Valid: userID != ""},
		PrivateAccessPolicy: string(policy),
	}); err != nil {
		logError(r, "collections.create: insert failed", "error", err)
		writeInternalError(w, r, "failed to create collection")
		return
	}
	// The creator is the first manager. Self-membership needs no consent step,
	// so it is accepted immediately; otherwise the creator would be locked out
	// of the collection they just made.
	if err := qtx.AddCollectionMember(r.Context(), db.AddCollectionMemberParams{
		CollectionID: id, UserID: userID, Role: collRoleManager,
		AcceptedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		// Self-membership: the creator invited themselves.
		InvitedBy: toNullString(userID),
	}); err != nil {
		logError(r, "collections.create: seed manager failed", "error", err)
		writeInternalError(w, r, "failed to create collection")
		return
	}
	if !commitCollectionMutation(w, r, tx, "collections.create") {
		return
	}

	LogActivityFromRequest(h.queries, r, "collection.create", fmt.Sprintf("Collection created: %s", req.Name))
	writeJSON(w, http.StatusCreated, collectionResponse{
		ID: id, Name: req.Name, Description: req.Description,
		PrivateAccessPolicy: policy, Role: collRoleManager,
	})
}

// Get handles GET /api/collections/{id} for any member (or admin).
func (h *CollectionHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tx, qtx, err := beginQueriesTx(r.Context(), h.queries, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		logError(r, "collections.get: snapshot failed", "collection", id, "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	c, _, found := h.collectionForRequest(w, r, qtx, id)
	if !found {
		return
	}
	role, ok := h.roleWithQueries(r, qtx, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	entryCount, err := qtx.CountCollectionEntries(r.Context(), sql.NullString{String: id, Valid: true})
	if err != nil {
		logError(r, "collections.get: entry count failed", "collection", id, "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if err := tx.Commit(); err != nil {
		logError(r, "collections.get: snapshot commit failed", "collection", id, "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, collectionResponse{
		ID: c.ID, Name: c.Name, Description: c.Description,
		PrivateAccessPolicy: privateaccess.Policy(c.PrivateAccessPolicy), Role: role, EntryCount: entryCount,
		CreatedAt: nullTimePtr(c.CreatedAt), UpdatedAt: nullTimePtr(c.UpdatedAt),
	})
}

// Update handles PUT /api/collections/{id} (manager or admin only).
func (h *CollectionHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name                string  `json:"name"`
		Description         string  `json:"description"`
		PrivateAccessPolicy *string `json:"private_access_policy"`
	}
	decodeErr := json.NewDecoder(r.Body).Decode(&req)
	tx, qtx, ok := h.beginMutation(w, r, "collections.update")
	if !ok {
		return
	}
	defer tx.Rollback()
	_, currentPolicy, found := h.collectionForRequest(w, r, qtx, id)
	if !found {
		return
	}
	role, ok := h.roleWithQueries(r, qtx, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can change it")
		return
	}
	// Every mutation of an already-protected collection is private, including a
	// downgrade back to standard. Otherwise a stolen public session could remove
	// the very network requirement intended to contain it.
	if !enforcePrivateAccessPolicy(w, r, currentPolicy, privateAccessSensitive, true, "collection not found") {
		return
	}
	if decodeErr != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	if message := validateLiveCollectionFields(&req.Name, req.Description); message != "" {
		writeBadRequest(w, r, message)
		return
	}
	var policy sql.NullString
	if req.PrivateAccessPolicy != nil {
		parsed, valid := privateaccess.Parse(*req.PrivateAccessPolicy)
		if !valid {
			writeBadRequest(w, r, "private_access_policy must be standard, sensitive_private, or fully_private")
			return
		}
		if !enforcePrivateAccessPolicy(w, r, parsed, privateAccessSensitive, false, "") {
			return
		}
		policy = sql.NullString{String: string(parsed), Valid: true}
	}
	if err := qtx.UpdateCollection(r.Context(), db.UpdateCollectionParams{
		Name: req.Name, Description: req.Description, PrivateAccessPolicy: policy, ID: id,
	}); err != nil {
		logError(r, "collections.update: failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if !commitCollectionMutation(w, r, tx, "collections.update") {
		return
	}
	LogActivityFromRequest(h.queries, r, "collection.update", fmt.Sprintf("Collection updated: %s", req.Name))
	w.WriteHeader(http.StatusNoContent)
}

// collectionDeleteEntrySample caps how many entry names DeleteCollection
// samples for the activity log. The exact count still comes from
// CountCollectionEntries and is always logged in full, so a collection past
// the cap is never under-reported, only under-NAMED; 25 is enough to name
// every entry in the overwhelming majority of real collections while keeping
// the append-only activity_log row bounded regardless of how large a
// collection grows.
const collectionDeleteEntrySample = 25

// Delete handles DELETE /api/collections/{id} (manager or admin only). Deleting
// a collection cascades to its members and entries via the FK's ON DELETE
// CASCADE, and that cascade is the ONLY thing in this product that can destroy
// a whole batch of secrets in one call with no recovery path (backups are
// deferred, and activity_log is the sole tamper-evident trail). Two things
// therefore happen before DeleteCollection ever runs:
//
//  1. Compare-and-swap on the entry count. A non-empty collection refuses the
//     delete unless the caller's ?entry_count= matches what the server
//     currently counts, the same shape as the last-manager and rotation CAS
//     guards elsewhere in this handler set: the caller must prove it knew the
//     state it was about to destroy, not just click a button. This is a
//     server-enforced backstop behind the UI's own confirmation dialog, not a
//     replacement for it: the dialog can be skipped by anyone calling the API
//     directly, and unlike its /members siblings this route allows a plain
//     0-secret collection to be deleted with no confirmation at all, which
//     matches "nothing is lost" and keeps an empty collection cheap to clean up.
//  2. The collection's name and a capped sample of the entries about to die
//     are read and logged BEFORE the cascade, so activity_log can answer
//     "which credentials do we now have to rotate upstream" afterwards
//     instead of only recording that a collection with some id was deleted.
func (h *CollectionHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tx, qtx, ok := h.beginMutation(w, r, "collections.delete")
	if !ok {
		return
	}
	defer tx.Rollback()
	c, policy, found := h.collectionForRequest(w, r, qtx, id)
	if !found {
		return
	}
	role, ok := h.roleWithQueries(r, qtx, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can delete it")
		return
	}
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessSensitive, true, "collection not found") {
		return
	}

	entryCount, err := qtx.CountCollectionEntries(r.Context(), sql.NullString{String: id, Valid: true})
	if err != nil {
		logError(r, "collections.delete: entry count failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	if entryCount > 0 {
		raw := r.URL.Query().Get("entry_count")
		if raw == "" {
			writeConflict(w, r, fmt.Sprintf(
				"this collection holds %d entries; resend the delete with ?entry_count=%d to confirm you intend to destroy them",
				entryCount, entryCount))
			return
		}
		expected, convErr := strconv.ParseInt(raw, 10, 64)
		if convErr != nil || expected != entryCount {
			writeConflict(w, r, fmt.Sprintf(
				"entry_count is stale: this collection now holds %d entries, refresh and confirm again", entryCount))
			return
		}
	}

	// Read the damage before the cascade, not after: once DeleteCollection runs
	// there is nothing left to name.
	sample, sampleErr := qtx.ListCollectionVaultEntryNamesSample(r.Context(), db.ListCollectionVaultEntryNamesSampleParams{
		CollectionID: sql.NullString{String: id, Valid: true},
		Limit:        collectionDeleteEntrySample,
	})
	if sampleErr != nil {
		// Best-effort: a failed sample must not block a delete the caller is
		// otherwise authorized and confirmed to make. The count above is still
		// logged, so the operation is never recorded as a bare id even if this
		// fails.
		logError(r, "collections.delete: entry sample failed", "error", sampleErr)
	}

	if err := qtx.DeleteCollection(r.Context(), id); err != nil {
		logError(r, "collections.delete: failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if !commitCollectionMutation(w, r, tx, "collections.delete") {
		return
	}

	detail := fmt.Sprintf("Collection deleted: %s (id: %s), %d entries destroyed", c.Name, id, entryCount)
	if len(sample) > 0 {
		names := make([]string, len(sample))
		for i, e := range sample {
			// Decrypted: this line exists so an operator reading the activity log
			// can see WHICH secrets a collection delete destroyed, and a list of
			// enc:v1: blobs tells them nothing. The names are the point of the
			// sample. vault is documented nil-safe on this handler, so the stored
			// form is the fallback rather than a panic on the delete path.
			names[i] = e.Name
			if h.vault != nil {
				names[i] = h.vault.EntryNamePlain(e.Name)
			}
		}
		// Alphabetical, which the query used to provide and cannot any more. The
		// log line is read by a human reconstructing what a delete destroyed.
		sort.Strings(names)
		if int64(len(sample)) < entryCount {
			detail += fmt.Sprintf("; sample of %d: %v (+%d more not shown)", len(names), names, entryCount-int64(len(names)))
		} else {
			detail += fmt.Sprintf(": %v", names)
		}
	}
	LogActivityFromRequest(h.queries, r, "collection.delete", detail)
	w.WriteHeader(http.StatusNoContent)
}

type memberResponse struct {
	UserID  string  `json:"user_id"`
	Email   string  `json:"email"`
	Name    string  `json:"name"`
	Role    string  `json:"role"`
	AddedAt *string `json:"added_at"`
	// Nil until the invitee accepts. A pending member has no access at all;
	// surfacing it lets a manager see who has not opted in yet.
	AcceptedAt *string `json:"accepted_at"`
	Pending    bool    `json:"pending"`
}

type pendingInviteResponse struct {
	CollectionID   string  `json:"collection_id"`
	Name           string  `json:"name"`
	Description    string  `json:"description"`
	Role           string  `json:"role"`
	InvitedAt      *string `json:"invited_at"`
	InvitedByEmail string  `json:"invited_by_email"`
}

// ListPendingInvites handles GET /api/collections/invitations and returns the
// collections the caller has been invited to but has not accepted. These grant
// no access until accepted, so this is the only place they surface.
func (h *CollectionHandler) ListPendingInvites(w http.ResponseWriter, r *http.Request) {
	rows, err := h.queries.ListPendingCollectionInvitesForUser(r.Context(), middleware.GetUserID(r.Context()))
	if err != nil {
		logError(r, "collections.pending: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	out := make([]pendingInviteResponse, 0, len(rows))
	for _, p := range rows {
		collection, policyErr := h.queries.GetCollection(r.Context(), p.ID)
		if policyErr != nil {
			logError(r, "collections.pending: private access policy lookup failed", "collection", p.ID, "error", policyErr)
			writeInternalError(w, r, "private access policy could not be verified")
			return
		}
		visible, policyErr := privateMetadataVisible(r.Context(), collection.PrivateAccessPolicy)
		if policyErr != nil {
			logError(r, "collections.pending: invalid private access policy", "collection", p.ID, "error", policyErr)
			writeInternalError(w, r, "private access policy could not be verified")
			return
		}
		if !visible {
			continue
		}
		out = append(out, pendingInviteResponse{
			CollectionID: p.ID, Name: p.Name, Description: p.Description, Role: p.Role,
			InvitedAt: nullTimePtr(p.AddedAt), InvitedByEmail: nullStringToString(p.InvitedByEmail),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// AcceptInvite handles POST /api/collections/{id}/accept. Only the invitee can
// call it, and only their own pending row is affected, so accepting can never
// grant access to anyone else.
func (h *CollectionHandler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())
	tx, qtx, ok := h.beginMutation(w, r, "collections.accept")
	if !ok {
		return
	}
	defer tx.Rollback()
	_, policy, found := h.collectionForRequest(w, r, qtx, id)
	if !found {
		return
	}
	membership, membershipErr := qtx.GetCollectionMembership(r.Context(), db.GetCollectionMembershipParams{
		CollectionID: id, UserID: userID,
	})
	if membershipErr != nil {
		if membershipErr != sql.ErrNoRows {
			logError(r, "collections.accept: membership lookup failed", "error", membershipErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		writeNotFound(w, r, "no pending invitation for this collection")
		return
	}
	if membership.AcceptedAt.Valid {
		writeNotFound(w, r, "no pending invitation for this collection")
		return
	}
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessSensitive, true, "collection not found") {
		return
	}
	res, err := qtx.AcceptCollectionInvite(r.Context(), db.AcceptCollectionInviteParams{
		CollectionID: id, UserID: userID,
	})
	if err != nil {
		logError(r, "collections.accept: failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeNotFound(w, r, "no pending invitation for this collection")
		return
	}
	// The seat has been answered, so it stops being pending. Leaving it behind
	// would show the manager a phantom pending invitation for someone who is now
	// listed as an accepted member.
	h.dropInvitationSeatWithQueries(r, qtx, id, userID)
	if !commitCollectionMutation(w, r, tx, "collections.accept") {
		return
	}
	LogActivityFromRequest(h.queries, r, "collection.invite_accepted", fmt.Sprintf("Accepted invitation to collection %s", id))
	w.WriteHeader(http.StatusNoContent)
}

// DeclineInvite handles POST /api/collections/{id}/decline and removes the
// caller's own pending membership. Declining is deliberately the same operation
// as leaving, so a user is never stuck in a collection someone else created.
func (h *CollectionHandler) DeclineInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())
	tx, qtx, ok := h.beginMutation(w, r, "collections.decline")
	if !ok {
		return
	}
	defer tx.Rollback()
	collection, policy, found := h.collectionForRequest(w, r, qtx, id)
	if !found {
		return
	}

	// Prove the caller has a seat before applying sensitive_private's actionable
	// 403. Otherwise a random authenticated user could use that code to discover
	// a protected collection id. fully_private was already hidden above.
	if _, err := qtx.GetCollectionMembership(r.Context(), db.GetCollectionMembershipParams{
		CollectionID: id, UserID: userID,
	}); err != nil {
		writeNotFound(w, r, "no invitation or membership for this collection")
		return
	}
	// This endpoint is both decline and leave. Both change access state, and a
	// fully-private collection must not become a public existence oracle merely
	// because the operation reduces the caller's privileges.
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessSensitive, true, "collection not found") {
		return
	}

	// Same last-manager guard RemoveMember has. This endpoint doubles as "leave
	// the collection", so without it the sole manager could walk out and orphan
	// it: no member could then add anyone, change a role or delete it, and every
	// secret inside would be stranded with only an instance admin able to
	// recover it. Declining a PENDING invite is unaffected, since an unaccepted
	// row is not a manager yet.
	role, roleErr := qtx.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
		CollectionID: id, UserID: userID,
	})
	if roleErr != nil && roleErr != sql.ErrNoRows {
		logError(r, "collections.decline: role lookup failed", "error", roleErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	if roleErr == nil && role == collRoleManager {
		count, cErr := qtx.CountCollectionManagers(r.Context(), id)
		if cErr != nil {
			logError(r, "collections.decline: manager count failed", "error", cErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if count <= 1 {
			writeConflict(w, r, "you are the last manager of this collection; promote another member before leaving")
			return
		}
	}

	res, err := qtx.RemoveCollectionMember(r.Context(), db.RemoveCollectionMemberParams{
		CollectionID: id, UserID: userID,
	})
	if err != nil {
		logError(r, "collections.decline: failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeNotFound(w, r, "no invitation or membership for this collection")
		return
	}
	// Declining answers the seat, and leaving vacates one. Either way it must not
	// stay in the members list as a pending invitation that nobody can act on.
	h.dropInvitationSeatWithQueries(r, qtx, id, userID)
	if !commitCollectionMutation(w, r, tx, "collections.decline") {
		return
	}
	// Same cleanup RemoveMember runs. Leaving and being removed are the same
	// DELETE of the membership row (the code says so, and the UI ships a Leave
	// button on every collection at every role), but only the remove path
	// purged the departing member's rotation targets. So leaving left the row
	// behind: every later rotation failed delivery, marked itself "partial" and
	// fired an alert forever, and the stale endpoint sat in the rotation panel
	// looking live. Worse, UpdateTargets used to restamp ConfiguredBy on the
	// whole submitted array, so the owner simply saving that panel re-authorized
	// the departed member's webhook and the next rotation POSTed them the fresh
	// plaintext secret. Best-effort: never fail the leave over cleanup.
	if summary := h.purgeTargetsConfiguredBy(r.Context(), id, userID); summary != "" {
		h.logTargetPurge(r, collection.Name, summary)
	}

	LogActivityFromRequest(h.queries, r, "collection.invite_declined", fmt.Sprintf("Declined or left collection %s", id))
	w.WriteHeader(http.StatusNoContent)
}

// ListMembers handles GET /api/collections/{id}/members for any member.
func (h *CollectionHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tx, qtx, err := beginQueriesTx(r.Context(), h.queries, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		logError(r, "collections.members: snapshot failed", "collection", id, "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	if _, _, found := h.collectionForRequest(w, r, qtx, id); !found {
		return
	}
	callerRole, ok := h.roleWithQueries(r, qtx, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	// A manager sees the address they invited, because they typed it. Everyone
	// else sees an anonymous pending seat (see below).
	canSeePending := callerRole == collRoleManager
	rows, err := qtx.ListCollectionMembers(r.Context(), id)
	if err != nil {
		logError(r, "collections.members: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	invites, err := qtx.ListCollectionInvitations(r.Context(), id)
	if err != nil {
		logError(r, "collections.members: invitation query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	// Pending seats come from collection_invitations, NEVER from a pending
	// collection_members row, and they carry no user_id and no display name.
	//
	// Both halves of that are load-bearing. AddMember deliberately answers
	// identically whether or not the address matches an account, but it could
	// only write a membership row when the address HAD one (user_id is a foreign
	// key), so this endpoint answered the same question one call later: the
	// pending row appeared, with the account's user id and real name, exactly
	// when the account existed. Any authenticated user can create a collection
	// and is seeded as its accepted manager, so the whole user directory was
	// enumerable by a vault_only account, which is the role
	// /api/invitations/redeem hands out over a PUBLIC endpoint. On a shared
	// instance that is one client harvesting another client's people.
	//
	// So the seat is now recorded by the invited EMAIL either way (migration
	// 00033) and the identity stays withheld until the invitee accepts, at which
	// point they are a real member and being visible is the point of a shared
	// collection. An unanswered invitation is also not yet a relationship the
	// invitee has agreed to expose to the rest of the team.
	out := make([]memberResponse, 0, len(rows)+len(invites))
	invited := make(map[string]struct{}, len(invites))
	acceptedEmail := make(map[string]struct{}, len(rows))
	for _, m := range rows {
		if !m.AcceptedAt.Valid {
			continue
		}
		acceptedEmail[emailidentity.Canonical(m.Email)] = struct{}{}
		out = append(out, memberResponse{
			UserID: m.UserID, Email: m.Email, Name: nullStringToString(m.Name),
			Role: m.Role, AddedAt: nullTimePtr(m.AddedAt),
			AcceptedAt: nullTimePtr(m.AcceptedAt), Pending: false,
		})
	}
	for _, inv := range invites {
		invited[emailidentity.Canonical(inv.Email)] = struct{}{}
		// Clearing the seat on accept is best-effort (the membership row is the
		// authoritative record), so a failed cleanup must not list a real member
		// twice, once accepted and once as a phantom pending invitation.
		if _, done := acceptedEmail[emailidentity.Canonical(inv.Email)]; done {
			continue
		}
		seat := memberResponse{Role: inv.Role, AddedAt: nullTimePtr(inv.CreatedAt), Pending: true}
		if canSeePending {
			seat.Email = inv.Email
		}
		out = append(out, seat)
	}
	// A pending membership with no invitation row can only come from a path that
	// predates migration 00033. Show the seat so it is not invisible (and can be
	// rescinded), but with no identity at all: emitting its email here would
	// reopen exactly the oracle above. The member's email is read only to match
	// it against a seat already listed, never to answer with.
	for _, m := range rows {
		if m.AcceptedAt.Valid {
			continue
		}
		if _, ok := invited[emailidentity.Canonical(m.Email)]; ok {
			continue
		}
		out = append(out, memberResponse{
			Role: m.Role, AddedAt: nullTimePtr(m.AddedAt), Pending: true,
		})
	}
	if err := tx.Commit(); err != nil {
		logError(r, "collections.members: snapshot commit failed", "collection", id, "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// RescindInvitation handles DELETE /api/collections/{id}/invitations (manager or
// admin) and withdraws a pending invitation by EMAIL.
//
// Removing a member is by user id, and a pending seat no longer carries one
// (ListMembers withholds it, and an address with no account never had one), so
// without this endpoint an invitation to an address that has not accepted could
// not be withdrawn at all. That is the same dead end RemoveMember's
// acceptance-agnostic existence check was written to fix.
//
// The response is 204 no matter what: whether a seat existed, whether the
// address matches an account, and whether that account had a pending membership.
// A 404 on "no such invitation" would hand back the enumeration oracle this
// whole change closes.
func (h *CollectionHandler) RescindInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Email string `json:"email"`
	}
	decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	tx, qtx, ok := h.beginMutation(w, r, "collections.rescind")
	if !ok {
		return
	}
	defer tx.Rollback()
	_, policy, found := h.collectionForRequest(w, r, qtx, id)
	if !found {
		return
	}
	role, ok := h.roleWithQueries(r, qtx, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can manage members")
		return
	}
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessSensitive, true, "collection not found") {
		return
	}
	if decodeErr != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	email := emailidentity.Canonical(req.Email)
	if email == "" {
		writeBadRequest(w, r, "email is required")
		return
	}
	if _, err := qtx.DeleteCollectionInvitation(r.Context(), db.DeleteCollectionInvitationParams{
		CollectionID: id, Email: email,
	}); err != nil {
		logError(r, "collections.rescind: delete invitation failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	// If the address does have an account, drop its PENDING membership too, or
	// the invitation would still be acceptable after the manager withdrew it.
	// An ACCEPTED membership is left alone on purpose: removing a real member
	// goes through RemoveMember, which carries the last-manager guard.
	user, userErr := qtx.GetUserByEmail(r.Context(), email)
	if userErr != nil && userErr != sql.ErrNoRows {
		logError(r, "collections.rescind: account lookup failed", "error", userErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	if userErr == nil && user.ID != "" {
		m, membershipErr := qtx.GetCollectionMembership(r.Context(), db.GetCollectionMembershipParams{
			CollectionID: id, UserID: user.ID,
		})
		if membershipErr != nil && membershipErr != sql.ErrNoRows {
			logError(r, "collections.rescind: membership lookup failed", "error", membershipErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if membershipErr == nil && !m.AcceptedAt.Valid {
			if _, rErr := qtx.RemoveCollectionMember(r.Context(), db.RemoveCollectionMemberParams{
				CollectionID: id, UserID: user.ID,
			}); rErr != nil {
				logError(r, "collections.rescind: remove pending membership failed", "error", rErr)
				writeInternalError(w, r, "internal server error")
				return
			}
		}
	}
	if !commitCollectionMutation(w, r, tx, "collections.rescind") {
		return
	}
	LogActivityFromRequest(h.queries, r, "collection.invite_rescinded",
		fmt.Sprintf("Withdrew the invitation to collection %s", id))
	w.WriteHeader(http.StatusNoContent)
}

// dropInvitationSeatWithQueries removes the pending seat recorded for a user's
// address once their membership is settled. The caller supplies qtx so this
// cleanup commits or rolls back with the access-state change it accompanies.
func (h *CollectionHandler) dropInvitationSeatWithQueries(r *http.Request, queries *db.Queries, collectionID, userID string) {
	email, err := queries.GetUserEmailByID(r.Context(), userID)
	if err != nil {
		return
	}
	if _, err := queries.DeleteCollectionInvitation(r.Context(), db.DeleteCollectionInvitationParams{
		CollectionID: collectionID, Email: emailidentity.Canonical(email),
	}); err != nil {
		logError(r, "collections: could not clear the invitation seat", "collection", collectionID, "error", err)
	}
}

// AddMember handles POST /api/collections/{id}/members (manager or admin). The
// member is identified by email and must already have an account. The same
// endpoint updates the role of an existing member (upsert).
func (h *CollectionHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	decodeErr := json.NewDecoder(r.Body).Decode(&req)
	tx, qtx, ok := h.beginMutation(w, r, "collections.addmember")
	if !ok {
		return
	}
	defer tx.Rollback()
	_, policy, found := h.collectionForRequest(w, r, qtx, id)
	if !found {
		return
	}
	role, ok := h.roleWithQueries(r, qtx, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can manage members")
		return
	}
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessSensitive, true, "collection not found") {
		return
	}
	if decodeErr != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	req.Email = emailidentity.Canonical(req.Email)
	if req.Email == "" {
		writeBadRequest(w, r, "email is required")
		return
	}
	if err := ValidateEmail(req.Email); err != nil {
		writeValidationError(w, r, err.Error())
		return
	}
	if req.Role == "" {
		req.Role = collRoleViewer
	}
	if !validCollectionRole(req.Role) {
		writeBadRequest(w, r, "role must be viewer, editor, or manager")
		return
	}
	// Invite, do not grant. The membership row is created PENDING
	// (accepted_at NULL) and confers nothing until the invitee accepts: without
	// that step any user could push entries into a colleague's vault list and
	// browser autofill, e.g. a fake SSO credential for a real company domain.
	//
	// The response is deliberately identical whether or not the email matches an
	// account, and never echoes the target's user id or display name. Otherwise
	// this endpoint is an account-enumeration and directory-disclosure oracle for
	// any authenticated user (create a throwaway collection, probe addresses).
	// The invitee learns of the invitation through their own pending list.
	user, userErr := qtx.GetUserByEmail(r.Context(), req.Email)
	if userErr != nil && userErr != sql.ErrNoRows {
		logError(r, "collections.addmember: account lookup failed", "error", userErr)
		writeInternalError(w, r, "internal server error")
		return
	}
	// The SEAT is recorded either way, and it is what the members list shows.
	// Writing it only on a hit was the whole bug: the constant-time answer above
	// meant nothing when GET /members revealed one call later whether the row had
	// appeared. Written before the membership row so a failure here cannot leave
	// an account-only seat, which would be the leaky state again.
	//
	// An already-ACCEPTED member is skipped: this endpoint doubles as the
	// role-change path, and a real member must not be pushed back into the
	// pending list by someone editing their role.
	accepted := false
	if userErr == nil && user.ID != "" {
		m, membershipErr := qtx.GetCollectionMembership(r.Context(), db.GetCollectionMembershipParams{
			CollectionID: id, UserID: user.ID,
		})
		if membershipErr != nil && membershipErr != sql.ErrNoRows {
			logError(r, "collections.addmember: membership lookup failed", "error", membershipErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		if membershipErr == nil && m.AcceptedAt.Valid {
			accepted = true
		}
	}
	if !accepted {
		if invErr := qtx.UpsertCollectionInvitation(r.Context(), db.UpsertCollectionInvitationParams{
			CollectionID: id, Email: req.Email, Role: req.Role,
			InvitedBy: toNullString(middleware.GetUserID(r.Context())),
		}); invErr != nil {
			logError(r, "collections.addmember: record invitation failed", "error", invErr)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if userErr == nil {
		// AddCollectionMember is an UPSERT, so this endpoint doubles as the
		// role-CHANGE path: the members UI sends it when a dropdown changes.
		// Without a last-manager check, one click could demote the only manager
		// and orphan the collection, with no manager left to invite one. Removal
		// and leaving both guard this; the third way to lose a manager did not.
		//
		// Demoting yourself is the reachable case, so it is worth naming the
		// account rather than returning a generic refusal.
		if user.ID != "" && req.Role != collRoleManager {
			current, roleErr := qtx.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
				CollectionID: id, UserID: user.ID,
			})
			if roleErr != nil && roleErr != sql.ErrNoRows {
				logError(r, "collections.addmember: role lookup failed", "error", roleErr)
				writeInternalError(w, r, "internal server error")
				return
			}
			if roleErr == nil && current == collRoleManager {
				count, cErr := qtx.CountCollectionManagers(r.Context(), id)
				if cErr != nil {
					logError(r, "collections.addmember: manager count failed", "error", cErr)
					writeInternalError(w, r, "internal server error")
					return
				}
				if count <= 1 {
					writeConflict(w, r, "this is the collection's only manager; promote another member to manager first")
					return
				}
			}
		}
		if addErr := qtx.AddCollectionMember(r.Context(), db.AddCollectionMemberParams{
			CollectionID: id, UserID: user.ID, Role: req.Role,
			AcceptedAt: sql.NullTime{}, // pending until the invitee accepts
			// The consent card shows this, so it must be who ACTUALLY invited
			// them, not the collection's creator.
			InvitedBy: toNullString(middleware.GetUserID(r.Context())),
		}); addErr != nil {
			logError(r, "collections.addmember: failed", "error", addErr)
			writeInternalError(w, r, "internal server error")
			return
		}
	}
	if !commitCollectionMutation(w, r, tx, "collections.addmember") {
		return
	}
	if userErr == sql.ErrNoRows {
		// Log the miss server-side for the operator without telling the caller.
		// slog output is not an API surface; the activity_log row below is, and
		// it is written identically on both branches.
		logError(r, "collections.addmember: no account for invited email", "collection", id)
	}
	// One activity row, same text, whether or not the address has an account.
	//
	// It used to be written only on a hit, so activity_log itself answered the
	// question the rest of this endpoint refuses to answer. /api/activity is
	// admin-only today, which is the only thing that kept it from being a live
	// oracle, and "safe because of an authorization rule somewhere else" is how
	// a leak survives the next refactor. The manager typed the address, so
	// echoing it back in their own audit trail costs nothing.
	LogActivityFromRequest(h.queries, r, "collection.member_invited",
		fmt.Sprintf("Invited %s to collection %s as %s (pending acceptance)", req.Email, id, req.Role))
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "invited",
		"detail": "If that address belongs to an account, an invitation is now pending their acceptance.",
	})
}

// RemoveMember handles DELETE /api/collections/{id}/members/{userId} (manager or
// admin). The last manager cannot be removed, so a collection is never orphaned.
func (h *CollectionHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	targetUser := chi.URLParam(r, "userId")
	tx, qtx, ok := h.beginMutation(w, r, "collections.removemember")
	if !ok {
		return
	}
	defer tx.Rollback()
	collection, policy, found := h.collectionForRequest(w, r, qtx, id)
	if !found {
		return
	}
	role, ok := h.roleWithQueries(r, qtx, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can manage members")
		return
	}
	if !enforcePrivateAccessPolicy(w, r, policy, privateAccessSensitive, true, "collection not found") {
		return
	}

	// Existence check must be acceptance-agnostic. Using the authorization query
	// here meant a PENDING invitation returned no row, so this 404'd with
	// "member not found" and an invitation could never be withdrawn by anyone:
	// it stayed acceptable forever, and the UI's Remove button simply failed.
	// Authorization elsewhere still uses GetCollectionMemberRole, which
	// correctly ignores pending rows.
	membership, err := qtx.GetCollectionMembership(r.Context(), db.GetCollectionMembershipParams{
		CollectionID: id, UserID: targetUser,
	})
	if err != nil {
		writeNotFound(w, r, "member not found")
		return
	}
	targetRole := membership.Role
	// The last-manager guard only applies to an ACCEPTED manager: a pending
	// invitee is not holding the collection open, and CountCollectionManagers
	// already counts accepted managers only.
	if targetRole == collRoleManager && membership.AcceptedAt.Valid {
		count, err := qtx.CountCollectionManagers(r.Context(), id)
		if err != nil {
			logError(r, "collections.removemember: manager count failed", "error", err)
			writeInternalError(w, r, "internal server error")
			return
		}
		if count <= 1 {
			writeConflict(w, r, "cannot remove the last manager; promote another member first")
			return
		}
	}

	result, err := qtx.RemoveCollectionMember(r.Context(), db.RemoveCollectionMemberParams{
		CollectionID: id, UserID: targetUser,
	})
	if err != nil {
		logError(r, "collections.removemember: failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		writeNotFound(w, r, "member not found")
		return
	}
	// Same cleanup the accept and decline paths do: an emptied seat must not keep
	// showing up as a pending invitation.
	h.dropInvitationSeatWithQueries(r, qtx, id, targetUser)
	if !commitCollectionMutation(w, r, tx, "collections.removemember") {
		return
	}
	LogActivityFromRequest(h.queries, r, "collection.member_removed", fmt.Sprintf("Member %s removed from collection %s", targetUser, id))

	// Offboarding cleanup. A collection editor can configure rotation delivery
	// targets on an entry they do not own, and removing them only deleted the
	// membership row: their webhook stayed attached and kept receiving the
	// plaintext secret on every rotation, so the rotation performed to revoke
	// their access was the very thing that handed them the new value.
	//
	// DeliverRotatedKey now refuses such a target outright, which is the
	// authoritative control and also covers targets planted before this existed.
	// Purging as well keeps a dead endpoint from sitting in the UI looking
	// active, from marking every future rotation "partial", and from silently
	// reactivating if the person is re-added. Best-effort: never fail the
	// removal over cleanup.
	if summary := h.purgeTargetsConfiguredBy(r.Context(), id, targetUser); summary != "" {
		h.logTargetPurge(r, collection.Name, summary)
	}

	w.WriteHeader(http.StatusNoContent)
}

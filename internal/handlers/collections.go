package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
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

// role returns the caller's role in a collection. Instance admins are treated as
// managers of every collection. The second return is false when the caller is
// neither a member nor an admin.
func (h *CollectionHandler) role(r *http.Request, collectionID string) (string, bool) {
	if middleware.IsAdmin(r.Context()) {
		return collRoleManager, true
	}
	role, err := h.queries.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
		CollectionID: collectionID,
		UserID:       middleware.GetUserID(r.Context()),
	})
	if err != nil {
		return "", false
	}
	return role, true
}

type collectionResponse struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Role        string  `json:"role,omitempty"`
	MemberCount int     `json:"member_count,omitempty"`
	EntryCount  int64   `json:"entry_count,omitempty"`
	CreatedAt   *string `json:"created_at"`
	UpdatedAt   *string `json:"updated_at"`
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
			out = append(out, collectionResponse{
				ID: c.ID, Name: c.Name, Description: c.Description, Role: collRoleManager,
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
		out = append(out, collectionResponse{
			ID: c.ID, Name: c.Name, Description: c.Description, Role: c.Role,
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
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeBadRequest(w, r, "name is required")
		return
	}
	if len(req.Name) > 255 {
		writeBadRequest(w, r, "name must be 255 characters or less")
		return
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		logError(r, "collections.create: id gen failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	id := hex.EncodeToString(idBytes)

	if err := h.queries.CreateCollection(r.Context(), db.CreateCollectionParams{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		CreatedBy:   sql.NullString{String: userID, Valid: userID != ""},
	}); err != nil {
		logError(r, "collections.create: insert failed", "error", err)
		writeInternalError(w, r, "failed to create collection")
		return
	}
	// The creator is the first manager. Self-membership needs no consent step,
	// so it is accepted immediately; otherwise the creator would be locked out
	// of the collection they just made.
	if err := h.queries.AddCollectionMember(r.Context(), db.AddCollectionMemberParams{
		CollectionID: id, UserID: userID, Role: collRoleManager,
		AcceptedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}); err != nil {
		logError(r, "collections.create: seed manager failed", "error", err)
		writeInternalError(w, r, "failed to create collection")
		return
	}

	LogActivityFromRequest(h.queries, r, "collection.create", fmt.Sprintf("Collection created: %s", req.Name))
	writeJSON(w, http.StatusCreated, collectionResponse{
		ID: id, Name: req.Name, Description: req.Description, Role: collRoleManager,
	})
}

// Get handles GET /api/collections/{id} for any member (or admin).
func (h *CollectionHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, ok := h.role(r, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	c, err := h.queries.GetCollection(r.Context(), id)
	if err != nil {
		writeNotFound(w, r, "collection not found")
		return
	}
	entryCount, _ := h.queries.CountCollectionEntries(r.Context(), sql.NullString{String: id, Valid: true})
	writeJSON(w, http.StatusOK, collectionResponse{
		ID: c.ID, Name: c.Name, Description: c.Description, Role: role, EntryCount: entryCount,
		CreatedAt: nullTimePtr(c.CreatedAt), UpdatedAt: nullTimePtr(c.UpdatedAt),
	})
}

// Update handles PUT /api/collections/{id} (manager or admin only).
func (h *CollectionHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, ok := h.role(r, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can change it")
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeBadRequest(w, r, "name is required")
		return
	}
	if err := h.queries.UpdateCollection(r.Context(), db.UpdateCollectionParams{
		Name: req.Name, Description: req.Description, ID: id,
	}); err != nil {
		logError(r, "collections.update: failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	LogActivityFromRequest(h.queries, r, "collection.update", fmt.Sprintf("Collection updated: %s", req.Name))
	w.WriteHeader(http.StatusNoContent)
}

// Delete handles DELETE /api/collections/{id} (manager or admin only). Deleting
// a collection cascades to its members and entries.
func (h *CollectionHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, ok := h.role(r, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can delete it")
		return
	}
	if err := h.queries.DeleteCollection(r.Context(), id); err != nil {
		logError(r, "collections.delete: failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	LogActivityFromRequest(h.queries, r, "collection.delete", fmt.Sprintf("Collection deleted (id: %s)", id))
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
	res, err := h.queries.AcceptCollectionInvite(r.Context(), db.AcceptCollectionInviteParams{
		CollectionID: id, UserID: middleware.GetUserID(r.Context()),
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
	LogActivityFromRequest(h.queries, r, "collection.invite_accepted", fmt.Sprintf("Accepted invitation to collection %s", id))
	w.WriteHeader(http.StatusNoContent)
}

// DeclineInvite handles POST /api/collections/{id}/decline and removes the
// caller's own pending membership. Declining is deliberately the same operation
// as leaving, so a user is never stuck in a collection someone else created.
func (h *CollectionHandler) DeclineInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())

	// Same last-manager guard RemoveMember has. This endpoint doubles as "leave
	// the collection", so without it the sole manager could walk out and orphan
	// it: no member could then add anyone, change a role or delete it, and every
	// secret inside would be stranded with only an instance admin able to
	// recover it. Declining a PENDING invite is unaffected, since an unaccepted
	// row is not a manager yet.
	if role, roleErr := h.queries.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
		CollectionID: id, UserID: userID,
	}); roleErr == nil && role == collRoleManager {
		count, cErr := h.queries.CountCollectionManagers(r.Context(), id)
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

	res, err := h.queries.RemoveCollectionMember(r.Context(), db.RemoveCollectionMemberParams{
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
	LogActivityFromRequest(h.queries, r, "collection.invite_declined", fmt.Sprintf("Declined or left collection %s", id))
	w.WriteHeader(http.StatusNoContent)
}

// ListMembers handles GET /api/collections/{id}/members for any member.
func (h *CollectionHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, ok := h.role(r, id); !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	rows, err := h.queries.ListCollectionMembers(r.Context(), id)
	if err != nil {
		logError(r, "collections.members: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	out := make([]memberResponse, 0, len(rows))
	for _, m := range rows {
		out = append(out, memberResponse{
			UserID: m.UserID, Email: m.Email, Name: nullStringToString(m.Name),
			Role: m.Role, AddedAt: nullTimePtr(m.AddedAt),
			AcceptedAt: nullTimePtr(m.AcceptedAt), Pending: !m.AcceptedAt.Valid,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// AddMember handles POST /api/collections/{id}/members (manager or admin). The
// member is identified by email and must already have an account. The same
// endpoint updates the role of an existing member (upsert).
func (h *CollectionHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, ok := h.role(r, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can manage members")
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid JSON")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" {
		writeBadRequest(w, r, "email is required")
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
	user, err := h.queries.GetUserByEmail(r.Context(), req.Email)
	if err == nil {
		if addErr := h.queries.AddCollectionMember(r.Context(), db.AddCollectionMemberParams{
			CollectionID: id, UserID: user.ID, Role: req.Role,
			AcceptedAt: sql.NullTime{}, // pending until the invitee accepts
		}); addErr != nil {
			logError(r, "collections.addmember: failed", "error", addErr)
			writeInternalError(w, r, "internal server error")
			return
		}
		LogActivityFromRequest(h.queries, r, "collection.member_invited",
			fmt.Sprintf("Invited %s to collection %s as %s (pending acceptance)", req.Email, id, req.Role))
	} else {
		// Log the miss server-side for the operator without telling the caller.
		logError(r, "collections.addmember: no account for invited email", "collection", id)
	}
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
	role, ok := h.role(r, id)
	if !ok {
		writeNotFound(w, r, "collection not found")
		return
	}
	if role != collRoleManager {
		writeForbidden(w, r, "only a collection manager can manage members")
		return
	}

	// Existence check must be acceptance-agnostic. Using the authorization query
	// here meant a PENDING invitation returned no row, so this 404'd with
	// "member not found" and an invitation could never be withdrawn by anyone:
	// it stayed acceptable forever, and the UI's Remove button simply failed.
	// Authorization elsewhere still uses GetCollectionMemberRole, which
	// correctly ignores pending rows.
	membership, err := h.queries.GetCollectionMembership(r.Context(), db.GetCollectionMembershipParams{
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
		count, err := h.queries.CountCollectionManagers(r.Context(), id)
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

	result, err := h.queries.RemoveCollectionMember(r.Context(), db.RemoveCollectionMemberParams{
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
		name := id
		if c, cErr := h.queries.GetCollection(r.Context(), id); cErr == nil {
			name = c.Name
		}
		h.logTargetPurge(r, name, summary)
	}

	w.WriteHeader(http.StatusNoContent)
}

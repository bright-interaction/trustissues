package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
}

func NewCollectionHandler(queries *db.Queries) *CollectionHandler {
	return &CollectionHandler{queries: queries}
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
	// The creator is the first manager.
	if err := h.queries.AddCollectionMember(r.Context(), db.AddCollectionMemberParams{
		CollectionID: id, UserID: userID, Role: collRoleManager,
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
	user, err := h.queries.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		writeNotFound(w, r, "no user with that email (they must have an account first)")
		return
	}
	if err := h.queries.AddCollectionMember(r.Context(), db.AddCollectionMemberParams{
		CollectionID: id, UserID: user.ID, Role: req.Role,
	}); err != nil {
		logError(r, "collections.addmember: failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	LogActivityFromRequest(h.queries, r, "collection.member_added", fmt.Sprintf("Member %s added to collection %s as %s", req.Email, id, req.Role))
	writeJSON(w, http.StatusOK, memberResponse{
		UserID: user.ID, Email: user.Email, Name: nullStringToString(user.Name), Role: req.Role,
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

	// Guard against orphaning: do not remove the last manager.
	targetRole, err := h.queries.GetCollectionMemberRole(r.Context(), db.GetCollectionMemberRoleParams{
		CollectionID: id, UserID: targetUser,
	})
	if err != nil {
		writeNotFound(w, r, "member not found")
		return
	}
	if targetRole == collRoleManager {
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
	w.WriteHeader(http.StatusNoContent)
}

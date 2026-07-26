package handlers

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
	"github.com/brightinteraction/trustissues/internal/middleware"
)

// ActivityHandler handles activity log endpoints.
type ActivityHandler struct {
	queries *db.Queries
}

// NewActivityHandler creates a new ActivityHandler.
func NewActivityHandler(queries *db.Queries) *ActivityHandler {
	return &ActivityHandler{queries: queries}
}

type activityEntry struct {
	ID        int     `json:"id"`
	UserID    *string `json:"user_id"`
	UserEmail *string `json:"user_email"`
	Action    string  `json:"action"`
	Detail    *string `json:"detail"`
	IPAddress *string `json:"ip_address"`
	UserAgent *string `json:"user_agent"`
	CreatedAt string  `json:"created_at"`
}

type activityListResponse struct {
	Entries []activityEntry `json:"entries"`
	Total   int             `json:"total"`
}

// List handles GET /api/activity (admin only) and returns recent activity log
// entries. Optional query params: ?action=...&user_id=...&limit=50&offset=0
func (h *ActivityHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	actionFilter := r.URL.Query().Get("action")
	userFilter := r.URL.Query().Get("user_id")
	ctx := r.Context()

	var total int64
	var listErr error
	entries := make([]activityEntry, 0)

	appendEntry := func(id int64, userID, userEmail, detail, ipAddress, userAgent sql.NullString, action string, createdAt sql.NullTime) {
		entries = append(entries, activityEntry{
			ID:        int(id),
			UserID:    nullStringPtr(userID),
			UserEmail: nullStringPtr(userEmail),
			Action:    action,
			Detail:    nullStringPtr(detail),
			IPAddress: nullStringPtr(ipAddress),
			UserAgent: nullStringPtr(userAgent),
			CreatedAt: nullTimeRFC3339(createdAt),
		})
	}

	switch {
	case userFilter != "":
		total, listErr = h.queries.CountActivityEntriesByUser(ctx, toNullString(userFilter))
		if listErr == nil {
			rows, err := h.queries.ListActivityEntriesByUser(ctx, db.ListActivityEntriesByUserParams{
				UserID: toNullString(userFilter), Limit: int64(limit), Offset: int64(offset),
			})
			if err != nil {
				listErr = err
			} else {
				for _, row := range rows {
					appendEntry(row.ID, row.UserID, row.UserEmail, row.Detail, row.IpAddress, row.UserAgent, row.Action, row.CreatedAt)
				}
			}
		}
	case actionFilter != "":
		total, listErr = h.queries.CountActivityEntriesByAction(ctx, actionFilter)
		if listErr == nil {
			rows, err := h.queries.ListActivityEntriesByAction(ctx, db.ListActivityEntriesByActionParams{
				Action: actionFilter, Limit: int64(limit), Offset: int64(offset),
			})
			if err != nil {
				listErr = err
			} else {
				for _, row := range rows {
					appendEntry(row.ID, row.UserID, row.UserEmail, row.Detail, row.IpAddress, row.UserAgent, row.Action, row.CreatedAt)
				}
			}
		}
	default:
		total, listErr = h.queries.CountActivityEntries(ctx)
		if listErr == nil {
			rows, err := h.queries.ListActivityEntries(ctx, db.ListActivityEntriesParams{
				Limit: int64(limit), Offset: int64(offset),
			})
			if err != nil {
				listErr = err
			} else {
				for _, row := range rows {
					appendEntry(row.ID, row.UserID, row.UserEmail, row.Detail, row.IpAddress, row.UserAgent, row.Action, row.CreatedAt)
				}
			}
		}
	}

	if listErr != nil {
		logError(r, "activity.list: query failed", "error", listErr)
		writeInternalError(w, r, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, activityListResponse{
		Entries: entries,
		Total:   int(total),
	})
}

// ExportCSV handles GET /api/activity/export/csv (admin only). Streams all
// matching activity log entries as a CSV download, honoring the same
// user_id/action filters as the list endpoint.
func (h *ActivityHandler) ExportCSV(w http.ResponseWriter, r *http.Request) {
	rows, err := h.queries.ExportActivityEntries(r.Context(), db.ExportActivityEntriesParams{
		UserFilter:   r.URL.Query().Get("user_id"),
		ActionFilter: r.URL.Query().Get("action"),
	})
	if err != nil {
		logError(r, "activity.export_csv: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	filename := fmt.Sprintf("trustissues-activity-%s.csv", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-cache")

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "user_id", "user_email", "action", "detail", "ip_address", "user_agent", "created_at"})
	for _, row := range rows {
		_ = cw.Write([]string{
			strconv.FormatInt(row.ID, 10),
			csvSafe(nullStringToString(row.UserID)),
			csvSafe(nullStringToString(row.UserEmail)),
			csvSafe(row.Action),
			csvSafe(nullStringToString(row.Detail)),
			csvSafe(nullStringToString(row.IpAddress)),
			csvSafe(nullStringToString(row.UserAgent)),
			nullTimeRFC3339(row.CreatedAt),
		})
	}
	cw.Flush()
}

// csvSafe neutralises spreadsheet formula injection in an exported CSV field.
//
// Activity rows carry attacker-influenced text: any user picks their own
// User-Agent, and detail/email embed user-supplied names. Excel, LibreOffice and
// Sheets execute a cell that begins with =, +, -, @, or a leading tab/CR as a
// formula, so a low-privileged user could plant a payload that runs on the
// ADMIN's workstation when they open the export. Prefixing a single quote makes
// the spreadsheet treat the cell as literal text; it is the standard OWASP
// mitigation and leaves ordinary values untouched.
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

// ExportJSON handles GET /api/activity/export/json (admin only). Streams all
// matching activity log entries as a JSON array download.
func (h *ActivityHandler) ExportJSON(w http.ResponseWriter, r *http.Request) {
	rows, err := h.queries.ExportActivityEntries(r.Context(), db.ExportActivityEntriesParams{
		UserFilter:   r.URL.Query().Get("user_id"),
		ActionFilter: r.URL.Query().Get("action"),
	})
	if err != nil {
		logError(r, "activity.export_json: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	entries := make([]activityEntry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, activityEntry{
			ID:        int(row.ID),
			UserID:    nullStringPtr(row.UserID),
			UserEmail: nullStringPtr(row.UserEmail),
			Action:    row.Action,
			Detail:    nullStringPtr(row.Detail),
			IPAddress: nullStringPtr(row.IpAddress),
			UserAgent: nullStringPtr(row.UserAgent),
			CreatedAt: nullTimeRFC3339(row.CreatedAt),
		})
	}

	filename := fmt.Sprintf("trustissues-activity-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	writeJSON(w, http.StatusOK, entries)
}

// LogActivity inserts an entry into the activity_log table. It is a
// package-level helper used by other handlers to record actions throughout the
// application. Uses a background context with timeout since activity logging
// is fire-and-forget. Pass nil userID for system events.
func LogActivity(q *db.Queries, userID *string, action, detail string) {
	logActivityInternal(q, userID, action, detail, "", "")
}

// LogActivityFromRequest logs an action extracting the user ID from the
// request's middleware context plus the client IP and user agent, so audit
// entries carry who did what from where.
func LogActivityFromRequest(q *db.Queries, r *http.Request, action, detail string) {
	userID := middleware.GetUserID(r.Context())
	var userPtr *string
	if userID != "" {
		userPtr = &userID
	}
	logActivityInternal(q, userPtr, action, detail, middleware.ClientIP(r), r.Header.Get("User-Agent"))
}

func logActivityInternal(q *db.Queries, userID *string, action, detail, ipAddress, userAgent string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := q.InsertActivity(ctx, db.InsertActivityParams{
		UserID:    sql.NullString{String: ptrToStr(userID), Valid: userID != nil},
		Action:    action,
		Detail:    sql.NullString{String: detail, Valid: detail != ""},
		IpAddress: sql.NullString{String: ipAddress, Valid: ipAddress != ""},
		UserAgent: sql.NullString{String: userAgent, Valid: userAgent != ""},
	})
	if err != nil {
		slog.Error("failed to log activity", "error", err, "action", action)
	}
}

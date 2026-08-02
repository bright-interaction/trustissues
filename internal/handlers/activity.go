package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
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
// likePrefixPattern turns a literal prefix into a SQL LIKE pattern that matches
// it and nothing cleverer.
//
// The filter value comes off the query string, so `_` and `%` in it would
// otherwise act as wildcards and let a caller widen their own filter (`%` alone
// matches every row). Escape them, and the escape character itself, and pair
// this with `ESCAPE '\'` in the query. Not a privilege boundary here (the whole
// endpoint is admin-only and the rows are already visible), but a filter that
// silently means something other than what it says is a bug either way.
func likePrefixPattern(prefix string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(prefix) + "%"
}

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

	// One query for all three filters, matching the export twin exactly.
	//
	// This used to be a switch whose first arm was "a user is selected", so
	// picking a user silently dropped the action filter, and the table and the
	// CSV export of the SAME view returned different rows. Two disagreeing
	// answers is the worst outcome for an audit surface.
	prefix := ""
	exact := actionFilter
	if strings.HasSuffix(actionFilter, ".*") {
		prefix = strings.TrimSuffix(actionFilter, "*")
		exact = ""
	}
	total, listErr = h.queries.CountActivityEntriesFiltered(ctx, db.CountActivityEntriesFilteredParams{
		UserFilter: userFilter, ActionFilter: exact, ActionPrefix: prefix,
	})
	if listErr == nil {
		rows, err := h.queries.ListActivityEntriesFiltered(ctx, db.ListActivityEntriesFilteredParams{
			UserFilter: userFilter, ActionFilter: exact, ActionPrefix: prefix,
			RowLimit: int64(limit), RowOffset: int64(offset),
		})
		if err != nil {
			listErr = err
		} else {
			for _, row := range rows {
				appendEntry(row.ID, row.UserID, row.UserEmail, row.Detail, row.IpAddress, row.UserAgent, row.Action, row.CreatedAt)
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
		ActionFilter: exportExactAction(r.URL.Query().Get("action")),
		ActionPrefix: exportPrefixAction(r.URL.Query().Get("action")),
	})
	if err != nil {
		logError(r, "activity.export_csv: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// Build the whole document BEFORE sending any of it.
	//
	// This wrote straight to the ResponseWriter with every cw.Write discarded as
	// `_ =` and no cw.Error() check after Flush, so a failure partway through
	// (a client disconnect, a broken pipe, a full disk on a proxy) produced a
	// TRUNCATED file delivered under a 200 and an attachment filename. An admin
	// exporting the audit trail for an incident or a compliance request got a
	// prefix of it and no indication anything was missing, which is the one
	// property an audit export has to get right.
	//
	// The rows are already fully materialised in memory above, so buffering the
	// CSV text is a proportional cost, not a new class of problem, and it buys
	// the ability to fail with a real 500 while the status line is still ours to
	// write.
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
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
	if err := cw.Error(); err != nil {
		logError(r, "activity.export_csv: encoding failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	filename := fmt.Sprintf("trustissues-activity-%s.csv", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-cache")
	// Content-Length makes a truncated transfer detectable by the CLIENT too: a
	// download cut short no longer looks like a complete file.
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	if _, err := w.Write(buf.Bytes()); err != nil {
		logError(r, "activity.export_csv: write failed", "error", err)
	}
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
		ActionFilter: exportExactAction(r.URL.Query().Get("action")),
		ActionPrefix: exportPrefixAction(r.URL.Query().Get("action")),
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

// Bounds on the attacker-influenced audit columns.
//
// user_agent came straight from the request header with nothing truncating it
// anywhere in the tree, the column has no length bound, the server sets no
// MaxHeaderBytes (so Go's 1 MB default applies to one header value), and
// migration 00003 installs an append-only trigger that makes DELETE impossible.
// So any authenticated user, including the lowest vault_only role, could commit
// ~1 MB of chosen bytes per request into the same SQLite file that holds the
// encrypted vault, at 500 requests/minute, with no way to remove it afterwards.
//
// That breaks two things at once, both on the surface an operator needs DURING
// such an incident: the activity list and the CSV/JSON exports become too large
// to read, and the disk backing the vault fills.
//
// 512 is well past any real User-Agent (the longest in the wild are ~250) and
// ip_address is bounded too because it can come from a forwarded header.
const (
	maxAuditUserAgentLen = 512
	maxAuditIPLen        = 64
	maxAuditDetailLen    = 4096
)

// truncateAudit clips an attacker-influenced audit field and marks that it was
// clipped, so a reader can tell a truncated value from a genuinely short one.
func truncateAudit(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}

func logActivityInternal(q *db.Queries, userID *string, action, detail, ipAddress, userAgent string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Clipped HERE, at the single chokepoint every audit row passes through,
	// rather than at each call site. There are 30+ call sites and the one that
	// forgets is the one that gets exploited.
	detail = truncateAudit(detail, maxAuditDetailLen)
	ipAddress = truncateAudit(ipAddress, maxAuditIPLen)
	userAgent = truncateAudit(userAgent, maxAuditUserAgentLen)
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

// exportPrefixAction / exportExactAction split a UI action filter into the two
// bind params ExportActivityEntries takes. The list endpoint learned the
// "vault.*" category convention; its export twin did not, so choosing a category
// and clicking Export downloaded an EMPTY file with no error, which reads as
// "no such activity" rather than "the filter is broken".
func exportPrefixAction(filter string) string {
	if strings.HasSuffix(filter, ".*") {
		return strings.TrimSuffix(filter, "*")
	}
	return ""
}

func exportExactAction(filter string) string {
	if strings.HasSuffix(filter, ".*") {
		return ""
	}
	return filter
}

// logAuthEvent records an authentication event WITH its source.
//
// The four authentication events (setup_completed, login, login_failed, logout)
// all went through LogActivity, which passes "" for both ip_address and
// user_agent, so the audit trail was blind on precisely the surface it exists
// for. Verified against production: every vault operation carries an IP, while
// every auth.login row has an empty ip_address column and the address only
// appears inside the free-text detail ("Login from 84.55.97.134"), where it
// cannot be filtered, grouped, or read out of the ip_address column that the
// activity UI and both exports display.
//
// auth.login_failed is the sharpest case: a brute-force or credential-stuffing
// attempt is exactly what an operator greps this table for, and the source was
// the one field never recorded.
//
// Separate from LogActivityFromRequest because these fire BEFORE the auth
// middleware has populated a user id in the context: the caller already knows
// which user row it is acting on and passes it explicitly.
func logAuthEvent(q *db.Queries, r *http.Request, userID *string, action, detail string) {
	logActivityInternal(q, userID, action, detail,
		middleware.ClientIP(r), r.Header.Get("User-Agent"))
}

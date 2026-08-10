package handlers

import (
	"net/http"
	"strconv"

	"github.com/bright-interaction/trustissues/internal/db"
)

// THE TRAIL FINALLY HAS A READER.
//
// capability_log has recorded every capability token issued, spent and denied
// since 00020. 00039 made it append-only. audit_name_crypto.go sealed the secret
// name inside it. Three passes hardened a table that no query, no route and no
// page had ever read: it was write-only for its entire life, and the two passes
// that protected it were protecting something nobody could look at.
//
// For a product whose pitch is that an agent spends a credential it never sees,
// "which agent spent which secret, when, to where, and was it refused" is the
// receipt the design exists to produce. Without a reader, the honest description
// of the feature was that the server keeps a record the operator cannot consult.
//
// WHAT THIS DELIBERATELY DOES NOT DO. It does not expose secret_id as a link
// into the vault, and it does not resolve a deleted entry's id back to anything.
// The NAME is what the row denormalises (that is the whole point of
// audit-after-delete: the trail has to survive the entry being removed, which is
// exactly the state an attacker engineers), and the name is what this returns.

// capabilityLogEntry is one row of the credential access trail, with the secret
// name OPENED for display.
type capabilityLogEntry struct {
	ID          string  `json:"id"`
	AgentID     string  `json:"agent_id"`
	SecretID    *string `json:"secret_id"`
	SecretName  string  `json:"secret_name"`
	Destination string  `json:"destination"`
	Method      string  `json:"method"`
	Event       string  `json:"event"`
	StatusCode  *int    `json:"status_code"`
	Error       string  `json:"error"`
	IssuedAt    string  `json:"issued_at"`
}

type capabilityLogResponse struct {
	Entries []capabilityLogEntry `json:"entries"`
	Total   int                  `json:"total"`
	Agents  []string             `json:"agents"`
}

// ListCapabilityLog handles GET /api/capability-log (admin only).
//
// Query params: ?agent_id=&event=&secret_id=&limit=50&offset=0
func (h *CapabilityHandler) ListCapabilityLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// The bridge holds a *sql.DB rather than a *db.Queries (it is mostly a proxy,
	// not a CRUD surface). Wrapping it is a struct literal, not a connection.
	queries := db.New(h.db)

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

	agentFilter := r.URL.Query().Get("agent_id")
	eventFilter := r.URL.Query().Get("event")
	secretFilter := r.URL.Query().Get("secret_id")

	total, err := queries.CountCapabilityLog(ctx, db.CountCapabilityLogParams{
		AgentFilter: agentFilter, EventFilter: eventFilter, SecretFilter: secretFilter,
	})
	if err != nil {
		logError(r, "capability_log.list: count failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	rows, err := queries.ListCapabilityLog(ctx, db.ListCapabilityLogParams{
		AgentFilter: agentFilter, EventFilter: eventFilter, SecretFilter: secretFilter,
		Lim: int64(limit), Off: int64(offset),
	})
	if err != nil {
		logError(r, "capability_log.list: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	// The agent list is what makes the filter usable: an agent id is an opaque
	// token nobody memorises, so a free-text box over it returns nothing and
	// reads as "this agent did nothing" rather than "you typed it wrong".
	agents, err := queries.ListCapabilityLogAgents(ctx)
	if err != nil {
		logError(r, "capability_log.list: agents query failed", "error", err)
		agents = []string{}
	}

	entries := make([]capabilityLogEntry, 0, len(rows))
	for _, row := range rows {
		e := capabilityLogEntry{
			ID:      row.ID,
			AgentID: row.AgentID,
			// Opened here and nowhere else. The column is sealed under the audit
			// DEK because in cleartext it rebuilt the inventory 00040 encrypted,
			// out of the same stolen file. openAuditName returns an unsealed
			// value unchanged, so rows written before the seal still read.
			SecretName:  h.vault.OpenAuditName(ctx, row.SecretName),
			Destination: row.Destination,
			Method:      row.Method,
			Event:       row.Event,
			Error:       row.Error,
			IssuedAt:    row.IssuedAt,
		}
		if row.SecretID.Valid {
			v := row.SecretID.String
			e.SecretID = &v
		}
		if row.StatusCode.Valid {
			v := int(row.StatusCode.Int64)
			e.StatusCode = &v
		}
		entries = append(entries, e)
	}

	writeJSON(w, http.StatusOK, capabilityLogResponse{
		Entries: entries,
		Total:   int(total),
		Agents:  agents,
	})
}

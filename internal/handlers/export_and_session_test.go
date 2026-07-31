package handlers

import (
	"context"
	"encoding/csv"
	"github.com/brightinteraction/trustissues/internal/db"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// A CSV audit export is complete or it is an error, never a silent prefix.
//
// Every cw.Write was discarded as `_ =` and nothing checked cw.Error() after Flush,
// while the writer wrote straight to the ResponseWriter under a 200 and an attachment
// filename. A failure partway through (client disconnect, broken pipe, a full disk on a
// proxy) therefore delivered a TRUNCATED file that looked exactly like a complete one.
//
// That is the one property an audit export has to get right: an admin pulling the trail
// for an incident or a compliance request has no other way to know rows are missing.
func TestActivityCSVExportIsCompleteOrFails(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	h := NewActivityHandler(queries)
	ctx := context.Background()
	user := mustUser(t, queries, "csv-export@example.com", "admin", "")

	const rowCount = 25
	for i := 0; i < rowCount; i++ {
		logActivityInternal(queries, &user, "test.export", "row "+strconv.Itoa(i), "10.0.0.1", "probe")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/activity/export/csv", nil)
	rec := httptest.NewRecorder()
	h.ExportCSV(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}

	// Content-Length makes a short transfer detectable by the CLIENT too, which
	// a chunked stream with no length never could.
	cl := rec.Header().Get("Content-Length")
	if cl == "" {
		t.Error("no Content-Length, so a truncated download still looks complete to the client")
	} else if n, _ := strconv.Atoi(cl); n != rec.Body.Len() {
		t.Errorf("Content-Length %s does not match the %d bytes sent", cl, rec.Body.Len())
	}

	// And the document must actually parse as complete CSV with every row.
	records, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("the export is not valid CSV: %v", err)
	}
	if len(records) != rowCount+1 { // +1 header
		t.Errorf("got %d CSV records, want %d (header + %d rows); a short export is "+
			"indistinguishable from a complete one to whoever opens it",
			len(records), rowCount+1, rowCount)
	}
	if records[0][0] != "id" {
		t.Errorf("header row is wrong: %v", records[0])
	}
}

// The HTTP session idle window is its own setting, not the vault auto-lock knob.
//
// sessionIdleModifier read vault_auto_lock_max_minutes, so two unrelated security
// properties shared one control. The vault auto-lock decides how long a DECRYPTED vault
// stays open in the browser; the session idle timeout decides how long an authenticated
// HTTP session survives unused. An admin widening the vault auto-lock to 240 minutes
// because re-unlocking was tiresome silently gave every session a 4 hour idle window,
// and nothing in the UI said so.
//
// Asserted through the settings ENDPOINT rather than the middleware helper, because the
// property that matters is that an operator can see and set the two independently.
func TestSessionIdleIsSeparateFromVaultAutoLock(t *testing.T) {
	_, queries := newCollectionAuthzEnv(t)
	h := NewSettingsHandler(queries, nil)
	ctx := context.Background()
	admin := mustUser(t, queries, "sess-settings@example.com", "admin", "")
	_ = admin

	// Widen the VAULT auto-lock. The session idle window must not move.
	if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: "vault_auto_lock_max_minutes", Value: "240",
	}); err != nil {
		t.Fatalf("seed vault knob: %v", err)
	}

	rec := httptest.NewRecorder()
	h.GetSessionDuration(rec, httptest.NewRequest(http.MethodGet, "/api/settings/session-duration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"idle_minutes":15`) {
		t.Errorf("widening the vault auto-lock to 240 changed the session idle window: %s\n"+
			"Those are different security properties and must not share one control.", body)
	}
}

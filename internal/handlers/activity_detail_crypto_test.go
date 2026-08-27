package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	timw "github.com/bright-interaction/trustissues/internal/middleware"
)

// THE PROPERTY, STATED AS THE THEFT IT PREVENTS.
//
// Every test here reads activity_log the way somebody holding a stolen copy of
// the file reads it: straight off the connection, no handler, no key. If the
// entry name is in there, the encryption of vault_entries.name and of the two
// audit tables bought nothing, because the log beside them still lists what the
// vault holds.

// distinctiveName is chosen so a false negative is impossible: no format string,
// column default or fixture in this package contains it, so a match is always
// the name and never the scaffolding around it.
const distinctiveName = "Zzyzx prod signing key"

// rawActivityDetails returns every detail column verbatim.
func rawActivityDetails(t *testing.T, h *VaultHandler) []string {
	t.Helper()
	rows, err := h.db.Query(`SELECT COALESCE(detail, '') FROM activity_log ORDER BY id`)
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// TestNoActivityWriterLeavesASecretNameInTheClear drives the writers through the
// real handlers and fails if the name reaches the column.
//
// Driven through the endpoints rather than by calling the seal directly, for the
// reason TestTheEntryNameIsNotReadableFromTheDatabaseFile records: a test that
// calls the crypto asserts that the crypto works, which was never in doubt. What
// is in doubt is whether the twelve call sites remember to use it, and only the
// handler answers that.
func TestNoActivityWriterLeavesASecretNameInTheClear(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "activity-seal@example.com", "user", "")

	authed := func(r *http.Request) *http.Request {
		ctx := context.WithValue(r.Context(), timw.UserIDKey, owner)
		ctx = context.WithValue(ctx, timw.UserRoleKey, "user")
		return r.WithContext(ctx)
	}

	// CREATE
	body, _ := json.Marshal(map[string]any{"name": distinctiveName, "value": "v"})
	rec := httptest.NewRecorder()
	h.Create(rec, authed(httptest.NewRequest(http.MethodPost, "/api/vault", strings.NewReader(string(body)))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("could not read the new entry id: %v %s", err, rec.Body.String())
	}

	// DELETE, which logs the name it just removed. The delete path is the one
	// that matters most for the denormalised copy: after it runs, the log is the
	// ONLY place the name still exists, which is exactly the state an attacker
	// who used a credential and then removed the entry engineers.
	rec = httptest.NewRecorder()
	h.Delete(rec, vaultAuthzRequest(http.MethodDelete, "/api/vault/"+created.ID, owner, "user", created.ID, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	details := rawActivityDetails(t, h)
	if len(details) == 0 {
		t.Fatal("no activity rows were written at all, so this test proves nothing")
	}

	var sawSealed bool
	for _, d := range details {
		if strings.Contains(d, distinctiveName) {
			t.Errorf("A SECRET NAME IS CLEARTEXT IN activity_log.detail: %q.\n"+
				"  vault_entries.name and both audit tables are encrypted so a stolen database file does "+
				"not yield the inventory. This column is the third copy of that same name, and it is "+
				"written on the busiest paths in the product.", d)
		}
		if strings.Contains(d, sealedNameOpen+"enc:v1:") {
			sawSealed = true
		}
	}
	if !sawSealed {
		t.Fatal("no activity row carries a sealed name span, so the writers are not sealing at all " +
			"and the cleartext check above passed for the wrong reason")
	}

	// The other half: the operator must still be able to read it back.
	var opened bool
	for _, d := range details {
		if strings.Contains(h.OpenActivityDetail(context.Background(), d), distinctiveName) {
			opened = true
		}
	}
	if !opened {
		t.Error("the sealed name cannot be read back through OpenActivityDetail, so the audit trail " +
			"has been made unreadable rather than confidential")
	}
}

// TestTheEntryIDSurvivesSealingInTheStoredRow is the constraint that decided the
// design, pinned so a later simplification to whole-line sealing cannot pass.
//
// Migrations 00034/00035/00036 attribute secret ownership with
// instr(al.detail, vault_entries.id) in SQL. SQL cannot decrypt, so an entry
// whose id stopped being matchable in the raw column looks to the backfill like
// one that was never in a collection, and a non-creator gets stamped as the
// owner of somebody else's secret. activity_entry_id_guard_test.go covers the
// actions the backfill reads today; this covers the interaction with sealing.
// It drives vault.entry_moved specifically, because that is the action the
// backfill reads AND the one whose line names a secret, so it is the single
// place the two requirements meet. (vault.entry_created carries no id and is not
// read by the backfill; entry_adopted and ownership_claimed carry an id and no
// name. Only the move has both.)
func TestTheEntryIDSurvivesSealingInTheStoredRow(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	owner := mustUser(t, queries, "activity-id@example.com", "user", "")
	mustCollection(t, queries, "coll-activity-id", owner, map[string]string{owner: collRoleManager})
	const entryID = "entry-activity-id"
	mustEntry(t, h, queries, entryID, owner, distinctiveName, "v")
	placeInCollection(t, queries, entryID, "coll-activity-id")

	rec := httptest.NewRecorder()
	h.MoveToCollection(rec, moveRequest(owner, "user", entryID, `{"collection_id":null}`))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("move: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	var matched bool
	for _, d := range rawActivityDetails(t, h) {
		if !strings.Contains(d, entryID) {
			continue
		}
		matched = true
		if strings.Contains(d, distinctiveName) {
			t.Errorf("the row keeps the id but leaks the name: %q", d)
		}
	}
	if !matched {
		t.Fatalf("no stored activity row contains the entry id %q in cleartext. The ownership "+
			"backfill matches this column with SQL instr() and cannot decrypt, so sealing that "+
			"swallows the id silently misattributes ownership", entryID)
	}
}

// TestOpenActivityDetailLeavesForeignSpansAlone covers the one span the reader
// does NOT own.
//
// The unsealed part of a line carries user-chosen text: collection labels and
// provider names. A user can therefore put something shaped like a sealed span
// into one. Replacing a span that fails to open with a marker would let them
// make an audit line report that a name was unavailable; leaving it verbatim
// means the worst they achieve is seeing their own string rendered back.
func TestOpenActivityDetailLeavesForeignSpansAlone(t *testing.T) {
	h, _ := newCollectionAuthzEnv(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name, in string
	}{
		{"not a span at all", "Vault secret created: plain (user: u)"},
		{"a span that cannot open", "moved to {{enc:v1:bm90LXJlYWxseS1jaXBoZXJ0ZXh0}} today"},
		{"an unterminated span", "moved to {{enc:v1:AAAA and then nothing"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.OpenActivityDetail(ctx, tc.in); got != tc.in {
				t.Errorf("the reader rewrote a line it does not own:\n  in:  %q\n  out: %q", tc.in, got)
			}
		})
	}
}

// TestSealedNameRoundTripsInsideASentence pins that the delimiters survive being
// embedded in the surrounding format strings, which is the whole reason they
// exist: the reader must find the end of the token without knowing what the
// writer put after it.
func TestSealedNameRoundTripsInsideASentence(t *testing.T) {
	h, _ := newCollectionAuthzEnv(t)
	ctx := context.Background()

	for _, name := range []string{
		distinctiveName,
		"a name with (parens) and, commas",
		"a name with {{braces}} in it",
		"ünïcödé näme 🔑",
		strings.Repeat("long", 200),
	} {
		sealed := h.sealSecretName(ctx, name)
		if strings.Contains(sealed, name) {
			t.Fatalf("the sealed form still contains the plaintext: %q", sealed)
		}
		line := "Vault secret rotated (auto/stripe): " + sealed + " (user: u, targets: 2)"
		opened := h.OpenActivityDetail(ctx, line)
		want := "Vault secret rotated (auto/stripe): " + name + " (user: u, targets: 2)"
		if opened != want {
			t.Errorf("round trip changed the line:\n  want: %q\n  got:  %q", want, opened)
		}
	}
}

// TestSealSecretNameFailsClosed is the direction that matters when the key is
// gone: a writer that cannot seal must not fall back to cleartext.
//
// The failure is induced the way a real instance produces it, by making the
// STORED DEK unopenable (the master key was changed with no previous key
// configured, so the wrapped row can no longer be unwrapped).
// loadOrCreateAuditDEK refuses rather than minting a replacement in that case,
// precisely so the names already sealed under the old DEK do not become
// permanently unreadable, and this pins what the writers do with that refusal.
func TestSealSecretNameFailsClosed(t *testing.T) {
	h, _ := newCollectionAuthzEnv(t)
	ctx := context.Background()

	// Seal once so the DEK row exists, then corrupt it.
	if got := h.sealSecretName(ctx, distinctiveName); !strings.Contains(got, "enc:v1:") {
		t.Fatalf("precondition: expected a sealed name, got %q", got)
	}
	if err := h.queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key:   auditDEKSetting,
		Value: "enc:v1:bm90LWEtcmVhbC13cmFwcGVkLWtleQ==",
	}); err != nil {
		t.Fatalf("corrupt the stored DEK: %v", err)
	}
	// Drop the process cache so the next seal has to load the corrupt row.
	h.auditKey = &auditNameKey{}

	got := h.sealSecretName(ctx, distinctiveName)
	if strings.Contains(got, distinctiveName) {
		t.Fatalf("sealing failed OPEN and wrote the name in the clear: %q", got)
	}
	if got != activityDetailUnavailable {
		t.Errorf("expected the fail-closed marker %q, got %q", activityDetailUnavailable, got)
	}
}

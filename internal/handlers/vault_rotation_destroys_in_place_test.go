package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// failIfCalledTransport fails the test the instant it is asked to make a real
// HTTP call. Both tests below use it in place of providerHTTP to PROVE the
// refusal happens before any upstream request, not merely that the response
// looks refused: a bug that called Cloudflare and then discarded the result
// would still show a clean row in the DB assertions alone.
type failIfCalledTransport struct{ t *testing.T }

func (f failIfCalledTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.t.Fatalf("a destroys-in-place provider must be refused before any upstream call; "+
		"got %s %s", req.Method, req.URL)
	return nil, nil
}

func swapProviderHTTPPoisoned(t *testing.T) {
	t.Helper()
	orig := providerHTTP
	providerHTTP = &http.Client{Transport: failIfCalledTransport{t}}
	t.Cleanup(func() { providerHTTP = orig })
}

// TestPredecessorFateReportsCloudflareAsRevoking pins the corrected fate.
//
// Cloudflare's own docs (https://developers.cloudflare.com/fundamentals/api/how-to/roll-token/)
// say verbatim that rolling a token invalidates the previous one as part of the
// SAME call: the roll IS the revoke, under the same token id, with no separable
// step. The table used to carry {false, "TODO: verify..."} here, which told an
// operator the old key stayed live -- backwards from what the vendor documents.
func TestPredecessorFateReportsCloudflareAsRevoking(t *testing.T) {
	fate, ok := predecessorFate["cloudflare"]
	if !ok {
		t.Fatal("cloudflare has no predecessorFate entry")
	}
	if fate.Status != fateRevokes {
		t.Errorf("predecessorFate[\"cloudflare\"].Status = %q, want %q: Cloudflare's roll "+
			"replaces the token value in place, which destroys the predecessor, not leaves it live",
			fate.Status, fateRevokes)
	}
	if strings.HasPrefix(fate.Note, "TODO") {
		t.Errorf("cloudflare's note is still an open TODO: %q", fate.Note)
	}
	const docsURL = "https://developers.cloudflare.com/fundamentals/api/how-to/roll-token/"
	if !strings.Contains(fate.Note, docsURL) {
		t.Errorf("cloudflare's note must cite the docs URL %q; got %q", docsURL, fate.Note)
	}
	if !strings.Contains(fate.Note, "same token id") {
		t.Errorf("cloudflare's note must say the roll replaces the value under the SAME token id "+
			"(no separable revoke step); got %q", fate.Note)
	}
	if !strings.Contains(fate.Note, "does not document the timing") {
		t.Errorf("cloudflare's note must say Cloudflare does not document the timing, so no "+
			"overlap with the old value may be assumed; got %q", fate.Note)
	}

	// The ListProviders() surface is what the UI (and an operator) actually
	// reads. A correct predecessorFate entry that ListProviders does not expose
	// would be a fix nobody can see.
	found := false
	for _, info := range ListProviders() {
		if info.Name != "cloudflare" {
			continue
		}
		found = true
		if !info.RevokesPredecessor {
			t.Error("ListProviders reports cloudflare as NOT revoking its predecessor")
		}
	}
	if !found {
		t.Fatal("ListProviders did not return a cloudflare entry")
	}

	// Machine-readable: the rotation path must be able to branch on this without
	// parsing prose. This is the fix for "the fate table is advisory text no code
	// reads."
	if !predecessorDestroysInPlace["cloudflare"] {
		t.Error("predecessorDestroysInPlace[\"cloudflare\"] = false, want true")
	}
}

// mustCloudflareEntry seeds an entry configured exactly the way the new
// provider-picker UI (agent/ti-p0-provider-ui) lets an operator configure one:
// provider = 'cloudflare', a real stored secret. No provider_meta is needed;
// CloudflareTokenProvider.Rotate only uses the current key.
func mustCloudflareEntry(t *testing.T, h *VaultHandler, queries *db.Queries, id, ownerID, name, value string) {
	t.Helper()
	mustEntry(t, h, queries, id, ownerID, name, value)
	if _, err := h.db.ExecContext(context.Background(),
		`UPDATE vault_entries SET provider = 'cloudflare' WHERE id = ?`, id); err != nil {
		t.Fatalf("set provider on %s: %v", id, err)
	}
}

// TestManualRotateRefusesDestroysInPlaceProviderRatherThanRiskLoss is the
// required gate: a Cloudflare-shaped provider must not be able to lose the
// credential to a write conflict, because Cloudflare's roll destroys the
// predecessor in place with no separable revoke step (see
// predecessorDestroysInPlace's doc comment). The chosen fix is to refuse the
// rotation before any upstream call, rather than attempt a mint that a later
// CAS miss could then strand with no copy anywhere.
//
// Before the fix: classifyProvider resolved "cloudflare" to providerAuto same
// as any other auto-rotating provider, and the handler called provider.Rotate
// unconditionally -- reaching the poisoned transport below and failing the
// test outright (proven by temporarily removing the guard; see the commit
// message for the observed failure). After the fix: the handler refuses
// before ever calling provider.Rotate, so the upstream is never touched and
// the stored value is provably unchanged.
func TestManualRotateRefusesDestroysInPlaceProviderRatherThanRiskLoss(t *testing.T) {
	swapProviderHTTPPoisoned(t)
	h, queries := newCollectionAuthzEnv(t)

	const password = "cf-rotator-pw"
	owner := mustUser(t, queries, "cf-owner@example.com", "user", password)
	const seedValue = "cf-token-live-value"
	mustCloudflareEntry(t, h, queries, "cf-entry", owner, "Cloudflare token", seedValue)

	before, err := queries.GetVaultEntryForRotation(context.Background(), "cf-entry")
	if err != nil {
		t.Fatalf("read before rotate: %v", err)
	}

	rec := httptest.NewRecorder()
	h.Rotate(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/cf-entry/rotate",
		owner, "user", "cf-entry", `{"password":`+quote(password)+`}`))

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected the rotation to be refused with 409, got %d: %s", rec.Code, rec.Body.String())
	}

	var out APIError
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if out.Code != "destroys_in_place_unsupported" {
		t.Errorf("error code = %q, want destroys_in_place_unsupported", out.Code)
	}

	// THE CREDENTIAL MUST NOT BE LOST: the stored ciphertext is byte-for-byte
	// unchanged. A refusal that still overwrote the row, or that lost the value
	// some other way, would defeat the entire point of refusing.
	after, err := queries.GetVaultEntryForRotation(context.Background(), "cf-entry")
	if err != nil {
		t.Fatalf("read after rotate: %v", err)
	}
	if string(after.EncryptedValue) != string(before.EncryptedValue) {
		t.Fatal("the stored secret changed even though the rotation was refused; " +
			"the original credential was lost")
	}
	plain, err := h.OpenEntrySecret(after.EncryptedValue, after.Nonce,
		int(after.EncryptionVersion.Int64), entryOrigin("cf-entry", "Cloudflare token"))
	if err != nil {
		t.Fatalf("decrypt after rotate: %v", err)
	}
	if !plain.EqualsString(seedValue) {
		t.Fatal("stored secret after refusal does not match the original value")
	}
	plain.Wipe()

	// The failure must not promise a retry it cannot honour. rotFailConflict says
	// "will be retried on the next pass"; for a refusal nothing was ever minted,
	// so that specific lie must not appear here -- rotFailDestroysInPlace should.
	afterMeta, err := queries.GetVaultEntryMeta(context.Background(), "cf-entry")
	if err != nil {
		t.Fatalf("read meta after rotate: %v", err)
	}
	if !afterMeta.LastRotationError.Valid || afterMeta.LastRotationError.String != rotFailDestroysInPlace {
		t.Errorf("last_rotation_error = %+v, want rotFailDestroysInPlace", afterMeta.LastRotationError)
	}
}

// TestScheduledSweepRefusesDestroysInPlaceProvider is the same gate on the
// OTHER rotation path. An entry with auto_rotate enabled reaches the
// scheduled sweep (vault_rotation.go), which has to make the identical
// decision independently of the manual handler; a guard added to only one
// path leaves the other exposed the moment an operator flips auto-rotate on
// for a cloudflare entry (which the new provider-picker UI makes possible for
// the first time).
func TestScheduledSweepRefusesDestroysInPlaceProvider(t *testing.T) {
	swapProviderHTTPPoisoned(t)
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "cf-sweep-owner@example.com", "user", "")
	const seedValue = "cf-token-live-value-sweep"
	mustEntry(t, h, queries, "cf-sweep-entry", owner, "Cloudflare token (auto)", seedValue)
	if _, err := h.db.ExecContext(ctx,
		`UPDATE vault_entries SET auto_rotate = 1, provider = 'cloudflare',
		 rotation_interval_days = 30, created_at = datetime('now', '-400 days') WHERE id = ?`,
		"cf-sweep-entry"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	due, err := queries.ListVaultEntriesNeedingRotation(ctx)
	if err != nil {
		t.Fatalf("sweep query: %v", err)
	}
	found := false
	for _, e := range due {
		if e.ID == "cf-sweep-entry" {
			found = true
		}
	}
	if !found {
		t.Fatal("ABORT: the fixture is not due for rotation, so this test cannot exercise the sweep")
	}

	before, err := queries.GetVaultEntryForRotation(ctx, "cf-sweep-entry")
	if err != nil {
		t.Fatalf("read before sweep: %v", err)
	}

	RotateVaultKeys(h.db, queries, h)

	after, err := queries.GetVaultEntryForRotation(ctx, "cf-sweep-entry")
	if err != nil {
		t.Fatalf("read after sweep: %v", err)
	}
	if string(after.EncryptedValue) != string(before.EncryptedValue) {
		t.Fatal("the sweep changed the stored secret for a destroys-in-place provider it should " +
			"have refused before minting anything")
	}
	afterMeta, err := queries.GetVaultEntryMeta(ctx, "cf-sweep-entry")
	if err != nil {
		t.Fatalf("read meta after sweep: %v", err)
	}
	if !afterMeta.LastRotationError.Valid || afterMeta.LastRotationError.String != rotFailDestroysInPlace {
		t.Errorf("last_rotation_error = %+v, want rotFailDestroysInPlace", afterMeta.LastRotationError)
	}
}

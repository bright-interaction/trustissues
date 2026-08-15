package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// This file covers the answers list_secrets and use_secret give when the
// decryption door is PRESENT and a row will not open through it.
//
// That distinction is the whole point. entry_name_at_rest_lookup_test.go
// already pins the nil-door case, and nil is unreachable in production:
// main.go os.Exit(1)s when NewCapabilityHandler fails, so the handler either
// has a capability handler or the process is not running. A name that will not
// open, on the other hand, needs only a damaged row or a master-key rotation
// observed mid-sweep, and the code silently swallowed every one of them:
// `continue`, then "You have no secrets available." with isError:false.
//
// The harm is specific. An agent told authoritatively, and with no error flag,
// that the user holds no credentials does not stop; it falls back, and the
// realistic fallback is asking the human to paste the key into the chat, which
// writes a live secret into the model provider's transcript. The product exists
// to keep that value away from that transcript.

// seedNameSealedUnderAForeignKey writes the row this file is about: a
// vault_entries row whose name column is a well-formed enc:v1: blob sealed
// under a key this handler does not hold. That is the shape a rotation in
// flight leaves behind, and EntryNamePlain answers "" for it, exactly as it
// does for a corrupted column.
//
// It ends with the anti-blind-fixture guard: if the running handler CAN open
// this name, the row is not unreadable and every assertion made against it
// would pass for the wrong reason.
func seedNameSealedUnderAForeignKey(t *testing.T, vh *VaultHandler, entryID, ownerID, plainName, value string) string {
	t.Helper()

	var rotatedAway [32]byte
	copy(rotatedAway[:], strings.Repeat("r", 32))
	sealed, err := vaultfield.SealColumn(rotatedAway, plainName)
	if err != nil {
		t.Fatalf("seal %q under the foreign key: %v", plainName, err)
	}
	if !vaultfield.IsSealedColumn(sealed) {
		t.Fatalf("ABORT: the fixture did not produce a sealed column: %q", sealed)
	}

	ct, nonce, err := vh.EncryptValue([]byte(value))
	if err != nil {
		t.Fatalf("encrypt value: %v", err)
	}
	if _, err := vh.db.Exec(
		`INSERT INTO vault_entries (id, user_id, secret_owner_user_id, name, name_bidx, encrypted_value, nonce, encryption_version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 2)`,
		entryID, ownerID, ownerID, sealed, "bidx-"+entryID, ct, nonce); err != nil {
		t.Fatalf("seed unopenable-name row %s: %v", entryID, err)
	}

	if plain := vh.EntryNamePlain(sealed); plain != "" {
		t.Fatalf("ABORT, the fixture is blind: the handler opened a name sealed under a key it does "+
			"not hold (%q). Nothing below would be testing an unreadable row", plain)
	}
	return sealed
}

// callMCPTool drives tools/call over the real Handle path and returns the text
// the model provider would receive together with the isError flag it would see.
// Both halves matter here: the defect was a true statement of absence carried on
// a false flag.
func callMCPTool(t *testing.T, h *MCPHandler, userID, tool string) (string, bool) {
	t.Helper()
	resp := doMCP(t, h, userID, "tools/call", map[string]any{"name": tool})
	if resp.Error != nil {
		t.Fatalf("tools/call %s returned a JSON-RPC error: %+v", tool, resp.Error)
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal tool result: %v", err)
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode tool result: %v (%s)", err, raw)
	}
	if len(out.Content) == 0 {
		t.Fatalf("tool result carried no content: %s", raw)
	}
	return out.Content[0].Text, out.IsError
}

// TestMCPListSecretsNeverReportsAnEmptyInventoryWhenNamesWereDropped is the
// regression test for the silent-drop defect.
//
// The user owns one secret. Its name will not open. The one answer that must
// never be produced is "You have no secrets available." with isError:false,
// because that is a confident denial of a credential that exists, and it is the
// sentence that sends an agent to ask for the key in chat instead.
//
// ABLATION: replace the `dropped++` counters in toolListSecrets with the bare
// `continue`s they had (or drop the `if dropped > 0` branch above the empty
// answer) and this fails on both the flag and the text.
func TestMCPListSecretsNeverReportsAnEmptyInventoryWhenNamesWereDropped(t *testing.T) {
	h, vh, queries := newRealMCPEnv(t)
	user := mustUser(t, queries, "unreadable@example.com", "user", "")

	blob := seedNameSealedUnderAForeignKey(t, vh, "mcp-unreadable", user, "Stripe live key", "sk_live_never_seen")

	text, isErr := callMCPTool(t, h, user, "list_secrets")

	if !isErr {
		t.Fatalf("a listing that could read NOTHING was reported as a success: %q. "+
			"An agent reads this as authoritative and falls back to asking the human to paste "+
			"the credential into the chat, which is the transcript this product exists to keep clean", text)
	}
	if strings.Contains(text, "no secrets available") {
		t.Fatalf("EMPTY MASQUERADED AS NONE: the user owns a secret and was told they own none: %q", text)
	}
	// The refusal must describe the failure with a COUNT and nothing else. A
	// name that would not open must not be described by anything that came out
	// of the column it was stored in.
	if strings.Contains(text, vaultfield.ColumnPrefix) || strings.Contains(text, blob) {
		t.Fatalf("CIPHERTEXT SHIPPED TO THE MODEL PROVIDER on the failure path: %q", text)
	}
	if strings.Contains(text, "Stripe live key") {
		t.Fatalf("the failure path produced a cleartext name from nowhere: %q", text)
	}
	if strings.Contains(text, "sk_live_never_seen") {
		t.Fatalf("the failure path shipped a secret VALUE: %q", text)
	}
}

// TestMCPListSecretsMarksAPartialInventory covers the more common half: some
// names open and some do not.
//
// This stays a success, because the readable names are still usable and
// refusing outright would take a working tool away over one damaged row. What
// it must not do is present a partial list as the whole inventory: an agent
// that cannot see the omission concludes the missing credential does not exist
// and goes to the same fallback.
//
// ABLATION: remove the `payload["warning"]` / `payload["omitted"]` block in
// toolListSecrets and this fails on the missing omission notice.
func TestMCPListSecretsMarksAPartialInventory(t *testing.T) {
	h, vh, queries := newRealMCPEnv(t)
	user := mustUser(t, queries, "partial@example.com", "user", "")

	readable := createEntryThroughTheRealWritePath(t, vh, user, "GitHub Token", "ghp_secret")
	requireSealedName(t, vh, readable, "GitHub Token")
	blob := seedNameSealedUnderAForeignKey(t, vh, "mcp-partial-unreadable", user, "AWS Prod", "aws_never_seen")

	text, isErr := callMCPTool(t, h, user, "list_secrets")

	if isErr {
		t.Fatalf("one unreadable row must not take away the names that DO open: %q", text)
	}
	if !strings.Contains(text, "GitHub Token") {
		t.Fatalf("the readable name vanished from a partial listing: %q", text)
	}
	// The listing must SAY it is incomplete. Anything else presents two names as
	// the whole inventory when there are three.
	if !strings.Contains(text, "omitted") {
		t.Fatalf("A PARTIAL LISTING WAS PRESENTED AS COMPLETE: one of this user's names could not "+
			"be read and the result does not say so: %q", text)
	}
	var payload struct {
		Secrets []string `json:"secrets"`
		Omitted int      `json:"omitted"`
		Warning string   `json:"warning"`
	}
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("the partial listing is not parseable JSON, so the agent cannot act on it: %v (%q)", err, text)
	}
	if payload.Omitted != 1 {
		t.Fatalf("omitted count = %d, want 1 (one name did not open): %q", payload.Omitted, text)
	}
	if payload.Warning == "" {
		t.Fatalf("the omission carries no human-readable statement, so a model reading the text "+
			"rather than the field still sees a complete inventory: %q", text)
	}
	if len(payload.Secrets) != 1 || payload.Secrets[0] != "GitHub Token" {
		t.Fatalf("secrets = %v, want exactly the one readable name", payload.Secrets)
	}
	if strings.Contains(text, vaultfield.ColumnPrefix) || strings.Contains(text, blob) {
		t.Fatalf("CIPHERTEXT SHIPPED TO THE MODEL PROVIDER in a partial listing: %q", text)
	}
	if strings.Contains(text, "AWS Prod") || strings.Contains(text, "aws_never_seen") ||
		strings.Contains(text, "ghp_secret") {
		t.Fatalf("the listing leaked a name it could not read, or a value: %q", text)
	}
}

// TestMCPUseSecretFailsClosedWithoutACapabilityHandler pins the guard the
// nameOpener comment claimed every caller had.
//
// toolUseSecret called h.capability.Issue unguarded, and Issue dereferences the
// same pointer nameOpener protects, so a nil handler panicked into chi's
// Recoverer and answered a bare 500 instead of a refusal. Not reachable in
// production (main.go exits if the capability handler fails to build), but the
// documented contract has to be true of the code, not of the intention: the
// sibling suite covered list_secrets only, so nothing reddened.
//
// ABLATION: delete the `h.nameOpener() == nil` guard in toolUseSecret and this
// fails with the recovered panic.
func TestMCPUseSecretFailsClosedWithoutACapabilityHandler(t *testing.T) {
	_, vh, queries := newRealMCPEnv(t)
	user := mustUser(t, queries, "nodoor-use@example.com", "user", "")
	id := createEntryThroughTheRealWritePath(t, vh, user, "Stripe live key", "sk_live_x")
	requireSealedName(t, vh, id, "Stripe live key")

	// nil capability: the shape mcp_test.go's own handler had until this year.
	doorless := NewMCPHandler(queries, nil, nil, nil, nil)

	// A REAL authenticated request. With no user in the context Issue returns
	// early on its own auth check and never reaches the dereference, so an
	// unauthenticated request here would make this test pass against the bug.
	r := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
	r = r.WithContext(context.WithValue(context.Background(), middleware.UserIDKey, user))

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("use_secret panicked without a capability handler (%v); chi's Recoverer "+
				"answers a bare 500 and the agent is told nothing it can act on", rec)
		}
	}()

	text, isErr := doorless.toolUseSecret(r, user, json.RawMessage(`{"name":"Stripe live key"}`))
	if !isErr {
		t.Fatalf("use_secret must fail CLOSED without a capability handler, got a success: %q", text)
	}
	if strings.Contains(text, "sk_live_x") {
		t.Fatalf("the doorless refusal shipped a secret value: %q", text)
	}
	if strings.Contains(text, vaultfield.ColumnPrefix) {
		t.Fatalf("the doorless refusal shipped ciphertext: %q", text)
	}
}

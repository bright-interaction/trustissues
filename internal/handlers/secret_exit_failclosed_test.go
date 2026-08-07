package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE FAIL-CLOSED HALVES OF THE OWNER RULE.
//
// The guards above prove the exit is a chokepoint and that it answers the owner
// question. These prove it answers NO in the three ways a gate stops guarding
// without anybody noticing:
//
//	nobody to ask       an unattributed destination
//	cannot tell         a read error while resolving the owner's destinations
//	nobody asked        a host the owner never recorded, planted straight into
//	                    the column the way a backup or an older binary does
//
// Every one of these was found by an ablation on a guard written this round.

// TestOwnerRuleRefusesAnUnattributedDestination pins "nobody to ask means no".
//
// A rotation target with no ConfiguredBy is exactly the row an import, a
// restored backup or a binary older than the attribution field leaves behind.
func TestOwnerRuleRefusesAnUnattributedDestination(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "unattributed-owner@example.com", "user", "")
	mustEntry(t, h, queries, "entry-unattributed", owner, "unattributed", "sk_live_X")

	pt, err := h.EntrySecretByID(ctx, "entry-unattributed")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, b, err := secretexit.Exit(ctx, pt,
		secretexit.ToHost("an unattributed delivery target", secretexit.ChosenBy(""), "consumer.example"))
	if err == nil {
		t.Fatal("a destination with no recorded chooser was authorised. There was nobody whose " +
			"authority could be checked, and that has to mean no")
	}
	if len(b) != 0 {
		t.Fatalf("%d bytes came back alongside the refusal", len(b))
	}

	// The positive control: the same host, attributed to the owner, is fine.
	if _, _, err := secretexit.Exit(ctx, pt,
		secretexit.ToHost("an attributed delivery target", secretexit.ChosenBy(owner),
			"consumer.example")); err != nil {
		t.Fatalf("the owner's own attributed destination was refused: %v", err)
	}
}

// TestOwnerRecordedDestinationsFailsClosedOnAReadError pins "cannot tell means
// no" for the entry's-own-record branch.
//
// The reader is broken by closing the database under it, which is the shape a
// transient error actually has: the query fails, and the question "what has this
// entry's owner recorded" has no answer.
func TestOwnerRecordedDestinationsFailsClosedOnAReadError(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	owner := mustUser(t, queries, "readerr-owner@example.com", "user", "")
	mustEntry(t, h, queries, "entry-readerr", owner, "readerr", "sk_live_X")
	if err := setDestinationPatternsFixture(t, queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["consumer.example/*"]`, ID: "entry-readerr",
	}); err != nil {
		t.Fatalf("seed ceiling: %v", err)
	}

	pt, err := h.EntrySecretByID(ctx, "entry-readerr")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Guard the setup: while the database is readable the recorded host IS
	// allowed, so a refusal below is the read error and not a mis-seeded fixture.
	if _, _, err := secretexit.Exit(ctx, pt,
		secretexit.ToHost("the ceiling", secretexit.ChosenByTheEntrysOwnRecord(),
			"consumer.example")); err != nil {
		t.Fatalf("ABORT: the recorded destination was refused before the fault was injected: %v", err)
	}

	if err := h.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	_, b, err := secretexit.Exit(ctx, pt,
		secretexit.ToHost("the ceiling", secretexit.ChosenByTheEntrysOwnRecord(), "consumer.example"))
	if err == nil {
		t.Fatal("a failed read of the owner's recorded destinations resolved to ALLOWED. " +
			"A transient database error must not open the gate: 'cannot tell' is how a guard stops " +
			"guarding without anybody noticing")
	}
	if len(b) != 0 {
		t.Fatalf("%d bytes came back alongside the refusal", len(b))
	}
	// UPDATED FOR THE ALLOWLIST REDACTOR FIX (see internal/handlers/capability.go
	// redactUpstreamError and internal/secretexit.ExitRefusedError). This
	// assertion used to pin `err.Error()` containing "not sent anywhere", which
	// only ever appeared attached to `o.Describe()` -- "the destinations
	// recorded on the secret in entry \"readerr\" (entry-readerr) ...". That is
	// exactly the entry-name-and-UUID leak the security fix closes: Exit() now
	// wraps every AuthorizeSecretExit refusal in a *secretexit.ExitRefusedError
	// whose Error() is a fixed structural string carrying no entry identity, so
	// the old substring can never appear in Error() again. The detailed reason
	// is not gone, only moved: it is still reachable via LogValue for
	// server-side logging, checked below.
	var refused *secretexit.ExitRefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("a read-error refusal is not a *secretexit.ExitRefusedError: %v (%T)", err, err)
	}
	for _, leaked := range []string{"entry-readerr", "readerr"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("Error() leaked entry identity %q: %q", leaked, err.Error())
		}
	}
	var reason string
	for _, a := range refused.LogValue().Group() {
		if a.Key == "reason" {
			reason = a.Value.String()
		}
	}
	if !strings.Contains(reason, "not sent anywhere") {
		t.Errorf("the reason available to slog lost the useful signal, got %q", reason)
	}
}

// TestOwnerRecordedDestinationsIsNotJustTheColumnBackAgain is the honest
// statement of what the entry's-own-record branch does and does not add.
//
// WHAT IT DOES NOT ADD, stated first because a guard nobody understands is a
// guard that gets trusted for the wrong reason: destination_patterns is READ OFF
// THE ROW. A pattern planted into that column with raw SQL is therefore inside
// the owner's recorded set, and the exit will honour it. That column's integrity
// is the job of the compile-enforced write path (internal/vaultegress plus
// egressgate.Ticket plus mayDirectSecretEgress), which is exactly why round 7
// KEPT all of it rather than claiming the exit subsumes it. The two are
// complementary: the write path decides what may be recorded, the exit decides
// what a recorded destination authorises.
//
// WHAT IT DOES ADD is everything below, and none of it is the column back again.
func TestOwnerRecordedDestinationsIsNotJustTheColumnBackAgain(t *testing.T) {
	env := newEgressEnv(t)
	ctx := context.Background()
	const entryID = "entry-cap-owner-record"
	owner := mustUser(t, env.queries, "cap-record-owner@example.com", "user", "")
	editor := mustUser(t, env.queries, "cap-record-editor@example.com", "vault_only", "")
	mustCollection(t, env.queries, "coll-cap-record", owner, map[string]string{
		owner:  collRoleManager,
		editor: collRoleEditor,
	})
	mustEntry(t, env.vault, env.queries, entryID, owner, "cap-record", "sk_live_CAP")
	placeInCollection(t, env.queries, entryID, "coll-cap-record")

	if err := setDestinationPatternsFixture(t, env.queries, vaultegress.DestinationPatternsParams{
		DestinationPatterns: `["consumer.example/*"]`, ID: entryID,
	}); err != nil {
		t.Fatalf("seed ceiling: %v", err)
	}

	// Baseline: the owner's own recorded host is there, so a later absence is a
	// refusal rather than an empty fixture.
	recorded, err := env.vault.ownerRecordedDestinations(ctx, entryID)
	if err != nil {
		t.Fatalf("owner destinations: %v", err)
	}
	if !recorded.Allows("consumer.example") {
		t.Fatalf("ABORT: the owner's own recorded host is missing from %s", recorded.Describe())
	}

	t.Run("a delivery target planted by an EDITOR contributes nothing", func(t *testing.T) {
		// Planted the way an older binary did: straight into the column,
		// attributed to a CURRENT, accepted editor, so nothing about membership
		// or account status refuses it. If the recorded set simply read the
		// column back, this host would re-authorise itself and the delivery gate
		// would be reading its answer out of the thing it is judging.
		planted, _ := json.Marshal([]RotationTarget{{
			Type: "webhook", WebhookURL: "https://collector.attacker.example/collect",
			ConfiguredBy: editor,
		}})
		enc, encErr := env.vault.encryptColumn(string(planted))
		if encErr != nil {
			t.Fatalf("encrypt: %v", encErr)
		}
		if err := setRotationTargetsFixture(t, env.queries, vaultegress.RotationTargetsParams{
			RotationTargets: toNullString(enc), ID: entryID,
		}); err != nil {
			t.Fatalf("plant: %v", err)
		}
		// Guard the setup: the editor really does have manage right now.
		if g := env.vault.grantFor(ctx, editor, false, entryID); !g.manage {
			t.Fatal("ABORT: the planted configurer has no manage, so this proves nothing about the " +
				"widening right")
		}
		got, gErr := env.vault.ownerRecordedDestinations(ctx, entryID)
		if gErr != nil {
			t.Fatalf("owner destinations: %v", gErr)
		}
		if got.Allows("collector.attacker.example") {
			t.Fatalf("an editor-planted delivery target re-authorised its own host: %s", got.Describe())
		}
		if !got.Allows("consumer.example") {
			t.Fatalf("the owner's own host went missing: %s", got.Describe())
		}
	})

	t.Run("a delivery target the OWNER configured does contribute", func(t *testing.T) {
		// The positive control for the rule above. Same column, same shape, one
		// different ConfiguredBy.
		mine, _ := json.Marshal([]RotationTarget{{
			Type: "webhook", WebhookURL: "https://mine.example/deploy", ConfiguredBy: owner,
		}})
		enc, encErr := env.vault.encryptColumn(string(mine))
		if encErr != nil {
			t.Fatalf("encrypt: %v", encErr)
		}
		if err := setRotationTargetsFixture(t, env.queries, vaultegress.RotationTargetsParams{
			RotationTargets: toNullString(enc), ID: entryID,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		got, gErr := env.vault.ownerRecordedDestinations(ctx, entryID)
		if gErr != nil {
			t.Fatalf("owner destinations: %v", gErr)
		}
		if !got.Allows("mine.example") {
			t.Fatalf("the OWNER's own delivery target was not counted: %s", got.Describe())
		}
	})

	t.Run("the AI gateway pin CAPS the set, whatever the column says", func(t *testing.T) {
		// The sharpest non-tautological case. An entry an admin wired into the AI
		// gateway is only ever delivered to that provider, so the recorded set is
		// the pin and nothing else, even though destination_patterns still names
		// consumer.example and a delivery target still names mine.example.
		if err := env.queries.UpsertSetting(ctx, db.UpsertSettingParams{
			Key: "ai_key_openai", Value: entryID,
		}); err != nil {
			t.Fatalf("pin: %v", err)
		}
		got, gErr := env.vault.ownerRecordedDestinations(ctx, entryID)
		if gErr != nil {
			t.Fatalf("owner destinations: %v", gErr)
		}
		if !got.Allows("api.openai.com") {
			t.Fatalf("the pinned provider host is not in %s, so the AI gateway would stop working",
				got.Describe())
		}
		for _, other := range []string{"consumer.example", "mine.example"} {
			if got.Allows(other) {
				t.Errorf("a PINNED entry still authorises %q. Its secret is the instance's provider "+
					"key and goes to the provider or nowhere: %s", other, got.Describe())
			}
		}
		// And on the wire question the capability bridge asks.
		pt, oErr := env.vault.EntrySecretByID(ctx, entryID)
		if oErr != nil {
			t.Fatalf("open: %v", oErr)
		}
		if _, _, err := secretexit.Exit(ctx, pt,
			secretexit.ToHost("this capability token", secretexit.ChosenByTheEntrysOwnRecord(),
				"consumer.example")); err == nil {
			t.Fatal("a pinned entry's secret was authorised for a host outside its pin")
		}
		if _, _, err := secretexit.Exit(ctx, pt,
			secretexit.ToHost("this capability token", secretexit.ChosenByTheEntrysOwnRecord(),
				"api.openai.com")); err != nil {
			t.Fatalf("the pinned provider host itself was refused: %v", err)
		}
	})
}

// TestUnlockOnlyReleasesEntriesTheCallerMayRead is the caller half of the exit,
// on the real route.
//
// POST /api/vault/unlock re-verifies the caller's password and then lists what
// they can reach. The exit asks the second question, per row: does the OWNER of
// each entry admit this caller? A refusal renders as the decryption-error
// sentinel rather than as the value.
func TestUnlockOnlyReleasesEntriesTheCallerMayRead(t *testing.T) {
	h, queries := newCollectionAuthzEnv(t)
	ctx := context.Background()

	const password = "unlock-caller-password"
	owner := mustUser(t, queries, "unlock-owner@example.com", "user", password)
	stranger := mustUser(t, queries, "unlock-stranger@example.com", "user", password)

	const mine = "sk_live_MINE"
	mustEntry(t, h, queries, "entry-unlock-mine", owner, "mine", mine)

	unlock := func(who string) string {
		t.Helper()
		body := `{"password":` + quote(password) + `}`
		rec := httptest.NewRecorder()
		h.Unlock(rec, vaultAuthzRequest(http.MethodPost, "/api/vault/unlock", who, "user", "", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("unlock as %s: %d %s", who, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	// The owner sees their own value: the positive control, first, so a later
	// refusal cannot be "unlock is simply broken".
	got := unlock(owner)
	if !strings.Contains(got, mine) {
		t.Fatalf("THE FEATURE IS BROKEN: the owner's unlock did not carry their own value: %s", got)
	}

	// A stranger's unlock must not carry it. They cannot reach the entry at all,
	// so the list query should not return it.
	got = unlock(stranger)
	if strings.Contains(got, mine) {
		t.Fatalf("a stranger's unlock carried somebody else's plaintext: %s", got)
	}

	// AND THE HONEST LIMIT OF THIS ONE, recorded rather than papered over.
	//
	// The caller half of the exit is DEFENCE IN DEPTH here, not the only thing
	// standing between a caller and a value. ListAccessibleVaultEntriesWithSecrets
	// already filters on a disabled account and on ACCEPTED membership, and the
	// schema pins collection_members.role with
	// CHECK (role IN ('viewer','editor','manager')), all three of which grantFor
	// grants read to. So there is no reachable database state in which the query
	// returns a row the exit then refuses, and an ablation that swaps the caller
	// id for the entry owner's is NOT independently observable through this
	// route. scripts/round7-ablations.json records that as a known miss with the
	// reason rather than pretending otherwise.
	//
	// What IS observable is the rule itself, asked directly, which is the next
	// assertion: the day that query widens, the exit is already there.

	// And the row-level property, asked directly: the exit refuses the stranger
	// for this entry even when handed the value.
	pt, err := h.EntrySecretByID(ctx, "entry-unlock-mine")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := secretexit.Exit(ctx, pt,
		secretexit.ToCaller("POST /api/vault/unlock", stranger)); err == nil {
		t.Fatal("the exit released an entry to a caller its owner never admitted. The list query is " +
			"then the only thing standing between a widened SELECT and every secret on the instance")
	}
	var out []map[string]any
	_ = json.Unmarshal([]byte(unlock(owner)), &out)
	if len(out) == 0 {
		t.Fatal("the owner's unlock returned no entries at all")
	}
}

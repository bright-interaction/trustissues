package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/vaultegress"
)

// THE WORST SHAPE OF BUG: ACCEPTED AT THE WRITE, SILENT AT THE NEXT ROTATION.
//
// A forgejo_secret target names another vault entry by NAME in auth_token, and
// that entry's secret becomes the bearer token of the delivery. Before the exit
// existed, delivering it required only that the person who configured the target
// could USE the referenced entry, which every member of the collection holding
// it can. That is the ordinary team shape:
//
//	Alice owns  app-key      in the shared collection
//	Bob   owns  forgejo-pat  in the same shared collection (one CI token, shared)
//	Alice wires app-key's rotation to push into Forgejo using forgejo-pat
//
// The exit narrowed that, correctly: the bearer half now asks whether Alice may
// choose where BOB'S secret goes, and she may not. That is the round-6 kill.
//
// But UpdateTargets never asked the same question. So the panel accepts Alice's
// target, reports it saved, shows it live, and the delivery fails at the NEXT
// scheduled rotation, which is weeks later, unattended, against a credential
// that has just been rolled at the provider. The consumer keeps the dead key.
//
// That is exactly the failure mode round 5 named as the worst of the three
// possible ones ("deliver, refuse at the write, accept-then-silent") and fixed
// once already, for the admin case. This is the same defect with the argument
// changed, which is this codebase's recurring shape.
//
// THE CHOICE MADE HERE, PLAINLY: the behaviour is MIGRATED, not preserved.
// Preserving it means reinstating the round-6 hole. So the write gate asks the
// delivery question, an operator is told at save time which entry the auth_token
// names and why they may not spend it, and the rows an existing instance already
// has are named at BOOT rather than discovered at the next rotation.

// authTokenTeamEnv is Alice, Bob, and one shared collection.
type authTokenTeamEnv struct {
	h        *VaultHandler
	alice    string
	bob      string
	appEntry string
	patName  string
	patValue string
	password string
}

func newAuthTokenTeamEnv(t *testing.T, tag string) *authTokenTeamEnv {
	t.Helper()
	swapProviderHTTP(t)
	h, queries := newCollectionAuthzEnv(t)

	env := &authTokenTeamEnv{
		h:        h,
		appEntry: "entry-app-" + tag,
		patName:  "forgejo-pat-" + tag,
		patValue: "gitea_PAT_" + strings.ToUpper(tag),
		password: "alice-pw",
	}
	env.alice = mustUser(t, queries, "at-alice-"+tag+"@example.com", "user", env.password)
	env.bob = mustUser(t, queries, "at-bob-"+tag+"@example.com", "user", "bob-pw")

	mustCollection(t, queries, "coll-at-"+tag, env.bob, map[string]string{
		env.alice: collRoleEditor,
		env.bob:   collRoleManager,
	})
	// Alice's own entry, in the collection. She is its creator and its owner.
	mustEntry(t, h, queries, env.appEntry, env.alice, "app-key-"+tag, "app-key-seed")
	placeInCollection(t, queries, env.appEntry, "coll-at-"+tag)
	// BOB's shared CI token. Alice may USE it (collection membership) and may not
	// choose where it goes (she is not its owner).
	mustEntry(t, h, queries, "entry-pat-"+tag, env.bob, env.patName, env.patValue)
	placeInCollection(t, queries, "entry-pat-"+tag, "coll-at-"+tag)
	return env
}

// TestAForgejoTargetNamingSomebodyElsesTokenIsRefusedAtTheWrite is the fix, and
// it is written as the failure it replaces: an operator must learn at SAVE TIME.
func TestAForgejoTargetNamingSomebodyElsesTokenIsRefusedAtTheWrite(t *testing.T) {
	env := newAuthTokenTeamEnv(t, "write")
	sink := newHeaderSink(t)

	body := `[{"type":"forgejo_secret","label":"ci","instance":` + quote(sink.URL) +
		`,"repo":"team/app","secret_name":"APP_KEY","auth_token":` + quote(env.patName) + `}]`
	rec := putTargets(t, env.h, env.alice, "user", env.appEntry, body)

	if rec.Code == http.StatusOK {
		t.Fatalf("THE WRITE WAS ACCEPTED. Alice's target names Bob's CI token as its bearer, and the "+
			"exit will refuse that at delivery. The panel says saved, the entry shows a live target, "+
			"and the rotation weeks from now drops it in silence against a credential that has just "+
			"been rolled. Refuse it here, where somebody is looking.\n  body: %s", rec.Body.String())
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the write was refused with %d; want 403 so the client can tell an authorization "+
			"refusal from a validation error.\n  %s", rec.Code, rec.Body.String())
	}
	// The message has to name the entry and the missing right, or the operator
	// cannot act on it.
	msg := rec.Body.String()
	for _, want := range []string{env.patName, "owner"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q, so it does not tell the operator what to fix: %s",
				want, msg)
		}
	}
	t.Logf("write refused %d: %s", rec.Code, strings.TrimSpace(msg))
}

// TestAForgejoTargetNamingYourOwnTokenStillSavesAndDelivers is the positive
// control. The gate must refuse the cross-owner case and nothing else.
func TestAForgejoTargetNamingYourOwnTokenStillSavesAndDelivers(t *testing.T) {
	env := newAuthTokenTeamEnv(t, "pos")
	sink := newHeaderSink(t)
	queries := env.h.queries

	// Alice's OWN CI token, personal. This is the shape the product is built for.
	mustEntry(t, env.h, queries, "entry-alice-pat", env.alice, "alice-pat", "gitea_ALICE_PAT")

	body := `[{"type":"forgejo_secret","label":"ci","instance":` + quote(sink.URL) +
		`,"repo":"team/app","secret_name":"APP_KEY","auth_token":"alice-pat"}]`
	if rec := putTargets(t, env.h, env.alice, "user", env.appEntry, body); rec.Code != http.StatusOK {
		t.Fatalf("THE FEATURE IS BROKEN. Alice could not configure a delivery using her OWN token "+
			"(%d: %s)", rec.Code, rec.Body.String())
	}

	rot := httptest.NewRecorder()
	env.h.Rotate(rot, vaultAuthzRequest(http.MethodPost, "/api/vault/"+env.appEntry+"/rotate",
		env.alice, "user", env.appEntry, `{"password":`+quote(env.password)+`}`))
	if rot.Code != http.StatusOK {
		t.Fatalf("rotate failed (%d: %s)", rot.Code, rot.Body.String())
	}
	if !env.h.WaitForDelivery(30 * time.Second) {
		t.Fatal("rotation delivery did not drain")
	}
	auths, lines, payloads := sink.received()
	if len(lines) == 0 {
		t.Fatal("THE FEATURE IS BROKEN. The legitimate forgejo delivery received nothing")
	}
	if !sink.sawSecret("gitea_ALICE_PAT") {
		t.Fatalf("the delivery did not carry Alice's own PAT as its bearer: %q", auths)
	}
	var pushed struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(payloads[0]), &pushed); err != nil {
		t.Fatalf("the sink received something that is not a forgejo payload (%q): %v", payloads[0], err)
	}
	if pushed.Data == "" || pushed.Data == "app-key-seed" {
		t.Fatalf("the pushed value is %q; want the freshly ROTATED value", pushed.Data)
	}
	t.Logf("wire, own-token forgejo delivery: %v, bearer carried, rotated value pushed", lines)
}

// mustStoreRotationTargetsForTest writes the column the way an older binary or a
// restored backup would: through the gated writer, with a ticket, but WITHOUT
// the new auth_token question the write gate now asks.
func mustStoreRotationTargetsForTest(t *testing.T, q *db.Queries, entryID, encrypted string) {
	t.Helper()
	if err := setRotationTargetsFixture(t, q, vaultegress.RotationTargetsParams{
		RotationTargets: sql.NullString{String: encrypted, Valid: true},
		ID:              entryID,
	}); err != nil {
		t.Fatalf("store rotation targets: %v", err)
	}
}

// TestExistingCrossOwnerTargetsAreNamedAtBootNotAtTheNextRotation is the
// migration half, and it is the half that matters for an instance that already
// has these rows.
//
// The write gate above only covers writes that happen after the deploy. A live
// instance has targets configured months ago under the old rule, and every one
// of them will fail at its next unattended rotation. That failure is recorded on
// last_rotation_error and fires a rotation_partial alert, which is better than
// nothing and still weeks late, against a credential that has already been
// rolled upstream.
//
// So the same question is asked once at boot, over the stored rows, and every
// target that will fail is NAMED on the activity log before anything rotates.
func TestExistingCrossOwnerTargetsAreNamedAtBootNotAtTheNextRotation(t *testing.T) {
	env := newAuthTokenTeamEnv(t, "boot")
	queries := env.h.queries

	// A row an OLDER BINARY would have written: stored directly, bypassing the
	// new write gate, exactly as a restored backup or a pre-deploy save would.
	stored := `[{"type":"forgejo_secret","label":"ci","instance":"https://git.example",` +
		`"repo":"team/app","secret_name":"APP_KEY","auth_token":"` + env.patName + `",` +
		`"configured_by":"` + env.alice + `"}]`
	enc, err := env.h.encryptColumn(stored)
	if err != nil {
		t.Fatalf("encrypt targets: %v", err)
	}
	mustStoreRotationTargetsForTest(t, queries, env.appEntry, enc)

	found := env.h.AuditCrossOwnerAuthTokenTargets(context.Background())
	if len(found) == 0 {
		t.Fatal("THE MIGRATION IS MISSING. A target stored under the old rule, which the exit will " +
			"refuse at its next rotation, was not reported at boot. A breaking change that only " +
			"appears at the next rotation ships green and fails weeks later with nobody watching")
	}
	joined := strings.Join(found, " | ")
	for _, want := range []string{env.appEntry, env.patName} {
		if !strings.Contains(joined, want) {
			t.Errorf("the boot report does not name %q, so an operator cannot act on it: %s", want, joined)
		}
	}
	t.Logf("boot report: %s", joined)

	// NEGATIVE CONTROLS. A boot warning that fires on healthy configuration is
	// noise, and noise is what makes the real one get ignored, so every shape
	// this audit must stay quiet about is driven here rather than assumed.
	//
	// The third case is the one an ablation caught: a forgejo target with NO
	// auth_token at all is storable (UpdateTargets requires instance, repo and
	// secret_name, not auth_token) and has nothing to do with cross-owner
	// references. Reporting it would name the wrong problem on a row that has a
	// different one.
	mustEntry(t, env.h, queries, "entry-alice-own", env.alice, "alice-own-pat", "gitea_ALICE")
	for _, tc := range []struct {
		name    string
		targets string
	}{
		{"a forgejo target naming a token its configurer owns",
			`[{"type":"forgejo_secret","label":"ci","instance":"https://git.example",` +
				`"repo":"team/app","secret_name":"APP_KEY","auth_token":"alice-own-pat",` +
				`"configured_by":"` + env.alice + `"}]`},
		{"a forgejo target with no auth_token at all",
			`[{"type":"forgejo_secret","label":"ci","instance":"https://git.example",` +
				`"repo":"team/app","secret_name":"APP_KEY","configured_by":"` + env.alice + `"}]`},
		{"a webhook target, which references no other entry",
			`[{"type":"webhook","label":"deploy","webhook_url":"https://hooks.example/deploy",` +
				`"configured_by":"` + env.alice + `"}]`},
		{"a notify target",
			`[{"type":"notify","label":"tell the team","configured_by":"` + env.alice + `"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encOK, encErr := env.h.encryptColumn(tc.targets)
			if encErr != nil {
				t.Fatalf("encrypt: %v", encErr)
			}
			mustStoreRotationTargetsForTest(t, queries, env.appEntry, encOK)
			if again := env.h.AuditCrossOwnerAuthTokenTargets(context.Background()); len(again) != 0 {
				t.Fatalf("a healthy target was reported as broken: %v", again)
			}
		})
	}
}

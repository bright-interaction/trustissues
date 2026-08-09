package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/trustissues/internal/db"
)

// The offboarding matrix.
//
// "Removing someone ends their access" failed in TEN distinct places over
// thirteen audit rounds, and every one was a different VERB on the same object:
// remove, deliver, mint, access, fetch-as-service, leave, read-targets,
// resolve-by-name, validate, stale-panel-write. Closing one never cleaned its
// neighbourhood, because each surface asked the question its own way.
//
// Enumerating the SUBJECTS was never going to work. This enumerates the verbs.
//
// The must-be-true-before half is the whole design. Round 11 shipped a
// compare-and-swap that ALWAYS failed and its test passed, because the test only
// asserted the failure case. A probe that always denies would sail through the
// after half here; asserting it grants BEFORE the removal is what makes that
// impossible.

// accessProbe is one way of asking "does this user still have reach".
type accessProbe struct {
	name string
	// spend is true when this probe is about USING the credential rather than
	// merely seeing it. The residual recovery read a removed creator keeps means
	// read-only probes legitimately stay true after removal, so the matrix has
	// to know which is which rather than demanding everything go false.
	spend bool
	run   func(t *testing.T, e *revocationEnv, userID string) bool
}

func accessProbes() []accessProbe {
	return []accessProbe{
		{name: "grant.read", run: func(t *testing.T, e *revocationEnv, u string) bool {
			return e.h.grantFor(context.Background(), u, false, e.entryID).read
		}},
		{name: "grant.use", spend: true, run: func(t *testing.T, e *revocationEnv, u string) bool {
			return e.h.grantFor(context.Background(), u, false, e.entryID).use
		}},
		{name: "grant.manage", spend: true, run: func(t *testing.T, e *revocationEnv, u string) bool {
			return e.h.grantFor(context.Background(), u, false, e.entryID).manage
		}},
		{name: "resolve-by-name", spend: true, run: func(t *testing.T, e *revocationEnv, u string) bool {
			_, err := e.h.resolveVaultReferenceFor(context.Background(), e.entryName, u)
			return err == nil
		}},
		{name: "rotation-delivery", spend: true, run: func(t *testing.T, e *revocationEnv, u string) bool {
			return deliveryStillAuthorized(context.Background(), e.h, e.entryID, RotationTarget{
				Type: "webhook", WebhookURL: "https://sink.example.com/h", ConfiguredBy: u,
			}) == nil
		}},
		{name: "capability-mint", spend: true, run: func(t *testing.T, e *revocationEnv, u string) bool {
			// The vault is the name decryptor now: lookupSecretByName matches on
			// the DECRYPTED name, because the column is ciphertext since 00040.
			// A handler without one cannot resolve any name at all, which would
			// make this probe report "no access" for the wrong reason and pass.
			ch := &CapabilityHandler{db: e.h.db, vault: e.h}
			_, err := ch.lookupSecretByName(context.Background(), u, e.entryName)
			return err == nil
		}},
		{name: "read-targets", spend: true, run: func(t *testing.T, e *revocationEnv, u string) bool {
			rec := httptest.NewRecorder()
			e.h.GetTargets(rec, vaultAuthzRequest("GET", "/api/vault/"+e.entryID+"/targets", u, "user", e.entryID, ""))
			return rec.Code == http.StatusOK
		}},
		{name: "unlock-list", spend: true, run: func(t *testing.T, e *revocationEnv, u string) bool {
			rows, err := e.h.queries.ListAccessibleVaultEntriesWithSecrets(context.Background(),
				db.ListAccessibleVaultEntriesWithSecretsParams{ID: u,
					UserID: u, UserID_2: u})
			if err != nil {
				return false
			}
			for _, r := range rows {
				if r.ID == e.entryID {
					return true
				}
			}
			return false
		}},
	}
}

// revocationEnv is a shared collection entry plus the member about to lose it.
type revocationEnv struct {
	h         *VaultHandler
	queries   *db.Queries
	entryID   string
	entryName string
	collID    string
	manager   string
}

func newRevocationEnv(t *testing.T, memberEmail string, role string) (*revocationEnv, string) {
	t.Helper()
	h, queries := newCollectionAuthzEnv(t)

	manager := mustUser(t, queries, "revmgr-"+randomHex(4)+"@example.com", "user", "")
	member := mustUser(t, queries, memberEmail, "user", "")
	collID := "coll-" + randomHex(4)
	mustCollection(t, queries, collID, manager, map[string]string{
		manager: collRoleManager,
		member:  role,
	})
	entryID := "entry-" + randomHex(4)
	entryName := "Shared " + randomHex(4)
	// The MEMBER creates it, which is the shape that keeps their user_id on the
	// row forever and made several of the ten doors reachable.
	mustEntry(t, h, queries, entryID, member, entryName, "SECRET-VALUE")
	placeInCollection(t, queries, entryID, collID)

	return &revocationEnv{
		h: h, queries: queries, entryID: entryID, entryName: entryName,
		collID: collID, manager: manager,
	}, member
}

// TestRemovalEndsEverySpendPath drives every probe through every removal verb.
func TestRemovalEndsEverySpendPath(t *testing.T) {
	verbs := []struct {
		name   string
		remove func(t *testing.T, e *revocationEnv, member string)
	}{
		{"remove from collection", func(t *testing.T, e *revocationEnv, m string) {
			if _, err := e.queries.RemoveCollectionMember(context.Background(),
				db.RemoveCollectionMemberParams{CollectionID: e.collID, UserID: m}); err != nil {
				t.Fatalf("remove: %v", err)
			}
		}},
		{"disable the account", func(t *testing.T, e *revocationEnv, m string) {
			if _, err := e.queries.SetUserDisabled(context.Background(),
				db.SetUserDisabledParams{Disabled: 1, ID: m}); err != nil {
				t.Fatalf("disable: %v", err)
			}
		}},
		{"delete the account", func(t *testing.T, e *revocationEnv, m string) {
			if _, err := e.queries.DeleteUser(context.Background(), m); err != nil {
				t.Fatalf("delete: %v", err)
			}
		}},
	}

	for _, v := range verbs {
		v := v
		t.Run(v.name, func(t *testing.T) {
			env, member := newRevocationEnv(t, "rev-"+randomHex(4)+"@example.com", collRoleEditor)

			// BEFORE: every probe must GRANT. This half is what makes a probe
			// that always denies fail, which is precisely the flaw that let a
			// permanently-failing compare-and-swap ship green in round 11.
			for _, p := range accessProbes() {
				if !p.run(t, env, member) {
					t.Fatalf("ABORT: probe %q denied an ACTIVE editor, so the after-half below "+
						"would pass for the wrong reason and this verb would be untested", p.name)
				}
			}

			v.remove(t, env, member)

			// AFTER: every SPEND probe must deny. Read-only probes may stay true,
			// because a removed creator deliberately keeps a recovery read.
			for _, p := range accessProbes() {
				got := p.run(t, env, member)
				if p.spend && got {
					t.Errorf("after %q, probe %q still grants: the credential can still be spent "+
						"by someone whose access was revoked", v.name, p.name)
				}
			}
		})
	}
}

// TestResidualReadIsReadOnly pins the one deliberate exception, so a future
// tightening does not quietly destroy a creator's ability to recover their own
// secret, and a future loosening does not turn it back into a spend right.
func TestResidualReadIsReadOnly(t *testing.T) {
	env, member := newRevocationEnv(t, "residual-"+randomHex(4)+"@example.com", collRoleEditor)
	ctx := context.Background()

	if _, err := env.queries.RemoveCollectionMember(ctx,
		db.RemoveCollectionMemberParams{CollectionID: env.collID, UserID: member}); err != nil {
		t.Fatalf("remove: %v", err)
	}

	g := env.h.grantFor(ctx, member, false, env.entryID)
	if !g.read {
		t.Error("the creator lost their recovery read; a colleague could move an entry into a " +
			"collection they are not in and take their own secret from them permanently")
	}
	if g.use {
		t.Error("the recovery read carries USE, so a removed member can still spend the credential")
	}
	if g.manage {
		t.Error("the recovery read carries MANAGE, so a removed member can still modify the entry")
	}
}

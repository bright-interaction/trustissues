package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/middleware"
	"github.com/bright-interaction/trustissues/internal/privateaccess"
)

func createIntoCollectionRequest(userID, collectionID, name string) *http.Request {
	body := fmt.Sprintf(`{"name":%q,"value":"destination-secret","collection_id":%q}`, name, collectionID)
	return vaultAuthzRequest(http.MethodPost, "/api/vault", userID, "user", "", body)
}

func assertDestinationResponsesEqual(t *testing.T, label string,
	left, right collectionProbeResponse, wantCode int) {
	t.Helper()
	if left.code != wantCode || !reflect.DeepEqual(left, right) {
		t.Fatalf("%s responses differ or have wrong status\nleft:  %#v\nright: %#v\nwant HTTP %d",
			label, left, right, wantCode)
	}
}

// TestVaultDestinationPolicyIsDisclosedOnlyAfterWriteAuthority covers both
// doors that put a secret in a collection. Missing and fully_private are exact
// 404 twins; outsiders see the same ordinary no-write 403 for standard and
// sensitive_private; only an authorized writer gets the actionable ingress
// code for sensitive_private.
func TestVaultDestinationPolicyIsDisclosedOnlyAfterWriteAuthority(t *testing.T) {
	vault, queries := newCollectionAuthzEnv(t)
	manager := mustUser(t, queries, "destination-manager@example.com", "user", "")
	outsider := mustUser(t, queries, "destination-outsider@example.com", "user", "")
	const (
		standardID  = "destination-standard"
		sensitiveID = "destination-sensitive"
		fullyID     = "destination-fully"
		missingID   = "destination-missing"
	)
	for _, collectionID := range []string{standardID, sensitiveID, fullyID} {
		mustCollection(t, queries, collectionID, manager, map[string]string{manager: collRoleManager})
	}
	setCollectionPrivateAccessPolicy(t, queries, sensitiveID, string(privateaccess.PolicySensitivePrivate))
	setCollectionPrivateAccessPolicy(t, queries, fullyID, string(privateaccess.PolicyFullyPrivate))

	t.Run("create", func(t *testing.T) {
		probe := func(collectionID, actor, name string) collectionProbeResponse {
			return runCollectionProbe(vault.Create, createIntoCollectionRequest(actor, collectionID, name))
		}
		assertDestinationResponsesEqual(t, "create missing/fully-private",
			probe(missingID, outsider, "create-missing"),
			probe(fullyID, outsider, "create-fully"), http.StatusNotFound)
		assertDestinationResponsesEqual(t, "create outsider standard/sensitive",
			probe(standardID, outsider, "create-standard"),
			probe(sensitiveID, outsider, "create-sensitive"), http.StatusForbidden)

		authorized := probe(sensitiveID, manager, "create-authorized")
		if authorized.code != http.StatusForbidden ||
			!strings.Contains(authorized.body, middleware.PrivateIngressRequiredCode) {
			t.Fatalf("authorized sensitive create = HTTP %d %s", authorized.code, authorized.body)
		}
	})

	t.Run("move", func(t *testing.T) {
		const outsiderEntry = "destination-outsider-entry"
		mustEntry(t, vault, queries, outsiderEntry, outsider, "outsider movable", "value")
		probe := func(collectionID string) collectionProbeResponse {
			return runCollectionProbe(vault.MoveToCollection,
				moveRequest(outsider, "user", outsiderEntry, `{"collection_id":"`+collectionID+`"}`))
		}
		assertDestinationResponsesEqual(t, "move missing/fully-private",
			probe(missingID), probe(fullyID), http.StatusNotFound)
		assertDestinationResponsesEqual(t, "move outsider standard/sensitive",
			probe(standardID), probe(sensitiveID), http.StatusForbidden)
		if got := entryCollection(t, queries, outsiderEntry); got != "" {
			t.Fatalf("denied outsider move changed collection to %q", got)
		}

		const managerEntry = "destination-manager-entry"
		mustEntry(t, vault, queries, managerEntry, manager, "manager movable", "value")
		authorized := runCollectionProbe(vault.MoveToCollection,
			moveRequest(manager, "user", managerEntry, `{"collection_id":"`+sensitiveID+`"}`))
		if authorized.code != http.StatusForbidden ||
			!strings.Contains(authorized.body, middleware.PrivateIngressRequiredCode) {
			t.Fatalf("authorized sensitive move = HTTP %d %s", authorized.code, authorized.body)
		}
		if got := entryCollection(t, queries, managerEntry); got != "" {
			t.Fatalf("refused public sensitive move changed collection to %q", got)
		}
	})
}

func stageSensitiveOutsiderTransition(t *testing.T, qtx *db.Queries,
	collectionID, userID string) {
	t.Helper()
	if err := qtx.UpdateCollection(context.Background(), db.UpdateCollectionParams{
		Name: collectionID, Description: "",
		PrivateAccessPolicy: sql.NullString{String: string(privateaccess.PolicySensitivePrivate), Valid: true},
		ID:                  collectionID,
	}); err != nil {
		t.Fatalf("stage sensitive promotion: %v", err)
	}
	if _, err := qtx.RemoveCollectionMember(context.Background(), db.RemoveCollectionMemberParams{
		CollectionID: collectionID, UserID: userID,
	}); err != nil {
		t.Fatalf("stage membership removal: %v", err)
	}
}

// TestVaultDestinationUsesOnePolicyAndMembershipSnapshot exercises the old
// check/use boundary directly. A competing transaction atomically promotes a
// destination and removes the writer while create/move wait for SQLite's write
// lock. Once committed, neither route may use the stale writer role or disclose
// the newly sensitive policy; both must match an ordinary standard outsider.
func TestVaultDestinationUsesOnePolicyAndMembershipSnapshot(t *testing.T) {
	for _, operation := range []string{"create", "move"} {
		t.Run(operation, func(t *testing.T) {
			vault, queries := newCollectionAuthzEnv(t)
			manager := mustUser(t, queries, operation+"-snapshot-manager@example.com", "user", "")
			actor := mustUser(t, queries, operation+"-snapshot-actor@example.com", "user", "")
			const (
				destinationID = "snapshot-destination"
				baselineID    = "snapshot-baseline"
			)
			mustCollection(t, queries, destinationID, manager, map[string]string{
				manager: collRoleManager,
				actor:   collRoleEditor,
			})
			mustCollection(t, queries, baselineID, manager, map[string]string{manager: collRoleManager})

			var start func(string) <-chan *httptest.ResponseRecorder
			var baseline collectionProbeResponse
			if operation == "create" {
				baseline = runCollectionProbe(vault.Create,
					createIntoCollectionRequest(actor, baselineID, "snapshot-baseline-create"))
				start = func(collectionID string) <-chan *httptest.ResponseRecorder {
					responses := make(chan *httptest.ResponseRecorder, 1)
					go func() {
						recorder := httptest.NewRecorder()
						vault.Create(recorder, createIntoCollectionRequest(actor, collectionID, "snapshot-raced-create"))
						responses <- recorder
					}()
					return responses
				}
			} else {
				const entryID = "snapshot-move-entry"
				mustEntry(t, vault, queries, entryID, actor, "snapshot movable", "value")
				baseline = runCollectionProbe(vault.MoveToCollection,
					moveRequest(actor, "user", entryID, `{"collection_id":"`+baselineID+`"}`))
				start = func(collectionID string) <-chan *httptest.ResponseRecorder {
					responses := make(chan *httptest.ResponseRecorder, 1)
					go func() {
						recorder := httptest.NewRecorder()
						vault.MoveToCollection(recorder,
							moveRequest(actor, "user", entryID, `{"collection_id":"`+collectionID+`"}`))
						responses <- recorder
					}()
					return responses
				}
			}
			if baseline.code != http.StatusForbidden ||
				strings.Contains(baseline.body, middleware.PrivateIngressRequiredCode) {
				t.Fatalf("ordinary outsider baseline = HTTP %d %s", baseline.code, baseline.body)
			}

			blocker, err := vault.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatalf("begin blocking transaction: %v", err)
			}
			defer blocker.Rollback() //nolint:errcheck
			stageSensitiveOutsiderTransition(t, queries.WithTx(blocker), destinationID, actor)

			responses := start(destinationID)
			select {
			case early := <-responses:
				t.Fatalf("request escaped the blocking authorization snapshot: HTTP %d %s", early.Code, early.Body.String())
			case <-time.After(100 * time.Millisecond):
			}
			if err := blocker.Commit(); err != nil {
				t.Fatalf("commit concurrent policy/membership change: %v", err)
			}
			raced := waitForCollectionResponse(t, responses)
			got := collectionProbeResponse{
				code: raced.Code, body: raced.Body.String(), header: raced.Result().Header.Clone(),
			}
			assertDestinationResponsesEqual(t, operation+" race/outsider baseline", got, baseline, http.StatusForbidden)
			if strings.Contains(got.body, middleware.PrivateIngressRequiredCode) {
				t.Fatalf("removed writer learned sensitive policy after race: %s", got.body)
			}
			if operation == "create" {
				count, err := queries.CountVaultEntriesForUser(context.Background(), actor)
				if err != nil || count != 0 {
					t.Fatalf("denied raced create left %d actor entries, err=%v", count, err)
				}
			} else if gotCollection := entryCollection(t, queries, "snapshot-move-entry"); gotCollection != "" {
				t.Fatalf("denied raced move changed collection to %q", gotCollection)
			}
		})
	}
}

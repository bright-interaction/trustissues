-- +goose Up
-- +goose StatementBegin

-- GET /api/collections/{id}/members was a user-directory oracle for anyone who
-- can create a collection, which is every authenticated role including
-- vault_only (the role /api/invitations/redeem hands out over a PUBLIC
-- endpoint).
--
-- POST /api/collections/{id}/members answers identically whether or not the
-- address matches an account, and that was carefully done. But it only wrote a
-- membership row when GetUserByEmail HIT, so the members list answered the
-- question one call later: a pending row appeared (carrying user_id, email and
-- the real display name) exactly when the address had an account, and was
-- simply absent when it did not. Create a throwaway collection, probe an
-- address, list the members. That is how one client of a shared instance
-- harvests another client's people, names and user ids, and it is the blocker
-- against inviting external clients into one instance at all.
--
-- The invitation is now recorded by the EMAIL the inviter typed, whether or not
-- it resolves to an account, so a pending seat looks identical either way.
-- collection_members keeps holding the pending row for addresses that DO have
-- an account, because acceptance still has to attach to a user id; the members
-- list just stops reading identity out of it until the invite is accepted.
CREATE TABLE collection_invitations (
  collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  -- Canonicalized by the handler to a bare, NFC-normalized, lower-cased
  -- addr-spec, the same representation AddMember applies before
  -- GetUserByEmail, so equivalent spellings update the seat instead of adding
  -- a second one.
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('viewer', 'editor', 'manager')),
  invited_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (collection_id, email)
);

-- Backfill the seats that are pending right now, so upgrading does not drop an
-- invitation somebody is still waiting on (and does not make live pending
-- invites vanish from the members list the moment this ships).
INSERT INTO collection_invitations (collection_id, email, role, invited_by, created_at)
SELECT cm.collection_id, lower(u.email), cm.role, cm.invited_by, cm.added_at
FROM collection_members cm
JOIN users u ON u.id = cm.user_id
WHERE cm.accepted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS collection_invitations;
-- +goose StatementEnd

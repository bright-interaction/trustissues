#!/usr/bin/env bash
# LIVE-INSTANCE SKEPTIC RE-RUN.
#
# The one that died on an API connection error last round. It asks the questions
# a unit test cannot: does a REAL binary, against a REAL sqlite file, still open
# data that a DIFFERENT binary wrote. That is the risk this round's change
# creates, because every AES-GCM open in the vault-key family moved into a new
# package.
#
# The order matters: the OLD binary writes, the NEW binary reads.
set -u

# OLD_SRC is a checkout of the binary that WROTE the data, NEW_SRC the one that
# must read it. Point OLD_SRC at whatever version you are upgrading from.
OLD_SRC="${OLD_SRC:-/tmp/ti-iso-exit3-base/trustissues}"
NEW_SRC="${NEW_SRC:-$(cd "$(dirname "$0")/.." && pwd)}"
WORK="$(mktemp -d)"
DATA="$WORK/data"
mkdir -p "$DATA"

VK="live-skeptic-vault-key-000000000000"
JW="live-skeptic-jwt-secret-00000000000000"
PORT=18731
BASE="http://127.0.0.1:$PORT"

pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }

echo "== building both binaries =="
( cd "$OLD_SRC" && go build -o "$WORK/ti-old" ./cmd/server ) || { echo "old build failed"; exit 1; }
( cd "$NEW_SRC" && go build -o "$WORK/ti-new" ./cmd/server ) || { echo "new build failed"; exit 1; }
echo "  old: $(shasum -a256 "$WORK/ti-old" | cut -c1-16)  new: $(shasum -a256 "$WORK/ti-new" | cut -c1-16)"

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

stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; for _ in $(seq 1 40); do curl -fsS "$BASE/health" >/dev/null 2>&1 || return 0; sleep 0.25; done; return 1; }

echo
echo "== phase 1: the OLD binary (base 61cb33d3) creates the data =="
PID=$(start "$WORK/ti-old" "$VK" "$WORK/old.log")
if ! wait_up; then echo "old binary did not come up:"; cat "$WORK/old.log"; exit 1; fi

CJ="$WORK/cookies"
curl -fsS -c "$CJ" -X POST "$BASE/api/auth/register" -H 'Content-Type: application/json' \
  -d '{"email":"live-admin@example.com","password":"correct-horse-battery-staple-1","name":"Live Admin"}' \
  >"$WORK/register.json" 2>&1 || { echo "register failed"; cat "$WORK/register.json" "$WORK/old.log"; exit 1; }
ok "first-run register on the old binary"

# A vault entry with every at-rest-encrypted metadata column populated, plus a
# secret:true custom field, so the read-back below exercises the whole family.
curl -fsS -b "$CJ" -c "$CJ" -X POST "$BASE/api/vault" -H 'Content-Type: application/json' \
  -H "Origin: $BASE" -d '{
    "name":"live-stripe","value":"sk_live_LIVE_SKEPTIC_VALUE","url":"https://dashboard.stripe.com",
    "alias_url":"https://stripe.com","username":"ops@example.com","category":"api_key",
    "notes":"written by the OLD binary",
    "custom_fields":[{"label":"recovery pin","value":"PIN-4821","secret":true}]
  }' >"$WORK/entry.json" 2>&1 || { echo "create entry failed"; cat "$WORK/entry.json"; exit 1; }
ENTRY_ID=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$WORK/entry.json" | head -1)
[ -n "$ENTRY_ID" ] && ok "vault entry created by the old binary ($ENTRY_ID)" || bad "no entry id"

# An invitation: THE column this round is about.
curl -fsS -b "$CJ" -c "$CJ" -X POST "$BASE/api/admin/invitations" -H 'Content-Type: application/json' \
  -H "Origin: $BASE" -d '{"email":"invitee@example.com","name":"Invitee","target_role":"vault_only"}' \
  >"$WORK/invite.json" 2>&1 || { echo "create invite failed"; cat "$WORK/invite.json"; exit 1; }
INVITE_CODE=$(sed -n 's/.*"code":"\([^"]*\)".*/\1/p' "$WORK/invite.json" | head -1)
[ -n "$INVITE_CODE" ] && ok "invitation created by the old binary (code $INVITE_CODE)" || bad "no invite code"

stop "$PID"
DBFILE=$(find "$DATA" -name "*.db" | head -1)
echo "  old binary stopped; sqlite file is $DBFILE ($(du -h "$DBFILE" | cut -f1))"

# Prove the invite code really is CIPHERTEXT at rest, or the read-back below
# proves nothing about decryption.
if command -v sqlite3 >/dev/null 2>&1; then
  STORED=$(sqlite3 "$DBFILE" "SELECT code FROM invitations LIMIT 1;")
  case "$STORED" in
    enc:v1:*) ok "invitations.code is sealed at rest (${STORED:0:14}...)" ;;
    *) bad "invitations.code is NOT sealed at rest: $STORED" ;;
  esac
  NOTES=$(sqlite3 "$DBFILE" "SELECT notes FROM vault_entries LIMIT 1;")
  case "$NOTES" in
    enc:v1:*) ok "vault_entries.notes is sealed at rest" ;;
    *) bad "vault_entries.notes is NOT sealed at rest: $NOTES" ;;
  esac
else
  echo "  note: sqlite3 not available, skipping the at-rest ciphertext check"
fi

echo
echo "== phase 2: the NEW binary reads what the old one wrote =="
PID=$(start "$WORK/ti-new" "$VK" "$WORK/new.log")
if ! wait_up; then echo "NEW binary did not come up on data the old one wrote:"; cat "$WORK/new.log"; exit 1; fi
ok "the new binary booted on a database the old binary wrote (the boot key gate accepted it)"

CJ2="$WORK/cookies2"
curl -fsS -c "$CJ2" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
  -H "Origin: $BASE" -d '{"email":"live-admin@example.com","password":"correct-horse-battery-staple-1"}' \
  >"$WORK/login.json" 2>&1 || { echo "login failed"; cat "$WORK/login.json"; exit 1; }
ok "login against the new binary"

curl -fsS -b "$CJ2" "$BASE/api/vault" >"$WORK/list.json" 2>&1
for want in 'https://dashboard.stripe.com' 'ops@example.com' 'written by the OLD binary' 'live-stripe'; do
  if grep -q "$want" "$WORK/list.json"; then ok "the new binary decrypted a column the old one sealed: $want"
  else bad "the new binary could NOT read $want (at-rest format regression)"; fi
done

curl -fsS -b "$CJ2" "$BASE/api/admin/invitations" >"$WORK/invites.json" 2>&1
if grep -q "$INVITE_CODE" "$WORK/invites.json"; then
  ok "the new binary decrypted invitations.code through the declared door (the fifth door, routed)"
else
  bad "the new binary could NOT read invitations.code: $(head -c 300 "$WORK/invites.json")"
fi

# THE CLASSIFICATION'S PREMISE, on a live server. invitations.code is classified
# instance-owned because both of its destinations are admin-only. Check it.
curl -fsS -b "$CJ2" -c "$CJ2" -X POST "$BASE/api/invitations/redeem" -H 'Content-Type: application/json' \
  -H "Origin: $BASE" -d "{\"code\":\"$INVITE_CODE\",\"password\":\"another-correct-horse-battery-1\",\"name\":\"Invitee\"}" \
  >"$WORK/redeem.json" 2>&1
if grep -q '"api_key"' "$WORK/redeem.json" || grep -q '"user"' "$WORK/redeem.json"; then
  ok "the invitation the OLD binary sealed still redeems against the NEW one"
else
  bad "redeem failed: $(head -c 300 "$WORK/redeem.json")"
fi

CJ3="$WORK/cookies3"
curl -fsS -c "$CJ3" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
  -H "Origin: $BASE" -d '{"email":"invitee@example.com","password":"another-correct-horse-battery-1"}' \
  >"$WORK/login3.json" 2>&1
CODE=$(curl -s -o "$WORK/vo.json" -w '%{http_code}' -b "$CJ3" "$BASE/api/admin/invitations")
if [ "$CODE" = "403" ] || [ "$CODE" = "401" ]; then
  ok "a vault_only member is refused GET /api/admin/invitations ($CODE), so the instance-owned ruling holds live"
else
  bad "a vault_only member got $CODE from GET /api/admin/invitations: $(head -c 200 "$WORK/vo.json")"
fi

stop "$PID"

echo
echo "== phase 3: the boot key gate still refuses a WRONG key =="
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
echo "== phase 4: the correct key still works after the refusal =="
PID=$(start "$WORK/ti-new" "$VK" "$WORK/again.log")
if wait_up; then ok "the correct key still boots (the refusal did not re-seal the sentinel)"; else bad "the correct key no longer boots"; fi
stop "$PID"

echo
echo "RESULT: $pass passed, $fail failed"
rm -rf "$WORK"
[ "$fail" -eq 0 ]

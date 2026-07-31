#!/usr/bin/env bash
#
# test-backup-restore.sh - prove backup.sh and restore.sh refuse the cases that
# cost you the vault.
#
# These two scripts had ZERO tests through sixteen audit rounds, while being the
# only path in the product with no second copy of the data. Every case below is
# a real confirmed finding: each one plants the failure and asserts the refusal,
# because a guard nobody watched refuse is a guard nobody knows works.
#
# Usage: ./scripts/test-backup-restore.sh
# Exit: 0 all cases passed, 1 a case failed.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

PASS=0
FAIL=0

ok()   { echo "  ok   $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 is required to run these tests" >&2
  exit 1
fi

# A minimal but genuine Trustissues-shaped database.
make_db() {
  rm -f "$1"
  sqlite3 "$1" "CREATE TABLE vault_entries (id TEXT PRIMARY KEY, name TEXT);
                INSERT INTO vault_entries VALUES ('e1','prod db password');"
}

echo "backup.sh"

# 1. A completed backup is verified and lands at the final name, with no .part left.
DATA="${WORK}/data"; mkdir -p "${DATA}"
make_db "${DATA}/trustissues.db"
DEST="${WORK}/backups"
TRUSTISSUES_DATA_DIR="${DATA}" "${HERE}/backup.sh" "${DEST}" >/dev/null 2>&1
SNAP="$(find "${DEST}" -name 'trustissues-*.db' ! -name '*.part' | head -1)"
if [ -n "${SNAP}" ] && [ -z "$(find "${DEST}" -name '*.part')" ]; then
  ok "a good backup lands at the final name and leaves no .part"
else
  bad "expected exactly one finished snapshot and no .part file"
fi

# 2. The snapshot is restorable, not merely present. This is the property the
#    whole feature exists for and nothing asserted it.
if [ -n "${SNAP}" ] && [ "$(sqlite3 "${SNAP}" 'PRAGMA integrity_check;')" = "ok" ] \
   && [ "$(sqlite3 "${SNAP}" "SELECT name FROM vault_entries WHERE id='e1';")" = "prod db password" ]; then
  ok "the snapshot passes integrity_check and carries the data"
else
  bad "the snapshot is not a readable copy of the source"
fi

echo "restore.sh"

# 3. A truncated snapshot must be refused. It keeps a valid 16-byte header, so
#    the old filetype check passed it and the live database was destroyed.
make_db "${WORK}/good.db"
TRUNC="${WORK}/truncated.db"
head -c 200 "${WORK}/good.db" > "${TRUNC}"
head -c 16 "${TRUNC}" | grep -q "SQLite format 3" \
  || { echo "fixture broken: truncated file lost its header"; exit 1; }
DATA2="${WORK}/data2"; mkdir -p "${DATA2}"
make_db "${DATA2}/trustissues.db"
if TRUSTISSUES_DATA_DIR="${DATA2}" TRUSTISSUES_RESTORE_FORCE=1 \
     "${HERE}/restore.sh" "${TRUNC}" >/dev/null 2>&1; then
  bad "a truncated snapshot was RESTORED over the live database"
else
  if [ "$(sqlite3 "${DATA2}/trustissues.db" "SELECT name FROM vault_entries WHERE id='e1';")" = "prod db password" ]; then
    ok "a truncated snapshot is refused and the live database is untouched"
  else
    bad "the restore was refused but the live database was damaged anyway"
  fi
fi

# 4. A structurally valid database from some OTHER product must be refused:
#    same lost-vault outcome, and the header check cannot tell them apart.
OTHER="${WORK}/other.db"
sqlite3 "${OTHER}" "CREATE TABLE songs (id TEXT); INSERT INTO songs VALUES ('x');"
if TRUSTISSUES_DATA_DIR="${DATA2}" TRUSTISSUES_RESTORE_FORCE=1 \
     "${HERE}/restore.sh" "${OTHER}" >/dev/null 2>&1; then
  bad "a foreign SQLite database was restored as if it were a Trustissues vault"
else
  ok "a foreign SQLite database is refused"
fi

# 5. The replaced database must be KEPT. The restore is the one operation with
#    no second copy, so a wrong-snapshot restore has to stay reversible.
DATA3="${WORK}/data3"; mkdir -p "${DATA3}"
make_db "${DATA3}/trustissues.db"
sqlite3 "${DATA3}/trustissues.db" "UPDATE vault_entries SET name='LIVE VALUE' WHERE id='e1';"
make_db "${WORK}/incoming.db"
TRUSTISSUES_DATA_DIR="${DATA3}" TRUSTISSUES_RESTORE_FORCE=1 \
  "${HERE}/restore.sh" "${WORK}/incoming.db" >/dev/null 2>&1
ASIDE="$(find "${DATA3}" -name 'trustissues.db.replaced-*' ! -name '*-wal' ! -name '*-shm' | head -1)"
if [ -n "${ASIDE}" ] && [ "$(sqlite3 "${ASIDE}" "SELECT name FROM vault_entries WHERE id='e1';")" = "LIVE VALUE" ]; then
  ok "the replaced database is kept aside and still readable"
else
  bad "the previous database was destroyed with no copy kept"
fi

# 6. A restore on an idle database must SUCCEED.
#
# The refusal cases above are only half the contract. The open-file guard used
# to be `command -v fuser && fuser "$DB"`, and macOS fuser exits 0 with an empty
# holder list, so on every macOS host that check reported "still running" and
# native restore was impossible. A guard that refuses everything passes every
# refusal test ever written, which is why this case exists.
DATA4="${WORK}/data4"; mkdir -p "${DATA4}"
make_db "${DATA4}/trustissues.db"
make_db "${WORK}/incoming4.db"
if TRUSTISSUES_DATA_DIR="${DATA4}" "${HERE}/restore.sh" "${WORK}/incoming4.db" >/dev/null 2>&1; then
  ok "a restore against an idle database succeeds"
else
  bad "a restore was refused although nothing holds the database open"
fi

# 7. The restored content must actually be the snapshot's.
if [ "$(sqlite3 "${DATA3}/trustissues.db" "SELECT name FROM vault_entries WHERE id='e1';")" = "prod db password" ]; then
  ok "the restored database holds the snapshot's data"
else
  bad "the restore did not put the snapshot in place"
fi

echo
echo "passed ${PASS}, failed ${FAIL}"
[ "${FAIL}" -eq 0 ]

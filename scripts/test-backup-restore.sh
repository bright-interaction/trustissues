#!/usr/bin/env bash
#
# test-backup-restore.sh - prove the backup path refuses the cases that cost you
# the vault, keeps the right files, and can actually restore.
#
# backup.sh and restore.sh had ZERO tests through sixteen audit rounds, while
# being the only path in the product with no second copy of the data. Every case
# below is a real confirmed finding or a real estate incident: each one plants
# the failure and asserts the refusal, because a guard nobody watched refuse is a
# guard nobody knows works.
#
# Covers scripts/backup.sh, scripts/restore.sh, scripts/prune-backups.sh,
# scripts/restore-drill.sh and the systemd units in deploy/systemd/.
#
# Usage: ./scripts/test-backup-restore.sh
# Exit: 0 all cases passed, 1 a case failed.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$(cd "${HERE}/../deploy" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

PASS=0
FAIL=0

ok()   { echo "  ok   $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }

# Setup commands below end in `|| true` on purpose. This script runs under
# `set -e`, so a bare `prune-backups.sh ...` that exits non-zero during FIXTURE
# SETUP kills the whole run before the summary line, and the output then looks
# like a crash rather than like a failing case. Found while ablating the octal
# guard in snapshot-lib.sh: the suite aborted mid-way and printed no totals at
# all, which is exactly the shape of "the tests did not catch it". The
# assertion after each setup step is what decides pass or fail; the setup step
# itself must never be the thing that ends the run.

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

# A snapshot named exactly the way backup.sh names them, at a chosen stamp.
make_snapshot() {
  make_db "$1/trustissues-$2.db"
}

# The set of snapshot basenames in a directory, sorted, newline separated.
snapshot_names() {
  find "$1" -maxdepth 1 -name 'trustissues-*.db' -exec basename {} \; | LC_ALL=C sort
}

# A stamp N days before today, in backup.sh's format. Used so freshness-sensitive
# cases do not go stale the day after they are written: a fixture with a
# hardcoded 2026 date would start failing the drill's max-age check on its own
# schedule, and somebody would "fix" it by deleting the check.
stamp_days_ago() {
  if date --version >/dev/null 2>&1; then
    date -u -d "$1 days ago" +%Y%m%dT%H%M%SZ      # GNU coreutils
  else
    date -u -v-"$1"d +%Y%m%dT%H%M%SZ              # BSD / macOS
  fi
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

echo "backup.sh destination guards"

# 8. The backup destination must never be the live data directory.
#
# It reads as harmless (trustissues-<stamp>.db never collides with
# trustissues.db) right up to the point retention runs, and then prune-backups.sh
# is an automated `rm` loose inside the directory holding the only live copy of
# the vault. There is no scenario where this is what the operator meant.
DATA5="${WORK}/data5"; mkdir -p "${DATA5}"
make_db "${DATA5}/trustissues.db"
if TRUSTISSUES_DATA_DIR="${DATA5}" "${HERE}/backup.sh" "${DATA5}" >/dev/null 2>&1; then
  bad "backup.sh wrote snapshots INTO the live data directory"
else
  ok "backup.sh refuses a destination that is the live data directory"
fi

# 9. Sharing a filesystem is allowed but must be said out loud. The shipped
#    Compose deploy makes "point it at a subdirectory of the data volume" the
#    obvious wrong move, and a silent success there is how one full disk ends up
#    destroying the database and every backup of it in the same instant.
OUT9="$(TRUSTISSUES_DATA_DIR="${DATA5}" "${HERE}/backup.sh" "${WORK}/backups9" 2>&1 || true)"
if printf '%s' "${OUT9}" | grep -q "same filesystem"; then
  ok "backup.sh warns when the backups share a filesystem with the database"
else
  bad "backup.sh said nothing about backups and database sharing a filesystem"
fi

# 10. The destination is readable from the environment. A systemd unit
#     configures itself from an EnvironmentFile and cannot pass positional
#     arguments without baking the path into the shipped unit file, so without
#     this the unit could not be configured at all.
DEST10="${WORK}/backups10"
TRUSTISSUES_DATA_DIR="${DATA5}" TRUSTISSUES_BACKUP_DIR="${DEST10}" \
  "${HERE}/backup.sh" >/dev/null 2>&1 || true
if [ -n "$(find "${DEST10}" -name 'trustissues-*.db' 2>/dev/null | head -1)" ]; then
  ok "backup.sh takes its destination from TRUSTISSUES_BACKUP_DIR"
else
  bad "TRUSTISSUES_BACKUP_DIR was ignored, so the systemd unit cannot be configured"
fi

echo "prune-backups.sh"

# 11. Retention keeps EXACTLY the right files.
#
# The dates are chosen so the answer is checkable by hand rather than by
# re-running the algorithm. With keep-daily=3 and keep-weekly=2, walking newest
# first:
#   08-02T10  new day  -> daily 1/3 KEEP, and it opens week [07-30..08-05]
#   08-02T02  same day as the one above, same week            -> DELETE
#   08-01T10  new day  -> daily 2/3 KEEP
#   07-31T10  new day  -> daily 3/3 KEEP
#   07-30T10  new day but the daily budget is spent, week already kept -> DELETE
#   07-24T10  week [07-23..07-29] is new -> weekly 2/2 KEEP
#   07-17T10  both budgets spent                              -> DELETE
#   07-10T10  both budgets spent                              -> DELETE
# The 7-day blocks run Thursday to Wednesday because they are counted from the
# epoch; that is documented in snapshot-lib.sh and is what these dates encode.
PD="${WORK}/prune-dated"; mkdir -p "${PD}"
for s in 20260802T100000Z 20260802T020000Z 20260801T100000Z 20260731T100000Z \
         20260730T100000Z 20260724T100000Z 20260717T100000Z 20260710T100000Z; do
  make_snapshot "${PD}" "${s}"
done
# Files that are not snapshots must be invisible to retention: an operator's
# own notes, an age-wrapped copy, a database from something else entirely.
touch "${PD}/notes.txt" "${PD}/trustissues-old.db" "${PD}/random.db"
TRUSTISSUES_BACKUP_KEEP_DAILY=3 TRUSTISSUES_BACKUP_KEEP_WEEKLY=2 \
  "${HERE}/prune-backups.sh" "${PD}" >/dev/null 2>&1 || true
EXPECT_KEPT="trustissues-20260724T100000Z.db
trustissues-20260731T100000Z.db
trustissues-20260801T100000Z.db
trustissues-20260802T100000Z.db"
GOT_KEPT="$(snapshot_names "${PD}" | grep -v '^trustissues-old.db$' || true)"
if [ "${GOT_KEPT}" = "${EXPECT_KEPT}" ]; then
  ok "retention keeps the newest of each of the last N days and M weeks, and nothing else"
else
  bad "retention kept the wrong set:
got:
${GOT_KEPT}
want:
${EXPECT_KEPT}"
fi
if [ -f "${PD}/notes.txt" ] && [ -f "${PD}/trustissues-old.db" ] && [ -f "${PD}/random.db" ]; then
  ok "retention leaves files that are not snapshots alone"
else
  bad "retention deleted a file it did not write"
fi

# 12. --dry-run must not delete. Operators reach for it precisely when they are
#     unsure, which is the worst moment for it to be a no-op alias for the real
#     thing.
PDR="${WORK}/prune-dry"; mkdir -p "${PDR}"
for s in 20260802T100000Z 20260701T100000Z 20260601T100000Z; do
  make_snapshot "${PDR}" "${s}"
done
BEFORE="$(snapshot_names "${PDR}")"
TRUSTISSUES_BACKUP_KEEP_DAILY=1 TRUSTISSUES_BACKUP_KEEP_WEEKLY=1 \
  "${HERE}/prune-backups.sh" --dry-run "${PDR}" >/dev/null 2>&1 || true
if [ "$(snapshot_names "${PDR}")" = "${BEFORE}" ]; then
  ok "--dry-run deletes nothing"
else
  bad "--dry-run actually deleted snapshots"
fi

# 13. A policy that keeps nothing is refused, not obeyed. An unset variable in
#     an EnvironmentFile expands to the empty string and a typo expands to 0;
#     both are well-formed instructions to delete every backup that exists.
PZ="${WORK}/prune-zero"; mkdir -p "${PZ}"
make_snapshot "${PZ}" "20260802T100000Z"
if TRUSTISSUES_BACKUP_KEEP_DAILY=0 TRUSTISSUES_BACKUP_KEEP_WEEKLY=0 \
     "${HERE}/prune-backups.sh" "${PZ}" >/dev/null 2>&1; then
  bad "a keep-nothing retention policy was accepted"
elif [ -f "${PZ}/trustissues-20260802T100000Z.db" ]; then
  ok "a keep-nothing retention policy is refused and nothing is deleted"
else
  bad "the keep-nothing policy was refused but the snapshot is gone anyway"
fi
if TRUSTISSUES_BACKUP_KEEP_DAILY="seven" TRUSTISSUES_BACKUP_KEEP_WEEKLY=4 \
     "${HERE}/prune-backups.sh" "${PZ}" >/dev/null 2>&1; then
  bad "a non-numeric retention value was accepted; the comparisons that follow decide what to delete"
else
  ok "a non-numeric retention value is refused"
fi
# A BLANK value, which is what a half-edited EnvironmentFile line produces, must
# fall back to the shipped default rather than to zero. Both are defensible
# readings of `KEEP=` and only one of them keeps your backups.
if TRUSTISSUES_BACKUP_KEEP_DAILY="" TRUSTISSUES_BACKUP_KEEP_WEEKLY="" \
     "${HERE}/prune-backups.sh" "${PZ}" >/dev/null 2>&1 \
   && [ -f "${PZ}/trustissues-20260802T100000Z.db" ]; then
  ok "a blank retention value falls back to the default instead of deleting everything"
else
  bad "a blank retention value did not fall back safely"
fi

# 14. August and September. Bash reads a zero-padded "08" as octal and aborts
#     with "value too great for base", so a naive implementation prunes fine for
#     ten months of the year and dies for two. That failure would first appear on
#     a live host, silently, as backups that stop being pruned.
POCT="${WORK}/prune-octal"; mkdir -p "${POCT}"
for s in 20260908T100000Z 20260809T100000Z 20250908T100000Z; do
  make_snapshot "${POCT}" "${s}"
done
if OUT14="$(TRUSTISSUES_BACKUP_KEEP_DAILY=1 TRUSTISSUES_BACKUP_KEEP_WEEKLY=1 \
     "${HERE}/prune-backups.sh" "${POCT}" 2>&1)"; then
  ok "retention handles zero-padded 08/09 dates without an octal parse error"
else
  bad "retention failed on an 08/09 date: ${OUT14}"
fi

# 15. Stale .part files are the other unbounded growth path. backup.sh's trap
#     removes its own on a normal failure, but a SIGKILL, an OOM kill or a lost
#     power cord skips the trap and strands a partial copy of the whole database
#     that no retention rule can ever match. A .part from RIGHT NOW may be a
#     backup in flight, so only old ones go.
PP="${WORK}/prune-part"; mkdir -p "${PP}"
make_snapshot "${PP}" "20260802T100000Z"
touch "${PP}/trustissues-20260101T000000Z.db.part"
touch -t 202601010000 "${PP}/trustissues-20260101T000000Z.db.part"
touch "${PP}/trustissues-20260802T110000Z.db.part"
TRUSTISSUES_BACKUP_KEEP_DAILY=7 TRUSTISSUES_BACKUP_KEEP_WEEKLY=4 \
  "${HERE}/prune-backups.sh" "${PP}" >/dev/null 2>&1 || true
if [ ! -f "${PP}/trustissues-20260101T000000Z.db.part" ] \
   && [ -f "${PP}/trustissues-20260802T110000Z.db.part" ]; then
  ok "retention removes a stale .part and leaves a fresh one alone"
else
  bad "stale .part handling is wrong (stale kept, or an in-flight backup deleted)"
fi

# 16. backup.sh only prunes when told to. A hand-run backup is what an operator
#     reaches for right before doing something frightening, and one that quietly
#     deletes older snapshots as a side effect is the opposite of what they
#     wanted.
# Two snapshots share 2026-01-01, so this fixture is prunable under ANY policy
# including the shipped defaults. Without that pair the fixture has four distinct
# days, the default keep-7-daily keeps all of them, and the case below would pass
# whether or not the opt-in gate exists. Confirmed by ablation: with the gate
# removed and three distinct days, the suite stayed green.
PB="${WORK}/prune-via-backup"; mkdir -p "${PB}"
for s in 20260101T100000Z 20260101T110000Z 20260201T100000Z 20260301T100000Z; do
  make_snapshot "${PB}" "${s}"
done
DATA6="${WORK}/data6"; mkdir -p "${DATA6}"
make_db "${DATA6}/trustissues.db"
TRUSTISSUES_DATA_DIR="${DATA6}" "${HERE}/backup.sh" "${PB}" >/dev/null 2>&1 || true
if [ "$(snapshot_names "${PB}" | grep -c .)" -eq 5 ]; then
  ok "a hand-run backup does not prune anything"
else
  bad "backup.sh pruned without being asked to"
fi
TRUSTISSUES_DATA_DIR="${DATA6}" TRUSTISSUES_BACKUP_PRUNE=1 \
  TRUSTISSUES_BACKUP_KEEP_DAILY=1 TRUSTISSUES_BACKUP_KEEP_WEEKLY=1 \
  "${HERE}/backup.sh" "${PB}" >/dev/null 2>&1 || true
if [ "$(snapshot_names "${PB}" | grep -c .)" -eq 1 ]; then
  ok "TRUSTISSUES_BACKUP_PRUNE=1 prunes after a successful backup"
else
  bad "TRUSTISSUES_BACKUP_PRUNE=1 did not prune"
fi

echo "restore-drill.sh"

# 17. The happy path. A drill that has never been seen to pass is as useless as
#     one that has never been seen to fail: if it refused everything it would
#     still satisfy every failure case below.
DATA7="${WORK}/data7"; mkdir -p "${DATA7}"
make_db "${DATA7}/trustissues.db"
DRILL7="${WORK}/drill7"
TRUSTISSUES_DATA_DIR="${DATA7}" "${HERE}/backup.sh" "${DRILL7}" >/dev/null 2>&1 || true
if OUT17="$(TRUSTISSUES_DATA_DIR="${DATA7}" "${HERE}/restore-drill.sh" "${DRILL7}" 2>&1)"; then
  if printf '%s' "${OUT17}" | grep -q "canary" && printf '%s' "${OUT17}" | grep -q "DRILL PASSED"; then
    ok "the drill restores the newest snapshot and names the canary it checked"
  else
    bad "the drill passed but did not say what it checked"
  fi
else
  bad "the drill failed on a snapshot that backup.sh had just verified: ${OUT17}"
fi

# 18. THE case this script exists for: a corrupted snapshot must fail the drill.
#     Truncation keeps a valid 16-byte SQLite header, which is what fooled the
#     original restore path, and integrity_check is what sees through it.
DRILL18="${WORK}/drill18"; mkdir -p "${DRILL18}"
TRUSTISSUES_DATA_DIR="${DATA7}" "${HERE}/backup.sh" "${DRILL18}" >/dev/null 2>&1 || true
NEWEST18="$(find "${DRILL18}" -name 'trustissues-*.db' | sed -n '1p')"
head -c 300 "${NEWEST18}" > "${NEWEST18}.tmp" && mv "${NEWEST18}.tmp" "${NEWEST18}"
head -c 16 "${NEWEST18}" | grep -q "SQLite format 3" \
  || { echo "fixture broken: truncated snapshot lost its header"; exit 1; }
if TRUSTISSUES_DATA_DIR="${DATA7}" "${HERE}/restore-drill.sh" "${DRILL18}" >/dev/null 2>&1; then
  bad "the drill PASSED on a truncated snapshot"
else
  ok "the drill fails on a truncated snapshot"
fi

# 19. Corruption that changes neither the header nor the file SIZE.
#
# Truncation is the easy case: the file is visibly short. This one is the case
# that actually happens to backups sitting on a disk, a flaky NFS mount or a USB
# drive, and it is invisible to everything except walking the b-tree. The
# 600 bytes go over the start of page 2, which is a b-tree page header, so the
# structure is broken rather than some free space in the middle of a page being
# scribbled on (that would still pass integrity_check, correctly).
DRILL19="${WORK}/drill19"; mkdir -p "${DRILL19}"
DATA19="${WORK}/data19"; mkdir -p "${DATA19}"
sqlite3 "${DATA19}/trustissues.db" \
  "CREATE TABLE vault_entries (id TEXT PRIMARY KEY, name TEXT);
   WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i<400)
   INSERT INTO vault_entries SELECT 'e'||i, 'secret value number '||i FROM c;"
TRUSTISSUES_DATA_DIR="${DATA19}" "${HERE}/backup.sh" "${DRILL19}" >/dev/null 2>&1 || true
NEWEST19="$(find "${DRILL19}" -name 'trustissues-*.db' | sed -n '1p')"
SIZE19="$(wc -c < "${NEWEST19}" | tr -d ' ')"
{
  head -c 4096 "${NEWEST19}"
  head -c 600 /dev/zero | tr '\0' 'X'
  tail -c "+4697" "${NEWEST19}"
} > "${WORK}/corrupt19.db"
mv "${WORK}/corrupt19.db" "${NEWEST19}"
[ "$(wc -c < "${NEWEST19}" | tr -d ' ')" = "${SIZE19}" ] \
  || { echo "fixture broken: the corruption changed the file size"; exit 1; }
head -c 16 "${NEWEST19}" | grep -q "SQLite format 3" \
  || { echo "fixture broken: the corruption destroyed the header, which is the easy case"; exit 1; }
if TRUSTISSUES_DATA_DIR="${DATA19}" "${HERE}/restore-drill.sh" "${DRILL19}" >/dev/null 2>&1; then
  bad "the drill PASSED on a snapshot corrupted in place, with a valid header and the right size"
else
  ok "the drill fails on corruption that changes neither the header nor the file size"
fi

# 20. The drill must pick the NEWEST snapshot, not any snapshot that happens to
#     work. A drill that scans until something restores reports green forever off
#     the back of one good file from March while every recent backup is broken.
DRILL20="${WORK}/drill20"; mkdir -p "${DRILL20}"
make_snapshot "${DRILL20}" "$(stamp_days_ago 1)"
NEWSTAMP="$(stamp_days_ago 0)"
make_snapshot "${DRILL20}" "${NEWSTAMP}"
head -c 300 "${DRILL20}/trustissues-${NEWSTAMP}.db" > "${WORK}/t20" \
  && mv "${WORK}/t20" "${DRILL20}/trustissues-${NEWSTAMP}.db"
if "${HERE}/restore-drill.sh" "${DRILL20}" >/dev/null 2>&1; then
  bad "the drill fell back to an older good snapshot instead of failing on the newest"
else
  ok "the drill fails when the NEWEST snapshot is bad, even with an older good one present"
fi
rm -f "${DRILL20}/trustissues-${NEWSTAMP}.db"
if "${HERE}/restore-drill.sh" "${DRILL20}" >/dev/null 2>&1; then
  ok "the drill passes once the bad newest snapshot is gone"
else
  bad "the drill fails on a directory whose newest snapshot is good"
fi

# 21. A stale timer must fail the drill.
#
# This is the failure mode the whole workstream is about. Backups stop, nothing
# tells anybody, and a drill that only checks "does the newest file restore"
# keeps reporting green off a snapshot from three months ago. Freshness is the
# only assertion that catches it.
DRILL21="${WORK}/drill21"; mkdir -p "${DRILL21}"
make_snapshot "${DRILL21}" "$(stamp_days_ago 30)"
if OUT21="$("${HERE}/restore-drill.sh" "${DRILL21}" 2>&1)"; then
  bad "the drill passed on a 30 day old snapshot, so a dead timer stays invisible"
else
  if printf '%s' "${OUT21}" | grep -q "timer"; then
    ok "the drill fails on a stale snapshot and points at the timer"
  else
    bad "the drill failed on a stale snapshot but not for the freshness reason: ${OUT21}"
  fi
fi
if TRUSTISSUES_DRILL_MAX_AGE_HOURS=0 "${HERE}/restore-drill.sh" "${DRILL21}" >/dev/null 2>&1; then
  ok "TRUSTISSUES_DRILL_MAX_AGE_HOURS=0 disables the freshness check"
else
  bad "the freshness check could not be disabled, so restoring from cold storage cannot be drilled"
fi

# 21b. A directory with MANY snapshots must still drill and still prune.
#
# `list_snapshots ... | head -1` looked correct and passed every case above,
# because head exiting after one line only kills the producer with SIGPIPE if
# the producer is still writing, which with two or three files it usually is
# not. Under `set -euo pipefail` that pipeline returns 141 and the script dies
# before a single assertion runs. It is a race that resolves the wrong way
# exactly when the backup directory is full, so it would have shipped green and
# started paging months later with an empty error message. Forty files makes it
# deterministic. This is the estate's "never judge a pipeline on its exit
# status" rule, in the one place nobody thought to look for it.
DRILL21B="${WORK}/drill21b"; mkdir -p "${DRILL21B}"
i=0
while [ "${i}" -lt 40 ]; do
  make_snapshot "${DRILL21B}" "$(printf '202607%02dT12%02d00Z' $(((i % 28) + 1)) "${i}")"
  i=$((i + 1))
done
make_snapshot "${DRILL21B}" "$(stamp_days_ago 0)"
if OUT21B="$("${HERE}/restore-drill.sh" "${DRILL21B}" 2>&1)"; then
  ok "the drill works on a directory with 40+ snapshots (no SIGPIPE from the list)"
else
  bad "the drill broke on a full backup directory: ${OUT21B}"
fi
if OUT21C="$(TRUSTISSUES_BACKUP_KEEP_DAILY=3 TRUSTISSUES_BACKUP_KEEP_WEEKLY=2 \
     "${HERE}/prune-backups.sh" "${DRILL21B}" 2>&1)"; then
  ok "retention works on a directory with 40+ snapshots"
else
  bad "retention broke on a full backup directory: ${OUT21C}"
fi

# 21c. The permission probe must return ONE mode string on this host.
#
# The drill fails the round trip when the restored vault is not 0600. That check
# was written as `stat -f '%Lp' f || stat -c '%a' f` inside a command
# substitution, which is correct on macOS and silently wrong on Linux: GNU
# stat's -f is --file-system and takes no format, so it reads '%Lp' as a
# filename, errors, and the `||` fires even though it also printed filesystem
# status for the real file. The substitution then captures both outputs and the
# mode never equals "600", so the weekly drill would fail on every Linux host
# and pass on the laptop it was written on. Assert the shape, not just the value.
# shellcheck source=snapshot-lib.sh
. "${HERE}/snapshot-lib.sh"
MODE_PROBE_FILE="${WORK}/mode-probe"
: > "${MODE_PROBE_FILE}"
chmod 600 "${MODE_PROBE_FILE}"
MODE600="$(file_mode "${MODE_PROBE_FILE}")"
chmod 644 "${MODE_PROBE_FILE}"
MODE644="$(file_mode "${MODE_PROBE_FILE}")"
if [ "${MODE600}" = "600" ] && [ "${MODE644}" = "644" ]; then
  ok "the permission probe returns exactly the mode on this platform"
else
  bad "the permission probe returned '${MODE600}' for 0600 and '${MODE644}' for 0644"
fi

# 22. An empty backup directory is a FAILURE, not a pass. "Nothing to check, so
#     nothing was wrong" is how a backup destination that was renamed six weeks
#     ago goes unnoticed.
DRILL22="${WORK}/drill22"; mkdir -p "${DRILL22}"
if "${HERE}/restore-drill.sh" "${DRILL22}" >/dev/null 2>&1; then
  bad "the drill passed against a directory with no snapshots at all"
else
  ok "the drill fails when there are no snapshots"
fi

# 23. A named row that is NOT in the snapshot must fail the drill. Without this
#     the drill proves a file opens, which restore.sh already checks, rather than
#     proving the data came back.
if TRUSTISSUES_DRILL_CANARY_SQL="SELECT count(*) FROM vault_entries WHERE id='not-in-this-database';" \
   TRUSTISSUES_DRILL_CANARY_EXPECT=1 \
   "${HERE}/restore-drill.sh" "${DRILL7}" >/dev/null 2>&1; then
  bad "the drill passed although its canary row was missing from the restore"
else
  ok "the drill fails when the canary row is missing"
fi

# 24. The drill must not touch the live database. It runs unattended and weekly;
#     if it ever restored over production it would do so on a schedule.
DATA24="${WORK}/data24"; mkdir -p "${DATA24}"
make_db "${DATA24}/trustissues.db"
sqlite3 "${DATA24}/trustissues.db" "UPDATE vault_entries SET name='LIVE AND UNTOUCHED' WHERE id='e1';"
DRILL24="${WORK}/drill24"
TRUSTISSUES_DATA_DIR="${DATA24}" "${HERE}/backup.sh" "${DRILL24}" >/dev/null 2>&1 || true
sqlite3 "${DATA24}/trustissues.db" "UPDATE vault_entries SET name='CHANGED AFTER THE SNAPSHOT' WHERE id='e1';"
TRUSTISSUES_DATA_DIR="${DATA24}" "${HERE}/restore-drill.sh" "${DRILL24}" >/dev/null 2>&1 || true
if [ "$(sqlite3 "${DATA24}/trustissues.db" "SELECT name FROM vault_entries WHERE id='e1';")" = "CHANGED AFTER THE SNAPSHOT" ] \
   && [ -z "$(find "${DATA24}" -name 'trustissues.db.replaced-*' 2>/dev/null)" ]; then
  ok "the drill leaves the live database completely alone"
else
  bad "the drill wrote to the LIVE data directory"
fi

# 24b. A script deployed WITHOUT its shared library must say so.
#
# Installing this is copying a list of files to /opt/trustissues, and
# snapshot-lib.sh is the entry on that list nobody thinks of, because no
# operator ever runs it directly. Bash's own message for a failed `.` names a
# line number in the wrong file, arrives in a cron log at 03:20, and reads like
# the backup script is broken.
LONELY="${WORK}/lonely"; mkdir -p "${LONELY}"
cp "${HERE}/prune-backups.sh" "${HERE}/restore-drill.sh" "${LONELY}/"
LONELY_MSGS=""
for s in prune-backups.sh restore-drill.sh; do
  OUT="$("${LONELY}/${s}" "${WORK}" 2>&1 || true)"
  printf '%s' "${OUT}" | grep -q "snapshot-lib.sh is missing" \
    || LONELY_MSGS="${LONELY_MSGS} ${s}"
done
if [ -z "${LONELY_MSGS}" ]; then
  ok "a script deployed without snapshot-lib.sh names the missing file"
else
  bad "these did not name the missing library:${LONELY_MSGS}"
fi

echo "deploy/systemd"

# 25. OnFailure= must be in [Unit].
#
# The estate shipped this exact line inside [Service] on dockyard-backup.service.
# systemd logged "Unknown key name 'OnFailure' in section 'Service', ignoring"
# and dropped it, so every nightly backup failure was silent from the day the
# unit was written until 2026-07-27, found only when a stale lock killed a run
# and no mail arrived. Nothing in `systemctl status` shows this. A text check
# does.
SD="${DEPLOY}/systemd"
for unit in trustissues-backup.service trustissues-restore-drill.service; do
  if [ ! -f "${SD}/${unit}" ]; then
    bad "${unit} is missing from deploy/systemd"
    continue
  fi
  if ! grep -q '^OnFailure=' "${SD}/${unit}"; then
    bad "${unit} has no OnFailure=, so its failures page nobody"
    continue
  fi
  SECTION="$(awk '/^\[/{s=$0} /^OnFailure=/{print s; exit}' "${SD}/${unit}")"
  if [ "${SECTION}" = "[Unit]" ]; then
    ok "${unit} has OnFailure= in [Unit]"
  else
    bad "${unit} has OnFailure= in ${SECTION}; systemd silently ignores it outside [Unit]"
  fi
done

# 26. And the unit it names has to EXIST. dockyard's did not, so even the
#     correct section would have alerted nobody. A templated target
#     `foo@%n.service` is satisfied by the file `foo@.service`.
for unit in trustissues-backup.service trustissues-restore-drill.service; do
  [ -f "${SD}/${unit}" ] || continue
  MISSING=""
  while IFS= read -r target; do
    [ -n "${target}" ] || continue
    RESOLVED="$(printf '%s' "${target}" | sed 's/@[^.]*\.service$/@.service/')"
    [ -f "${SD}/${RESOLVED}" ] || MISSING="${MISSING} ${target} -> ${RESOLVED}"
  done <<EOF
$(grep -E '^OnFailure=' "${SD}/${unit}" | sed 's/^OnFailure=//')
EOF
  if [ -z "${MISSING}" ]; then
    ok "${unit}'s OnFailure target ships as a real unit file"
  else
    bad "${unit} points OnFailure= at a unit that does not exist:${MISSING}"
  fi
done

# 27. Both timers must actually name their service, and both services must be
#     reachable from a timer. A .timer whose Unit= has a typo enables cleanly,
#     shows up in `systemctl list-timers`, and never runs anything.
for pair in "trustissues-backup.timer trustissues-backup.service" \
            "trustissues-restore-drill.timer trustissues-restore-drill.service"; do
  set -- ${pair}
  if [ -f "${SD}/$1" ] && grep -q "^Unit=$2\$" "${SD}/$1"; then
    ok "$1 triggers $2"
  else
    bad "$1 does not name $2 in Unit="
  fi
done

# 27b. Every ExecStart= must name a file this repo actually ships.
#
# Same family as the missing alert unit, one level down: a unit that runs a
# script nobody installed enables cleanly, shows up in `systemctl list-timers`,
# and fails on its first trigger at 03:20 with "No such file or directory". The
# units spell /opt/trustissues because ExecStart= takes an absolute path and a
# unit file has no variables; install.sh puts the scripts there and rewrites the
# paths if the operator moved the install. Map back to the repo and check.
for unit in trustissues-backup.service trustissues-restore-drill.service \
            trustissues-backup-alert@.service; do
  [ -f "${SD}/${unit}" ] || { bad "${unit} is missing from deploy/systemd"; continue; }
  MISSING=""
  while IFS= read -r cmd; do
    [ -n "${cmd}" ] || continue
    BIN="${cmd%% *}"
    case "${BIN}" in
      /opt/trustissues/*) REL="${BIN#/opt/trustissues/}" ;;
      *) MISSING="${MISSING} ${BIN} (not under /opt/trustissues, so install.sh cannot place it)"; continue ;;
    esac
    [ -x "${HERE}/../${REL}" ] || MISSING="${MISSING} ${BIN} -> ${REL} missing or not executable"
  done <<EOF
$(grep -E '^ExecStart=' "${SD}/${unit}" | sed 's/^ExecStart=//')
EOF
  if [ -z "${MISSING}" ]; then
    ok "${unit}'s ExecStart= runs a script this repo ships"
  else
    bad "${unit} has an ExecStart= that cannot resolve:${MISSING}"
  fi
done

# 28. The alerter must never exit non-zero and must never hang.
#
# Non-zero would make systemd page about the pager and bury the real failure.
# Hanging is the estate's port 465 incident: outbound 465 is blocked here, a
# send to smtps://host:465 does not error, it HANGS, and the unit sits in
# "activating" looking like it did nothing. The `timeout` is what converts that
# into a logged failure inside a minute.
ALERT="${SD}/trustissues-backup-alert.sh"
if [ -x "${ALERT}" ]; then
  if TRUSTISSUES_ALERT_CONFIG="${WORK}/definitely-not-here.env" \
       "${ALERT}" trustissues-backup.service >/dev/null 2>&1; then
    ok "the alerter exits 0 when it has no configuration"
  else
    bad "the alerter exits non-zero with no configuration, so systemd pages about the pager"
  fi
  cat > "${WORK}/alert-halfempty.env" <<'ENVEOF'
ALERT_TO=ops@example.com
SMTP_FROM=trustissues@example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=trustissues@example.com
SMTP_PASS=
ENVEOF
  if TRUSTISSUES_ALERT_CONFIG="${WORK}/alert-halfempty.env" \
       "${ALERT}" trustissues-backup.service >/dev/null 2>&1; then
    ok "the alerter exits 0 when a required setting is blank"
  else
    bad "the alerter exits non-zero on incomplete configuration"
  fi
  # Assert against the CODE, not the file. The header comment in the alerter
  # explains the 465 trap and names --ssl-reqd, so a plain `grep --ssl-reqd
  # file` stays green after the flag is deleted from the actual curl call. That
  # is the "check the content, not the mention" trap; caught by ablation, which
  # removed the flag and the suite reported 44 green.
  ALERT_CODE="$(grep -v '^[[:space:]]*#' "${ALERT}")"
  CURL_CALL="$(printf '%s\n' "${ALERT_CODE}" | awk '/curl /{f=1} f{print} /--upload-file/{f=0}')"
  if printf '%s' "${CURL_CALL}" | grep -q 'timeout [0-9][0-9]* curl'; then
    ok "the alerter's send is wrapped in a timeout (blocked port 465 hangs, it does not error)"
  else
    bad "the alerter can hang forever on a blocked SMTP port"
  fi
  if printf '%s' "${ALERT_CODE}" | grep -q 'smtp://' \
     && printf '%s' "${CURL_CALL}" | grep -q -- '--ssl-reqd'; then
    ok "the alerter uses STARTTLS on 587 and its curl call forces the upgrade with --ssl-reqd"
  else
    bad "the alerter's curl call does not force TLS, so credentials can be sent in the clear"
  fi
else
  bad "deploy/systemd/trustissues-backup-alert.sh is missing or not executable"
fi

# 29. The cron fallback must route failures somewhere. cron mails output to the
#     crontab owner only if the box runs an MTA, and most do not, so relying on
#     MAILTO means the failure goes to a spool nobody reads. Every scheduled line
#     needs an explicit `|| alert`.
CRON="${DEPLOY}/cron/trustissues-backup.cron"
if [ -f "${CRON}" ]; then
  JOBS="$(grep -E '^[0-9*]' "${CRON}" | grep -v '^PATH=' | grep -v '^SHELL=' || true)"
  UNALERTED="$(printf '%s\n' "${JOBS}" | grep -v 'trustissues-backup-alert.sh' || true)"
  if [ -n "${JOBS}" ] && [ -z "$(printf '%s' "${UNALERTED}" | tr -d '[:space:]')" ]; then
    ok "every cron job routes its failure to the alerter"
  else
    bad "a cron job has no failure alerting:
${UNALERTED}"
  fi
  if printf '%s' "${JOBS}" | grep -q 'restore-drill.sh'; then
    ok "the cron fallback schedules the restore drill, not just the backup"
  else
    bad "the cron fallback schedules backups with nothing that proves they restore"
  fi
else
  bad "deploy/cron/trustissues-backup.cron is missing"
fi

echo
echo "passed ${PASS}, failed ${FAIL}"
[ "${FAIL}" -eq 0 ]

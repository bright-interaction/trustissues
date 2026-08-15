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

# Compose projects and the throwaway image are torn down here rather than at the
# end of their section, so an assertion that fails (or a Ctrl-C) does not leave a
# container, a named volume holding a copy of a vault, and an image behind on the
# machine. Every step is `|| true`: cleanup must not be able to change the exit
# status of the run, and a docker that went away mid-run must not mask a failure.
COMPOSE_PROJECT_DIRS=""
COMPOSE_IMAGE=""
cleanup() {
  for d in ${COMPOSE_PROJECT_DIRS}; do
    ( cd "${d}" 2>/dev/null && docker compose down -v --remove-orphans >/dev/null 2>&1 ) || true
  done
  if [ -n "${COMPOSE_IMAGE}" ]; then
    docker rmi -f "${COMPOSE_IMAGE}" >/dev/null 2>&1 || true
  fi
  rm -rf "${WORK}" || true
}
trap cleanup EXIT

PASS=0
FAIL=0
SKIPPED=0
SKIP_WHY=""

ok()   { echo "  ok   $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }
# A skip is a case that could NOT be run here, and it is reported in the summary
# line and again as a warning, because the failure this suite exists to prevent
# is a green run that proved less than it looks like it proved. Nothing skips on
# a host that has docker; the Compose cases are the only skippable ones.
skip() { echo "  SKIP $1"; SKIPPED=$((SKIPPED + 1)); SKIP_WHY="${SKIP_WHY}
  - $1"; }

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

# A database carrying CLEARTEXT RESIDUE, the way every pre-00040 vault does.
#
# SQLite does not zero what it frees. These rows are inserted in the clear,
# deleted, and the survivors re-encrypted, which is exactly what migration
# 00040's backfill did to vault entry names. Afterwards no live row contains the
# marker and the raw file is full of it.
RESIDUE_MARKER="CLEARTEXT-VAULT-NAME-MARKER"
make_db_with_residue() {
  rm -f "$1" "$1-wal" "$1-shm"
  sqlite3 "$1" "PRAGMA journal_mode=WAL;
                CREATE TABLE vault_entries (id TEXT PRIMARY KEY, name TEXT);
                WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i<2000)
                  INSERT INTO vault_entries(id,name)
                  SELECT 'e'||i, '${RESIDUE_MARKER}-' || i || '-' || hex(randomblob(40)) FROM c;
                DELETE FROM vault_entries WHERE id <> 'e1';
                UPDATE vault_entries SET name='prod db password';
                PRAGMA wal_checkpoint(TRUNCATE);" > /dev/null
}

# How many times the marker appears in the RAW BYTES of a file. Not a query: the
# point is to read it the way someone holding a stolen backup would.
#
# The trailing `|| true` is load bearing. grep exits 1 when it finds nothing, and
# finding nothing is the ANSWER this helper exists to report, not a failure. This
# suite runs under `set -euo pipefail`, so without the guard the command
# substitution inherits grep's 1, the assignment fails, and `set -e` kills the
# entire run at exactly the moment a case was about to PASS. That is how it
# first showed up: the suite died silently right after the compaction case
# cleaned the file, which reads like a crash rather than like a pass.
residue_hits() {
  LC_ALL=C grep -a -o "${RESIDUE_MARKER}" "$1" 2>/dev/null | wc -l | tr -d ' ' || true
}

# 2a. THE FINDING. A snapshot must not carry cleartext that the live database
#     freed but never zeroed.
#
#     backup.sh used to use `.backup`, the online backup API, which copies the
#     database PAGE BY PAGE including freelist pages. It is WAL-safe and it is
#     also a faithful reproduction of every deleted row. Since the snapshot is
#     the artifact that goes off-host, into storage THREAT-MODEL.md trusts less
#     than the host, that cancels the at-rest encryption it was relying on.
#     `VACUUM INTO` rebuilds instead of copying, so there is no freelist to
#     carry. Measured here rather than asserted.
DATAR="${WORK}/data-residue"; mkdir -p "${DATAR}"
make_db_with_residue "${DATAR}/trustissues.db"
LIVE_HITS="$(residue_hits "${DATAR}/trustissues.db")"
if [ "${LIVE_HITS}" -gt 0 ]; then
  ok "fixture: the live database really does carry ${LIVE_HITS} copies of freed cleartext"
else
  bad "fixture is broken: no residue in the live file, so the next case proves nothing"
fi

DESTR="${WORK}/backups-residue"
TRUSTISSUES_DATA_DIR="${DATAR}" "${HERE}/backup.sh" "${DESTR}" >/dev/null 2>&1
SNAPR="$(find "${DESTR}" -name 'trustissues-*.db' ! -name '*.part' | head -1)"
if [ -z "${SNAPR}" ]; then
  bad "no snapshot was produced from the residue fixture"
elif [ "$(residue_hits "${SNAPR}")" = "0" ]; then
  ok "the snapshot carries NONE of the ${LIVE_HITS} freed-cleartext copies"
else
  bad "the snapshot carries $(residue_hits "${SNAPR}") copies of freed cleartext off-host"
fi

# 2b. Compacting away the residue must not cost any live data. A backup that is
#     clean and empty would pass 2a and lose the vault.
if [ -n "${SNAPR}" ] \
   && [ "$(sqlite3 "${SNAPR}" 'PRAGMA integrity_check;')" = "ok" ] \
   && [ "$(sqlite3 "${SNAPR}" "SELECT name FROM vault_entries WHERE id='e1';")" = "prod db password" ]; then
  ok "the residue-free snapshot still restores and still carries the live row"
else
  bad "the snapshot lost data while dropping the freelist"
fi

echo "compact-db.sh"

# 2b. THE DRY RUN HAS TO REPORT THE RESIDUE IT IS LOOKING AT.
#
#     compact-db.sh measured the freelist with
#
#       sqlite3 -readonly "${DB}" 'PRAGMA freelist_count;' 2>/dev/null || echo 0
#
#     and a read-only open of a WAL database needs the -shm sidecar, which is
#     gone the moment nothing has the database open -- i.e. after step 2 of the
#     procedure the script itself prints, "stop the server". The probe failed,
#     `|| echo 0` turned that failure into a zero, and the operator was told
#
#       free pages:    0 x 4096B = 0 B of unreachable old content
#       note: the freelist is already empty, so there is no residue to destroy.
#
#     on a database carrying thousands of cleartext names. Note that 4096 is
#     REAL: page_size is answered from the file header during open and survives,
#     freelist_count needs the pager and does not, so the lie came with a
#     plausible number attached.
#
#     Cases 2c/2d/2e below all passed throughout, because --yes runs VACUUM
#     whatever the probe said. The defect was entirely in what the tool TELLS
#     you, and what it told you was not to bother running it.
DATAB="${WORK}/data-compact-report"; mkdir -p "${DATAB}"
make_db_with_residue "${DATAB}/trustissues.db"
# Read the truth through a read-WRITE connection, which can always create the
# -shm, then put the directory back into the state a stopped server leaves: the
# database alone, no sidecars. That state is the whole point of the case.
TRUE_FREE="$(sqlite3 "${DATAB}/trustissues.db" 'PRAGMA freelist_count;')"
rm -f "${DATAB}/trustissues.db-shm" "${DATAB}/trustissues.db-wal"
REPORT="$(TRUSTISSUES_DATA_DIR="${DATAB}" "${HERE}/compact-db.sh" 2>&1)" || true
REPORTED="$(printf '%s\n' "${REPORT}" | sed -n 's/^free pages: *\([0-9][0-9]*\) x.*/\1/p')"
if [ "${TRUE_FREE}" = "0" ]; then
  bad "the residue fixture has an empty freelist, so this case would prove nothing"
elif [ "${REPORTED}" = "${TRUE_FREE}" ]; then
  ok "the dry run reports the real freelist (${REPORTED} pages) with no -shm present"
else
  bad "the dry run reported '${REPORTED:-<no free pages line>}' free pages where the database has ${TRUE_FREE}"
fi

# 2b-ii. And it must not actively tell the operator to stand down.
case "${REPORT}" in
  *"no residue to destroy"*)
    bad "the dry run said there is no residue to destroy on a database with ${TRUE_FREE} free pages" ;;
  *)
    ok "the dry run does not claim an empty freelist on a database that has one" ;;
esac

# 2b-iii. A dry run must not create sidecars while it looks. It promises to
#         change nothing, and a root-owned -shm left next to a database the
#         service user has to open is a change with consequences.
if [ -e "${DATAB}/trustissues.db-shm" ] || [ -e "${DATAB}/trustissues.db-wal" ]; then
  bad "the dry run left sidecars behind: $(ls "${DATAB}" | tr '\n' ' ')"
else
  ok "the dry run created no -wal/-shm sidecars"
fi

# 2c. The default is a DRY RUN. This script rewrites the only live copy of the
#     vault, so running it to see what it says must not change anything.
DATAC="${WORK}/data-compact"; mkdir -p "${DATAC}"
make_db_with_residue "${DATAC}/trustissues.db"
BEFORE_HITS="$(residue_hits "${DATAC}/trustissues.db")"
TRUSTISSUES_DATA_DIR="${DATAC}" "${HERE}/compact-db.sh" >/dev/null 2>&1 || true
if [ "$(residue_hits "${DATAC}/trustissues.db")" = "${BEFORE_HITS}" ]; then
  ok "a dry run changes nothing (residue still ${BEFORE_HITS})"
else
  bad "the dry run modified the live database"
fi

# 2d. With --yes it destroys the residue in the LIVE file. This is the half that
#     _secure_delete cannot do: the pragma only zeroes pages as they are freed
#     from that point on, so a database that accumulated free pages before it was
#     turned on keeps every one of them until something rebuilds the file.
if TRUSTISSUES_DATA_DIR="${DATAC}" "${HERE}/compact-db.sh" --yes >/dev/null 2>&1; then
  REMAIN="$(residue_hits "${DATAC}/trustissues.db")"
  WAL_REMAIN="$(residue_hits "${DATAC}/trustissues.db-wal")"
  if [ "${REMAIN}" = "0" ] && [ "${WAL_REMAIN}" = "0" ]; then
    ok "--yes destroyed all ${BEFORE_HITS} copies in the live file and its -wal"
  else
    bad "after compaction the live file still holds ${REMAIN} copies (${WAL_REMAIN} in -wal)"
  fi
else
  bad "compact-db.sh --yes failed on a valid database"
fi

# 2e. Compaction must not eat the vault either.
if [ "$(sqlite3 "${DATAC}/trustissues.db" 'PRAGMA integrity_check;')" = "ok" ] \
   && [ "$(sqlite3 "${DATAC}/trustissues.db" "SELECT name FROM vault_entries WHERE id='e1';")" = "prod db password" ]; then
  ok "the compacted live database passes integrity_check and kept its rows"
else
  bad "compaction damaged the live database"
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

# 8b. And it must still be the live data directory when it is spelled as a
#     SYMLINK to it.
#
# The guard compared `cd "$dir" && pwd` on both sides, which is the LOGICAL path:
# bash prints the symlink you asked for, not the directory you landed in, so the
# two spellings of one directory compared unequal and the refusal never fired.
# Proven before the fix: backup.sh exited 0 and the live data dir ended up
# holding trustissues-<stamp>.db beside trustissues.db. The shipped
# trustissues-backup.service sets TRUSTISSUES_BACKUP_PRUNE=1, so the next
# scheduled run is then an automated rm inside the live data dir, which is the
# precise outcome the guard's own comment says must never happen.
# Assert on the DIRECTORY, not just the exit status: a refusal that still wrote
# the file would be worse than no refusal.
DATA8B="${WORK}/data8b"; mkdir -p "${DATA8B}"
make_db "${DATA8B}/trustissues.db"
ln -s "${DATA8B}" "${WORK}/backups8b-link"
OUT8B="$(TRUSTISSUES_DATA_DIR="${DATA8B}" "${HERE}/backup.sh" "${WORK}/backups8b-link" 2>&1 || true)"
if [ -z "$(find "${DATA8B}" -name 'trustissues-*.db' 2>/dev/null)" ]; then
  ok "backup.sh refuses a destination that is a SYMLINK to the live data directory"
else
  bad "backup.sh wrote snapshots into the live data dir through a symlink: ${OUT8B}"
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

# 13b. Retention must refuse to run inside the LIVE data directory.
#
# backup.sh refused this from the start and prune-backups.sh, the script that
# does the actual deleting, had no such check at all. Proven before the fix:
# `prune-backups.sh <live data dir>` deleted two snapshots in place. trustissues.db
# itself survives because the name regex saves it, so the blast radius was
# snapshots rather than the database, but the invariant was enforced in the script
# that WRITES and not in the one that DELETES, which is where it matters.
#
# Three routes into the same directory, because each check alone has a hole:
# the env var (set by the systemd unit), the env var through a symlink (logical
# pwd compares one directory unequal to itself), and no env var at all, which is
# every hand-run invocation.
#
# The fixtures are deliberately NOT identical. Only the marker route plants a
# trustissues.db; the other two are a data directory before its first boot, which
# is a real state. If all three planted one, the marker check alone would satisfy
# all three cases, deleting the env-var checks would leave the suite green, and
# these would be three tests that measure one thing. Caught by ablation on the
# first draft of this very case.
#
# Every case asserts the SNAPSHOTS SURVIVED, not merely that the exit code was
# non-zero: a refusal that deletes first is not a refusal.
PLIVE_SNAPS="20260802T100000Z 20260701T100000Z 20260601T100000Z 20260501T100000Z"
for route in envvar symlink marker; do
  PL="${WORK}/prune-live-${route}"; mkdir -p "${PL}"
  for s in ${PLIVE_SNAPS}; do make_snapshot "${PL}" "${s}"; done
  BEFORE13B="$(snapshot_names "${PL}")"
  case "${route}" in
    envvar)  RAN="$(TRUSTISSUES_DATA_DIR="${PL}" TRUSTISSUES_BACKUP_KEEP_DAILY=1 TRUSTISSUES_BACKUP_KEEP_WEEKLY=1 \
                      "${HERE}/prune-backups.sh" "${PL}" 2>&1 || true)" ;;
    symlink) ln -s "${PL}" "${WORK}/prune-live-link"
             RAN="$(TRUSTISSUES_DATA_DIR="${WORK}/prune-live-link" TRUSTISSUES_BACKUP_KEEP_DAILY=1 TRUSTISSUES_BACKUP_KEEP_WEEKLY=1 \
                      "${HERE}/prune-backups.sh" "${PL}" 2>&1 || true)" ;;
    # env -u, not just "do not set it": if the operator running this suite happens
    # to have TRUSTISSUES_DATA_DIR exported, this case would silently be testing
    # the env-var route again and the marker check would never be exercised.
    marker)  make_db "${PL}/trustissues.db"
             RAN="$(env -u TRUSTISSUES_DATA_DIR TRUSTISSUES_BACKUP_KEEP_DAILY=1 TRUSTISSUES_BACKUP_KEEP_WEEKLY=1 \
                      "${HERE}/prune-backups.sh" "${PL}" 2>&1 || true)" ;;
  esac
  if [ "$(snapshot_names "${PL}")" = "${BEFORE13B}" ]; then
    ok "retention refuses to delete inside the live data dir (${route}) and deletes nothing"
  else
    bad "retention DELETED inside the live data dir (${route}): ${RAN}"
  fi
done
# The refusal must not be a blanket one: a genuine backup directory, which is
# every real invocation, still has to prune. A guard that refuses everything
# passes every refusal case ever written.
PNL="${WORK}/prune-not-live"; mkdir -p "${PNL}"
for s in ${PLIVE_SNAPS}; do make_snapshot "${PNL}" "${s}"; done
TRUSTISSUES_DATA_DIR="${WORK}/data5" TRUSTISSUES_BACKUP_KEEP_DAILY=1 TRUSTISSUES_BACKUP_KEEP_WEEKLY=1 \
  "${HERE}/prune-backups.sh" "${PNL}" >/dev/null 2>&1 || true
if [ "$(snapshot_names "${PNL}" | grep -c .)" -lt 4 ]; then
  ok "retention still prunes a directory that is not the live data dir"
else
  bad "the live-data-dir refusal blocked retention on a normal backup directory"
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

# 21d. A TYPO in the max-age value must be refused, not ignored.
#
# `[ "${AGE_HOURS}" -gt "48h" ]` returns 2 with "integer expected" on stderr, and
# set -e does not apply inside an `if ... && ...` condition, so the branch is
# simply false and the freshness check is skipped entirely. Measured against this
# 30 day old fixture before the fix: 48 -> exit 1 (correct), 48h -> exit 0
# "DRILL PASSED", two -> exit 0 "DRILL PASSED". The unit exits 0, systemd is
# green, OnFailure never fires, and the stderr line lands in a journal nobody
# reads because nothing failed. A drill that passes when it checked nothing is
# worse than no drill, and this is one character in the file install.sh tells the
# operator to edit.
#
# Assert on the OUTPUT as well as the exit code. "did not exit 0" would also be
# satisfied by the drill dying for some unrelated reason; what has to be true is
# that it never claims to have passed.
for badage in "48h" "two" "48 " "-1" "4.8"; do
  if OUT21D="$(TRUSTISSUES_DRILL_MAX_AGE_HOURS="${badage}" "${HERE}/restore-drill.sh" "${DRILL21}" 2>&1)"; then
    bad "TRUSTISSUES_DRILL_MAX_AGE_HOURS='${badage}' was accepted and the drill exited 0 on a 30 day old snapshot"
  elif printf '%s' "${OUT21D}" | grep -q "DRILL PASSED"; then
    bad "TRUSTISSUES_DRILL_MAX_AGE_HOURS='${badage}' printed DRILL PASSED"
  elif printf '%s' "${OUT21D}" | grep -q "TRUSTISSUES_DRILL_MAX_AGE_HOURS"; then
    ok "a non-numeric TRUSTISSUES_DRILL_MAX_AGE_HOURS ('${badage}') is refused by name"
  else
    bad "TRUSTISSUES_DRILL_MAX_AGE_HOURS='${badage}' failed for some other reason: ${OUT21D}"
  fi
done
# A BLANK value is a half-edited line, not a typo, and must fall back to the
# shipped default rather than be refused. Same reading prune-backups.sh gives it.
# The fixture is 30 days old, so "fell back to 48" and "was refused" are told
# apart by which message comes out.
if OUT21DB="$(TRUSTISSUES_DRILL_MAX_AGE_HOURS="" "${HERE}/restore-drill.sh" "${DRILL21}" 2>&1)"; then
  bad "a blank TRUSTISSUES_DRILL_MAX_AGE_HOURS disabled the freshness check"
elif printf '%s' "${OUT21DB}" | grep -q "timer"; then
  ok "a blank TRUSTISSUES_DRILL_MAX_AGE_HOURS falls back to the default limit"
else
  bad "a blank TRUSTISSUES_DRILL_MAX_AGE_HOURS did not fall back to the default: ${OUT21DB}"
fi

# 21e. A snapshot stamped in the FUTURE must fail the drill.
#
# The other way to blind the freshness check, and one clock-skewed run is all it
# takes. trustissues-20300101T000000Z.db sorts newest forever, its age comes out
# NEGATIVE, `-gt 48` is false, and the drill reported
# "snapshot: trustissues-20300101T000000Z.db (-29936h old) ... DRILL PASSED".
# Retention then makes it permanent, because the newest snapshot is never a
# deletion candidate, so the one file that never expires is the bogus one while
# every real backup ages out around it.
DRILL21E="${WORK}/drill21e"; mkdir -p "${DRILL21E}"
make_snapshot "${DRILL21E}" "$(stamp_days_ago 0)"
make_snapshot "${DRILL21E}" "20300101T000000Z"
if OUT21E="$("${HERE}/restore-drill.sh" "${DRILL21E}" 2>&1)"; then
  bad "the drill PASSED on a snapshot stamped in the future, so a skewed clock blinds it forever"
elif printf '%s' "${OUT21E}" | grep -q "FUTURE"; then
  ok "the drill fails on a future-stamped snapshot and says why"
else
  bad "the drill failed on a future-stamped snapshot for the wrong reason: ${OUT21E}"
fi

# 21f. A TRUSTISSUES_DATA_DIR that does not resolve must be reported as itself,
#      not as a containment refusal that never happened.
#
# The containment check resolved the path inline and fell back to "" when cd
# failed, so `case "${DRILL_ABS}/" in "${LIVE_ABS}"/*)` collapsed to `/*` and
# matched every absolute path on the machine. The drill then failed with
#   DRILL FAILED: the drill directory /var/folders/.../trustissues-drill.Cf2XWA
#   is inside the LIVE data dir; refusing
# about a directory it had never been near. Reachable from a typo, an unmounted
# volume, or backup.env.example's Compose path on a host whose compose project is
# not named exactly "trustissues". The alerter's hint table has no case for that
# string, so the operator got a weekly mail asserting a refusal that did not
# happen, while backup.sh reported the same misconfiguration correctly. A false
# page every week is how a real one gets ignored.
if OUT21F="$(TRUSTISSUES_DATA_DIR="${WORK}/no-such-data-dir" \
     "${HERE}/restore-drill.sh" "${DRILL7}" 2>&1)"; then
  bad "the drill ignored a TRUSTISSUES_DATA_DIR that does not exist"
elif printf '%s' "${OUT21F}" | grep -q "inside the LIVE data dir"; then
  bad "the drill blamed a containment refusal that never happened: ${OUT21F}"
elif printf '%s' "${OUT21F}" | grep -q "does not resolve"; then
  ok "an unresolvable TRUSTISSUES_DATA_DIR is named as itself, not as a false containment refusal"
else
  bad "the drill failed on an unresolvable TRUSTISSUES_DATA_DIR with an unhelpful message: ${OUT21F}"
fi

# 21g. And the containment refusal must still fire when the live data dir is
#      reached through a SYMLINK.
#
# Both sides of that comparison used the logical pwd, which prints the symlink
# you asked for rather than the directory you landed in, so one directory
# compared unequal to itself. Point TRUSTISSUES_DATA_DIR at a symlink to the
# drill's own TMPDIR and the check misses: the drill restores a full copy of the
# vault INSIDE the live data dir and reports success. pwd -P on both sides is
# what makes two names for one directory agree.
DRILL21G="${WORK}/drill21g"; mkdir -p "${DRILL21G}"
make_snapshot "${DRILL21G}" "$(stamp_days_ago 0)"
TMP21G="${WORK}/tmp21g"; mkdir -p "${TMP21G}"
ln -s "${TMP21G}" "${WORK}/data21g-link"
if OUT21G="$(TMPDIR="${TMP21G}" TRUSTISSUES_DATA_DIR="${WORK}/data21g-link" \
     "${HERE}/restore-drill.sh" "${DRILL21G}" 2>&1)"; then
  bad "the drill restored INSIDE the live data dir because it was named through a symlink"
elif printf '%s' "${OUT21G}" | grep -q "inside the LIVE data dir"; then
  ok "the drill refuses to restore inside the live data dir named through a symlink"
else
  bad "the drill failed under a symlinked data dir for the wrong reason: ${OUT21G}"
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

# 25b. Neither scheduled unit may carry a Condition*=, and both must keep an
#      EnvironmentFile= with no `-` prefix.
#
# These two lines are one mechanism. EnvironmentFile=/etc/trustissues/backup.env
# without a leading `-` FAILS the unit when the file is missing, which is what
# fires OnFailure= and pages. ConditionPathExists= on that same file makes systemd
# SKIP the unit and mark the job SUCCESSFUL instead: a condition that does not
# hold never moves a unit to failed, so OnFailure= is never triggered. Both units
# shipped with it, so renaming or losing backup.env would have silenced the backup
# AND the drill that exists to notice the backup went silent, with
# `systemctl list-timers` still green. That is the dockyard-backup incident
# through a different door, and the estate has now been bitten four separate ways
# by silent systemd alerting. Nothing in systemctl output distinguishes "skipped"
# from "ran and was fine"; a text check does.
for unit in trustissues-backup.service trustissues-restore-drill.service; do
  [ -f "${SD}/${unit}" ] || { bad "${unit} is missing from deploy/systemd"; continue; }
  COND="$(grep -E '^Condition[A-Za-z]+=' "${SD}/${unit}" || true)"
  ENVF="$(grep -E '^EnvironmentFile=' "${SD}/${unit}" || true)"
  if [ -n "${COND}" ]; then
    bad "${unit} has ${COND}; a failed condition marks the job SUCCESSFUL, so OnFailure= never fires"
  elif [ -z "${ENVF}" ]; then
    bad "${unit} has no EnvironmentFile=, so a missing backup.env is not the loud failure it must be"
  elif printf '%s' "${ENVF}" | grep -q '^EnvironmentFile=-'; then
    bad "${unit} has ${ENVF}; the leading - makes a missing config file a silent no-op"
  else
    ok "${unit} fails loudly on a missing backup.env (no Condition*=, no EnvironmentFile=-)"
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
  # The alerter has to be REACHED ON FAILURE, not merely mentioned. Grepping the
  # line for the string 'trustissues-backup-alert.sh' is satisfied by a job that
  # names it in a trailing comment, or that pipes to it unconditionally, and this
  # suite has already been bitten once by exactly that shape (--ssl-reqd matched
  # inside a comment while the real curl call had lost the flag). Require the
  # `|| <alerter>` that makes it a failure hook.
  UNALERTED="$(printf '%s\n' "${JOBS}" | grep -v '|| *[^ ]*trustissues-backup-alert\.sh' || true)"
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

echo "multi-line numeric settings"

# 30. A numeric setting whose FIRST LINE is digits must be refused too.
#
# Both validators used `printf '%s' "$v" | grep -Eq '^[0-9]+$'`, and grep anchors
# ^ and $ to a LINE, not to the value. So $'48\nfoo' passed validation, and every
# later `[ "${AGE_HOURS}" -gt "48\nfoo" ]` is an "integer expression expected"
# error, which inside an `if ... &&` condition is simply FALSE. The freshness
# check is then skipped and the drill prints DRILL PASSED on a snapshot of any
# age: the same silent green the digits-only rule was written to close, reached
# by a different encoding. A multi-line value is one unterminated quote away in
# backup.env, because systemd keeps accumulating lines inside an open quote.
NLDIR="${WORK}/newline-drill"; mkdir -p "${NLDIR}"
make_snapshot "${NLDIR}" "$(stamp_days_ago 30)"
NL_RC=0
NL_OUT="$(TRUSTISSUES_DRILL_MAX_AGE_HOURS=$'48\nfoo' \
  "${HERE}/restore-drill.sh" "${NLDIR}" 2>&1)" || NL_RC=$?
if [ "${NL_RC}" = "2" ] \
   && printf '%s' "${NL_OUT}" | grep -q "TRUSTISSUES_DRILL_MAX_AGE_HOURS must be a whole number" \
   && ! printf '%s' "${NL_OUT}" | grep -q "DRILL PASSED"; then
  ok "the drill refuses a multi-line TRUSTISSUES_DRILL_MAX_AGE_HOURS instead of skipping the freshness check"
else
  bad "TRUSTISSUES_DRILL_MAX_AGE_HOURS=\$'48\\nfoo' gave exit ${NL_RC} on a 30-day-old snapshot:
${NL_OUT}"
fi

# 31. Same hole, same fix, in the sibling that DELETES.
#
# TRUSTISSUES_BACKUP_KEEP_DAILY=$'1\nfoo' passed the old regex, then every
# `[ "${n_daily}" -lt "1\nfoo" ]` evaluated false, so keep-daily silently
# degraded to zero and the prune deleted snapshots it had been told to keep.
NLP="${WORK}/newline-prune"; mkdir -p "${NLP}"
for d in 1 2 3; do make_snapshot "${NLP}" "$(stamp_days_ago "${d}")"; done
NLP_BEFORE="$(snapshot_names "${NLP}")"
NLP_RC=0
NLP_OUT="$(TRUSTISSUES_BACKUP_KEEP_DAILY=$'1\nfoo' \
  "${HERE}/prune-backups.sh" "${NLP}" 2>&1)" || NLP_RC=$?
NLP_AFTER="$(snapshot_names "${NLP}")"
if [ "${NLP_RC}" != "0" ] && [ "${NLP_AFTER}" = "${NLP_BEFORE}" ] \
   && printf '%s' "${NLP_OUT}" | grep -q "TRUSTISSUES_BACKUP_KEEP_DAILY must be a non-negative integer"; then
  ok "prune refuses a multi-line TRUSTISSUES_BACKUP_KEEP_DAILY and deletes nothing"
else
  bad "TRUSTISSUES_BACKUP_KEEP_DAILY=\$'1\\nfoo' exited ${NLP_RC} and left:
${NLP_AFTER}"
fi

echo "backup.sh retention opt-in"

# 32. --prune must beat TRUSTISSUES_BACKUP_PRUNE=0 in the environment.
#
# The scheduled unit used to opt into retention with
# `Environment=TRUSTISSUES_BACKUP_PRUNE=1` beside
# `EnvironmentFile=/etc/trustissues/backup.env`, and systemd documents that
# settings from an EnvironmentFile OVERRIDE settings made with Environment=. So
# one line in the config file the installer tells the operator to go and edit
# switched retention off on the only path that fills the disk, and NOTHING
# failed: the backup exits 0, the timer stays green, the drill keeps passing, and
# the directory grows by a full copy of the database every night until SQLite
# starts failing writes on the disk the LIVE database is on. The opt-in is an
# ExecStart= argument now, which no environment file can override.
PFD="${WORK}/prune-flag"; mkdir -p "${PFD}/data" "${PFD}/backups"
make_db "${PFD}/data/trustissues.db"
for d in 1 2 3 4 5 6 7 8 9 10 11 12; do make_snapshot "${PFD}/backups" "$(stamp_days_ago "${d}")"; done
PF_BEFORE="$(snapshot_names "${PFD}/backups" | grep -c . || true)"
PF_RC=0
PF_OUT="$(TRUSTISSUES_DATA_DIR="${PFD}/data" TRUSTISSUES_BACKUP_PRUNE=0 \
  "${HERE}/backup.sh" --prune "${PFD}/backups" 2>&1)" || PF_RC=$?
PF_AFTER="$(snapshot_names "${PFD}/backups" | grep -c . || true)"
if [ "${PF_RC}" = "0" ] && [ "${PF_AFTER}" -lt "$((PF_BEFORE + 1))" ] \
   && printf '%s' "${PF_OUT}" | grep -q "  removed trustissues-"; then
  ok "--prune runs retention even with TRUSTISSUES_BACKUP_PRUNE=0 in the environment"
else
  bad "--prune did not prune under TRUSTISSUES_BACKUP_PRUNE=0: exit ${PF_RC}, ${PF_BEFORE} snapshots before, ${PF_AFTER} after
${PF_OUT}"
fi

# 33. And the flag wins in the other direction too, so a hand-run can refuse
#     retention on a host whose backup.env turns it on. A flag that only works
#     one way is a flag nobody can reason about.
PFD2="${WORK}/prune-flag-off"; mkdir -p "${PFD2}/data" "${PFD2}/backups"
make_db "${PFD2}/data/trustissues.db"
for d in 1 2 3 4 5 6 7 8 9 10 11 12; do make_snapshot "${PFD2}/backups" "$(stamp_days_ago "${d}")"; done
PF2_BEFORE="$(snapshot_names "${PFD2}/backups" | grep -c . || true)"
PF2_RC=0
PF2_OUT="$(TRUSTISSUES_DATA_DIR="${PFD2}/data" TRUSTISSUES_BACKUP_PRUNE=1 \
  "${HERE}/backup.sh" --no-prune "${PFD2}/backups" 2>&1)" || PF2_RC=$?
PF2_AFTER="$(snapshot_names "${PFD2}/backups" | grep -c . || true)"
if [ "${PF2_RC}" = "0" ] && [ "${PF2_AFTER}" = "$((PF2_BEFORE + 1))" ] \
   && printf '%s' "${PF2_OUT}" | grep -q "retention is OFF"; then
  ok "--no-prune keeps every snapshot even with TRUSTISSUES_BACKUP_PRUNE=1 in the environment"
else
  bad "--no-prune still pruned: exit ${PF2_RC}, ${PF2_BEFORE} before, ${PF2_AFTER} after"
fi

# 34. The shipped unit must carry the flag and must NOT rely on Environment=.
if grep -q '^ExecStart=/opt/trustissues/scripts/backup\.sh --prune$' "${SD}/trustissues-backup.service" \
   && ! grep -q '^Environment=TRUSTISSUES_BACKUP_PRUNE' "${SD}/trustissues-backup.service"; then
  ok "trustissues-backup.service opts into retention on the ExecStart= line, which no EnvironmentFile can override"
else
  bad "trustissues-backup.service still opts into retention through Environment=, which its own EnvironmentFile overrides"
fi

# 34b. A fresh destination directory must not be created world-readable.
#      The file names in a backup directory are an inventory of the vault.
UMD="${WORK}/umask-probe"; mkdir -p "${UMD}/data"
make_db "${UMD}/data/trustissues.db"
( umask 022; TRUSTISSUES_DATA_DIR="${UMD}/data" "${HERE}/backup.sh" "${UMD}/fresh-dest" >/dev/null 2>&1 ) || true
UM_MODE="$(file_mode "${UMD}/fresh-dest" 2>/dev/null || echo "")"
if [ "${UM_MODE}" = "700" ]; then
  ok "backup.sh creates a missing destination directory 0700 regardless of the caller's umask"
else
  bad "backup.sh created its destination directory mode ${UM_MODE:-<missing>} under umask 022"
fi

echo "deploy/systemd/install.sh, executed"

# 35. The installer has to RUN. This is the case whose absence shipped an
#     install that could not complete on any host.
#
# install.sh had zero execution coverage: everything about it was checked by
# reading the unit files it reads, never by running it. What shipped was a check
# that refused one of its own units. The OnFailure= loop iterated over every unit
# including the two .timer files, skipped only *@.service, and died on
# `trustissues-backup.timer has no OnFailure=` after copying the units into
# /etc/systemd/system and BEFORE seeding /etc/trustissues/backup.env, before
# creating the backup directory and before enabling either timer. docs/BACKUP.md
# makes `sudo ./deploy/systemd/install.sh` step 1 of the preferred path and every
# later step depends on it, so the headline deliverable of this workstream did
# not install, and the operator's first contact with it was an error accusing a
# timer of a defect a timer cannot have (OnFailure= on a .timer fires when the
# TIMER fails to start, not when the backup fails; the backup failing fails the
# .SERVICE and leaves the timer green).
#
# `--root DIR` runs the real script, in order, with its real checks, against a
# throwaway tree. Nothing here re-implements the installer.
INSTALL_SH="${SD}/install.sh"
STUBBIN="${WORK}/stubbin"; mkdir -p "${STUBBIN}"
# systemctl stand-in, covering ONLY the offline `--root` enable the rehearsal
# uses. It records every invocation and reproduces what systemd itself does on
# disk for an enable: the WantedBy= symlink under <root>/etc/systemd/system.
# macOS has no systemctl at all, so this is also what makes the case runnable
# here rather than only on the target host.
cat > "${STUBBIN}/systemctl" <<'STUBEOF'
#!/bin/sh
printf '%s\n' "$*" >> "${SYSTEMCTL_LOG:-/dev/null}"
root=""; cmd=""; units=""
for a in "$@"; do
  case "$a" in
    --root=*) root="${a#--root=}" ;;
    -*) ;;
    *) if [ -z "${cmd}" ]; then cmd="$a"; else units="${units} $a"; fi ;;
  esac
done
[ "${cmd}" = "enable" ] || exit 0
for u in ${units}; do
  f="${root}/etc/systemd/system/${u}"
  if [ ! -f "${f}" ]; then
    echo "Failed to enable unit: Unit file ${u} does not exist." >&2
    exit 1
  fi
  want="$(sed -n 's/^WantedBy=//p' "${f}" | head -1)"
  if [ -z "${want}" ]; then
    echo "The unit files have no installation config (WantedBy=, RequiredBy=)." >&2
    exit 1
  fi
  mkdir -p "${root}/etc/systemd/system/${want}.wants"
  ln -sf "${f}" "${root}/etc/systemd/system/${want}.wants/${u}"
done
STUBEOF
chmod 0755 "${STUBBIN}/systemctl"

INSTALL_RC=0
INSTALL_OUT=""
# run_install <repo-root> <staging-root>
run_install() {
  mkdir -p "$2"
  INSTALL_RC=0
  INSTALL_OUT="$(PATH="${STUBBIN}:${PATH}" SYSTEMCTL_LOG="$2/systemctl.log" \
    "$1/deploy/systemd/install.sh" --root "$2" 2>&1)" || INSTALL_RC=$?
}

# fake_repo <dir> - a copy of exactly the files install.sh reads, so a case can
# plant a defect in a unit and watch the installer refuse it without touching the
# real tree.
fake_repo() {
  mkdir -p "$1/scripts" "$1/deploy/systemd" "$1/docs"
  for f in backup.sh restore.sh prune-backups.sh restore-drill.sh snapshot-lib.sh; do
    cp "${HERE}/${f}" "$1/scripts/${f}"
  done
  cp "${SD}"/*.service "${SD}"/*.timer "${SD}/install.sh" \
     "${SD}/trustissues-backup-alert.sh" "${SD}/backup.env.example" "$1/deploy/systemd/"
  cp "${HERE}/../docs/BACKUP.md" "$1/docs/BACKUP.md"
  chmod 0755 "$1/deploy/systemd/install.sh" "$1/deploy/systemd/trustissues-backup-alert.sh"
  chmod 0755 "$1"/scripts/*.sh
}

IROOT="${WORK}/instroot"
run_install "${HERE}/.." "${IROOT}"
if [ "${INSTALL_RC}" = "0" ]; then
  ok "install.sh runs end to end on a clean host (exit 0)"
else
  bad "install.sh exited ${INSTALL_RC} on a clean host, so the documented install cannot complete:
${INSTALL_OUT}"
fi

# 36. Both timers enabled. `systemctl enable` is the last step of the install, so
#     this is also the assertion that the script got all the way there.
IW="${IROOT}/etc/systemd/system/timers.target.wants"
if [ -L "${IW}/trustissues-backup.timer" ] && [ -L "${IW}/trustissues-restore-drill.timer" ] \
   && grep -q 'enable.*trustissues-backup\.timer.*trustissues-restore-drill\.timer' "${IROOT}/systemctl.log" 2>/dev/null; then
  ok "install.sh enables BOTH timers"
else
  bad "install.sh did not enable both timers (wants dir: $(ls "${IW}" 2>/dev/null | tr '\n' ' '))"
fi

# 37. Configuration seeded, 0600, in place. The install dies before this line if
#     any of the unit checks refuses, which is exactly what shipped.
if [ -f "${IROOT}/etc/trustissues/backup.env" ] \
   && [ "$(file_mode "${IROOT}/etc/trustissues/backup.env")" = "600" ]; then
  ok "install.sh seeds backup.env at mode 0600"
else
  bad "install.sh did not seed backup.env (or seeded it with the wrong mode)"
fi

# 38. The backup directory from that config, 0700. It holds ciphertext copies of
#     a credential store; 0755 there means every account on the box can read them.
IBDIR="${IROOT}/var/backups/trustissues"
if [ -d "${IBDIR}" ] && [ "$(file_mode "${IBDIR}")" = "700" ]; then
  ok "install.sh creates the backup directory 0700"
else
  bad "install.sh left the backup directory missing or loose (mode $(file_mode "${IBDIR}" 2>/dev/null || echo none))"
fi

# 39. The scripts landed executable and the units point at where they landed.
#     A unit whose ExecStart= names a path nothing was installed to enables
#     cleanly and fails on its first trigger at 03:20.
IMISS=""
for f in backup.sh restore.sh prune-backups.sh restore-drill.sh snapshot-lib.sh; do
  [ -f "${IROOT}/opt/trustissues/scripts/${f}" ] || IMISS="${IMISS} ${f}"
done
IEXEC="$(grep -h '^ExecStart=' "${IROOT}/etc/systemd/system/trustissues-backup.service" \
  | sed 's/^ExecStart=//' | awk '{print $1}')"
if [ -z "${IMISS}" ] && [ -x "${IEXEC}" ]; then
  ok "install.sh installs the scripts and rewrites ExecStart= to where they went"
else
  bad "install.sh left${IMISS:- nothing} missing and ExecStart=${IEXEC} is not executable"
fi

# 40. Re-running must be safe. An installer that clobbers the operator's edited
#     backup.env on every upgrade takes the SMTP password with it, and the alert
#     path is then dead until somebody notices no mail.
printf '\n# operator edit\nALERT_TO=someone@example.com\n' >> "${IROOT}/etc/trustissues/backup.env"
run_install "${HERE}/.." "${IROOT}"
if [ "${INSTALL_RC}" = "0" ] && grep -q 'someone@example.com' "${IROOT}/etc/trustissues/backup.env"; then
  ok "a second install.sh run succeeds and leaves an edited backup.env alone"
else
  bad "re-running install.sh exited ${INSTALL_RC} or overwrote the operator's backup.env"
fi

# 41-44. The installer's own checks, watched refusing.
#
# Three of them existed and none had ever been executed, which is how the fourth
# (the timer refusal above) shipped broken. Each case plants ONE defect in a copy
# of the tree and asserts install.sh refuses it and never reaches the config
# seeding. They are the same defects scripts/test-backup-restore.sh asserts
# against the repo's unit files, checked here against the INSTALLED copies,
# which is where a hand edit lands.
FR1="${WORK}/fakerepo-onfailure"; fake_repo "${FR1}"
grep -v '^OnFailure=' "${FR1}/deploy/systemd/trustissues-backup.service" \
  > "${FR1}/deploy/systemd/trustissues-backup.service.new"
mv "${FR1}/deploy/systemd/trustissues-backup.service.new" "${FR1}/deploy/systemd/trustissues-backup.service"
run_install "${FR1}" "${WORK}/instroot-onfailure"
if [ "${INSTALL_RC}" != "0" ] \
   && printf '%s' "${INSTALL_OUT}" | grep -q 'trustissues-backup.service has no OnFailure=' \
   && [ ! -f "${WORK}/instroot-onfailure/etc/trustissues/backup.env" ]; then
  ok "install.sh refuses a backup service with no OnFailure= (and stops before seeding)"
else
  bad "install.sh accepted a unit with no OnFailure= (exit ${INSTALL_RC}):
${INSTALL_OUT}"
fi

FR2="${WORK}/fakerepo-condition"; fake_repo "${FR2}"
printf 'ConditionPathExists=/etc/trustissues/backup.env\n' \
  >> "${FR2}/deploy/systemd/trustissues-restore-drill.service"
run_install "${FR2}" "${WORK}/instroot-condition"
if [ "${INSTALL_RC}" != "0" ] \
   && printf '%s' "${INSTALL_OUT}" | grep -q 'ConditionPathExists'; then
  ok "install.sh refuses a Condition*= that would turn a failure into a silent skip"
else
  bad "install.sh accepted a ConditionPathExists= (exit ${INSTALL_RC}):
${INSTALL_OUT}"
fi

FR3="${WORK}/fakerepo-section"; fake_repo "${FR3}"
# Move OnFailure= out of [Unit] and into [Service], the exact shape that made
# every dockyard-backup failure silent for months.
awk '/^OnFailure=/{next} {print} /^\[Service\]/{print "OnFailure=trustissues-backup-alert@%n.service"}' \
  "${FR3}/deploy/systemd/trustissues-backup.service" > "${FR3}/deploy/systemd/tmp.service"
mv "${FR3}/deploy/systemd/tmp.service" "${FR3}/deploy/systemd/trustissues-backup.service"
run_install "${FR3}" "${WORK}/instroot-section"
if [ "${INSTALL_RC}" != "0" ] \
   && printf '%s' "${INSTALL_OUT}" | grep -q 'OnFailure= in \[Service\]'; then
  ok "install.sh refuses OnFailure= outside [Unit], where systemd silently drops it"
else
  bad "install.sh accepted OnFailure= in [Service] (exit ${INSTALL_RC}):
${INSTALL_OUT}"
fi

FR4="${WORK}/fakerepo-timer"; fake_repo "${FR4}"
# A timer pointed at a unit nobody installed. This is what the timer branch of
# the OnFailure check has to catch now that it no longer demands OnFailure= on
# the timer itself: a waived check would pass this.
sed 's/^Unit=trustissues-backup\.service$/Unit=trustissues-nope.service/' \
  "${FR4}/deploy/systemd/trustissues-backup.timer" > "${FR4}/deploy/systemd/tmp.timer"
mv "${FR4}/deploy/systemd/tmp.timer" "${FR4}/deploy/systemd/trustissues-backup.timer"
run_install "${FR4}" "${WORK}/instroot-timer"
if [ "${INSTALL_RC}" != "0" ] \
   && printf '%s' "${INSTALL_OUT}" | grep -q 'trustissues-nope.service'; then
  ok "install.sh refuses a timer that triggers a unit which is not installed"
else
  bad "install.sh accepted a timer pointing at a missing service (exit ${INSTALL_RC}):
${INSTALL_OUT}"
fi

echo "restore.sh --compose, against a real docker daemon"

# 45-48. The Compose branch, DRIVEN, not read.
#
# docker-compose.yml is the shipped deploy and `restore.sh --compose <snapshot>`
# is its documented restore, but this suite drove only the native branch: it
# contained the string "compose" exactly once, inside a comment. The Compose
# branch is also where the three least verifiable fixes live, and their own
# comments record why: `docker compose create` on a fresh host (without it,
# `docker compose cp` fails with "no container found" in exactly the total-loss
# case the procedure is written for), `--user 0` on the cleanup run (without it
# the chown cannot run, the restored file stays owned by whoever docker cp made
# it, and the app crash-loops on its first write right after a disaster), and the
# `test -w` proof that the service user can actually write what was restored.
#
# So: a real daemon, a real named volume, a real unprivileged image user, and the
# real script. The image is built from a locally present alpine and torn down at
# exit. On a host with no docker these cases SKIP, loudly, and the summary says so.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  CIMG="ti-restore-drill-test:$$"
  CPROJ="${WORK}/ti-compose-fresh"
  mkdir -p "${CPROJ}"
  cat > "${CPROJ}/Dockerfile" <<'DFEOF'
FROM alpine:3.21
RUN addgroup -S trustissues && adduser -S trustissues -G trustissues \
 && mkdir -p /app/data && chown trustissues:trustissues /app/data
WORKDIR /app
VOLUME ["/app/data"]
USER trustissues
ENTRYPOINT ["/bin/sh", "-c", "sleep 86400"]
DFEOF
  if docker build -q -t "${CIMG}" "${CPROJ}" >/dev/null 2>&1; then
    COMPOSE_IMAGE="${CIMG}"
    cat > "${CPROJ}/docker-compose.yml" <<DCEOF
services:
  trustissues:
    image: ${CIMG}
    volumes:
      - trustissues_data:/app/data
volumes:
  trustissues_data:
DCEOF
    COMPOSE_PROJECT_DIRS="${COMPOSE_PROJECT_DIRS} ${CPROJ}"

    CSNAPD="${WORK}/compose-backups"; mkdir -p "${CSNAPD}"
    make_snapshot "${CSNAPD}" "$(stamp_days_ago 0)"
    CSNAP="$(find "${CSNAPD}" -name 'trustissues-*.db' | head -1)"

    # 45. Fresh host: the compose project exists, no container does.
    CR_RC=0
    CR_OUT="$( cd "${CPROJ}" && "${HERE}/restore.sh" --compose "${CSNAP}" 2>&1 )" || CR_RC=$?
    if [ "${CR_RC}" = "0" ]; then
      ok "restore.sh --compose restores onto a fresh host with no container yet"
    else
      bad "restore.sh --compose failed on a fresh host (exit ${CR_RC}):
${CR_OUT}"
    fi

    # 46. The data is IN the volume and comes back out intact. Copying it back
    #     through docker and reading it with sqlite3 is the only assertion that
    #     the restore put a usable database where the app will look for it.
    CBACK="${WORK}/compose-roundtrip.db"
    ( cd "${CPROJ}" && docker compose cp trustissues:/app/data/trustissues.db "${CBACK}" ) >/dev/null 2>&1 || true
    if [ -f "${CBACK}" ] \
       && [ "$(sqlite3 "${CBACK}" 'PRAGMA integrity_check;' 2>&1)" = "ok" ] \
       && [ "$(sqlite3 "${CBACK}" "SELECT name FROM vault_entries WHERE id='e1';" 2>&1)" = "prod db password" ]; then
      ok "the restored database is in the volume, intact, with its rows"
    else
      bad "the database in the trustissues volume is missing or unreadable after a --compose restore"
    fi

    # 47. Owned by the service user and 0600, proved from inside the container.
    #     Without --user 0 on the cleanup run the chown cannot happen at all.
    COWN="$( cd "${CPROJ}" && docker compose run --rm --no-deps --user 0 --entrypoint sh trustissues \
      -c 'stat -c "%U %a" /app/data/trustissues.db' 2>/dev/null | tr -d '\r' )" || true
    if [ "${COWN}" = "trustissues 600" ]; then
      ok "the restored database is owned by the service user, mode 600, inside the volume"
    else
      bad "the restored database is '${COWN}' inside the volume, expected 'trustissues 600'; the app would crash-loop on its first write"
    fi

    # 48. Second restore over a volume holding a stale WAL and a root-owned
    #     database: the real re-restore, and the case that proves the sidecar
    #     removal and the chown both run on an existing container.
    ( cd "${CPROJ}" && docker compose run --rm --no-deps --user 0 --entrypoint sh trustissues -c \
        'echo stale > /app/data/trustissues.db-wal; echo stale > /app/data/trustissues.db-shm; chown root:root /app/data/trustissues.db' ) >/dev/null 2>&1 || true
    CR2_RC=0
    CR2_OUT="$( cd "${CPROJ}" && "${HERE}/restore.sh" --compose "${CSNAP}" 2>&1 )" || CR2_RC=$?
    CLS="$( cd "${CPROJ}" && docker compose run --rm --no-deps --user 0 --entrypoint sh trustissues \
      -c 'ls /app/data; stat -c "%U" /app/data/trustissues.db' 2>/dev/null | tr -d '\r' )" || true
    if [ "${CR2_RC}" = "0" ] \
       && ! printf '%s' "${CLS}" | grep -q 'trustissues.db-wal' \
       && ! printf '%s' "${CLS}" | grep -q 'trustissues.db-shm' \
       && printf '%s' "${CLS}" | grep -q '^trustissues$'; then
      ok "a re-restore clears the stale WAL/SHM sidecars and re-chowns the database"
    else
      bad "re-restore left sidecars or the wrong owner (exit ${CR2_RC}):
${CLS}
${CR2_OUT}"
    fi

    # 49. The writability proof must REFUSE when the service user cannot write.
    #     A compose file that pins `user:` to an id the image does not know is a
    #     plausible operator config, and it is the shape where the chown succeeds
    #     (root can always chown) and the app still cannot open its database.
    CPROJ2="${WORK}/ti-compose-nowrite"
    mkdir -p "${CPROJ2}"
    cat > "${CPROJ2}/docker-compose.yml" <<DC2EOF
services:
  trustissues:
    image: ${CIMG}
    user: "12345"
    volumes:
      - trustissues_data:/app/data
volumes:
  trustissues_data:
DC2EOF
    COMPOSE_PROJECT_DIRS="${COMPOSE_PROJECT_DIRS} ${CPROJ2}"
    CR3_RC=0
    CR3_OUT="$( cd "${CPROJ2}" && "${HERE}/restore.sh" --compose "${CSNAP}" 2>&1 )" || CR3_RC=$?
    if [ "${CR3_RC}" = "2" ] \
       && printf '%s' "${CR3_OUT}" | grep -q 'not writable by the service user'; then
      ok "restore.sh --compose refuses when the service user cannot write the restored database"
    else
      bad "restore.sh --compose reported success on a database the service user cannot write (exit ${CR3_RC}):
${CR3_OUT}"
    fi
  else
    skip "could not build the throwaway compose image, so the Compose restore branch was NOT exercised"
  fi
else
  skip "docker is not available here, so the Compose restore branch was NOT exercised"
fi

echo
echo "passed ${PASS}, failed ${FAIL}, skipped ${SKIPPED}"
if [ "${SKIPPED}" -gt 0 ]; then
  echo "WARNING: ${SKIPPED} case(s) did not run, so this green is narrower than it looks:${SKIP_WHY}"
fi
[ "${FAIL}" -eq 0 ]

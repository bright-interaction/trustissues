#!/usr/bin/env bash
#
# restore-drill.sh - restore the newest snapshot into a throwaway directory and
# prove a known row came back.
#
# A backup nobody has restored is a hypothesis. Everything upstream of this
# script checks that a file was WRITTEN: backup.sh integrity-checks what it just
# produced, the timer reports that the unit exited 0, the retention policy keeps
# the file around. None of that exercises the path you actually need at 3am,
# which is restore.sh putting the snapshot back and the data being there
# afterwards. The two have failed independently before: restore.sh's own header
# records a documented restore step that could not be performed at all, and the
# whole pair shipped through sixteen audit rounds with zero tests.
#
# So this runs the REAL restore.sh, into a temporary directory, on a schedule,
# and fails loudly when the answer is not the one it wanted. It never touches
# the live database and never starts the server.
#
# Usage:
#   ./scripts/restore-drill.sh /secure/backups
#   TRUSTISSUES_BACKUP_DIR=/secure/backups ./scripts/restore-drill.sh
#
# Env:
#   TRUSTISSUES_BACKUP_DIR         where snapshots live (or pass it as $1)
#   TRUSTISSUES_DATA_DIR           the LIVE data dir; used read-only to pick a
#                                  canary row. Optional, see "canary" below.
#   TRUSTISSUES_DRILL_MAX_AGE_HOURS  fail if the newest snapshot is older than
#                                  this (default 48, 0 disables)
#   TRUSTISSUES_DRILL_CANARY_SQL   a query to run against the restored copy
#   TRUSTISSUES_DRILL_CANARY_EXPECT  what that query must return
#   TRUSTISSUES_DRILL_KEEP=1       keep the throwaway directory for inspection
#
# Exit codes: 0 drill passed, 1 drill FAILED, 2 could not run the drill.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# Same reason as in prune-backups.sh: deploying is copying a list of files, and
# the shared library is the one that gets left off the list. Name it.
if [ ! -f "${HERE}/snapshot-lib.sh" ]; then
  echo "drill cannot run: ${HERE}/snapshot-lib.sh is missing; it must sit next to this script" >&2
  exit 2
fi
# shellcheck source=snapshot-lib.sh
. "${HERE}/snapshot-lib.sh"

fail()  { echo "DRILL FAILED: $*" >&2; exit 1; }
setup() { echo "drill cannot run: $*" >&2; exit 2; }

BACKUP_DIR="${1:-${TRUSTISSUES_BACKUP_DIR:-}}"
[ -n "${BACKUP_DIR}" ] || setup "no backup directory given (pass it as \$1 or set TRUSTISSUES_BACKUP_DIR)"
[ -d "${BACKUP_DIR}" ] || setup "backup directory not found: ${BACKUP_DIR}"
command -v sqlite3 >/dev/null 2>&1 || setup "sqlite3 CLI not found on PATH"
[ -x "${HERE}/restore.sh" ] || setup "restore.sh not found next to this script"

# 1. The newest snapshot, by the timestamp in its name.
#
# NOT `list_snapshots ... | head -1`. head exits after the first line, the
# producer takes SIGPIPE on its next write, and under `set -euo pipefail` the
# whole pipeline returns 141 and kills this script before a single assertion
# runs. It is a RACE, so it looks fine with two snapshots on a fast disk and
# starts aborting once a real backup directory has thirty of them: the drill
# would then exit non-zero, page the operator, and say nothing about why.
# Caught by ablation, and it is the same trap the estate's mirror gates were
# bitten by three times ("never judge a pipeline on its exit status").
#
# Reading the whole list into a variable and taking the first line with
# parameter expansion has no pipeline and no subprocess at all.
SNAPSHOT_LIST="$(list_snapshots "${BACKUP_DIR}")"
SNAPSHOT="${SNAPSHOT_LIST%%$'\n'*}"
[ -n "${SNAPSHOT}" ] || fail "there are no snapshots in ${BACKUP_DIR} at all"
SNAP_BASE="$(basename "${SNAPSHOT}")"

# 2. Freshness. This is the check that catches the failure this whole workstream
#    exists to prevent: the timer silently stopped weeks ago and every drill
#    since has been happily proving that an ancient file still restores. A drill
#    that passes on a three month old snapshot is worse than no drill, because
#    it reports green.
MAX_AGE_HOURS="${TRUSTISSUES_DRILL_MAX_AGE_HOURS:-48}"
NOW_EPOCH="$(date -u +%s)"
SNAP_EPOCH="$(snapshot_epoch "${SNAP_BASE}")"
AGE_HOURS=$(((NOW_EPOCH - SNAP_EPOCH) / 3600))
if [ "${MAX_AGE_HOURS}" != "0" ] && [ "${AGE_HOURS}" -gt "${MAX_AGE_HOURS}" ]; then
  fail "the newest snapshot ${SNAP_BASE} is ${AGE_HOURS}h old (limit ${MAX_AGE_HOURS}h). The backup timer is not running: check 'systemctl status trustissues-backup.timer'."
fi

# 3. Read the facts out of the snapshot BEFORE restoring, so the comparison
#    afterwards is against something recorded, not against the same file read
#    twice.
SNAP_TABLES="$(sqlite3 "${SNAPSHOT}" \
  "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';" 2>&1)" \
  || fail "cannot read ${SNAP_BASE} at all: ${SNAP_TABLES}"
printf '%s' "${SNAP_TABLES}" | grep -Eq '^[0-9]+$' \
  || fail "cannot read the schema of ${SNAP_BASE}: ${SNAP_TABLES}"
SNAP_ENTRIES="$(sqlite3 "${SNAPSHOT}" "SELECT count(*) FROM vault_entries;" 2>/dev/null || echo "")"

# 4. The canary. In priority order, so the strongest available check wins:
#      a. an operator-supplied query, when they know a row that must be there
#      b. the oldest row in the LIVE vault, read-only. Oldest, not newest:
#         anything created after the snapshot legitimately will not be in it,
#         so asserting on a recent row would fail on a healthy system.
#      c. the snapshot's own oldest row, which still proves the round trip moved
#         the data even though it cannot prove the snapshot matches production.
#    Whichever runs is named in the output. A drill that will not say what it
#    checked is not evidence.
CANARY_KIND=""
CANARY_SQL=""
CANARY_EXPECT=""

if [ -n "${TRUSTISSUES_DRILL_CANARY_SQL:-}" ]; then
  [ -n "${TRUSTISSUES_DRILL_CANARY_EXPECT:-}" ] \
    || setup "TRUSTISSUES_DRILL_CANARY_SQL is set but TRUSTISSUES_DRILL_CANARY_EXPECT is not"
  CANARY_KIND="operator-supplied query"
  CANARY_SQL="${TRUSTISSUES_DRILL_CANARY_SQL}"
  CANARY_EXPECT="${TRUSTISSUES_DRILL_CANARY_EXPECT}"
else
  LIVE_DB="${TRUSTISSUES_DATA_DIR:-}/trustissues.db"
  LIVE_ID=""
  if [ -n "${TRUSTISSUES_DATA_DIR:-}" ] && [ -f "${LIVE_DB}" ]; then
    # -readonly, so a drill can never write to, checkpoint, or lock the live
    # database it is reporting on. If the open fails for any reason (a WAL with
    # no -shm and a read-only directory is the usual one) fall through quietly
    # to the snapshot canary rather than failing the drill: the live database is
    # a nice-to-have here, not the subject.
    LIVE_ID="$(sqlite3 -readonly "${LIVE_DB}" \
      "SELECT id FROM vault_entries ORDER BY rowid LIMIT 1;" 2>/dev/null || echo "")"
  fi
  if [ -n "${LIVE_ID}" ]; then
    CANARY_KIND="oldest live vault entry (id ${LIVE_ID})"
    CANARY_SQL="SELECT count(*) FROM vault_entries WHERE id='${LIVE_ID}';"
    CANARY_EXPECT="1"
  else
    SNAP_ID="$(sqlite3 "${SNAPSHOT}" \
      "SELECT id FROM vault_entries ORDER BY rowid LIMIT 1;" 2>/dev/null || echo "")"
    if [ -n "${SNAP_ID}" ]; then
      CANARY_KIND="oldest vault entry in the snapshot (id ${SNAP_ID})"
      CANARY_SQL="SELECT count(*) FROM vault_entries WHERE id='${SNAP_ID}';"
      CANARY_EXPECT="1"
    else
      # An empty vault is a legitimate state (a brand new instance), and the
      # drill still has to mean something there, so fall back to the schema
      # itself. Named as a weak canary in the output so nobody reads this as
      # "a row survived" when no row existed.
      CANARY_KIND="schema only (the vault has no entries to check)"
      CANARY_SQL="SELECT count(*) FROM sqlite_master WHERE type='table' AND name='vault_entries';"
      CANARY_EXPECT="1"
    fi
  fi
fi

# 5. Throwaway destination.
DRILL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trustissues-drill.XXXXXX")"
if [ "${TRUSTISSUES_DRILL_KEEP:-}" = "1" ]; then
  trap 'echo "drill directory kept at ${DRILL_DIR}"' EXIT
else
  trap 'rm -rf "${DRILL_DIR}"' EXIT
fi
chmod 700 "${DRILL_DIR}"

# The one thing this script must never do is restore over production. mktemp
# will not hand back a path inside the data dir, but the cost of checking is one
# string comparison and the cost of being wrong is the live vault.
if [ -n "${TRUSTISSUES_DATA_DIR:-}" ]; then
  LIVE_ABS="$(cd "${TRUSTISSUES_DATA_DIR}" 2>/dev/null && pwd || echo "")"
  DRILL_ABS="$(cd "${DRILL_DIR}" && pwd)"
  case "${DRILL_ABS}/" in
    "${LIVE_ABS}"/*) fail "the drill directory ${DRILL_ABS} is inside the LIVE data dir; refusing" ;;
  esac
fi

echo "restore drill"
echo "  snapshot: ${SNAP_BASE} (${AGE_HOURS}h old)"
echo "  into:     ${DRILL_DIR}"
echo "  canary:   ${CANARY_KIND}"

# 6. The real restore, through restore.sh, not a cp.
#
# TRUSTISSUES_RESTORE_FORCE=1 is correct HERE and nowhere else: it only disables
# restore.sh's "I cannot prove the service is stopped" refusal, and the target
# is a directory mktemp created three lines ago, so nothing can be holding it
# open. Without it the drill fails on any host that ships neither lsof nor
# fuser, which is most slim containers, and a drill that cannot run in the
# container is a drill nobody runs.
RESTORE_OUT="$(TRUSTISSUES_DATA_DIR="${DRILL_DIR}" TRUSTISSUES_RESTORE_FORCE=1 \
  "${HERE}/restore.sh" "${SNAPSHOT}" 2>&1)" \
  || fail "restore.sh refused or errored on ${SNAP_BASE}:
${RESTORE_OUT}"

RESTORED="${DRILL_DIR}/trustissues.db"
[ -f "${RESTORED}" ] || fail "restore.sh exited 0 but produced no ${RESTORED}"

# 7. Assertions on what came out the other end.
POST_INTEGRITY="$(sqlite3 "${RESTORED}" 'PRAGMA integrity_check;' 2>&1 || true)"
[ "${POST_INTEGRITY}" = "ok" ] \
  || fail "the RESTORED database fails integrity_check: ${POST_INTEGRITY}"

POST_TABLES="$(sqlite3 "${RESTORED}" \
  "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';" 2>&1 || true)"
[ "${POST_TABLES}" = "${SNAP_TABLES}" ] \
  || fail "the restored database has ${POST_TABLES} tables, the snapshot had ${SNAP_TABLES}"

if [ -n "${SNAP_ENTRIES}" ]; then
  POST_ENTRIES="$(sqlite3 "${RESTORED}" "SELECT count(*) FROM vault_entries;" 2>&1 || true)"
  [ "${POST_ENTRIES}" = "${SNAP_ENTRIES}" ] \
    || fail "vault_entries went from ${SNAP_ENTRIES} rows in the snapshot to ${POST_ENTRIES} after restore"
fi

# Sidecars from an earlier database in this directory would let SQLite recover
# somebody else's tail over the restored file. There is no earlier database in a
# fresh mktemp dir, which is exactly why finding one here means restore.sh
# stopped removing them.
if [ -f "${RESTORED}-wal" ] || [ -f "${RESTORED}-shm" ]; then
  fail "restore.sh left WAL/SHM sidecars next to the restored database"
fi

# The snapshot is credentials. If the restore path widens the mode, every drill
# leaves a world-readable copy of the vault in the temp directory.
MODE="$(file_mode "${RESTORED}")"
if [ -n "${MODE}" ] && [ "${MODE}" != "600" ]; then
  fail "the restored database is mode ${MODE}, expected 600"
fi

CANARY_GOT="$(sqlite3 "${RESTORED}" "${CANARY_SQL}" 2>&1 || true)"
[ "${CANARY_GOT}" = "${CANARY_EXPECT}" ] \
  || fail "the canary row did not survive the round trip: expected '${CANARY_EXPECT}', got '${CANARY_GOT}' (${CANARY_KIND})"

SIZE="$(wc -c < "${RESTORED}" | tr -d ' ')"
echo "  ok: integrity_check clean, ${POST_TABLES} tables, ${SIZE} bytes, canary matched"
echo "DRILL PASSED: ${SNAP_BASE} restores and the canary row survived"

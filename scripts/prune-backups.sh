#!/usr/bin/env bash
#
# prune-backups.sh - keep N daily and M weekly snapshots, delete the rest.
#
# A scheduled backup with no retention is a scheduled outage. backup.sh writes a
# full copy of the database every run, so an hourly timer against a 200MB vault
# fills 4.8GB a day, and the disk it fills is the one the LIVE DATABASE is on
# (see the volume warning in backup.sh and docs/BACKUP.md). SQLite handles a
# full disk by failing writes, so unbounded backups take the product down and
# then corrupt the newest backup on the way.
#
# Policy, matching the shape restic uses so it is not a new thing to learn:
#
#   TRUSTISSUES_BACKUP_KEEP_DAILY   the newest snapshot of each of the last N
#                                   distinct UTC days                (default 7)
#   TRUSTISSUES_BACKUP_KEEP_WEEKLY  the newest snapshot of each of the last M
#                                   distinct 7-day blocks            (default 4)
#
# The two policies are independent and overlap freely: a snapshot kept as a
# daily also counts as its week's keeper. So the defaults hold roughly ten
# files, not eleven, and the exact set is deterministic from the file names.
# "7-day blocks" are counted from the epoch (Thursday to Wednesday), not ISO
# calendar weeks. See scripts/snapshot-lib.sh.
#
# Usage:
#   ./scripts/prune-backups.sh /secure/backups
#   ./scripts/prune-backups.sh --dry-run /secure/backups
#   TRUSTISSUES_BACKUP_KEEP_DAILY=14 ./scripts/prune-backups.sh /secure/backups
#
# Exit codes: 0 ok, 1 usage/precondition error.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# Say which file is missing rather than letting bash say
# "prune-backups.sh: line 39: .../snapshot-lib.sh: No such file or directory".
# Deploying these scripts means copying a LIST of files to /opt/trustissues, and
# a library that only some of them mention is exactly the one left behind. The
# symptom then appears at 03:20 in a cron log, not at install time.
if [ ! -f "${HERE}/snapshot-lib.sh" ]; then
  echo "error: ${HERE}/snapshot-lib.sh is missing; it must sit next to this script" >&2
  exit 1
fi
# shellcheck source=snapshot-lib.sh
. "${HERE}/snapshot-lib.sh"

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ] || [ "${1:-}" = "-n" ]; then
  DRY_RUN=1
  shift
fi

DEST_DIR="${1:-${TRUSTISSUES_BACKUP_DIR:-}}"
if [ -z "${DEST_DIR}" ]; then
  echo "usage: $0 [--dry-run] <backup-directory>" >&2
  echo "  or set TRUSTISSUES_BACKUP_DIR" >&2
  exit 1
fi
if [ ! -d "${DEST_DIR}" ]; then
  echo "error: backup directory not found: ${DEST_DIR}" >&2
  exit 1
fi

KEEP_DAILY="${TRUSTISSUES_BACKUP_KEEP_DAILY:-7}"
KEEP_WEEKLY="${TRUSTISSUES_BACKUP_KEEP_WEEKLY:-4}"

# Reject a policy rather than enforcing it literally.
#
# `KEEP_DAILY=0 KEEP_WEEKLY=0` is a perfectly well-formed instruction to delete
# every backup that exists, and a typo or an unset variable in an EnvironmentFile
# produces exactly that string. There is no legitimate reason to run this script
# to end up with nothing, so it refuses instead of obeying. Non-numeric input is
# refused for the same reason: `[ "" -lt 1 ]` is a syntax error under set -e in
# some shells and a silent 0 in others, and neither is a safe way to decide
# whether to delete the only copy of a credential store.
for pair in "TRUSTISSUES_BACKUP_KEEP_DAILY=${KEEP_DAILY}" "TRUSTISSUES_BACKUP_KEEP_WEEKLY=${KEEP_WEEKLY}"; do
  val="${pair#*=}"
  if ! printf '%s' "${val}" | grep -Eq '^[0-9]+$'; then
    echo "error: ${pair%%=*} must be a non-negative integer, got '${val}'" >&2
    exit 1
  fi
done
if [ "${KEEP_DAILY}" -eq 0 ] && [ "${KEEP_WEEKLY}" -eq 0 ]; then
  echo "error: keeping 0 daily AND 0 weekly would delete every snapshot; refusing" >&2
  exit 1
fi

SNAPSHOTS="$(list_snapshots "${DEST_DIR}")"
if [ -z "${SNAPSHOTS}" ]; then
  echo "prune: no snapshots in ${DEST_DIR}, nothing to do"
  exit 0
fi

# Membership sets as space-delimited strings rather than associative arrays:
# macOS still ships bash 3.2, where `declare -A` is a parse error, and an
# operator running the drill from a laptop is a case this has to survive.
seen_daily=" "
seen_weekly=" "
n_daily=0
n_weekly=0
KEEP_LIST=""
DELETE_LIST=""

while IFS= read -r path; do
  [ -n "${path}" ] || continue
  base="$(basename "${path}")"
  day="$(snapshot_day "${base}")"
  week="$(snapshot_week "${base}")"
  keep=0

  # Newest first, so the FIRST snapshot seen for a bucket is that bucket's
  # newest, which is the one both policies want.
  case "${seen_daily}" in
    *" ${day} "*) : ;;
    *)
      if [ "${n_daily}" -lt "${KEEP_DAILY}" ]; then
        seen_daily="${seen_daily}${day} "
        n_daily=$((n_daily + 1))
        keep=1
      fi
      ;;
  esac
  case "${seen_weekly}" in
    *" ${week} "*) : ;;
    *)
      if [ "${n_weekly}" -lt "${KEEP_WEEKLY}" ]; then
        seen_weekly="${seen_weekly}${week} "
        n_weekly=$((n_weekly + 1))
        keep=1
      fi
      ;;
  esac

  if [ "${keep}" -eq 1 ]; then
    KEEP_LIST="${KEEP_LIST}${path}
"
  else
    DELETE_LIST="${DELETE_LIST}${path}
"
  fi
done <<EOF
${SNAPSHOTS}
EOF

# Belt and braces on top of the policy arithmetic: whatever the buckets worked
# out to, the newest snapshot is never a deletion candidate. If this ever fires
# it means the bucket logic is wrong, and the failure mode of wrong bucket logic
# must not be "the only current backup is gone".
# First line by parameter expansion, not `| head -1`: head closes the pipe after
# one line and the producer takes SIGPIPE, which under `set -euo pipefail` makes
# the pipeline return 141 and aborts the prune. It is a race, so it passes with a
# handful of snapshots and starts failing once the directory is full, which is
# precisely when retention has to run. Same defect, same day, in restore-drill.sh.
NEWEST="${SNAPSHOTS%%$'\n'*}"
case "
${DELETE_LIST}" in
  *"
${NEWEST}
"*)
    echo "error: the retention policy selected the NEWEST snapshot for deletion" >&2
    echo "       (${NEWEST}); this is a bug in prune-backups.sh, refusing to delete anything" >&2
    exit 1
    ;;
esac

KEPT_N="$(printf '%s' "${KEEP_LIST}" | grep -c . || true)"
DEL_N="$(printf '%s' "${DELETE_LIST}" | grep -c . || true)"

echo "prune: ${DEST_DIR}"
echo "  policy: keep ${KEEP_DAILY} daily, ${KEEP_WEEKLY} weekly"
echo "  keeping ${KEPT_N}, removing ${DEL_N}"

while IFS= read -r path; do
  [ -n "${path}" ] || continue
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "  would remove $(basename "${path}")"
  else
    rm -f -- "${path}"
    echo "  removed $(basename "${path}")"
  fi
done <<EOF
${DELETE_LIST}
EOF

# Stale .part files are the other way this directory grows without bound.
#
# backup.sh removes its own .part on any normal failure via a trap, but a
# SIGKILL, an OOM kill or a yanked power cord skips the trap and leaves a
# partial copy of the whole database behind. Those never expire under the
# retention policy above (they are not snapshots, and deliberately so: they must
# never be picked for restore). Anything still named .part a day later cannot be
# an in-flight backup, so it is dead weight. The age check is what keeps this
# from racing a backup that is running right now.
STALE_PARTS="$(find "${DEST_DIR}" -maxdepth 1 -type f -name 'trustissues-*.db.part' -mtime +0 2>/dev/null || true)"
if [ -n "${STALE_PARTS}" ]; then
  while IFS= read -r path; do
    [ -n "${path}" ] || continue
    if [ "${DRY_RUN}" -eq 1 ]; then
      echo "  would remove stale partial $(basename "${path}")"
    else
      rm -f -- "${path}"
      echo "  removed stale partial $(basename "${path}")"
    fi
  done <<EOF
${STALE_PARTS}
EOF
fi

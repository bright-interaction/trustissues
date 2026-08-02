#!/usr/bin/env bash
#
# backup.sh - take a consistent, WAL-safe snapshot of the Trustissues database.
#
# Trustissues runs SQLite in WAL mode, so a naive `cp trustissues.db` can copy a
# torn or stale file: recent commits live in the -wal sidecar until a checkpoint.
# This script uses SQLite's online backup API (via the sqlite3 CLI ".backup"
# command), which produces a single consistent file even while the server is
# running, then locks the copy down to mode 0600.
#
# It backs up ONLY the database. The database holds AES-256-GCM ciphertext; it is
# useless to a thief without TRUSTISSUES_VAULT_KEY. That is exactly why the key
# must be stored somewhere else. Never put this backup and the vault key in the
# same place: together they are plaintext.
#
# Usage:
#   TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/backup.sh /secure/backups
#   ./scripts/backup.sh /secure/backups            # uses TRUSTISSUES_DATA_DIR or ./data
#   TRUSTISSUES_BACKUP_DIR=/secure/backups ./scripts/backup.sh   # destination from env
#
# Env:
#   TRUSTISSUES_DATA_DIR      the live data dir holding trustissues.db (default ./data)
#   TRUSTISSUES_BACKUP_DIR    destination, when not given as $1
#   TRUSTISSUES_BACKUP_PRUNE  set to 1 to run scripts/prune-backups.sh after a
#                             successful snapshot (opt-in: see the note below)
#
# Exit codes: 0 ok, 1 usage/precondition error, 2 backup failed.
#
# See docs/BACKUP.md for the full backup + restore + key-custody procedure.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

DATA_DIR="${TRUSTISSUES_DATA_DIR:-./data}"
DB_NAME="trustissues.db"
DB_PATH="${DATA_DIR%/}/${DB_NAME}"

# The destination is also readable from the environment, because a systemd unit
# configures itself from an EnvironmentFile and cannot pass positional arguments
# without hardcoding the path into the shipped unit file. An explicit $1 still
# wins, so every documented command line keeps working unchanged.
DEST_DIR="${1:-${TRUSTISSUES_BACKUP_DIR:-}}"
if [ -z "${DEST_DIR}" ]; then
  echo "usage: $0 <backup-directory>" >&2
  echo "  or set TRUSTISSUES_BACKUP_DIR" >&2
  echo "  set TRUSTISSUES_DATA_DIR to point at the live data dir (default ./data)" >&2
  exit 1
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "error: sqlite3 CLI not found on PATH; install it or run the .backup inside the container" >&2
  exit 1
fi

if [ ! -f "${DB_PATH}" ]; then
  echo "error: database not found at ${DB_PATH}" >&2
  echo "  set TRUSTISSUES_DATA_DIR to the directory that holds ${DB_NAME}" >&2
  exit 1
fi

mkdir -p "${DEST_DIR}"

# Refuse to write snapshots INTO the live data directory.
#
# It looks harmless (the names never collide with trustissues.db) right up to
# the moment prune-backups.sh runs, at which point an automated `rm` is loose
# inside the directory that holds the only live copy of the vault. Retention and
# the live database must not share a directory, full stop. A separate directory
# on the same disk is merely bad, and warned about below; the same directory is
# refused.
#
# pwd -P, not pwd. This guard used to compare LOGICAL paths, and bash's
# `cd sym && pwd` prints the symlink you asked for rather than the directory you
# landed in. So `ln -s <data dir> <backup dir>` walked straight past it: backup.sh
# exited 0 and the live data dir ended up holding trustissues-<stamp>.db next to
# trustissues.db. With TRUSTISSUES_BACKUP_PRUNE=1, which the shipped
# trustissues-backup.service sets, that is exactly the automated rm inside the
# live data dir that the paragraph above says must never happen. The physical
# path is the only spelling two names for one directory agree on.
DEST_ABS="$(cd "${DEST_DIR}" && pwd -P)"
DATA_ABS="$(cd "${DATA_DIR}" && pwd -P)"
if [ "${DEST_ABS}" = "${DATA_ABS}" ]; then
  echo "error: the backup destination is the live data directory (${DEST_ABS})" >&2
  echo "       Snapshots must not live beside the database they protect: retention" >&2
  echo "       pruning would then be deleting files inside the live data dir." >&2
  exit 1
fi

# Warn when they merely share a filesystem.
#
# The shipped Compose deploy puts the database in the trustissues_data volume,
# and the obvious place to point this script is a subdirectory of that same
# volume. That arrangement survives "I deleted a row" and nothing else: one full
# disk, one corrupt filesystem, one `docker volume rm` takes the database and
# every snapshot of it in the same instant. Warn, do not refuse, because a
# single-disk box with an off-box copy job downstream is a legitimate setup.
if command -v df >/dev/null 2>&1; then
  DEST_FS="$(df -P "${DEST_ABS}" 2>/dev/null | awk 'NR==2{print $1}' || true)"
  DATA_FS="$(df -P "${DATA_ABS}" 2>/dev/null | awk 'NR==2{print $1}' || true)"
  if [ -n "${DEST_FS}" ] && [ "${DEST_FS}" = "${DATA_FS}" ]; then
    echo "warning: ${DEST_ABS} is on the same filesystem as the database (${DEST_FS})." >&2
    echo "         A full disk or a lost volume takes the database AND every backup" >&2
    echo "         of it at once. Point TRUSTISSUES_BACKUP_DIR at separate storage." >&2
  fi
fi

# Create the destination file with tight perms before sqlite writes into it, so
# the snapshot never briefly exists as world-readable.
umask 077

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST_PATH="${DEST_DIR%/}/trustissues-${STAMP}.db"

# Write to a .part name and rename only once the copy is complete AND verified.
#
# This used to write straight to the final name. The error branch cleans up
# after a non-zero exit, but a SIGKILL, a full disk or a yanked power cord skips
# that branch entirely and leaves a truncated file sitting under the real
# backup name, byte-indistinguishable from a good one until the day it is
# restored. A rename is atomic within a filesystem, so a file at the final name
# now means "sqlite finished and the result verified".
PART_PATH="${DEST_PATH}.part"
trap 'rm -f "${PART_PATH}"' EXIT

# .backup uses the online backup API: a consistent, WAL-safe copy of the live DB.
if ! sqlite3 "${DB_PATH}" ".backup '${PART_PATH}'"; then
  echo "error: sqlite backup failed" >&2
  exit 2
fi

# Verify what was just written rather than trusting the exit status. A backup
# nobody can restore is worse than a failed backup, because it is silent, and
# this is the last moment the live database is still available to redo it.
INTEGRITY="$(sqlite3 "${PART_PATH}" 'PRAGMA integrity_check;' 2>&1 || true)"
if [ "${INTEGRITY}" != "ok" ]; then
  echo "error: the snapshot just written fails integrity_check; not keeping it" >&2
  echo "       sqlite3 said: ${INTEGRITY}" >&2
  exit 2
fi

chmod 600 "${PART_PATH}"
mv "${PART_PATH}" "${DEST_PATH}"
trap - EXIT

echo "backup written: ${DEST_PATH}"

# Retention, opt-in.
#
# Pruning is deliberately NOT the default. This script is the thing an operator
# reaches for by hand when they are about to do something frightening, and a
# hand-run backup that silently deletes older snapshots as a side effect is the
# opposite of what they wanted. The scheduled path (deploy/systemd) sets
# TRUSTISSUES_BACKUP_PRUNE=1 explicitly, because THAT path is the one that fills
# the disk.
#
# The alternative was to leave retention out of this script entirely and let the
# unit call two commands. It is here instead so the notice below exists: an
# operator running from cron with no retention needs to be told once, in the
# output they are already reading, that the directory grows without bound.
if [ "${TRUSTISSUES_BACKUP_PRUNE:-}" = "1" ]; then
  echo
  "${HERE}/prune-backups.sh" "${DEST_DIR}"
else
  echo "note: retention is OFF, so ${DEST_DIR} grows by one full database copy per run."
  echo "      Enable it with TRUSTISSUES_BACKUP_PRUNE=1, or run scripts/prune-backups.sh."
fi

echo
echo "REMINDER: this file is ciphertext. Store TRUSTISSUES_VAULT_KEY separately."
echo "  A backup + the vault key in the same place is the same as no encryption."
echo "  Losing the key makes this and every other backup permanently unreadable."

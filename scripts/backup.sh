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
#
# Exit codes: 0 ok, 1 usage/precondition error, 2 backup failed.
#
# See docs/BACKUP.md for the full backup + restore + key-custody procedure.

set -euo pipefail

DATA_DIR="${TRUSTISSUES_DATA_DIR:-./data}"
DB_NAME="trustissues.db"
DB_PATH="${DATA_DIR%/}/${DB_NAME}"

DEST_DIR="${1:-}"
if [ -z "${DEST_DIR}" ]; then
  echo "usage: $0 <backup-directory>" >&2
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
echo
echo "REMINDER: this file is ciphertext. Store TRUSTISSUES_VAULT_KEY separately."
echo "  A backup + the vault key in the same place is the same as no encryption."
echo "  Losing the key makes this and every other backup permanently unreadable."

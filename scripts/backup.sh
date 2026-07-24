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

# .backup uses the online backup API: a consistent, WAL-safe copy of the live DB.
if ! sqlite3 "${DB_PATH}" ".backup '${DEST_PATH}'"; then
  echo "error: sqlite backup failed" >&2
  rm -f "${DEST_PATH}"
  exit 2
fi

chmod 600 "${DEST_PATH}"

echo "backup written: ${DEST_PATH}"
echo
echo "REMINDER: this file is ciphertext. Store TRUSTISSUES_VAULT_KEY separately."
echo "  A backup + the vault key in the same place is the same as no encryption."
echo "  Losing the key makes this and every other backup permanently unreadable."

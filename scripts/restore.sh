#!/usr/bin/env bash
#
# restore.sh - put a snapshot back, in both the bare-metal and Compose layouts.
#
# This exists because the documented restore had a step nobody could perform. It
# said to remove the stale -wal/-shm sidecars so SQLite opens the restored file
# cleanly, which is correct and important: leaving them in place lets SQLite
# recover the OLD database's tail over your restored file, silently undoing the
# restore. But for the Compose deploy the data lives inside a named volume, and
# the only tool the docs offered was `docker compose exec`, which requires a
# RUNNING container. Starting the container is precisely the thing that performs
# that unwanted recovery, so the instruction could only be followed by doing the
# damaging thing first.
#
# Both modes here work with the service stopped, and neither starts it.
#
# Usage:
#   # bare metal
#   TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/restore.sh /secure/backups/trustissues-....db
#
#   # docker compose (run from the directory holding docker-compose.yml)
#   ./scripts/restore.sh --compose /secure/backups/trustissues-....db
#
# Exit codes: 0 ok, 1 usage/precondition error, 2 restore failed.
#
# See docs/BACKUP.md. Restoring under the WRONG TRUSTISSUES_VAULT_KEY is not
# recoverable by any tool: verify by revealing a secret after starting up.

set -euo pipefail

MODE="native"
if [ "${1:-}" = "--compose" ]; then
  MODE="compose"
  shift
fi

SNAPSHOT="${1:-}"
if [ -z "${SNAPSHOT}" ]; then
  echo "usage: $0 [--compose] <snapshot.db>" >&2
  exit 1
fi
if [ ! -f "${SNAPSHOT}" ]; then
  echo "error: snapshot not found: ${SNAPSHOT}" >&2
  exit 1
fi
# A truncated or non-SQLite file restored over a good database is unrecoverable,
# so refuse anything that is not a SQLite 3 image before touching the target.
if ! head -c 16 "${SNAPSHOT}" | grep -q "SQLite format 3"; then
  echo "error: ${SNAPSHOT} is not a SQLite 3 database; refusing to restore it" >&2
  exit 1
fi

SERVICE="${TRUSTISSUES_COMPOSE_SERVICE:-trustissues}"

if [ "${MODE}" = "compose" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker not found on PATH" >&2
    exit 1
  fi
  # The container MUST be stopped. A running writer would checkpoint its old WAL
  # over the file we are about to replace.
  if [ -n "$(docker compose ps -q "${SERVICE}" 2>/dev/null)" ] && \
     docker compose ps --status running "${SERVICE}" 2>/dev/null | grep -q "${SERVICE}"; then
    echo "error: ${SERVICE} is still running. Run 'docker compose stop ${SERVICE}' first," >&2
    echo "       otherwise the live writer will overwrite the restored file." >&2
    exit 1
  fi

  echo "restoring into the ${SERVICE} volume (container stopped)..."
  docker compose cp "${SNAPSHOT}" "${SERVICE}:/app/data/trustissues.db"
  # Remove the sidecars WITHOUT starting the service: a one-shot container with
  # no entrypoint, sharing the same volume.
  docker compose run --rm --no-deps --entrypoint sh "${SERVICE}" -c \
    'rm -f /app/data/trustissues.db-wal /app/data/trustissues.db-shm && chmod 600 /app/data/trustissues.db' \
    || { echo "error: could not clear WAL sidecars inside the volume" >&2; exit 2; }
  echo "done. Start with: docker compose up -d ${SERVICE}"
else
  DATA_DIR="${TRUSTISSUES_DATA_DIR:-./data}"
  DB_PATH="${DATA_DIR%/}/trustissues.db"
  if [ ! -d "${DATA_DIR}" ]; then
    echo "error: data dir not found: ${DATA_DIR}" >&2
    exit 1
  fi
  # Refuse while something still holds the database open, when we can tell.
  if command -v fuser >/dev/null 2>&1 && fuser "${DB_PATH}" >/dev/null 2>&1; then
    echo "error: ${DB_PATH} is open by another process; stop Trustissues first" >&2
    exit 1
  fi

  echo "restoring ${DB_PATH}..."
  cp "${SNAPSHOT}" "${DB_PATH}"
  rm -f "${DB_PATH}-wal" "${DB_PATH}-shm"
  chmod 600 "${DB_PATH}"
  echo "done. Start Trustissues with the SAME TRUSTISSUES_VAULT_KEY the snapshot was taken under."
fi

echo
echo "Verify before you trust it: log in, unlock the vault, reveal one secret."
echo "Cleartext means the key and the snapshot match. '[decryption error]' means"
echo "you restored under the wrong key: stop, keep your good backup, find the key."

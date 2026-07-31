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

# ...but those 16 bytes are the FIRST 16 of the file, so a snapshot truncated at
# any point after the header passes them. backup.sh writes with the online
# backup API, which is safe, yet the file can still be cut short by a full disk,
# a killed process or a partial copy off the box, and this script then destroys
# the live database in place. Header bytes are a filetype check, not an
# integrity check.
#
# integrity_check walks the whole b-tree, so it reads the parts a truncated file
# does not have. Skipped only when sqlite3 is genuinely absent, and then it says
# so rather than implying the snapshot was verified.
if command -v sqlite3 >/dev/null 2>&1; then
  echo "verifying snapshot integrity (this reads the whole file)..."
  INTEGRITY="$(sqlite3 "${SNAPSHOT}" 'PRAGMA integrity_check;' 2>&1 || true)"
  if [ "${INTEGRITY}" != "ok" ]; then
    echo "error: ${SNAPSHOT} fails integrity_check; refusing to restore it" >&2
    echo "       sqlite3 said: ${INTEGRITY}" >&2
    echo "       Keep this file, and try an older snapshot." >&2
    exit 1
  fi
  # A structurally valid database from a DIFFERENT product would also pass, and
  # restoring one is the same lost-vault outcome.
  if ! sqlite3 "${SNAPSHOT}" \
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_entries';" | grep -q 1; then
    echo "error: ${SNAPSHOT} has no vault_entries table; this is not a Trustissues database" >&2
    exit 1
  fi
else
  echo "warning: sqlite3 not found, so the snapshot was NOT integrity-checked." >&2
  echo "         Only its first 16 bytes were verified. A truncated file will restore." >&2
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

  # `docker compose cp` needs a container to exist. On a FRESH host, which is
  # the total-host-loss case this whole procedure is written for, none does:
  # the operator has a compose file and a snapshot and nothing else, and the cp
  # below failed with "no container found". Starting the service to create one
  # is the damaging act this script exists to avoid, because the server would
  # boot on an empty volume, run migrations and write a key sentinel before the
  # snapshot was ever in place.
  #
  # `create` makes the container and its volume WITHOUT starting it, which is
  # exactly the state the rest of this branch already assumes. It is a no-op
  # when the container is already there.
  if [ -z "$(docker compose ps -aq "${SERVICE}" 2>/dev/null)" ]; then
    echo "no ${SERVICE} container yet (fresh host); creating it stopped so the volume exists..."
    if ! docker compose create "${SERVICE}" >/dev/null 2>&1; then
      echo "error: could not create the ${SERVICE} container; check docker-compose.yml and .env" >&2
      exit 2
    fi
  fi

  echo "restoring into the ${SERVICE} volume (container stopped)..."
  docker compose cp "${SNAPSHOT}" "${SERVICE}:/app/data/trustissues.db"
  # Remove the sidecars WITHOUT starting the service: a one-shot container with
  # no entrypoint, sharing the same volume.
  # Run the cleanup as ROOT inside the one-shot container, because
  # `docker compose cp` writes the file owned by the host user (root), and the
  # service runs as the unprivileged `trustissues` user. Without the chown the
  # restored database is readable but not writable by the app, so it starts and
  # then crash-loops on the first write, right after a disaster recovery. chown
  # needs root, which is why --user 0 is here and not just chmod.
  docker compose run --rm --no-deps --user 0 --entrypoint sh "${SERVICE}" -c \
    'rm -f /app/data/trustissues.db-wal /app/data/trustissues.db-shm \
     && chown trustissues:trustissues /app/data/trustissues.db \
     && chmod 600 /app/data/trustissues.db' \
    || { echo "error: could not clear WAL sidecars or fix ownership inside the volume" >&2; exit 2; }

  # Prove the service user can actually WRITE it, rather than assuming the chown
  # landed. A restore that only looks right is how you find out at 3am.
  if ! docker compose run --rm --no-deps --entrypoint sh "${SERVICE}" -c \
      'test -w /app/data/trustissues.db'; then
    echo "error: the restored database is not writable by the service user; the app would crash-loop" >&2
    exit 2
  fi
  echo "done. Start with: docker compose up -d ${SERVICE}"
else
  DATA_DIR="${TRUSTISSUES_DATA_DIR:-./data}"
  DB_PATH="${DATA_DIR%/}/trustissues.db"
  if [ ! -d "${DATA_DIR}" ]; then
    echo "error: data dir not found: ${DATA_DIR}" >&2
    exit 1
  fi
  # Refuse while something still holds the database open.
  #
  # This was `command -v fuser && fuser ...`, so on any host without fuser the
  # whole guard silently evaporated and the restore proceeded under a live
  # writer, which is the case that silently undoes the restore. README states
  # flatly that it "refuses while the service is running", so a missing tool
  # must not quietly downgrade that promise. fuser is not in coreutils and is
  # absent from slim images, which is exactly where a panicked 3am restore runs.
  #
  # Judge these on their OUTPUT, never on their exit status.
  #
  # macOS fuser exits 0 with an EMPTY holder list when nothing has the file
  # open, so `fuser file >/dev/null` is true on every macOS host and the old
  # guard refused every native restore there. It never showed up because these
  # scripts had no tests: the estate rule "capture the output and test the
  # content, never the pipeline exit status" applies to process probes too.
  # Both tools print one PID per holder and nothing when there are none.
  HOLDERS=""
  if command -v lsof >/dev/null 2>&1; then
    HOLDERS="$(lsof -t -- "${DB_PATH}" 2>/dev/null || true)"
  elif command -v fuser >/dev/null 2>&1; then
    HOLDERS="$(fuser "${DB_PATH}" 2>/dev/null || true)"
  fi
  if [ -n "$(printf '%s' "${HOLDERS}" | tr -d '[:space:]')" ]; then
    echo "error: ${DB_PATH} is open by another process (${HOLDERS}); stop Trustissues first" >&2
    exit 1
  fi
  if ! command -v lsof >/dev/null 2>&1 && ! command -v fuser >/dev/null 2>&1; then
    echo "warning: neither fuser nor lsof is available, so it cannot be verified that" >&2
    echo "         Trustissues is stopped. A running writer will checkpoint its old WAL" >&2
    echo "         over the restored file and silently undo this restore." >&2
    echo "         Stop the service, then re-run with TRUSTISSUES_RESTORE_FORCE=1." >&2
    if [ "${TRUSTISSUES_RESTORE_FORCE:-}" != "1" ]; then
      exit 1
    fi
  fi

  # Keep the database being replaced.
  #
  # The restore is the one operation with no second copy: it used to `cp` over
  # the live file and `rm` its WAL, so a snapshot that turned out to be the
  # wrong one, or taken under a different vault key, had already destroyed the
  # only thing that could still be read. Moving it aside costs one rename and
  # makes the whole operation reversible.
  if [ -f "${DB_PATH}" ]; then
    ASIDE="${DB_PATH}.replaced-$(date -u +%Y%m%dT%H%M%SZ)"
    mv "${DB_PATH}" "${ASIDE}"
    # The sidecars belong to the database just moved aside, never to the
    # incoming one. Keep them together so the pre-restore state stays openable.
    #
    # Full if blocks, not `[ -f x ] && mv x y`: under `set -e` that one-liner
    # returns non-zero when the sidecar is absent, which is the NORMAL case
    # (a cleanly stopped service has no WAL), and kills the restore right after
    # the live database has been moved aside. Caught by test-backup-restore.sh.
    if [ -f "${DB_PATH}-wal" ]; then
      mv "${DB_PATH}-wal" "${ASIDE}-wal"
    fi
    if [ -f "${DB_PATH}-shm" ]; then
      mv "${DB_PATH}-shm" "${ASIDE}-shm"
    fi
    echo "previous database kept at: ${ASIDE}"
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

#!/usr/bin/env bash
#
# compact-db.sh - rebuild the LIVE database to destroy cleartext already sitting
# in its free pages. One-time, manual, never scheduled.
#
# WHY THIS EXISTS
#
# SQLite does not zero what it frees. A deleted row's bytes, and the OLD bytes of
# any row an UPDATE rewrote, stay verbatim in the page they used to occupy; a
# page that empties out joins the freelist still holding its content. Nothing
# reads those bytes through SQL again, and `grep` on the file finds them anyway.
#
# Migration 00040 encrypted vault entry names at rest. Its backfill sweep rewrote
# every row, which FREED the old cleartext rather than overwriting it. So on any
# database that predates 00040 the column reads as ciphertext while the file
# still holds the plaintext names. THREAT-MODEL.md treats an off-host copy as a
# lower-trust location than the host, and the entire argument for shipping this
# file off-box is that it is ciphertext.
#
# Two other changes ship alongside this script and neither one replaces it:
#
#   the server now opens with _secure_delete=on   zeroes pages as they are freed
#                                                 FROM NOW ON. Does nothing to
#                                                 pages that are already free.
#   backup.sh now uses VACUUM INTO                the SNAPSHOT is rebuilt, so it
#                                                 never carries the freelist.
#                                                 The live file is untouched.
#
# So after deploying those two, new snapshots are clean and new deletes are
# zeroed, and the live file on disk still holds every byte of pre-existing
# residue. Closing that last part means rebuilding the live file, which is what
# this script does, and it is a production operation with real consequences:
#
#   - VACUUM takes a write lock and rebuilds the whole database. Writers block
#     for the duration. Trustissues is single-writer already (_txlock=immediate),
#     so this is a longer version of something the app does anyway, but it is
#     still an outage for writes.
#   - It needs roughly 2x the database size in free space: SQLite builds the new
#     file before it replaces the old one.
#   - It cannot run inside a transaction.
#
# That is why it is a script an operator runs deliberately, with a maintenance
# window, and NOT something the server does on boot. Do not add it to a timer.
#
# USAGE
#
#   scripts/compact-db.sh                      # dry run: report, change nothing
#   scripts/compact-db.sh --yes                # actually compact
#   TRUSTISSUES_DATA_DIR=/opt/trustissues/data scripts/compact-db.sh --yes
#   scripts/compact-db.sh --yes /var/lib/.../_data
#
# The dry run is the default ON PURPOSE. Every other script in this directory is
# safe to run to see what it says; this one rewrites the only live copy of the
# vault, so it makes you ask twice.
#
# RECOMMENDED ORDER
#
#   1. scripts/backup.sh /secure/backups        take a snapshot first
#   2. stop the server (systemctl stop trustissues, or docker compose stop)
#   3. scripts/compact-db.sh --yes              rebuild
#   4. start the server, reveal one secret to prove the key still decrypts
#
# Step 2 is strongly recommended rather than enforced: VACUUM against a running
# server works, it just means every write blocks until it finishes and a slow
# disk turns that into user-visible timeouts.
#
# Exit codes: 0 ok (including a dry run), 1 usage/precondition error, 2 the
# compaction itself failed.

set -euo pipefail

APPLY=0
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --yes|-y)   APPLY=1; shift ;;
    --dry-run)  APPLY=0; shift ;;
    -h|--help)  sed -n '2,70p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --)         shift; break ;;
    -*)         echo "error: unknown option $1" >&2
                echo "usage: $0 [--yes] [data-dir]" >&2
                exit 1 ;;
    *)          break ;;
  esac
done

DATA_DIR="${1:-${TRUSTISSUES_DATA_DIR:-./data}}"
DB_PATH="${DATA_DIR%/}/trustissues.db"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "error: sqlite3 CLI not found on PATH; install it (apt-get install -y sqlite3)" >&2
  exit 1
fi

if [ ! -f "${DB_PATH}" ]; then
  echo "error: database not found at ${DB_PATH}" >&2
  echo "  set TRUSTISSUES_DATA_DIR to the directory that holds trustissues.db" >&2
  exit 1
fi

# file_size <path> - bytes, via whichever stat this host has, 0 if absent.
#
# GNU and BSD stat disagree on the flag AND on what -f means, the same trap
# snapshot-lib.sh documents at length in file_mode(). Probe, then read.
file_size() {
  [ -f "$1" ] || { echo 0; return 0; }
  if stat -c '%s' "$1" >/dev/null 2>&1; then
    stat -c '%s' "$1"
  elif stat -f '%z' "$1" >/dev/null 2>&1; then
    stat -f '%z' "$1"
  else
    wc -c < "$1" | tr -d ' '
  fi
}

human() {
  awk -v b="$1" 'BEGIN{
    split("B KB MB GB TB",u," "); i=1
    while (b>=1024 && i<5) { b/=1024; i++ }
    printf (i==1 ? "%d %s\n" : "%.1f %s\n"), b, u[i]
  }'
}

DB_BYTES="$(file_size "${DB_PATH}")"
WAL_BYTES="$(file_size "${DB_PATH}-wal")"

# READING A WAL DATABASE IS NOT A READ-ONLY OPEN
#
# This is the bug that made this script a no-op on every database it mattered
# on, so it gets the full explanation.
#
# WAL mode keeps its index in a -shm shared-memory file, and a connection opened
# SQLITE_OPEN_READONLY cannot create one. On a cleanly stopped server the -wal
# and -shm sidecars are gone, so the probe simply fails:
#
#   $ sqlite3 -readonly trustissues.db 'PRAGMA freelist_count;'
#   Error: stepping, unable to open database file (14)
#
# Note WHICH pragmas fail, because it is what made the result so convincing.
# page_size is answered out of the 100-byte file header while the file is being
# opened and still returns 4096. freelist_count has to step the pager into the
# WAL machinery, and does not. Every probe here used to end in `|| echo 0`, so
# that failure printed as
#
#   free pages:    0 x 4096B = 0 B of unreachable old content
#   note: the freelist is already empty, so there is no residue to destroy.
#
# A measured-looking zero, with a real page size beside it, from a probe that
# never opened the database. And it fired hardest exactly where it cost the
# most: step 2 of the RECOMMENDED ORDER above tells the operator to stop the
# server, and stopping the server is what removes the -shm. Following the
# instructions was what guaranteed the wrong answer.
#
# db_uri renders a path as a file: URI for the immutable fallback below.
# Everything after the first '?' is parsed as parameters, so a data directory
# containing one would otherwise become a truncated filename plus a bogus
# option -- and '#' ends the path, and a literal '%' starts an escape.
db_uri() {
  local p="$1" out="" c i=0
  case "$p" in /*) ;; *) p="${PWD}/$p" ;; esac
  while [ "$i" -lt "${#p}" ]; do
    c="${p:$i:1}"
    case "$c" in
      '%') out="${out}%25" ;;
      '?') out="${out}%3f" ;;
      '#') out="${out}%23" ;;
      ' ') out="${out}%20" ;;
      *)   out="${out}${c}" ;;
    esac
    i=$((i + 1))
  done
  printf 'file:%s' "${out}"
}

# The journal mode straight out of the file header, which needs no open at all:
# byte 18 of the header is the write version, 1 for a rollback journal and 2 for
# WAL. Used when the immutable fallback answered, because an immutable
# connection reports journal_mode as "delete" whatever the file actually says --
# true of that connection, and misleading about the database.
header_journal_mode() {
  local v
  v="$(od -An -tu1 -j18 -N1 "$1" 2>/dev/null | tr -d ' ')"
  case "$v" in
    1) echo "rollback journal" ;;
    2) echo "wal" ;;
    *) echo "unknown" ;;
  esac
}

# probe_counters - print "<page_size> <freelist_count> <journal_mode> <how>",
# or fail with the reason in PROBE_ERR. All three values come from ONE
# connection so they cannot disagree with each other.
PROBE_ERR=""
probe_counters() {
  local out
  if out="$(sqlite3 -readonly "${DB_PATH}" 'PRAGMA page_size; PRAGMA freelist_count; PRAGMA journal_mode;' 2>&1)"; then
    printf '%s %s %s read-only\n' \
      "$(printf '%s\n' "${out}" | sed -n 1p)" \
      "$(printf '%s\n' "${out}" | sed -n 2p)" \
      "$(printf '%s\n' "${out}" | sed -n 3p)"
    return 0
  fi
  PROBE_ERR="${out}"

  # immutable=1 promises SQLite the file cannot change underneath it, which is
  # what lets it skip the -shm entirely. That promise is only true when there is
  # no -wal sidecar holding committed frames this read would then ignore, so it
  # is gated on the sidecar being absent rather than offered as a general
  # workaround: reading PAST a populated WAL would under-report the freelist,
  # which is the same wrong answer in a different disguise.
  if [ ! -e "${DB_PATH}-wal" ]; then
    if out="$(sqlite3 -readonly "$(db_uri "${DB_PATH}")?immutable=1" 'PRAGMA page_size; PRAGMA freelist_count;' 2>&1)"; then
      printf '%s %s %s immutable\n' \
        "$(printf '%s\n' "${out}" | sed -n 1p)" \
        "$(printf '%s\n' "${out}" | sed -n 2p)" \
        "$(header_journal_mode "${DB_PATH}")"
      return 0
    fi
    PROBE_ERR="${PROBE_ERR} | immutable retry: ${out}"
  fi

  # Last resort, and ONLY when we are already committed to rewriting the file.
  # A read-write open creates the -wal/-shm sidecars, owned by whoever ran this
  # script; doing that during a DRY RUN would break the promise on the tin
  # ("report, change nothing") and can leave root-owned sidecars next to a
  # database the service user has to open. With --yes we are about to VACUUM
  # through exactly such a connection anyway, so it costs nothing new.
  if [ "${APPLY}" = "1" ]; then
    if out="$(sqlite3 "${DB_PATH}" 'PRAGMA page_size; PRAGMA freelist_count; PRAGMA journal_mode;' 2>&1)"; then
      printf '%s %s %s read-write\n' \
        "$(printf '%s\n' "${out}" | sed -n 1p)" \
        "$(printf '%s\n' "${out}" | sed -n 2p)" \
        "$(printf '%s\n' "${out}" | sed -n 3p)"
      return 0
    fi
    PROBE_ERR="${PROBE_ERR} | read-write retry: ${out}"
  fi
  return 1
}

# The freelist is the residue, measured rather than guessed. freelist_count is
# pages currently free; multiplied by page_size that is how many bytes of old
# content this file is carrying that no query will ever return.
if ! COUNTERS="$(probe_counters)"; then
  echo "error: could not read the page counters out of ${DB_PATH}." >&2
  echo "       sqlite3 said: ${PROBE_ERR}" >&2
  echo >&2
  echo "       This script will not guess. A freelist it could not measure used" >&2
  echo "       to print as '0 pages', which reads as 'there is no residue to" >&2
  echo "       destroy' on a database that may be full of it." >&2
  echo >&2
  echo "       In WAL mode a read-only open needs the -shm sidecar, which only" >&2
  echo "       exists while something has the database open. If a -wal file is" >&2
  echo "       sitting there without a -shm, the server did not shut down" >&2
  echo "       cleanly: start it once and stop it again, or re-run with --yes," >&2
  echo "       which may open read-write." >&2
  exit 1
fi
PAGE_SIZE="$(printf '%s' "${COUNTERS}" | cut -d' ' -f1)"
FREE_PAGES="$(printf '%s' "${COUNTERS}" | cut -d' ' -f2)"
JOURNAL="$(printf '%s' "${COUNTERS}" | cut -d' ' -f3)"
PROBE_HOW="$(printf '%s' "${COUNTERS}" | cut -d' ' -f4)"

# A probe that "succeeded" and printed something that is not a number is the
# same class of failure as one that did not run: refuse it rather than let it
# reach the arithmetic below, where an empty string is silently zero.
case "${PAGE_SIZE}" in ''|*[!0-9]*) BAD_COUNTER="page_size=${PAGE_SIZE}" ;; *) BAD_COUNTER="" ;; esac
case "${FREE_PAGES}" in ''|*[!0-9]*) BAD_COUNTER="${BAD_COUNTER} freelist_count=${FREE_PAGES}" ;; esac
if [ -n "${BAD_COUNTER}" ]; then
  echo "error: sqlite3 returned a non-numeric page counter (${BAD_COUNTER})." >&2
  echo "       Refusing to report a freelist size derived from it." >&2
  exit 1
fi
FREE_BYTES=$(( PAGE_SIZE * FREE_PAGES ))

echo "database:      ${DB_PATH}"
echo "size:          $(human "${DB_BYTES}")"
echo "wal sidecar:   $(human "${WAL_BYTES}")"
echo "journal mode:  ${JOURNAL}"
echo "free pages:    ${FREE_PAGES} x ${PAGE_SIZE}B = $(human "${FREE_BYTES}") of unreachable old content (read ${PROBE_HOW})"
echo

# Free space, on the filesystem holding the database. VACUUM writes the rebuilt
# database before it drops the original, so the peak requirement is about twice
# the current size. Refusing here is much kinder than running out of disk
# halfway through a rebuild of the live vault.
#
# df -P for the POSIX format; the value is in 1024-byte blocks, which is the one
# thing -P actually pins down across GNU and BSD.
NEED_KB=$(( (DB_BYTES / 1024) * 2 + 1024 ))
AVAIL_KB="$(df -P "${DATA_DIR}" 2>/dev/null | awk 'NR==2{print $4}' || echo "")"
if [ -n "${AVAIL_KB}" ]; then
  echo "free space:    $(human $(( AVAIL_KB * 1024 ))) available, $(human $(( NEED_KB * 1024 ))) needed (about 2x the database)"
  if [ "${AVAIL_KB}" -lt "${NEED_KB}" ]; then
    echo >&2
    echo "error: not enough free space on the filesystem holding the database." >&2
    echo "       VACUUM builds the new file before dropping the old one, so it needs" >&2
    echo "       room for both at once. Free space or point SQLITE_TMPDIR at a" >&2
    echo "       larger filesystem, then run this again." >&2
    exit 1
  fi
else
  echo "free space:    could not determine (df unavailable); VACUUM needs about 2x $(human "${DB_BYTES}")"
fi

if [ "${FREE_PAGES}" = "0" ] && [ "${WAL_BYTES}" = "0" ]; then
  echo
  echo "note: the freelist is already empty, so there is no residue to destroy."
  echo "      Compacting anyway is harmless but pointless."
fi

if [ "${APPLY}" != "1" ]; then
  echo
  echo "DRY RUN. Nothing has been changed."
  echo "  This would checkpoint the WAL, run VACUUM (rebuilding the live database"
  echo "  in place, blocking writers), checkpoint again, and verify integrity."
  echo
  echo "  Take a backup first:  scripts/backup.sh /secure/backups"
  echo "  Stop the server:      systemctl stop trustissues   (or docker compose stop)"
  echo "  Then re-run with:     $0 --yes ${DATA_DIR}"
  exit 0
fi

echo
echo "compacting. Writers block until this finishes."

# Checkpoint BEFORE the rebuild.
#
# In WAL mode a committed page lives in the -wal sidecar until a checkpoint moves
# it into the main file. Those frames are page IMAGES, so a frame written before
# migration 00040 can still hold a cleartext entry name even though the main file
# has moved on. VACUUM rebuilds the main database and would leave that sidecar
# sitting next to it, so fold it in first and again afterwards.
#
# TRUNCATE (rather than PASSIVE or FULL) sets the -wal file length to zero, which
# is the part that matters: a checkpoint that merely rewinds the write pointer
# leaves the old frames readable in the file.
#
# Not fatal if it cannot complete. TRUNCATE needs every reader to have finished,
# so on a running server it can come back busy. The VACUUM still rebuilds the
# main file; the second checkpoint below gets the sidecar.
if ! sqlite3 "${DB_PATH}" 'PRAGMA busy_timeout=60000; PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null 2>&1; then
  echo "warning: the pre-VACUUM checkpoint did not complete (readers still active?)." >&2
  echo "         Continuing; the post-VACUUM checkpoint is the one that must land." >&2
fi

# The rebuild.
#
# secure_delete is set on this connection too. VACUUM alone already drops the
# freelist, so this is belt and braces for the pages VACUUM itself frees while it
# works, and it costs nothing on a one-shot maintenance run.
#
# busy_timeout is 5 minutes, not the app's 5 seconds: this deliberately waits for
# a live writer rather than dying instantly, because the operator has a window
# open and a "database is locked" 200ms in wastes it.
# >/dev/null because a PRAGMA that SETS a value also RETURNS it, so without this
# the operator's transcript gets a bare "300000" and "1" between the progress
# lines, which reads like a diagnostic code rather than like the echo of a
# setting. Only stdout is dropped; a real error still comes back on stderr.
if ! sqlite3 "${DB_PATH}" 'PRAGMA busy_timeout=300000; PRAGMA secure_delete=ON; VACUUM;' >/dev/null; then
  echo "error: VACUUM failed; the database is unchanged" >&2
  echo "       If it said 'database is locked', stop the server and run this again." >&2
  echo "       If it said 'disk is full', free space and run this again." >&2
  exit 2
fi

# Checkpoint AFTER the rebuild, and this one is load-bearing rather than
# opportunistic. VACUUM's own writes go through the WAL, so at this point the
# sidecar holds the rebuilt pages and, worse, may still hold pre-rebuild frames.
# Truncating it to zero length is what stops the compaction being undone on disk
# by the file sitting next to it.
if ! sqlite3 "${DB_PATH}" 'PRAGMA busy_timeout=60000; PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null 2>&1; then
  echo "warning: the post-VACUUM checkpoint did not complete." >&2
  echo "         The main database is compacted, but ${DB_PATH}-wal may still hold" >&2
  echo "         old page images. Stop the server and run this script again to" >&2
  echo "         clear it (a clean shutdown also checkpoints and removes it)." >&2
fi

# Verify, rather than trusting the exit status. This is the last moment anyone is
# paying attention, and an unreadable vault discovered next Tuesday is worse than
# one discovered now with a fresh backup in hand.
INTEGRITY="$(sqlite3 "${DB_PATH}" 'PRAGMA integrity_check;' 2>&1 || true)"
if [ "${INTEGRITY}" != "ok" ]; then
  echo >&2
  echo "error: the compacted database FAILS integrity_check." >&2
  echo "       sqlite3 said: ${INTEGRITY}" >&2
  echo "       Restore the snapshot you took before running this:" >&2
  echo "         scripts/restore.sh <snapshot> ${DATA_DIR}" >&2
  exit 2
fi

NEW_BYTES="$(file_size "${DB_PATH}")"
# Same probe as before the rebuild, for the same reason: sqlite3 has closed the
# last connection by now, so the -shm is gone again and a bare read-only open
# fails exactly as it did above. This one used to fall back to '?', which is at
# least honest, but it is the number that proves the rebuild worked.
if NEW_COUNTERS="$(probe_counters)"; then
  NEW_FREE="$(printf '%s' "${NEW_COUNTERS}" | cut -d' ' -f2)"
else
  NEW_FREE="unreadable (${PROBE_ERR})"
fi
NEW_WAL="$(file_size "${DB_PATH}-wal")"

echo
echo "compacted: $(human "${DB_BYTES}") -> $(human "${NEW_BYTES}")   (freelist ${FREE_PAGES} -> ${NEW_FREE} pages, wal now $(human "${NEW_WAL}"))"
echo "integrity_check: ok"
echo
echo "The live database no longer carries the freed cleartext. Two things remain"
echo "true and are worth saying out loud:"
echo "  - SNAPSHOTS TAKEN BEFORE THIS STILL CONTAIN IT. They were page copies of"
echo "    the old file. Prune them (scripts/prune-backups.sh) or, if they went"
echo "    off-host, forget them there too."
echo "  - The bytes this freed are unlinked, not shredded, at the FILESYSTEM"
echo "    layer. On a normal disk that is the end of it; if the threat model"
echo "    includes someone imaging the raw block device, that is a disk-encryption"
echo "    question and this script is not the answer to it."

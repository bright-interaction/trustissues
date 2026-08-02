#!/usr/bin/env bash
#
# snapshot-lib.sh - shared parsing for the snapshot names backup.sh writes.
#
# Sourced by prune-backups.sh and restore-drill.sh. It is one file rather than
# two copies on purpose: the estate has repeatedly improved a shared gate inside
# ONE consumer and never back-ported it, and a retention policy that disagrees
# with the drill about which snapshot is "newest" deletes the file the drill was
# about to prove. One parser, one answer.
#
# The name format is fixed by backup.sh:
#
#   trustissues-YYYYMMDDTHHMMSSZ.db      (always UTC, always zero padded)
#
# Everything here is integer arithmetic on that string. No `date -d` and no
# `date -j -f`: those two spellings are mutually exclusive (GNU vs BSD) and the
# restore drill has to run on whatever host the operator is holding at the time.
# Deriving the instant from the NAME also means a snapshot copied off the box,
# or restored from cold storage with a fresh mtime, still reports the moment it
# was actually taken instead of the moment it was last touched.

# The one authoritative pattern. Anything that does not match is not a snapshot
# this tooling wrote, so prune-backups.sh must never delete it and the drill
# must never pick it.
SNAPSHOT_GLOB='trustissues-*.db'
SNAPSHOT_RE='^trustissues-[0-9]{8}T[0-9]{6}Z\.db$'

# snapshot_stamp_valid <basename> - true when the name is a real snapshot name.
snapshot_stamp_valid() {
  printf '%s' "$1" | grep -Eq "${SNAPSHOT_RE}"
}

# days_from_civil <y> <m> <d> - days since 1970-01-01, Hinnant's civil algorithm.
#
# 10# prefixes everywhere are load bearing, not decoration: bash reads a
# zero-padded "08" as octal and dies with "value too great for base", so August
# and September of every year would abort the prune with a syntax error while
# the other ten months worked. That is the kind of bug that ships green.
days_from_civil() {
  local y m d era yoe doy doe mp
  y=$((10#$1)); m=$((10#$2)); d=$((10#$3))
  if [ "${m}" -le 2 ]; then y=$((y - 1)); fi
  if [ "${y}" -ge 0 ]; then era=$((y / 400)); else era=$(((y - 399) / 400)); fi
  yoe=$((y - era * 400))
  if [ "${m}" -gt 2 ]; then mp=$((m - 3)); else mp=$((m + 9)); fi
  doy=$(((153 * mp + 2) / 5 + d - 1))
  doe=$((yoe * 365 + yoe / 4 - yoe / 100 + doy))
  echo $((era * 146097 + doe - 719468))
}

# snapshot_day <basename> - days since the epoch for the snapshot's date part.
snapshot_day() {
  local s="$1"
  days_from_civil "${s:12:4}" "${s:16:2}" "${s:18:2}"
}

# snapshot_epoch <basename> - UTC seconds since 1970 for the whole stamp.
snapshot_epoch() {
  local s="$1" day hh mm ss
  day="$(snapshot_day "${s}")"
  hh=$((10#${s:21:2})); mm=$((10#${s:23:2})); ss=$((10#${s:25:2}))
  echo $((day * 86400 + hh * 3600 + mm * 60 + ss))
}

# snapshot_week <basename> - the 7-day bucket a snapshot falls in.
#
# These are 7-day blocks counted from the epoch (so they run Thursday to
# Wednesday), NOT ISO calendar weeks. The retention docs say so. It matters only
# in that "keep 4 weekly" means "the newest snapshot in each of the last 4
# 7-day blocks", which is the property the operator actually cares about, and it
# needs no calendar table to compute.
snapshot_week() {
  local day
  day="$(snapshot_day "$1")"
  echo $((day / 7))
}

# file_mode <path> - the octal permission bits, or empty if neither stat works.
#
# GNU and BSD stat disagree on everything, including on what `-f` means: on BSD
# it introduces the format string, on GNU it is --file-system and takes no
# argument. So the obvious
#
#   MODE="$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null)"
#
# is broken on Linux in a way that is invisible on a Mac. GNU stat reads '%Lp'
# as a FILENAME, fails on it, succeeds on the real file, and exits non-zero, so
# the `||` runs the second stat as well and the command substitution captures
# BOTH outputs: "…filesystem info…\n600". The drill then reports "the restored
# database is mode <a page of filesystem status>, expected 600" and fails every
# week on exactly the hosts it ships to. Probe first, then read.
file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"                 # GNU coreutils
  elif stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"                # BSD / macOS
  else
    echo ""
  fi
}

# list_snapshots <dir> - every valid snapshot in <dir>, NEWEST FIRST, one per line.
#
# The names are fixed width and zero padded, so a reverse lexical sort is a
# reverse chronological sort. Filtered through the regex so a stray
# `trustissues-old.db` or a half-written `.part` can never be treated as a
# snapshot: prune would delete real backups to make room for it in the policy,
# and the drill would try to restore it.
list_snapshots() {
  local dir="$1" path base
  [ -d "${dir}" ] || return 0
  while IFS= read -r path; do
    [ -n "${path}" ] || continue
    base="$(basename "${path}")"
    if snapshot_stamp_valid "${base}"; then
      printf '%s\n' "${path}"
    fi
  done < <(find "${dir}" -maxdepth 1 -type f -name "${SNAPSHOT_GLOB}" | LC_ALL=C sort -r)
}

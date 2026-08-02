#!/usr/bin/env bash
#
# trustissues-backup-alert.sh - paged by systemd via OnFailure= on
# trustissues-backup.service and trustissues-restore-drill.service.
#
# Invoked by: trustissues-backup-alert@<failed-unit>.service
# Config:     /etc/trustissues/backup.env  (same file the backup reads, so
#             there is one file to install and one credential to rotate)
#
# WHY THIS FILE EXISTS AT ALL, spelled out because the estate has now been bitten
# by every one of these separately:
#
#   1. OnFailure= is a [Unit] directive. Put in [Service] it is parsed as an
#      unknown key and DROPPED, with one line in the journal and no other
#      symptom, so every failure is silent. That is what happened to
#      dockyard-backup.service between the day it was written and 2026-07-27.
#   2. The unit named by OnFailure= has to exist. dockyard's did not, so even
#      the correct section would have alerted nobody.
#   3. Outbound port 465 is BLOCKED on the estate host. Sending to
#      smtps://host:465 does not error, it HANGS until the timeout, which reads
#      exactly like "the alerter did nothing". 587 + STARTTLS is open and
#      verified. See the SMTP_URL block at the bottom.
#   4. `systemctl status` said "active" while the alert unit had never run,
#      because nothing ever asserted the chain end to end. install.sh has a
#      --test-alert flag that fires the whole path on demand.
#
# Design rules, mirroring the estate's other two alerters on purpose:
#   - NEVER exit non-zero. If the alerter fails, systemd would page about the
#     alerter and bury the real failure. Log it and move on.
#   - Missing or half-filled config exits 0 quietly. A host with no alerting
#     configured must not turn one failed backup into two failed units.
#   - SMTP_PASS goes to curl via --user only. Never echoed, never in argv logs
#     beyond what curl itself does.

set -u

# The override exists so scripts/test-backup-restore.sh can drive the two paths
# that matter without a real /etc/trustissues (no config at all, and a config
# with a blank required value). The systemd units never set it, and the units are
# the only thing that runs this as root.
CONFIG_FILE="${TRUSTISSUES_ALERT_CONFIG:-/etc/trustissues/backup.env}"
FAILURE_LOG="/var/log/trustissues-backup-failures.log"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_S="$(hostname -s 2>/dev/null || echo trustissues)"

# systemd passes the failed unit's name as %i. Validate it before handing it to
# journalctl: it is an instance name from a unit file, so it should never be
# anything but a unit name, and a script that runs as root should not be the one
# place that assumes so.
FAILED_UNIT="${1:-trustissues-backup.service}"
if ! printf '%s' "${FAILED_UNIT}" | grep -Eq '^[A-Za-z0-9@:_.\-]+\.(service|timer)$'; then
  echo "[${TIMESTAMP}] alert: refusing suspicious unit name '${FAILED_UNIT}', using default"
  FAILED_UNIT="trustissues-backup.service"
fi

if [ ! -f "${CONFIG_FILE}" ]; then
  echo "[${TIMESTAMP}] alert: ${CONFIG_FILE} not found, skipping email"
  exit 0
fi

# shellcheck source=/dev/null
set -a
. "${CONFIG_FILE}"
set +a

for v in ALERT_TO SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_FROM; do
  eval "val=\${${v}:-}"
  if [ -z "${val}" ]; then
    echo "[${TIMESTAMP}] alert: ${v} is not set in ${CONFIG_FILE}, skipping email"
    exit 0
  fi
done

# Where the failure text comes from. systemd hosts have the journal; the cron
# fallback in deploy/cron/ has no unit and no journal at all, so it points
# TRUSTISSUES_ALERT_LOG at the log file it redirects into. Without this branch
# the cron path would send a mail whose entire body is "(journalctl
# unavailable)", which tells the reader that something broke and nothing about
# what, which is most of the way back to no alerting.
if [ -n "${TRUSTISSUES_ALERT_LOG:-}" ] && [ -f "${TRUSTISSUES_ALERT_LOG}" ]; then
  JOURNAL_TAIL="$(tail -n 40 "${TRUSTISSUES_ALERT_LOG}" 2>&1 || echo '(log unreadable)')"
  SOURCE_DESC="${TRUSTISSUES_ALERT_LOG}"
elif command -v journalctl >/dev/null 2>&1; then
  JOURNAL_TAIL="$(journalctl -u "${FAILED_UNIT}" -n 40 --no-pager 2>&1 \
    || echo '(journalctl failed)')"
  SOURCE_DESC="journal for ${FAILED_UNIT}"
else
  JOURNAL_TAIL="(no journalctl on this host and TRUSTISSUES_ALERT_LOG is not set, so there is no failure text to include)"
  SOURCE_DESC="nothing"
fi

# Name the concrete cause up front so the mail is actionable from a phone
# without SSHing in. Every one of these is a failure this backup path can
# actually produce.
HINT=""
case "${JOURNAL_TAIL}" in
  *"fails integrity_check"*)
    HINT="A snapshot is CORRUPT. Do not delete it and do not prune yet; an older snapshot is probably still good. Run: scripts/restore-drill.sh \$TRUSTISSUES_BACKUP_DIR" ;;
  *"No space left"*|*"no space left"*|*"disk I/O error"*|*"database or disk is full"*)
    HINT="Disk full. This also stops the LIVE database from writing. Check df -h, then reduce TRUSTISSUES_BACKUP_KEEP_DAILY/WEEKLY in ${CONFIG_FILE} and run scripts/prune-backups.sh." ;;
  *"is not running"*|*"timer is not running"*|*"h old (limit"*)
    HINT="The drill found the newest snapshot too OLD, which means backups stopped running some time ago. Check: systemctl status trustissues-backup.timer && systemctl list-timers trustissues-backup.timer" ;;
  *"canary row did not survive"*)
    HINT="The snapshot restored but the expected row was missing. Either the canary configuration is stale or the snapshot is not of this database. Do NOT restore it over production." ;;
  *"database not found"*)
    HINT="TRUSTISSUES_DATA_DIR in ${CONFIG_FILE} does not point at a directory containing trustissues.db. On the Compose deploy this is the volume's _data path and needs root." ;;
  *"sqlite3 CLI not found"*)
    HINT="sqlite3 is missing from the host PATH. Install it (apt-get install -y sqlite3) or run the backup inside the container." ;;
  *"same filesystem"*)
    HINT="Backups are on the same filesystem as the database. Not the failure itself, but fix it: one full disk loses both." ;;
esac

mkdir -p "$(dirname "${FAILURE_LOG}")" 2>/dev/null || true
echo "[${TIMESTAMP}] ${FAILED_UNIT} failed on ${HOSTNAME_S}. ${HINT:-no hint matched}" \
  >> "${FAILURE_LOG}" 2>/dev/null || true

MSG_FILE="$(mktemp -t ti-backup-alert.XXXXXX)"
trap 'rm -f "${MSG_FILE}"' EXIT

{
  printf 'From: %s\r\n' "${SMTP_FROM}"
  printf 'To: %s\r\n' "${ALERT_TO}"
  printf 'Subject: [ALERT] Trustissues %s FAILED on %s\r\n' "${FAILED_UNIT}" "${HOSTNAME_S}"
  printf 'Date: %s\r\n' "$(date -R 2>/dev/null || date)"
  printf 'Content-Type: text/plain; charset=UTF-8\r\n'
  printf '\r\n'
  printf '%s failed at %s on %s.\r\n' "${FAILED_UNIT}" "${TIMESTAMP}" "${HOSTNAME_S}"
  printf '\r\n'
  printf 'Trustissues holds login credentials, API keys and TOTP seeds. A failed\r\n'
  printf 'backup means there is no verified recovery point for that data since the\r\n'
  printf 'last successful run, and a failed restore drill means the snapshots you\r\n'
  printf 'do have are unproven.\r\n'
  printf '\r\n'
  if [ -n "${HINT}" ]; then
    printf 'LIKELY CAUSE: %s\r\n' "${HINT}"
    printf '\r\n'
  fi
  printf 'Last 40 lines from %s:\r\n' "${SOURCE_DESC}"
  printf -- '----\r\n'
  printf '%s\r\n' "${JOURNAL_TAIL}"
  printf -- '----\r\n'
  printf '\r\n'
  printf 'Re-run the backup:  systemctl start trustissues-backup.service\r\n'
  printf 'Re-run the drill:   systemctl start trustissues-restore-drill.service\r\n'
  printf 'Snapshot list:      ls -l "$TRUSTISSUES_BACKUP_DIR"\r\n'
  printf '\r\n'
  printf 'The vault key is NOT in the backup and is NOT in this mail. A restore\r\n'
  printf 'needs TRUSTISSUES_VAULT_KEY from wherever you kept it, separately.\r\n'
} > "${MSG_FILE}"

# The URL scheme must match the port's TLS mode:
#   465 = implicit TLS -> smtps://
#   587 = STARTTLS     -> smtp:// plus --ssl-reqd, which FORCES the upgrade, so
#                         this is encrypted, not plaintext. --ssl-reqd is the
#                         difference between "TLS if offered" and "TLS or fail";
#                         without it a hostile or broken relay can strip it and
#                         curl will happily send the credentials in the clear.
#
# Prefer 587. On the estate host outbound 465 and 25 are BLOCKED by the provider
# and a send to 465 does not error, it HANGS. The `timeout 60` is what turns
# that into a logged failure inside a minute instead of a systemd unit stuck in
# "activating" for as long as curl feels like waiting.
if [ "${SMTP_PORT}" = "465" ]; then
  SMTP_URL="smtps://${SMTP_HOST}:${SMTP_PORT}"
  echo "[${TIMESTAMP}] alert: using implicit TLS on 465; if this times out, switch SMTP_PORT to 587 (many providers block 465 outbound)"
else
  SMTP_URL="smtp://${SMTP_HOST}:${SMTP_PORT}"
fi

if timeout 60 curl --silent --show-error --ssl-reqd \
     --url "${SMTP_URL}" \
     --user "${SMTP_USER}:${SMTP_PASS}" \
     --mail-from "${SMTP_FROM}" \
     --mail-rcpt "${ALERT_TO}" \
     --upload-file "${MSG_FILE}" 2>&1; then
  echo "[${TIMESTAMP}] alert: sent to ${ALERT_TO} about ${FAILED_UNIT}"
else
  echo "[${TIMESTAMP}] alert: SEND FAILED (see curl output above). The ${FAILED_UNIT} failure is the thing that matters; see ${FAILURE_LOG}."
fi

# Always 0. See the header.
exit 0

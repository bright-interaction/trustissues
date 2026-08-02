#!/usr/bin/env bash
#
# install.sh - put the backup timer, the restore drill and the failure alerter
# on a systemd host, and prove the alert path works before you rely on it.
#
# Run as root on the Trustissues host:
#
#   ./deploy/systemd/install.sh                 # install + enable
#   ./deploy/systemd/install.sh --test-alert    # send one test alert and stop
#   ./deploy/systemd/install.sh --uninstall
#
# This exists as a script rather than a list of steps in a doc because the two
# failures this workstream is guarding against are both installation failures,
# not code failures: an OnFailure= that points at a unit nobody created, and an
# alert path nobody ever fired. A README cannot check either. This does.
#
# It does NOT write /etc/trustissues/backup.env for you beyond seeding the
# example, because that file needs an SMTP password and a backup destination
# that only you know.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"

UNIT_DIR="/etc/systemd/system"
CONF_DIR="/etc/trustissues"
CONF_FILE="${CONF_DIR}/backup.env"
APP_DIR="${TRUSTISSUES_INSTALL_DIR:-/opt/trustissues}"

say()  { echo "==> $*"; }
warn() { echo "!!  $*" >&2; }
die()  { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run this as root"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found; this host does not use systemd (see the cron fallback in docs/BACKUP.md)"

UNITS="trustissues-backup.service trustissues-backup.timer
trustissues-restore-drill.service trustissues-restore-drill.timer
trustissues-backup-alert@.service"

# ---------------------------------------------------------------- --test-alert
if [ "${1:-}" = "--test-alert" ]; then
  [ -f "${APP_DIR}/deploy/systemd/trustissues-backup-alert.sh" ] \
    || die "${APP_DIR}/deploy/systemd/trustissues-backup-alert.sh is not installed yet; run this script with no arguments first"
  say "firing the alerter directly (this sends a real email)"
  "${APP_DIR}/deploy/systemd/trustissues-backup-alert.sh" trustissues-backup.service
  echo
  say "if no mail arrived, check the lines above. The two usual causes:"
  echo "    - a value in ${CONF_FILE} is empty, so the alerter skipped quietly"
  echo "    - SMTP_PORT=465 is blocked outbound and curl hit the 60s timeout; use 587"
  exit 0
fi

# ---------------------------------------------------------------- --uninstall
if [ "${1:-}" = "--uninstall" ]; then
  say "disabling timers"
  systemctl disable --now trustissues-backup.timer trustissues-restore-drill.timer 2>/dev/null || true
  for u in ${UNITS}; do
    rm -f "${UNIT_DIR}/${u}"
  done
  systemctl daemon-reload
  say "units removed. ${CONF_FILE} and your snapshots were left alone."
  exit 0
fi

# ---------------------------------------------------------------- install
say "installing scripts under ${APP_DIR}"
install -d -m 0755 "${APP_DIR}/scripts" "${APP_DIR}/deploy/systemd" "${APP_DIR}/docs"
for f in backup.sh restore.sh prune-backups.sh restore-drill.sh snapshot-lib.sh; do
  [ -f "${REPO}/scripts/${f}" ] || die "missing ${REPO}/scripts/${f}"
  install -m 0755 "${REPO}/scripts/${f}" "${APP_DIR}/scripts/${f}"
done
install -m 0755 "${HERE}/trustissues-backup-alert.sh" "${APP_DIR}/deploy/systemd/trustissues-backup-alert.sh"
[ -f "${REPO}/docs/BACKUP.md" ] && install -m 0644 "${REPO}/docs/BACKUP.md" "${APP_DIR}/docs/BACKUP.md"

say "installing units into ${UNIT_DIR}"
for u in ${UNITS}; do
  [ -f "${HERE}/${u}" ] || die "missing unit file ${HERE}/${u}"
  install -m 0644 "${HERE}/${u}" "${UNIT_DIR}/${u}"
done

# The shipped units spell /opt/trustissues literally, because a unit file has no
# variables and ExecStart= must be an absolute path. If the operator moved the
# install with TRUSTISSUES_INSTALL_DIR, the units would point at scripts that are
# not there and every timer would fail with "No such file or directory" at 03:20.
# Rewrite the installed copies to match where the scripts actually went, rather
# than documenting a knob that only half works.
if [ "${APP_DIR}" != "/opt/trustissues" ]; then
  say "rewriting unit paths from /opt/trustissues to ${APP_DIR}"
  for u in ${UNITS}; do
    sed -i.bak "s#/opt/trustissues#${APP_DIR}#g" "${UNIT_DIR}/${u}"
    rm -f "${UNIT_DIR}/${u}.bak"
  done
fi

# Every ExecStart= has to resolve to something that exists and can run. A unit
# that references a script nobody installed enables cleanly, appears in
# `systemctl list-timers`, and fails on its first trigger.
say "checking every ExecStart= resolves to an installed executable"
for u in ${UNITS}; do
  while IFS= read -r cmd; do
    [ -n "${cmd}" ] || continue
    bin="${cmd%% *}"
    [ -x "${bin}" ] || die "${u} runs ${bin}, which is not present or not executable"
  done <<EOF
$(grep -E '^ExecStart=' "${UNIT_DIR}/${u}" | sed 's/^ExecStart=//')
EOF
done

# Verify the OnFailure chain rather than assuming it.
#
# This is the check that the estate did not have. dockyard-backup.service named
# an alert unit that had never been written, and systemd reports that as nothing
# at all until the day something fails. Resolve every OnFailure= target to a
# file on disk, mapping a templated `foo@%n.service` back to `foo@.service`.
say "checking every OnFailure= target resolves to an installed unit"
for u in ${UNITS}; do
  case "${u}" in *@.service) continue ;; esac
  targets="$(grep -E '^OnFailure=' "${UNIT_DIR}/${u}" | sed 's/^OnFailure=//' || true)"
  [ -n "${targets}" ] || die "${u} has no OnFailure=; a silent backup failure is the bug this ships to prevent"
  for t in ${targets}; do
    resolved="$(printf '%s' "${t}" | sed 's/@[^.]*\.service$/@.service/')"
    [ -f "${UNIT_DIR}/${resolved}" ] \
      || die "${u} points OnFailure= at ${t}, which resolves to ${resolved} and is NOT installed"
  done
  # And that it is in the right section. Everything from the last [ ... ] header
  # before the OnFailure line has to be [Unit].
  section="$(awk '/^\[/{s=$0} /^OnFailure=/{print s; exit}' "${UNIT_DIR}/${u}")"
  [ "${section}" = "[Unit]" ] \
    || die "${u} has OnFailure= in ${section}; systemd only honours it in [Unit] and silently drops it anywhere else"
  # A Condition*= undoes everything the two checks above just proved. When a
  # condition does not hold, systemd SKIPS the unit and marks the job successful,
  # and OnFailure= is only reached from the failed state. Both units shipped a
  # ConditionPathExists= on the very EnvironmentFile whose absence is supposed to
  # page, which converted the loud failure into a silent skip on the backup AND on
  # the drill that exists to notice silence. Checked here as well as in
  # scripts/test-backup-restore.sh because this reads the INSTALLED copies, which
  # is where a hand edit lands.
  cond="$(grep -E '^Condition[A-Za-z]+=' "${UNIT_DIR}/${u}" || true)"
  [ -z "${cond}" ] \
    || die "${u} has ${cond}; a condition that does not hold marks the job SUCCESSFUL, so OnFailure= never fires. Remove it."
done

say "seeding configuration"
install -d -m 0700 "${CONF_DIR}"
if [ -f "${CONF_FILE}" ]; then
  say "${CONF_FILE} already exists, leaving it alone"
else
  install -m 0600 "${HERE}/backup.env.example" "${CONF_FILE}"
  warn "${CONF_FILE} was created from the example and is NOT usable as is."
  warn "Edit it now: TRUSTISSUES_DATA_DIR, TRUSTISSUES_BACKUP_DIR, and the SMTP settings."
fi

# shellcheck source=/dev/null
set -a; . "${CONF_FILE}"; set +a

BACKUP_DIR="${TRUSTISSUES_BACKUP_DIR:-/var/backups/trustissues}"
say "preparing ${BACKUP_DIR}"
install -d -m 0700 "${BACKUP_DIR}"
# 0700 and owned by the unit's user, which is root: these files are a credential
# store. Anything looser and every account on the box can read the vault.
chown root:root "${BACKUP_DIR}"
chmod 0700 "${BACKUP_DIR}"

case "${BACKUP_DIR}" in
  /home/*|/root/*)
    warn "TRUSTISSUES_BACKUP_DIR is under a home directory, and the units set"
    warn "ProtectHome=read-only, so the backup will fail with a permission error."
    warn "Pick something under /var, /srv or /mnt." ;;
esac

if [ -n "${TRUSTISSUES_DATA_DIR:-}" ] && [ -d "${TRUSTISSUES_DATA_DIR}" ] && command -v df >/dev/null 2>&1; then
  a="$(df -P "${BACKUP_DIR}" | awk 'NR==2{print $1}')"
  b="$(df -P "${TRUSTISSUES_DATA_DIR}" | awk 'NR==2{print $1}')"
  if [ "${a}" = "${b}" ]; then
    warn "${BACKUP_DIR} and ${TRUSTISSUES_DATA_DIR} are on the same filesystem (${a})."
    warn "One full disk or one lost volume then destroys the database and every backup."
  fi
fi

command -v sqlite3 >/dev/null 2>&1 \
  || warn "sqlite3 is not on PATH; the backup will fail until you install it (apt-get install -y sqlite3)"

say "enabling timers"
systemctl daemon-reload
systemctl enable --now trustissues-backup.timer trustissues-restore-drill.timer

echo
say "installed. Next, in this order:"
echo "    1. edit ${CONF_FILE}"
echo "    2. ${HERE}/install.sh --test-alert     # prove the alert path BEFORE you need it"
echo "    3. systemctl start trustissues-backup.service       # take one now"
echo "    4. systemctl start trustissues-restore-drill.service # prove it restores"
echo "    5. systemctl list-timers 'trustissues-*'"
echo
say "the vault key is NOT backed up by any of this. Store TRUSTISSUES_VAULT_KEY"
say "somewhere these snapshots are not. Without it every snapshot is unreadable."

#!/usr/bin/env bash
#
# Periodic correlation + AI-triage pass over recent Windows endpoint events
# (Windows Endpoint Analyzer, feature Part 3).
#
# Installed as a *user* crontab entry for the `aegisflow` account -- NOT a
# systemd unit:
#
#     */10 * * * * /home/aegisflow/app/deploy/cron-triage-endpoint-events.sh
#
# Part 3 deliberately chose host cron over a systemd timer: the repo has no
# scheduled-job framework and `triage_endpoint_events` is a plain management
# command. Pointing the crontab entry at this in-repo script keeps
# "installed" == "committed" -- the app is served straight from this git
# checkout, so there is no second copy to drift out of sync (unlike
# deploy/aegisflow.service, whose reconciliation is already tracked).
#
# All output (the command's one-line summary, plus any traceback) is
# appended to logs/triage-endpoint-events.log. flock keeps a slow AI run
# from stacking up on the next 10-minute tick.
#
# Overridable via the environment (mainly for ad-hoc runs / a different
# layout): AEGIS_APP_DIR, AEGIS_PYTHON, AEGIS_TRIAGE_LOG, AEGIS_TRIAGE_LOCK.
# Extra args are passed straight through to the management command, e.g.
#   AEGIS_TRIAGE_LOG=/dev/stdout ./deploy/cron-triage-endpoint-events.sh --dry-run

set -euo pipefail

APP_DIR="${AEGIS_APP_DIR:-/home/aegisflow/app}"
PYTHON="${AEGIS_PYTHON:-/home/aegisflow/venv/bin/python}"
LOG_FILE="${AEGIS_TRIAGE_LOG:-$APP_DIR/logs/triage-endpoint-events.log}"
LOCK_FILE="${AEGIS_TRIAGE_LOCK:-/tmp/aegis-triage-endpoint-events.lock}"

cd "$APP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"
exec >>"$LOG_FILE" 2>&1

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
trap 'echo "[$(ts)] triage_endpoint_events: FAILED (exit $?)"' ERR

echo "[$(ts)] triage_endpoint_events: start (pid $$)"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
	echo "[$(ts)] triage_endpoint_events: previous run still active; skipping this tick"
	exit 0
fi

"$PYTHON" manage.py triage_endpoint_events "$@"
echo "[$(ts)] triage_endpoint_events: done"

#!/usr/bin/env bash
# Offline ONLY: exercises synthetic Python fixtures, not real libvirt/VMs.
# The sole permanent output is one private TXT report under $HOME.
set -Eeuo pipefail
umask 077
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
for file in \
  command2_portable_fresh_count_plan.py \
  command2_target_host_preflight.py \
  command2_cold_checkpoint.py \
  test_command2_portable_fresh_count_plan.py \
  test_command2_target_host_preflight.py \
  command2_guest_identity_blueprint.py \
  test_command2_guest_identity_blueprint.py \
  test_command2_cold_checkpoint.py \
  test_command2_cold_checkpoint_capture.py
do
  [[ -f "$HERE/$file" && ! -L "$HERE/$file" ]] || {
    echo "BLOCKED: Missing/linked test input $file" >&2; exit 2;
  }
done
REPORT_BASE="$HOME"
APPROVED="$HOME/CAPE_Approved_Reports"
if [[ -d "$APPROVED" && ! -L "$APPROVED" ]] &&
   [[ "$(stat -c '%u' "$APPROVED")" == "$(id -u)" ]] &&
   [[ "$(stat -c '%a' "$APPROVED")" == "700" ]]; then
  REPORT_BASE="$APPROVED"
fi
REPORT="$(mktemp "$REPORT_BASE/CAPE_Command2_OfflinePreflightTests_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
echo "Private test report: $REPORT"
set +e
(
  set -Eeuo pipefail
  echo 'COMMAND2 PORTABLE PREFLIGHT + COLD CAPTURE GUARD OFFLINE TESTS'
  date -Is
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest discover \
    -s "$HERE" -p 'test_command2_portable_fresh_count_plan.py' -v
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest discover \
    -s "$HERE" -p 'test_command2_target_host_preflight.py' -v
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest discover \
    -s "$HERE" -p 'test_command2_cold_checkpoint*.py' -v
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest discover \
    -s "$HERE" -p 'test_command2_guest_identity_blueprint.py' -v
  echo 'RESULT: COMMAND2_OFFLINE_PREFLIGHT_TESTS_PASS'
) > "$REPORT" 2>&1
RESULT=$?
set -e
tail -n 65 "$REPORT" || true
echo "EXIT: $RESULT"
echo "REPORT: $REPORT"
echo "No VM created, started, stopped, snapshotted or networked by this runner."
exit "$RESULT"

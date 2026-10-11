#!/usr/bin/env bash
# One TXT acceptance for development-only cold checkpoint and total-count planning.
# NO snapshot capture, VM start/stop, NIC attachment, or firewall/network changes.
set -Eeuo pipefail
umask 077
[[ -t 0 ]] || { echo 'BLOCKED: Interactive terminal needed for sudo' >&2; exit 2; }
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
for file in command2_cold_checkpoint.py command2_continuation_plan.py \
  test_command2_cold_checkpoint.py test_command2_cold_checkpoint_capture.py \
  test_command2_continuation_plan.py; do
  [[ -f "$HERE/$file" && ! -L "$HERE/$file" ]] || {
    echo "BLOCKED: Missing or linked test/module: $file" >&2; exit 2;
  }
done
COUNT=5
if [[ "$#" -ge 1 ]]; then COUNT="$1"; fi
[[ "$COUNT" =~ ^[1-9][0-9]*$ ]] || { echo 'BLOCKED: Invalid target total count' >&2; exit 2; }
sudo -v || exit 2
REPORT="$(mktemp "$HOME/CAPE_Command2A_ColdAndCountPlan_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
echo "REPORT: $REPORT"
set +e
(
  set -Eeuo pipefail
  echo 'COMMAND2A COLD CHECKPOINT + COUNT PLAN - READ ONLY'
  date -Is
  echo 'STEP 1: Offline mocked unit tests'
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest discover \
    -s "$HERE" -p 'test_command2_cold_checkpoint*.py' -v
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest discover \
    -s "$HERE" -p 'test_command2_continuation_plan.py' -v
  echo 'STEP 2: Existing clone cold checkpoint PLAN - NO CAPTURE'
  sudo -n /usr/bin/python3 -B "$HERE/command2_cold_checkpoint.py" --mode plan
  echo "STEP 3: Total count $COUNT continuation PLAN - NO STAGING"
  sudo -n /usr/bin/python3 -B "$HERE/command2_continuation_plan.py" --count "$COUNT"
  echo 'RESULT: COLD_AND_COUNT_READONLY_PLAN_COMPLETE'
) >"$REPORT" 2>&1
STATUS=$?
set -e
tail -n 80 "$REPORT" || true
echo "EXIT: $STATUS"
echo "REPORT: $REPORT"
if [[ "$STATUS" != 0 ]]; then
  echo 'BLOCKED: No further host action until the report is reviewed.'
else
  echo 'PASS: Offline tests and read-only plans; NO backup or clone created.'
fi
exit "$STATUS"

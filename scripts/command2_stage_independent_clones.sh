#!/usr/bin/env bash
# Command 2A SSL-55 operator entry point: plan or stage independent no-NIC VMs.
# This is NOT the complete Command 2 deployment or malware approval.
set -Eeuo pipefail
umask 077
HERE="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MODE=plan
COUNT=""
for arg in "$@"; do
  case "$arg" in
    --plan) MODE=plan ;;
    --stage) MODE=stage ;;
    --count=*) COUNT="${arg#--count=}" ;;
    -h|--help)
      echo "Usage: bash scripts/command2_stage_independent_clones.sh [--plan|--stage] [--count=N]"
      echo "Default is read-only --plan. --stage copies disks & defines SHUT-OFF zero-NIC clones."
      exit 0 ;;
    *) echo "BLOCKED: unsupported option" >&2;exit 2;;
  esac
done
[[ -x /usr/bin/python3 || -f /usr/bin/python3 ]] ||
  { echo 'BLOCKED: Ubuntu Python3 missing' >&2;exit 2; }
[[ -f "$HERE/command2_stage_independent_clones.py" ]] ||
  { echo "BLOCKED: Command 2A script missing" >&2;exit 2; }
if [[ -z "$COUNT" ]]; then
  [[ -t 0 ]] || { echo 'BLOCKED: --count=N required if no interactive terminal' >&2;exit 2; }
  read -r -p 'How many Windows analysis clones should be prepared [1–16]? ' COUNT
fi
[[ "$COUNT" =~ ^[1-9][0-9]?$ ]] &&
  (( 10#$COUNT >= 1 && 10#$COUNT <= 16 )) ||
  { echo 'BLOCKED: count must be from 1 to 16' >&2;exit 2; }
# Canonicalize leading zero notation for argparse int.
COUNT=$((10#$COUNT))
if [[ "$MODE" == stage ]]; then
  echo 'This will write independent QCOW2 + NVRAM files and DEFINE'
  echo "$COUNT new Windows VMs, SHUT OFF with ZERO NICs. Master stays protected."
  echo 'It will not personalize Windows, start VMs or attach networks.'
  [[ -t 0 ]] || { echo 'BLOCKED: stage requires interactive console' >&2;exit 2; }
  read -r -p 'Type STAGE-COLD-CLONES to authorize: ' ACK
  [[ "$ACK" == STAGE-COLD-CLONES ]] || { echo 'BLOCKED: staging not authorized' >&2;exit 2; }
fi
sudo -v || exit 2
REPORT="$(mktemp "$HOME/CAPE_Command2A_${MODE}_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
echo "Command 2A mode: $MODE; count: $COUNT"
set +e
sudo /usr/bin/python3 "$HERE/command2_stage_independent_clones.py" \
    --mode "$MODE" --count "$COUNT" >"$REPORT" 2>&1
STATUS=$?
set -e
echo "Report: $REPORT"
echo "Exit status: $STATUS"
tail -n 35 "$REPORT" || true
echo 'Upload the TXT report; do not retry automatically if BLOCKED or partially staged.'
exit "$STATUS"
